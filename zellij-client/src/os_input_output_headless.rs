//! The client side of `zellij attach --headless`: a normal client with no terminal.
//! It reports a fixed size, never touches raw mode, reads input from stdin and
//! writes the render stream to stdout, which the caller redirects.

use std::io;
use std::path::Path;
use std::sync::mpsc::Receiver;

use zellij_utils::{
    data::Palette,
    errors::ErrorContext,
    ipc::{ClientToServerMsg, IpcReceiveError, ServerToClientMsg},
    pane_size::Size,
};

use crate::os_input_output::{AsyncSignals, AsyncStdin, ClientOsApi, ClientOsInputOutput};

#[derive(Clone, Debug)]
pub struct HeadlessClientOsApi {
    inner: ClientOsInputOutput,
    size: Size,
}

impl HeadlessClientOsApi {
    pub fn new(inner: ClientOsInputOutput, size: Size) -> Self {
        HeadlessClientOsApi { inner, size }
    }
}

/// An empty read means stdin reached its end. That is no reason to detach, and
/// returning it would make the stdin pump call again at once, forever, so the
/// thread parks until the client is signalled or its session ends.
fn park_at_end_of_input(read: Result<Vec<u8>, &'static str>) -> Result<Vec<u8>, &'static str> {
    match read {
        Ok(bytes) if bytes.is_empty() => loop {
            std::thread::park();
        },
        other => other,
    }
}

impl ClientOsApi for HeadlessClientOsApi {
    fn get_terminal_size(&self) -> Size {
        self.size
    }
    fn set_raw_mode(&mut self) {}
    fn unset_raw_mode(&self) -> Result<(), io::Error> {
        Ok(())
    }
    fn get_stdout_writer(&self) -> Box<dyn io::Write> {
        self.inner.get_stdout_writer()
    }
    fn get_stdin_reader(&self) -> Box<dyn io::BufRead> {
        self.inner.get_stdin_reader()
    }
    fn stdin_is_terminal(&self) -> bool {
        self.inner.stdin_is_terminal()
    }
    fn stdout_is_terminal(&self) -> bool {
        self.inner.stdout_is_terminal()
    }
    fn update_session_name(&mut self, new_session_name: String) {
        self.inner.update_session_name(new_session_name)
    }
    fn read_from_stdin(&mut self) -> Result<Vec<u8>, &'static str> {
        park_at_end_of_input(self.inner.read_from_stdin())
    }
    fn box_clone(&self) -> Box<dyn ClientOsApi> {
        Box::new(self.clone())
    }
    fn send_to_server(&self, msg: ClientToServerMsg) {
        self.inner.send_to_server(msg)
    }
    fn recv_from_server(&self) -> Option<(ServerToClientMsg, ErrorContext)> {
        self.inner.recv_from_server()
    }
    fn try_recv_from_server(&self) -> Result<(ServerToClientMsg, ErrorContext), IpcReceiveError> {
        self.inner.try_recv_from_server()
    }
    fn handle_signals(
        &self,
        sigwinch_cb: Box<dyn Fn()>,
        quit_cb: Box<dyn Fn()>,
        resize_receiver: Option<Receiver<()>>,
    ) {
        self.inner
            .handle_signals(sigwinch_cb, quit_cb, resize_receiver)
    }
    fn connect_to_server(&self, path: &Path) {
        self.inner.connect_to_server(path)
    }
    fn spawn_server(&self, socket_path: &Path, debug: bool) -> Result<(), io::Error> {
        self.inner.spawn_server(socket_path, debug)
    }
    fn should_install_panic_hook(&self) -> bool {
        self.inner.should_install_panic_hook()
    }
    fn load_palette(&self) -> Palette {
        self.inner.load_palette()
    }
    fn enable_mouse(&self) -> anyhow::Result<()> {
        self.inner.enable_mouse()
    }
    fn disable_mouse(&self) -> anyhow::Result<()> {
        self.inner.disable_mouse()
    }
    fn restore_console_mode(&self) {
        self.inner.restore_console_mode()
    }
    fn env_variable(&self, name: &str) -> Option<String> {
        self.inner.env_variable(name)
    }
    fn get_async_stdin_reader(&self) -> Box<dyn AsyncStdin> {
        self.inner.get_async_stdin_reader()
    }
    fn get_async_signal_listener(&self) -> io::Result<Box<dyn AsyncSignals>> {
        self.inner.get_async_signal_listener()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os_input_output::get_client_os_input;
    use std::sync::mpsc;
    use std::time::Duration;

    fn headless(rows: usize, cols: usize) -> HeadlessClientOsApi {
        HeadlessClientOsApi::new(get_client_os_input().unwrap(), Size { rows, cols })
    }

    #[test]
    fn reports_the_size_it_was_given_instead_of_asking_a_terminal() {
        assert_eq!(
            headless(40, 120).get_terminal_size(),
            Size {
                rows: 40,
                cols: 120
            }
        );
    }

    #[test]
    fn a_clone_keeps_the_size() {
        assert_eq!(
            headless(30, 100).box_clone().get_terminal_size(),
            Size {
                rows: 30,
                cols: 100
            }
        );
    }

    #[test]
    fn raw_mode_is_never_touched() {
        // Without a terminal (as in CI) the terminal-backed client panics here
        let mut os_input = headless(40, 120);
        os_input.set_raw_mode();
        assert!(os_input.unset_raw_mode().is_ok());
    }

    #[test]
    fn input_and_errors_pass_through() {
        assert_eq!(
            park_at_end_of_input(Ok(b"ls\r".to_vec())),
            Ok(b"ls\r".to_vec())
        );
        assert_eq!(
            park_at_end_of_input(Err("Session ended")),
            Err("Session ended")
        );
    }

    #[test]
    fn end_of_input_parks_instead_of_returning_an_empty_read() {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(park_at_end_of_input(Ok(Vec::new())));
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "an empty read came back, so the stdin pump would spin on a closed pipe"
        );
    }
}
