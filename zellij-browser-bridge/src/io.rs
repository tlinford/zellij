use std::path::Path;
use std::sync::{Arc, Mutex};

use zellij_utils::consts::ipc_connect;
use zellij_utils::data::Palette;
use zellij_utils::errors::ErrorContext;
use zellij_utils::ipc::{
    ClientToServerMsg, IpcReceiverWithContext, IpcSenderWithContext, ServerToClientMsg,
};
use zellij_utils::pane_size::Size;
use zellij_utils::shared::default_palette;
use crate::virtual_client::SessionLink;

use crate::factory::SessionLinkFactory;

#[derive(Clone)]
pub struct LoopbackLink {
    sender: Arc<Mutex<Option<IpcSenderWithContext<ClientToServerMsg>>>>,
    receiver: Arc<Mutex<Option<IpcReceiverWithContext<ServerToClientMsg>>>>,
    session_name: Arc<Mutex<Option<String>>>,
    terminal_size: Size,
}

impl std::fmt::Debug for LoopbackLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackLink")
            .field("session_name", &self.session_name)
            .field("terminal_size", &self.terminal_size)
            .finish()
    }
}

impl LoopbackLink {
    pub fn new(terminal_size: Size) -> Self {
        LoopbackLink {
            sender: Arc::new(Mutex::new(None)),
            receiver: Arc::new(Mutex::new(None)),
            session_name: Arc::new(Mutex::new(None)),
            terminal_size,
        }
    }
}

impl SessionLink for LoopbackLink {
    fn send_to_server(&self, msg: ClientToServerMsg) {
        match self.sender.lock().unwrap().as_mut() {
            Some(sender) => {
                let _ = sender.send_client_msg(msg);
            },
            None => log::warn!("Relay virtual client not connected, dropping message."),
        }
    }

    fn recv_from_server(&self) -> Option<(ServerToClientMsg, ErrorContext)> {
        self.receiver
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|receiver| receiver.recv_server_msg())
    }

    fn connect_to_server(&self, path: &Path) {
        let socket = loop {
            match ipc_connect(path) {
                Ok(sock) => break sock,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        };
        let sender = IpcSenderWithContext::new(socket);
        let receiver = sender.get_receiver();
        *self.sender.lock().unwrap() = Some(sender);
        *self.receiver.lock().unwrap() = Some(receiver);
    }

    fn get_terminal_size(&self) -> Size {
        self.terminal_size
    }

    fn load_palette(&self) -> Palette {
        default_palette()
    }

    fn update_session_name(&mut self, new_session_name: String) {
        *self.session_name.lock().unwrap() = Some(new_session_name);
    }

    fn spawn_server(&self, _socket_path: &Path, _debug: bool) -> Result<(), std::io::Error> {
        // The in-process relay host only ever attaches to an already-running
        // session, so it never spawns a server. Surfacing an error here keeps
        // a misuse visible rather than silently hanging.
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "LoopbackLink cannot spawn a server; the session must already exist",
        ))
    }

    fn box_clone(&self) -> Box<dyn SessionLink> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct LoopbackLinkFactory {
    terminal_size: Size,
}

impl LoopbackLinkFactory {
    pub fn new(terminal_size: Size) -> Self {
        LoopbackLinkFactory { terminal_size }
    }
}

impl SessionLinkFactory for LoopbackLinkFactory {
    fn create(&self) -> Result<Box<dyn SessionLink>, Box<dyn std::error::Error>> {
        Ok(Box::new(LoopbackLink::new(self.terminal_size)))
    }
}
