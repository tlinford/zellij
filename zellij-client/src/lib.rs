pub mod os_input_output;

#[cfg(not(windows))]
#[path = "os_input_output_unix.rs"]
mod os_input_output_unix;
#[cfg(windows)]
#[path = "os_input_output_windows.rs"]
mod os_input_output_windows;

pub mod cli_client;
mod command_is_executing;
mod input_handler;
mod keyboard_parser;
mod nested_reannounce;
#[cfg(feature = "web_server_capability")]
pub use zellij_relay_client::attach as remote_attach;
mod stdin_ansi_parser;
mod stdin_handler;
#[cfg(windows)]
mod stdin_handler_windows;
#[cfg(feature = "web_server_capability")]
pub mod web_client;

use log::info;
use std::env::current_exe;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use zellij_utils::errors::FatalError;
use zellij_utils::shared::web_server_base_url;

#[cfg(feature = "web_server_capability")]
use futures_util::{SinkExt, StreamExt};
#[cfg(feature = "web_server_capability")]
use tokio_tungstenite::tungstenite::Message;

#[cfg(feature = "web_server_capability")]
use zellij_browser_bridge::protocol::{
    FromBrowser, WebClientToWebServerControlMessagePayload,
    ToBrowser,
};

static ASYNC_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
use std::sync::OnceLock;

const ENTER_ALTERNATE_SCREEN: &str = "\u{1b}[?1049h";
const EXIT_ALTERNATE_SCREEN: &str = "\u{1b}[?1049l";
const ENABLE_BRACKETED_PASTE: &str = "\u{1b}[?2004h";
const RESET_STYLE: &str = "\u{1b}[m";
const SHOW_CURSOR: &str = "\u{1b}[?25h";
const ENTER_KITTY_KEYBOARD_MODE: &str = "\u{1b}[>1u";
const EXIT_KITTY_KEYBOARD_MODE: &str = "\u{1b}[<1u";
const CLEAR_CLIENT_TERMINAL_ATTRIBUTES: &str = "\u{1b}[?1l\u{1b}=\u{1b}[r\u{1b}[?1000l\u{1b}[?1002l\u{1b}[?1003l\u{1b}[?1005l\u{1b}[?1006l\u{1b}[?12l";
/// Subscribe to host color-palette theme notifications (CSI 2031). Hosts
/// that support it begin emitting unsolicited DSR 997 reports on theme
/// change after this is sent.
const ENABLE_HOST_THEME_NOTIFY: &str = "\u{1b}[?2031h";
/// Cancel the CSI 2031 subscription (sent on detach / shutdown so we
/// don't leave the host emitting DSR 997s into nothing).
const DISABLE_HOST_THEME_NOTIFY: &str = "\u{1b}[?2031l";
/// Actively query the current host theme (DSR 996). Reply arrives in the
/// same `CSI ? 997 ; {1|2} n` form as unsolicited notifications, so the
/// stdin parser handles both uniformly.
const QUERY_HOST_THEME: &str = "\u{1b}[?996n";

/// Spawn an async runtime for this client instance.
///
/// The number of workers can be configured to any nonzero value. Passing zero or `None` will spawn
/// one worker per physical CPU on the current machine.
pub(crate) fn async_runtime(maybe_number_of_workers: Option<usize>) -> tokio::runtime::Handle {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.clone(),
        _ => {
            let number_of_workers = match maybe_number_of_workers {
                Some(value) if value > 0 => {
                    log::debug!(
                        "Creating client async runtime with {} tasks based on user request",
                        value
                    );
                    value
                },
                _ => {
                    let cpus = num_cpus::get_physical();
                    log::debug!(
                        "Creating client async runtime with {} tasks based on CPU count",
                        cpus
                    );
                    cpus
                },
            };
            let runtime = ASYNC_RUNTIME.get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(number_of_workers)
                    .thread_name("zellij client async-runtime")
                    .enable_all()
                    .build()
                    .expect("Failed to create tokio runtime")
            });
            runtime.handle().clone()
        },
    }
}

#[cfg(feature = "web_server_capability")]
pub use zellij_relay_client::RemoteClientError;

use crate::stdin_ansi_parser::{AnsiStdinInstruction, StdinAnsiParser, SyncOutput};
use crate::{
    command_is_executing::CommandIsExecuting, input_handler::input_loop,
    os_input_output::ClientOsApi, stdin_handler::stdin_loop,
};
use zellij_utils::cli::CliArgs;
use zellij_utils::{
    channels::{self, ChannelWithContext, SenderWithContext},
    consts::{set_permissions, ZELLIJ_SOCK_DIR},
    data::{ClientId, ConnectToSession, KeyWithModifier, LayoutInfo, LayoutMetadata},
    envs,
    errors::{ClientContext, ContextType, ErrorInstruction},
    input::{cli_assets::CliAssets, config::Config, options::Options},
    ipc::{ClientToServerMsg, ExitReason, ServerToClientMsg},
    nested_session,
    pane_size::Size,
    vendored::termwiz::input::InputEvent,
};

/// Instructions related to the client-side application
#[derive(Debug, Clone)]
pub(crate) enum ClientInstruction {
    Error(String),
    Render(String),
    UnblockInputThread,
    Exit(ExitReason),
    Connected,
    Log(Vec<String>),
    LogError(Vec<String>),
    SwitchSession(ConnectToSession),
    SetSynchronizedOutput(Option<SyncOutput>),
    UnblockCliPipeInput(()), // String -> pipe name
    CliPipeOutput((), ()),   // String -> pipe name, String -> output
    QueryTerminalSize,
    StartWebServer,
    #[allow(dead_code)] // we need the session name here even though we're not currently using it
    RenamedSession(String), // String -> new session name
    ConfigFileUpdated,
    /// Server asked us to forward `query_bytes` to the host terminal and
    /// collect the reply bytes into the window identified by `token`.
    ForwardQueryToHost {
        token: u32,
        query_bytes: Vec<u8>,
    },
    EmitNestedSessionFrame(Vec<u8>),
}

impl From<ServerToClientMsg> for ClientInstruction {
    fn from(instruction: ServerToClientMsg) -> Self {
        match instruction {
            ServerToClientMsg::Exit { exit_reason } => ClientInstruction::Exit(exit_reason),
            ServerToClientMsg::Render { content } => ClientInstruction::Render(content),
            ServerToClientMsg::UnblockInputThread => ClientInstruction::UnblockInputThread,
            ServerToClientMsg::Connected => ClientInstruction::Connected,
            ServerToClientMsg::Log { lines } => ClientInstruction::Log(lines),
            ServerToClientMsg::LogError { lines } => ClientInstruction::LogError(lines),
            ServerToClientMsg::SwitchSession { connect_to_session } => {
                ClientInstruction::SwitchSession(connect_to_session)
            },
            ServerToClientMsg::UnblockCliPipeInput { .. } => {
                ClientInstruction::UnblockCliPipeInput(())
            },
            ServerToClientMsg::CliPipeOutput { .. } => ClientInstruction::CliPipeOutput((), ()),
            ServerToClientMsg::QueryTerminalSize => ClientInstruction::QueryTerminalSize,
            ServerToClientMsg::StartWebServer => ClientInstruction::StartWebServer,
            ServerToClientMsg::RenamedSession { name } => ClientInstruction::RenamedSession(name),
            ServerToClientMsg::ConfigFileUpdated => ClientInstruction::ConfigFileUpdated,
            ServerToClientMsg::ForwardQueryToHost { token, query_bytes } => {
                ClientInstruction::ForwardQueryToHost { token, query_bytes }
            },
            ServerToClientMsg::EmitNestedSessionFrame { payload_bytes } => {
                ClientInstruction::EmitNestedSessionFrame(payload_bytes)
            },
            // Subscribe-only messages — not handled by regular interactive clients
            ServerToClientMsg::PaneRenderUpdate { .. } => ClientInstruction::UnblockInputThread,
            ServerToClientMsg::SubscribedPaneClosed { .. } => ClientInstruction::UnblockInputThread,
            ServerToClientMsg::SetSoftKeyboard { .. } => ClientInstruction::UnblockInputThread,
            ServerToClientMsg::MobileState { .. } => ClientInstruction::UnblockInputThread,
            ServerToClientMsg::SessionSize { .. } => ClientInstruction::UnblockInputThread,
        }
    }
}

impl From<&ClientInstruction> for ClientContext {
    fn from(client_instruction: &ClientInstruction) -> Self {
        match *client_instruction {
            ClientInstruction::Exit(_) => ClientContext::Exit,
            ClientInstruction::Error(_) => ClientContext::Error,
            ClientInstruction::Render(_) => ClientContext::Render,
            ClientInstruction::UnblockInputThread => ClientContext::UnblockInputThread,
            ClientInstruction::Connected => ClientContext::Connected,
            ClientInstruction::Log(_) => ClientContext::Log,
            ClientInstruction::LogError(_) => ClientContext::LogError,
            ClientInstruction::SwitchSession(..) => ClientContext::SwitchSession,
            ClientInstruction::SetSynchronizedOutput(..) => ClientContext::SetSynchronisedOutput,
            ClientInstruction::UnblockCliPipeInput(..) => ClientContext::UnblockCliPipeInput,
            ClientInstruction::CliPipeOutput(..) => ClientContext::CliPipeOutput,
            ClientInstruction::QueryTerminalSize => ClientContext::QueryTerminalSize,
            ClientInstruction::StartWebServer => ClientContext::StartWebServer,
            ClientInstruction::RenamedSession(..) => ClientContext::RenamedSession,
            ClientInstruction::ConfigFileUpdated => ClientContext::ConfigFileUpdated,
            ClientInstruction::ForwardQueryToHost { .. } => ClientContext::ForwardQueryToHost,
            ClientInstruction::EmitNestedSessionFrame(..) => ClientContext::EmitNestedSessionFrame,
        }
    }
}

impl ErrorInstruction for ClientInstruction {
    fn error(err: String) -> Self {
        ClientInstruction::Error(err)
    }
}

#[cfg(all(feature = "web_server_capability", not(windows)))]
fn spawn_web_server(cli_args: &CliArgs) -> Result<String, String> {
    let mut cmd = Command::new(current_exe().map_err(|e| e.to_string())?);
    if let Some(config_file_path) = Config::config_file_path(cli_args) {
        let config_file_path_exists = Path::new(&config_file_path).exists();
        if !config_file_path_exists {
            return Err(format!(
                "Config file: {} does not exist",
                config_file_path.display()
            ));
        }
        // this is so that if Zellij itself was started with a different config file, we'll use it
        // to start the webserver
        cmd.arg("--config");
        cmd.arg(format!("{}", config_file_path.display()));
    }
    cmd.arg("web");
    cmd.arg("-d");
    let output = cmd.output();
    match output {
        Ok(output) => {
            if output.status.success() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).to_string())
            }
        },
        Err(e) => Err(e.to_string()),
    }
}

/// On Windows, cmd.output() creates pipe handles for stdout/stderr. The child
/// (zellij web -d) spawns a grandchild (the web server) which inherits these
/// pipe handles. cmd.output() waits for EOF on the pipes, but the long-lived
/// grandchild keeps them open — hanging forever.
///
/// Redirecting the grandchild's stdio to null is not sufficient: on Windows,
/// CreateProcess with bInheritHandles=TRUE inherits ALL inheritable handles,
/// not just the stdio handles specified in STARTUPINFO. The pipe handles leak
/// through regardless of the grandchild's stdio configuration.
///
/// Use cmd.status() instead: no pipes are created, so nothing to hang on.
#[cfg(all(feature = "web_server_capability", windows))]
fn spawn_web_server(cli_args: &CliArgs) -> Result<String, String> {
    let mut cmd = Command::new(current_exe().map_err(|e| e.to_string())?);
    if let Some(config_file_path) = Config::config_file_path(cli_args) {
        let config_file_path_exists = Path::new(&config_file_path).exists();
        if !config_file_path_exists {
            return Err(format!(
                "Config file: {} does not exist",
                config_file_path.display()
            ));
        }
        cmd.arg("--config");
        cmd.arg(format!("{}", config_file_path.display()));
    }
    cmd.arg("web");
    cmd.arg("-d");
    match cmd.status() {
        Ok(status) => {
            if status.success() {
                Ok(String::new())
            } else {
                Err(format!(
                    "Web server process exited with code: {}",
                    status.code().unwrap_or(-1)
                ))
            }
        },
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(not(feature = "web_server_capability"))]
fn spawn_web_server(_cli_args: &CliArgs) -> Result<String, String> {
    log::error!(
        "This version of Zellij was compiled without web server support, cannot run web server!"
    );
    Ok("".to_owned())
}

fn check_ipc_pipe_length(ipc_pipe: &Path) {
    use zellij_utils::consts::ZELLIJ_SOCK_MAX_LENGTH;
    let path_len = ipc_pipe.as_os_str().len();
    if path_len >= ZELLIJ_SOCK_MAX_LENGTH {
        eprintln!(
            "Error: the IPC socket path is too long ({} bytes, max {}):\n  {}\n\n\
             This is usually caused by a long $TMPDIR path.\n\
             To fix this, set a shorter socket directory, eg.:\n  \
             ZELLIJ_SOCKET_DIR=/tmp/zellij zellij",
            path_len,
            ZELLIJ_SOCK_MAX_LENGTH - 1,
            ipc_pipe.display()
        );
        std::process::exit(1);
    }
}

#[derive(Clone, Copy)]
struct TerminalTeardown {
    include_kitty_exit: bool,
}

fn exit_after_startup_error(teardown: Option<TerminalTeardown>, message: String) -> ! {
    log::error!("{}", message);
    match teardown {
        Some(teardown) => {
            let kitty_exit = if teardown.include_kitty_exit {
                EXIT_KITTY_KEYBOARD_MODE
            } else {
                ""
            };
            let rendered = format!(
                "{}{}{}{}{}\r\n{}\n",
                kitty_exit,
                DISABLE_HOST_THEME_NOTIFY,
                EXIT_ALTERNATE_SCREEN,
                RESET_STYLE,
                SHOW_CURSOR,
                message
            );
            let mut stdout = io::stdout();
            let _ = stdout.write_all(rendered.as_bytes());
            let _ = stdout.flush();
        },
        None => {
            eprintln!("{}", message);
        },
    }
    std::process::exit(1);
}

fn spawn_server_error_message(e: io::Error) -> String {
    format!(
        "Error: failed to start the Zellij server process:\n\n\
         Reason: {}\n\n\
         This can happen if the Zellij binary cannot be executed, or if the server \
         could not create its session socket - for example due to a permission issue \
         in the socket directory.\n\
         To fix a socket directory issue, set a writable socket directory, eg.:\n  \
         ZELLIJ_SOCKET_DIR=/tmp/zellij-$USER zellij",
        e
    )
}

fn create_ipc_pipe(teardown: Option<TerminalTeardown>) -> PathBuf {
    let mut sock_dir = ZELLIJ_SOCK_DIR.clone();
    if let Err(e) = std::fs::create_dir_all(&sock_dir) {
        exit_after_startup_error(
            teardown,
            format!(
                "Error: failed to create the Zellij socket directory:\n  {}\n\n\
                 Reason: {}\n\n\
                 This usually means the directory (or one of its parents) is owned by \
                 another user or is not writable - for example if Zellij was previously \
                 run with `sudo`, or if $XDG_RUNTIME_DIR points to a directory you do not \
                 own.\nTo fix this, remove or correct the offending directory, or set a \
                 writable socket directory, eg.:\n  ZELLIJ_SOCKET_DIR=/tmp/zellij-$USER zellij",
                sock_dir.display(),
                e
            ),
        );
    }
    if let Err(e) = set_permissions(&sock_dir, 0o700) {
        exit_after_startup_error(
            teardown,
            format!(
                "Error: failed to set permissions (0700) on the Zellij socket directory:\n  {}\n\n\
                 Reason: {}\n\n\
                 This usually means the directory is owned by another user.\n\
                 To fix this, remove or correct the offending directory, or set a writable \
                 socket directory, eg.:\n  ZELLIJ_SOCKET_DIR=/tmp/zellij-$USER zellij",
                sock_dir.display(),
                e
            ),
        );
    }
    sock_dir.push(envs::get_session_name().unwrap());
    check_ipc_pipe_length(&sock_dir);
    sock_dir
}

/// Spawn the Zellij server process.
///
/// On Unix the server daemonizes (double-fork) inside start_server(), so
/// the intermediate child exits immediately and `cmd.status()` returns.
#[cfg(not(windows))]
pub fn spawn_server(socket_path: &Path, debug: bool) -> io::Result<()> {
    let mut cmd = Command::new(current_exe()?);
    cmd.arg("--server").arg(socket_path);
    if debug {
        cmd.arg("--debug");
    }
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        let msg = "Process returned non-zero exit code";
        let err_msg = match status.code() {
            Some(c) => format!("{}: {}", msg, c),
            None => msg.to_string(),
        };
        Err(io::Error::new(io::ErrorKind::Other, err_msg))
    }
}

/// Spawn the Zellij server process.
///
/// On Windows there is no daemonize — we launch the server as a background
/// process with a hidden console.  We use CREATE_NO_WINDOW (not
/// DETACHED_PROCESS) so the server gets valid standard handles;
/// DETACHED_PROCESS leaves stdin/stdout/stderr as NULL, which breaks PTY
/// creation, WASM plugin loading, and logging.
#[cfg(windows)]
pub fn spawn_server(socket_path: &Path, debug: bool) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(current_exe()?);
    cmd.arg("--server").arg(socket_path);
    if debug {
        cmd.arg("--debug");
    }
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
    cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    cmd.spawn()?;
    Ok(())
}

#[derive(Debug, Clone)]
pub enum ClientInfo {
    Attach(String, Options),
    New(String, Option<LayoutInfo>, Option<PathBuf>), // PathBuf -> explicit cwd
    Resurrect(String, PathBuf, bool, Option<PathBuf>), // (name, path_to_layout, force_run_commands, cwd)
    Watch(String, Options),                            // Watch mode (read-only)
}

impl ClientInfo {
    pub fn get_session_name(&self) -> &str {
        match self {
            Self::Attach(ref name, _) => name,
            Self::New(ref name, _layout_info, _layout_cwd) => name,
            Self::Resurrect(ref name, _, _, _) => name,
            Self::Watch(ref name, _) => name,
        }
    }
    pub fn set_layout_info(&mut self, new_layout_info: LayoutInfo) {
        match self {
            ClientInfo::New(_, layout_info, _) => *layout_info = Some(new_layout_info),
            _ => {},
        }
    }
    pub fn set_cwd(&mut self, new_cwd: PathBuf) {
        match self {
            ClientInfo::New(_, _, cwd) => *cwd = Some(new_cwd),
            ClientInfo::Resurrect(_, _, _, cwd) => *cwd = Some(new_cwd),
            _ => {},
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum InputInstruction {
    KeyEvent(InputEvent, Vec<u8>),
    KeyWithModifierEvent(KeyWithModifier, Vec<u8>, bool), // bool = is_kitty_keyboard_protocol
    #[allow(dead_code)] // constructed in stdin_handler_windows.rs (Windows-only)
    MouseEvent(zellij_utils::input::mouse::MouseEvent),
    AnsiStdinInstructions(Vec<AnsiStdinInstruction>),
    DesktopNotificationResponse(Vec<u8>),
    /// The continuous host-reply parser closed a forwarding window (barrier
    /// reply seen or timeout fired). Payload is the accumulated raw bytes
    /// to ship to the server.
    ForwardedReplyFromHostComplete {
        token: u32,
        reply_bytes: Vec<u8>,
    },
    NestedSessionFrameFromHost(Vec<u8>),
    Exit,
}

#[cfg(feature = "web_server_capability")]
#[cfg(unix)]
fn os_hostname() -> Option<String> {
    let raw = nix::unistd::gethostname().ok()?;
    let name = raw.to_str()?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(not(unix))]
fn os_hostname() -> Option<String> {
    None
}

#[cfg(feature = "web_server_capability")]
fn encode_control_out(
    relay_keys: Option<&zellij_relay_protocol::crypto::ViewerKeys>,
    seq: &mut u64,
    json: String,
) -> Option<Message> {
    use zellij_relay_protocol::crypto;
    match relay_keys {
        Some(keys) => {
            match crypto::encrypt_seq(
                &keys.control_v2s,
                *seq,
                crypto::FRAME_TYPE_CONTROL,
                crypto::DIRECTION_VIEWER_TO_SHARER,
                json.as_bytes(),
            ) {
                Ok(ct) => {
                    *seq += 1;
                    Some(Message::Binary(ct.into()))
                },
                Err(e) => {
                    log::error!("e2e control encrypt failed: {} — dropping frame", e);
                    None
                },
            }
        },
        None => Some(Message::Text(json.into())),
    }
}

#[cfg(feature = "web_server_capability")]
fn heartbeat_expired(last_pong_ms: u64, now_ms: u64, timeout_ms: u64) -> bool {
    now_ms.saturating_sub(last_pong_ms) > timeout_ms
}

#[cfg(feature = "web_server_capability")]
fn heartbeat_secs_from_env(var_name: &str, default_secs: u64) -> u64 {
    std::env::var(var_name)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(default_secs)
}

#[cfg(feature = "web_server_capability")]
async fn send_pump_control<S>(
    control_ws: &mut S,
    relay_keys: &zellij_relay_protocol::crypto::ViewerKeys,
    seq: &mut u64,
    payload: &WebClientToWebServerControlMessagePayload,
) -> Result<(), RemoteClientError>
where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let json = serde_json::to_string(payload).unwrap();
    if let Some(msg) = encode_control_out(Some(relay_keys), seq, json) {
        control_ws
            .send(msg)
            .await
            .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;
    }
    Ok(())
}

#[cfg(feature = "web_server_capability")]
pub async fn run_admission_handshake(
    attached: &mut remote_attach::AttachedSession,
) -> Result<(), RemoteClientError> {
    use zellij_relay_protocol::crypto;
    let relay_keys = match attached.relay_keys.clone() {
        Some(keys) => keys,
        None => return Ok(()),
    };

    if let Some(sas) = attached.sas.as_ref() {
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(
            format!(
                "\r\nWaiting to be admitted. Read this code to the host to confirm: {}\r\n",
                sas
            )
            .as_bytes(),
        );
        let _ = stderr.flush();
    }

    let device_reconnect = attached.device_reconnect;
    let device_seed = attached.device_seed;
    let server_url = attached.server_url.clone();
    let mut out_seq: u64 = attached.control_out_seq;
    let mut in_window = crypto::ReplayWindow::new();
    let mut enrolling_seed: Option<[u8; crypto::DEVICE_SEED_LEN]> = None;
    let control_ws = &mut attached.connections.control_ws;

    if device_reconnect {
        send_pump_control(
            control_ws,
            &relay_keys,
            &mut out_seq,
            &WebClientToWebServerControlMessagePayload::DeviceAuthRequest,
        )
        .await?;
    }

    loop {
        let text = match control_ws.next().await {
            Some(Ok(Message::Binary(data))) => match crypto::decrypt_seq(
                &relay_keys.control_s2v,
                crypto::FRAME_TYPE_CONTROL,
                crypto::DIRECTION_SHARER_TO_VIEWER,
                &data,
            ) {
                Ok((seq, pt)) => {
                    if !in_window.accept(seq) {
                        continue;
                    }
                    match String::from_utf8(pt) {
                        Ok(s) => s,
                        Err(_) => continue,
                    }
                },
                Err(_) => continue,
            },
            Some(Ok(Message::Close(_))) | None => {
                return Err(RemoteClientError::ConnectionFailed(
                    "control channel closed before admission".to_string(),
                ));
            },
            Some(Err(e)) => {
                return Err(RemoteClientError::ConnectionFailed(e.to_string()));
            },
            _ => continue,
        };
        match serde_json::from_str::<ToBrowser>(&text) {
            Ok(ToBrowser::DeviceAuthChallenge { nonce }) => {
                let Some(seed) = device_seed.as_ref() else {
                    return Err(RemoteClientError::ConnectionFailed(
                        "device auth challenge received but no device key is loaded".to_string(),
                    ));
                };
                let signature = crypto::sign_device_challenge(seed, &nonce);
                send_pump_control(
                    control_ws,
                    &relay_keys,
                    &mut out_seq,
                    &WebClientToWebServerControlMessagePayload::DeviceAuthResponse {
                        signature: signature.to_vec(),
                    },
                )
                .await?;
            },
            Ok(ToBrowser::Admitted { enroll }) => {
                if !enroll {
                    break;
                }
                let (seed, pubkey) = crypto::generate_device_keypair();
                enrolling_seed = Some(seed);
                send_pump_control(
                    control_ws,
                    &relay_keys,
                    &mut out_seq,
                    &WebClientToWebServerControlMessagePayload::DeviceEnrollRequest {
                        pubkey_alg: "ed25519".to_string(),
                        pubkey: pubkey.to_vec(),
                        requested_label: os_hostname(),
                    },
                )
                .await?;
            },
            Ok(ToBrowser::DeviceEnrollAck {
                device_id,
                device_secret,
                scope,
                access_read_only,
                ..
            }) => {
                if let Some(seed) = enrolling_seed.take() {
                    remote_attach::device_store::save_enrolled(
                        &server_url,
                        &seed,
                        &device_id,
                        &device_secret,
                        access_read_only,
                        scope,
                    );
                }
                send_pump_control(
                    control_ws,
                    &relay_keys,
                    &mut out_seq,
                    &WebClientToWebServerControlMessagePayload::EnrollComplete,
                )
                .await?;
                break;
            },
            Ok(ToBrowser::Rejected { reason }) => {
                if device_reconnect {
                    remote_attach::device_store::delete(&server_url);
                }
                return Err(RemoteClientError::ConnectionFailed(format!(
                    "Not admitted by the host: {}",
                    reason
                )));
            },
            Ok(ToBrowser::Exit { reason }) => {
                return Err(RemoteClientError::ConnectionFailed(reason));
            },
            _ => {},
        }
    }

    attached.control_out_seq = out_seq;
    attached.control_in_window = in_window;
    Ok(())
}

#[cfg(feature = "web_server_capability")]
pub async fn run_remote_client_terminal_loop(
    os_input: Box<dyn ClientOsApi>,
    attached: remote_attach::AttachedSession,
    nested_session_name: Option<String>,
) -> Result<Option<ConnectToSession>, RemoteClientError> {
    let mut connections = attached.connections;
    let e2e_key = attached.e2e_key;
    let relay_keys = attached.relay_keys;
    let mut terminal_out_seq: u64 = 0;
    let mut control_out_seq: u64 = attached.control_out_seq;
    let mut terminal_in_window = zellij_relay_protocol::crypto::ReplayWindow::new();
    let mut control_in_window = attached.control_in_window;
    // Phase 5: on r/o attach the terminal stream is clipped to the
    // local viewport rather than written out raw, and STDIN / outbound
    // resizes are suppressed (the relay drops the former at its side,
    // and the sharer's viewport is authoritative for size).
    let is_read_only = attached.is_read_only;
    // `0` is the relay's cold-start sentinel for fresh r/o fan-out
    // groups whose `SessionSize` has not yet been observed. Mirrors
    // the browser's `sessionRows || 24` / `sessionCols || 80` default
    // (`zellij-web-client-assets/assets/websockets.js:44`). The first
    // `SessionSizeChanged` from the relay corrects these.
    let initial_session_rows: u16 = if attached.session_rows == 0 {
        24
    } else {
        attached.session_rows as u16
    };
    let initial_session_cols: u16 = if attached.session_cols == 0 {
        80
    } else {
        attached.session_cols as u16
    };
    // Clipping is only for the legacy shared-stream fan-out, signalled by a
    // known (non-zero) session size. Under the E2E per-viewer model each
    // read-only viewer gets its own correctly-sized stream (the relay reports
    // size 0), so render it verbatim — input is still gated by `is_read_only`.
    let mut clipper: Option<zellij_ansi_clip::ClipState> =
        if is_read_only && attached.session_rows > 0 {
            Some(zellij_ansi_clip::ClipState::new(
                initial_session_rows,
                initial_session_cols,
            ))
        } else {
            None
        };
    use crate::os_input_output::{AsyncSignals, AsyncStdin};

    let synchronised_output = match os_input.env_variable("TERM").as_deref() {
        Some("alacritty") => Some(SyncOutput::DCS),
        _ => None,
    };

    let mut async_stdin: Box<dyn AsyncStdin> = os_input.get_async_stdin_reader();
    let mut async_signals: Box<dyn AsyncSignals> = os_input
        .get_async_signal_listener()
        .map_err(|e| RemoteClientError::IoError(e))?;

    let create_resize_message = |size: Size| -> String {
        serde_json::to_string(&FromBrowser {
            web_client_id: connections.web_client_id.clone(),
            payload: WebClientToWebServerControlMessagePayload::TerminalResize(size),
        })
        .unwrap()
    };

    if let Some(msg) = encode_control_out(
        relay_keys.as_ref(),
        &mut control_out_seq,
        serde_json::to_string(&WebClientToWebServerControlMessagePayload::VersionRequest).unwrap(),
    ) {
        if let Err(e) = connections.control_ws.send(msg).await {
            log::error!("Failed to send version request: {}", e);
        }
    }

    let mut nested_frame_extractor = nested_session::NestedFrameExtractor::new();
    let mut last_heard_from_host = std::time::Instant::now();
    let mut reannounce_check = tokio::time::interval(std::time::Duration::from_millis(
        nested_session::reannounce_check_interval_ms(),
    ));
    reannounce_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    if !is_read_only {
        let new_size = os_input.get_terminal_size();
        if let Some(msg) = encode_control_out(
            relay_keys.as_ref(),
            &mut control_out_seq,
            create_resize_message(new_size),
        ) {
            if let Err(e) = connections.control_ws.send(msg).await {
                log::error!("Failed to send resize message: {}", e);
            }
        }
    }

    // Phase 3 client-commitment rule: under E2E, no STDIN byte may be
    // transmitted before at least one server frame has decrypted
    // cleanly. We gate the stdin branch of the select below on this
    // flag; in the non-E2E path it starts unlocked. Stdin back-pressure
    // is handled naturally — the tokio::select! branch simply becomes
    // uninterested in the stdin future until the flag flips.
    // Phase 5: r/o viewers must never send STDIN, so the flag starts
    // locked and never flips for them.
    let mut stdin_unlocked = e2e_key.is_none() && relay_keys.is_none() && !is_read_only;

    // Phase 6 (Session A): heartbeat on both WS legs. `heartbeat_ticker`
    // fires every 15s; a full ping cadence is every 30s (two ticks) and
    // the watchdog trips when either leg has been silent > 60s.
    let attach_heartbeat_interval_secs: u64 =
        heartbeat_secs_from_env("ZELLIJ_ATTACH_HEARTBEAT_INTERVAL_SECS", 30);
    let attach_heartbeat_timeout_secs: u64 =
        heartbeat_secs_from_env("ZELLIJ_ATTACH_HEARTBEAT_TIMEOUT_SECS", 60);
    const ATTACH_WS_SEND_TIMEOUT_SECS: u64 = 10;
    let mut heartbeat_ticker = tokio::time::interval(std::time::Duration::from_secs(
        (attach_heartbeat_interval_secs / 2).max(1),
    ));
    heartbeat_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat_ticker.tick().await; // burn first immediate tick
    let mut heartbeat_tick_count: u32 = 0;
    let now_ms = || -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    };
    let mut last_terminal_activity_ms = now_ms();
    let mut last_control_activity_ms = now_ms();
    let mut sharer_heartbeat_active = false;
    let mut last_sharer_pong_ms = now_ms();

    loop {
        tokio::select! {
            // Handle stdin input (gated under E2E until first clean decrypt;
            // r/o viewers never transmit so the arm is permanently closed).
            result = async_stdin.read(), if stdin_unlocked && !is_read_only => {
                match result {
                    Ok(buf) if !buf.is_empty() => {
                        // Nested-session control frames arriving on stdin are
                        // consumed here and relayed over the control channel;
                        // only the cleaned byte stream reaches the terminal WS.
                        let (cleaned, nested_frames) = nested_frame_extractor.extract(&buf);
                        for payload_bytes in nested_frames {
                            last_heard_from_host = std::time::Instant::now();
                            match nested_session::decode_payload(&payload_bytes) {
                                Some(nested_session::NestedSessionMessage::Ping) => {
                                    let mut stdout = os_input.get_stdout_writer();
                                    let _ = stdout.write_all(&nested_session::encode_frame(
                                        &nested_session::NestedSessionMessage::Pong,
                                    ));
                                    let _ = stdout.flush();
                                },
                                Some(_) => {
                                    if let Some(control_msg) = encode_control_out(
                                        relay_keys.as_ref(),
                                        &mut control_out_seq,
                                        serde_json::to_string(&FromBrowser {
                                            web_client_id: connections.web_client_id.clone(),
                                            payload: WebClientToWebServerControlMessagePayload::NestedSessionFrameFromHost {
                                                payload_bytes,
                                            },
                                        })
                                        .unwrap(),
                                    ) {
                                        if let Err(e) = connections.control_ws.send(control_msg).await {
                                            log::error!("Failed to forward nested session frame over control WebSocket: {}", e);
                                        }
                                    }
                                },
                                None => {},
                            }
                        }
                        if cleaned.is_empty() {
                            continue;
                        }
                        let buf = cleaned;
                        // Defense-in-depth: the `if` guard above already
                        // closes this arm on r/o. The relay also drops r/o
                        // input before it reaches Zellij. Drop-and-continue
                        // here is the belt over the braces.
                        if is_read_only {
                            continue;
                        }
                        // With E2E on, encrypt before sending; the server
                        // decrypts with the same key it derived at auth
                        // time. See `derive_e2e_key_if_needed` for the
                        // key material.
                        let payload = if let Some(keys) = relay_keys.as_ref() {
                            match zellij_relay_protocol::crypto::encrypt_seq(
                                &keys.terminal_v2s,
                                terminal_out_seq,
                                zellij_relay_protocol::crypto::FRAME_TYPE_TERMINAL,
                                zellij_relay_protocol::crypto::DIRECTION_VIEWER_TO_SHARER,
                                &buf,
                            ) {
                                Ok(ct) => {
                                    terminal_out_seq += 1;
                                    ct
                                }
                                Err(err) => {
                                    log::error!("e2e encrypt failed: {} — dropping stdin chunk", err);
                                    continue;
                                }
                            }
                        } else if let Some(k) = &e2e_key {
                            match zellij_relay_protocol::crypto::encrypt(k, &buf) {
                                Ok(ct) => ct,
                                Err(err) => {
                                    log::error!("e2e encrypt failed: {} — dropping stdin chunk", err);
                                    continue;
                                }
                            }
                        } else {
                            buf
                        };
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(ATTACH_WS_SEND_TIMEOUT_SECS),
                            connections.terminal_ws.send(Message::Binary(payload.into())),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                log::error!("remote-attach: stdin->terminal ws send error: {} — exiting loop", e);
                                break;
                            }
                            Err(_) => {
                                log::error!("remote-attach: stdin->terminal ws send timed out — exiting loop");
                                break;
                            }
                        }
                    }
                    Ok(_) => {
                        log::info!("remote-attach: stdin EOF — exiting loop");
                        break;
                    }
                    Err(e) => {
                        log::error!("remote-attach: stdin read error: {} — exiting loop", e);
                        break;
                    }
                }
            }

            _ = reannounce_check.tick() => {
                if let Some(session_name) = &nested_session_name {
                    if last_heard_from_host.elapsed()
                        >= std::time::Duration::from_millis(nested_session::reannounce_silence_ms())
                    {
                        let announce = nested_session::NestedSessionMessage::Announce {
                            session_name: session_name.clone(),
                            capabilities: vec![nested_session::NestedSessionCapability::NestedControl],
                        };
                        let mut stdout = os_input.get_stdout_writer();
                        if stdout
                            .write_all(&nested_session::encode_frame(&announce))
                            .is_ok()
                        {
                            let _ = stdout.flush();
                        }
                    }
                }
            }

            // Handle signals
            Some(signal) = async_signals.recv() => {
                match signal {
                    crate::os_input_output::SignalEvent::Resize => {
                        let new_size = os_input.get_terminal_size();
                        if is_read_only {
                            // R/O: re-clip the cached session frame to
                            // the new local viewport and paint it.
                            // Zero outbound traffic. Mirrors the browser
                            // path in `websockets.js::setupResizeHandler`.
                            if let Some(clip) = clipper.as_mut() {
                                let emitted = clip.emit(
                                    new_size.rows as u16,
                                    new_size.cols as u16,
                                );
                                let mut stdout = os_input.get_stdout_writer();
                                if let Some(sync) = synchronised_output {
                                    stdout
                                        .write_all(sync.start_seq())
                                        .expect("cannot write to stdout");
                                }
                                stdout
                                    .write_all(&emitted)
                                    .expect("cannot write to stdout");
                                if let Some(sync) = synchronised_output {
                                    stdout
                                        .write_all(sync.end_seq())
                                        .expect("cannot write to stdout");
                                }
                                stdout.flush().expect("could not flush");
                            }
                        } else {
                            let mut send_failed = false;
                            for json in [create_resize_message(new_size)] {
                                if let Some(msg) = encode_control_out(relay_keys.as_ref(), &mut control_out_seq, json) {
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(ATTACH_WS_SEND_TIMEOUT_SECS),
                                        connections.control_ws.send(msg),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => {}
                                        Ok(Err(e)) => {
                                            log::error!("Failed to send resize message: {}", e);
                                            send_failed = true;
                                            break;
                                        }
                                        Err(_) => {
                                            log::error!("Timed out sending resize message");
                                            send_failed = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            if send_failed {
                                break;
                            }
                        }
                    }
                    crate::os_input_output::SignalEvent::Quit => {
                        log::info!("remote-attach: quit signal — exiting loop");
                        break;
                    }
                }
            }

            // Phase 6 (Session A): heartbeat tick. On every full cadence
            // emit a Ping on both sockets; on every half-cadence check
            // the silence budget. Tungstenite auto-replies to Pings
            // from the remote peer, so inbound Pong frames show up in
            // the terminal/control arms below and refresh the activity
            // timestamps.
            _ = heartbeat_ticker.tick() => {
                let now = now_ms();
                log::info!(
                    "remote-attach: heartbeat tick (terminal silent {}ms, control silent {}ms, sharer-pong silent {}ms, active {}, timeout {}ms)",
                    now.saturating_sub(last_terminal_activity_ms),
                    now.saturating_sub(last_control_activity_ms),
                    now.saturating_sub(last_sharer_pong_ms),
                    sharer_heartbeat_active,
                    attach_heartbeat_timeout_secs * 1000
                );
                if sharer_heartbeat_active
                    && heartbeat_expired(
                        last_sharer_pong_ms,
                        now,
                        attach_heartbeat_timeout_secs * 1000,
                    )
                {
                    log::warn!(
                        "remote-attach: sharer heartbeat watchdog tripped (no Pong for {}ms — sharer gone or revoked) — exiting loop",
                        now.saturating_sub(last_sharer_pong_ms)
                    );
                    break;
                }
                if now.saturating_sub(last_terminal_activity_ms)
                    > attach_heartbeat_timeout_secs * 1000
                    && now.saturating_sub(last_control_activity_ms)
                        > attach_heartbeat_timeout_secs * 1000
                {
                    log::warn!(
                        "remote-attach: transport watchdog tripped (terminal silent {}ms, control silent {}ms) — exiting loop",
                        now.saturating_sub(last_terminal_activity_ms),
                        now.saturating_sub(last_control_activity_ms)
                    );
                    break;
                }
                heartbeat_tick_count += 1;
                if u64::from(heartbeat_tick_count) * (attach_heartbeat_interval_secs / 2).max(1)
                    >= attach_heartbeat_interval_secs
                {
                    heartbeat_tick_count = 0;
                    let payload = b"hb".to_vec();
                    let send_timeout = std::time::Duration::from_secs(ATTACH_WS_SEND_TIMEOUT_SECS);
                    match tokio::time::timeout(
                        send_timeout,
                        connections.terminal_ws.send(Message::Ping(payload.clone().into())),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        _ => {
                            log::warn!("attach heartbeat: terminal ws send failed or stalled");
                            break;
                        }
                    }
                    match tokio::time::timeout(
                        send_timeout,
                        connections.control_ws.send(Message::Ping(payload.into())),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        _ => {
                            log::warn!("attach heartbeat: control ws send failed or stalled");
                            break;
                        }
                    }
                    if sharer_heartbeat_active {
                        if let Some(out) = encode_control_out(
                            relay_keys.as_ref(),
                            &mut control_out_seq,
                            serde_json::to_string(
                                &WebClientToWebServerControlMessagePayload::Ping,
                            )
                            .unwrap(),
                        ) {
                            match tokio::time::timeout(
                                send_timeout,
                                connections.control_ws.send(out),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                _ => {
                                    log::warn!("remote-attach: sharer ping send failed or stalled — exiting loop");
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // Handle terminal messages
            terminal_msg = connections.terminal_ws.next() => {
                last_terminal_activity_ms = now_ms();
                match terminal_msg {
                    Some(Ok(Message::Text(text))) => {
                        if e2e_key.is_some() || relay_keys.is_some() {
                            log::warn!("got plaintext Text frame under E2E — dropping");
                            continue;
                        }
                        {
                            let mut stdout = os_input.get_stdout_writer();
                            if let Some(sync) = synchronised_output {
                                stdout
                                    .write_all(sync.start_seq())
                                    .expect("cannot write to stdout");
                            }
                            stdout
                                .write_all(text.as_bytes())
                                .expect("cannot write to stdout");
                            if let Some(sync) = synchronised_output {
                                stdout
                                    .write_all(sync.end_seq())
                                    .expect("cannot write to stdout");
                            }
                            stdout.flush().expect("could not flush");
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        // With E2E on, the server sends ciphertext as
                        // Binary. Decrypt into the plaintext ANSI stream
                        // before writing to stdout.
                        let decrypted: Vec<u8> = if let Some(keys) = relay_keys.as_ref() {
                            match zellij_relay_protocol::crypto::decrypt_seq(
                                &keys.terminal_s2v,
                                zellij_relay_protocol::crypto::FRAME_TYPE_TERMINAL,
                                zellij_relay_protocol::crypto::DIRECTION_SHARER_TO_VIEWER,
                                &data,
                            ) {
                                Ok((seq, pt)) => {
                                    if !terminal_in_window.accept(seq) {
                                        log::warn!("replayed/reordered terminal frame seq={} — dropping", seq);
                                        continue;
                                    }
                                    pt
                                }
                                Err(err) => {
                                    log::warn!("e2e decrypt failed: {} — dropping frame", err);
                                    continue;
                                }
                            }
                        } else if let Some(k) = &e2e_key {
                            match zellij_relay_protocol::crypto::decrypt(k, &data) {
                                Ok(pt) => pt,
                                Err(err) => {
                                    log::warn!("e2e decrypt failed: {} — dropping frame", err);
                                    continue;
                                }
                            }
                        } else {
                            data.to_vec()
                        };
                        // First clean decrypt under E2E unlocks stdin
                        // transmission. In the non-E2E path this is a
                        // no-op — the flag started `true`. R/O viewers
                        // never unlock (the STDIN arm is gated
                        // independently on `!is_read_only`).
                        stdin_unlocked = true;
                        if !sharer_heartbeat_active {
                            sharer_heartbeat_active = true;
                            last_sharer_pong_ms = now_ms();
                            log::info!("remote-attach: sharer heartbeat activated (first frame received)");
                        }
                        // Phase 5: on r/o, feed the decrypted ANSI into
                        // the viewport clipper and emit a normalised
                        // stream sized for this viewer. On r/w (or
                        // non-relay web clients) write the decrypted
                        // bytes verbatim. Mirrors the browser path in
                        // `websockets.js::wsTerminal.onmessage`.
                        let output: Vec<u8> = if let Some(clip) = clipper.as_mut() {
                            clip.apply_chunk(&decrypted);
                            let term_size = os_input.get_terminal_size();
                            clip.emit(term_size.rows as u16, term_size.cols as u16)
                        } else {
                            decrypted
                        };
                        let mut stdout = os_input.get_stdout_writer();
                        if let Some(sync) = synchronised_output {
                            stdout
                                .write_all(sync.start_seq())
                                .expect("cannot write to stdout");
                        }
                        stdout
                            .write_all(&output)
                            .expect("cannot write to stdout");
                        if let Some(sync) = synchronised_output {
                            stdout
                                .write_all(sync.end_seq())
                                .expect("cannot write to stdout");
                        }
                        stdout.flush().expect("could not flush");
                    }
                    Some(Ok(Message::Close(_))) => {
                        log::info!("remote-attach: terminal ws closed by relay — exiting loop");
                        break;
                    }
                    Some(Err(e)) => {
                        log::error!("remote-attach: terminal ws error: {} — exiting loop", e);
                        break;
                    }
                    None => {
                        log::error!("remote-attach: terminal ws stream ended — exiting loop");
                        break;
                    }
                    _ => {}
                }
            }

            control_msg = connections.control_ws.next() => {
                last_control_activity_ms = now_ms();
                let control_json: Option<String> = match control_msg {
                    Some(Ok(Message::Text(msg))) => {
                        if relay_keys.is_some() {
                            log::warn!("got plaintext control Text frame under E2E — dropping");
                            None
                        } else {
                            Some(msg.to_string())
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(keys) = relay_keys.as_ref() {
                            match zellij_relay_protocol::crypto::decrypt_seq(
                                &keys.control_s2v,
                                zellij_relay_protocol::crypto::FRAME_TYPE_CONTROL,
                                zellij_relay_protocol::crypto::DIRECTION_SHARER_TO_VIEWER,
                                &data,
                            ) {
                                Ok((seq, pt)) => {
                                    if !control_in_window.accept(seq) {
                                        log::warn!("replayed/reordered control frame seq={} — dropping", seq);
                                        None
                                    } else {
                                        match String::from_utf8(pt) {
                                            Ok(s) => Some(s),
                                            Err(_) => {
                                                log::warn!("decrypted control frame not UTF-8 — dropping");
                                                None
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    log::warn!("e2e control decrypt failed: {} — dropping frame", err);
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        log::info!("remote-attach: control ws closed by relay — exiting loop");
                        break;
                    }
                    Some(Err(e)) => {
                        log::error!("remote-attach: control ws error: {} — exiting loop", e);
                        break;
                    }
                    None => {
                        log::error!("remote-attach: control ws stream ended — exiting loop");
                        break;
                    }
                    _ => None,
                };
                if let Some(msg) = control_json {
                        let deserialized_msg: Result<ToBrowser, _> =
                            serde_json::from_str(&msg);
                        match deserialized_msg {
                            Ok(ToBrowser::SetConfig(..)) => {}
                            Ok(ToBrowser::Pong) => {
                                last_sharer_pong_ms = now_ms();
                            }
                            Ok(ToBrowser::VersionAnnounce { zellij_version, .. }) => {
                                log::info!("relay sharer reports Zellij version {}", zellij_version);
                            }
                            Ok(ToBrowser::QueryTerminalSize) => {
                                let new_size = os_input.get_terminal_size();
                                if let Some(out) = encode_control_out(relay_keys.as_ref(), &mut control_out_seq, create_resize_message(new_size)) {
                                    if let Err(e) = connections.control_ws.send(out).await {
                                        log::error!("Failed to send resize message: {}", e);
                                    }
                                }
                            }
                            Ok(ToBrowser::Log { lines }) => {
                                for line in lines {
                                    log::info!("{}", line);
                                }
                            }
                            Ok(ToBrowser::LogError { lines }) => {
                                for line in lines {
                                    log::error!("{}", line);
                                }
                            }
                            Ok(ToBrowser::SwitchedSession{ .. }) => {
                                // no-op
                            }
                            Ok(ToBrowser::SetSoftKeyboard{ .. }) => {
                                // no-op
                            }
                            Ok(ToBrowser::MobileState { .. }) => {
                                // native viewers do not render the mobile chrome
                            }
                            Ok(ToBrowser::Exit { reason }) => {
                                log::info!("remote-attach: host ended session ({}) — exiting loop", reason);
                                let mut stderr = std::io::stderr();
                                let _ = stderr.write_all(
                                    format!("\r\n{}\r\n", reason).as_bytes(),
                                );
                                let _ = stderr.flush();
                                break;
                            }
                            Ok(ToBrowser::Rejected { reason }) => {
                                log::info!("remote-attach: rejected by host ({}) — exiting loop", reason);
                                let mut stderr = std::io::stderr();
                                let _ = stderr.write_all(
                                    format!("\r\nNot admitted by the host: {}\r\n", reason)
                                        .as_bytes(),
                                );
                                let _ = stderr.flush();
                                break;
                            }
                            Ok(ToBrowser::SessionSizeChanged { rows, cols }) => {
                                // Phase 5: r/o viewers resize the clipper's
                                // virtual session grid and repaint. Mirrors
                                // the browser handler in
                                // `websockets.js::startWsControl`'s
                                // `SessionSizeChanged` branch. r/w viewers
                                // ignore the message (the sharer does not
                                // receive size updates from itself).
                                if let Some(clip) = clipper.as_mut() {
                                    clip.resize_session(rows as u16, cols as u16);
                                    let term_size = os_input.get_terminal_size();
                                    let emitted = clip.emit(
                                        term_size.rows as u16,
                                        term_size.cols as u16,
                                    );
                                    let mut stdout = os_input.get_stdout_writer();
                                    if let Some(sync) = synchronised_output {
                                        stdout
                                            .write_all(sync.start_seq())
                                            .expect("cannot write to stdout");
                                    }
                                    stdout
                                        .write_all(&emitted)
                                        .expect("cannot write to stdout");
                                    if let Some(sync) = synchronised_output {
                                        stdout
                                            .write_all(sync.end_seq())
                                            .expect("cannot write to stdout");
                                    }
                                    stdout.flush().expect("could not flush");
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                log::debug!("Ignoring unrecognized control message: {}", e);
                            }
                        }
                }
            }

        }
    }

    log::info!("remote-attach: terminal loop exited — returning to caller");
    Ok(None)
}

/// Attach to a remote Zellij session given its URL.
///
/// `extra_relay_urls` should carry the local `relay_server_url` config
/// (if any) plus any other trusted relay URLs. Hosts extracted from
/// these are appended to the hard-coded `zellij.online` known-relay list
/// so self-hosted setups get the same downgrade-refusal treatment.
#[cfg(feature = "web_server_capability")]
pub fn start_remote_client(
    mut os_input: Box<dyn ClientOsApi>,
    remote_session_url: &str,
    token: Option<String>,
    remember: bool,
    forget: bool,
    repin: bool,
    ca_cert: Option<std::path::PathBuf>,
    insecure: bool,
    async_worker_tasks: Option<usize>,
    extra_relay_urls: Vec<String>,
    mouse_mode: bool,
    support_kitty_keyboard_protocol: bool,
) -> Result<Option<ConnectToSession>, RemoteClientError> {
    info!("Starting Zellij client!");

    let is_nested_inside_zellij_pane = os_input.env_variable("ZELLIJ").is_some();
    let remote_session_name = remote_session_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_owned();

    let runtime = crate::async_runtime(async_worker_tasks);

    let mut connections = remote_attach::attach_to_remote_session(
        runtime.clone(),
        remote_session_url,
        token,
        remember,
        forget,
        repin,
        ca_cert.as_deref(),
        insecure,
        &extra_relay_urls,
    )?;

    runtime.block_on(run_admission_handshake(&mut connections))?;

    let reconnect_to_session = None;
    os_input.unset_raw_mode().unwrap();

    let mut stdout = os_input.get_stdout_writer();
    stdout.write_all(ENTER_ALTERNATE_SCREEN.as_bytes()).unwrap();
    stdout
        .write_all(CLEAR_CLIENT_TERMINAL_ATTRIBUTES.as_bytes())
        .unwrap();
    if support_kitty_keyboard_protocol {
        stdout
            .write_all(ENTER_KITTY_KEYBOARD_MODE.as_bytes())
            .unwrap();
    }
    stdout
        .write_all(ENABLE_HOST_THEME_NOTIFY.as_bytes())
        .unwrap();
    stdout.write_all(QUERY_HOST_THEME.as_bytes()).unwrap();

    envs::set_zellij("0".to_string());

    let full_screen_ws = os_input.get_terminal_size();

    os_input.set_raw_mode();
    stdout.write_all(ENABLE_BRACKETED_PASTE.as_bytes()).unwrap();
    if is_nested_inside_zellij_pane {
        let announce = nested_session::NestedSessionMessage::Announce {
            session_name: remote_session_name.clone(),
            capabilities: vec![nested_session::NestedSessionCapability::NestedControl],
        };
        stdout
            .write_all(&nested_session::encode_frame(&announce))
            .unwrap();
        let _ = stdout.flush();
    }
    if mouse_mode {
        os_input.enable_mouse().non_fatal();
    }

    std::panic::set_hook({
        use zellij_utils::errors::handle_panic;
        let os_input = os_input.clone();
        Box::new(move |info| {
            os_input.disable_mouse().non_fatal();
            os_input.restore_console_mode();
            if let Ok(()) = os_input.unset_raw_mode() {
                handle_panic::<ClientInstruction>(info, None);
            }
        })
    });

    let reset_controlling_terminal_state = |e: String, exit_status: i32| {
        log::info!("remote-attach: reset_controlling_terminal_state begin (status {})", exit_status);
        os_input.disable_mouse().non_fatal();
        os_input.unset_raw_mode().unwrap();
        os_input.restore_console_mode();
        let error = terminal_teardown_message(&e, full_screen_ws.rows, true);
        let mut stdout = os_input.get_stdout_writer();
        stdout.write_all(error.as_bytes()).unwrap();
        stdout.flush().unwrap();
        if exit_status == 0 {
            log::info!("{}", e);
        } else {
            log::error!("{}", e);
        };
        log::info!("remote-attach: calling process::exit({})", exit_status);
        std::process::exit(exit_status);
    };

    let nested_session_name = if is_nested_inside_zellij_pane {
        Some(remote_session_name.clone())
    } else {
        None
    };
    log::info!("remote-attach: entering terminal loop");
    runtime.block_on(run_remote_client_terminal_loop(
        os_input.clone(),
        connections,
        nested_session_name,
    ))?;
    log::info!("remote-attach: terminal loop returned — restoring terminal and exiting");

    if is_nested_inside_zellij_pane {
        let mut stdout = os_input.get_stdout_writer();
        let _ = stdout.write_all(&nested_session::encode_frame(
            &nested_session::NestedSessionMessage::Bye,
        ));
        let _ = stdout.flush();
    }

    let exit_msg = String::from("Bye from Zellij!");

    if reconnect_to_session.is_none() {
        reset_controlling_terminal_state(exit_msg, 0);
        std::process::exit(0);
    } else {
        let clear_screen = "\u{1b}[2J";
        let mut stdout = os_input.get_stdout_writer();
        stdout.write_all(clear_screen.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }

    Ok(reconnect_to_session)
}

pub fn start_client(
    mut os_input: Box<dyn ClientOsApi>,
    cli_args: CliArgs,
    config: Config,          // saved to disk (or default?)
    config_options: Options, // CLI options merged into (getting priority over) saved config options
    info: ClientInfo,
    tab_position_to_focus: Option<usize>,
    pane_id_to_focus: Option<(u32, bool)>, // (pane_id, is_plugin)
    is_a_reconnect: bool,
    start_detached_and_exit: bool,
) -> Option<ConnectToSession> {
    if start_detached_and_exit {
        start_server_detached(os_input, cli_args, config, config_options, info);
        return None;
    }
    info!("Starting Zellij client!");

    let is_nested_inside_zellij_pane = os_input.env_variable("ZELLIJ").is_some();
    let own_session_name = info.get_session_name().to_owned();

    let explicitly_disable_kitty_keyboard_protocol = config_options
        .support_kitty_keyboard_protocol
        .map(|e| !e)
        .unwrap_or(false);
    let support_kitty_graphics_protocol = config_options
        .support_kitty_graphics_protocol
        .unwrap_or(true);
    let should_start_web_server = config_options.web_server.map(|w| w).unwrap_or(false);
    let mut reconnect_to_session = None;
    os_input.unset_raw_mode().unwrap();

    if !is_a_reconnect {
        // we don't do this for a reconnect because our controlling terminal already has the
        // attributes we want from it, and some terminals don't treat these atomically (looking at
        // you Windows Terminal...)
        let mut stdout = os_input.get_stdout_writer();
        stdout.write_all(ENTER_ALTERNATE_SCREEN.as_bytes()).unwrap();
        stdout
            .write_all(CLEAR_CLIENT_TERMINAL_ATTRIBUTES.as_bytes())
            .unwrap();
        if !explicitly_disable_kitty_keyboard_protocol {
            stdout
                .write_all(ENTER_KITTY_KEYBOARD_MODE.as_bytes())
                .unwrap();
        }
        // Subscribe to host CSI 2031 theme notifications and query the
        // current mode. Sent right after CLEAR_CLIENT_TERMINAL_ATTRIBUTES
        // so there's no window in which the host is unsubscribed.
        // Hosts that don't support 2031 ignore both sequences.
        stdout
            .write_all(ENABLE_HOST_THEME_NOTIFY.as_bytes())
            .unwrap();
        stdout.write_all(QUERY_HOST_THEME.as_bytes()).unwrap();
    }
    envs::set_zellij("0".to_string());
    config.env.set_vars();

    let full_screen_ws = os_input.get_terminal_size();

    let web_server_ip = config_options
        .web_server_ip
        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let web_server_port = config_options.web_server_port.unwrap_or_else(|| 8082);
    let has_certificate =
        config_options.web_server_cert.is_some() && config_options.web_server_key.is_some();
    let enforce_https_for_localhost = config_options.enforce_https_for_localhost.unwrap_or(false);

    let terminal_teardown = TerminalTeardown {
        include_kitty_exit: !explicitly_disable_kitty_keyboard_protocol,
    };

    let (first_msg, ipc_pipe) = match info {
        ClientInfo::Attach(name, config_options) => {
            envs::set_session_name(name.clone());
            os_input.update_session_name(name);
            let ipc_pipe = create_ipc_pipe(Some(terminal_teardown));
            let is_web_client = false;

            let cli_assets = CliAssets {
                config_file_path: Config::config_file_path(&cli_args),
                config_dir: cli_args.config_dir.clone(),
                should_ignore_config: cli_args.is_setup_clean(),
                configuration_options: Some(config_options.clone()),
                layout: if let Some(layout_string) = &cli_args.layout_string {
                    Some(LayoutInfo::Stringified(layout_string.clone()))
                } else {
                    cli_args
                        .layout
                        .as_ref()
                        .and_then(|l| {
                            LayoutInfo::from_cli(
                                &config_options.layout_dir,
                                &Some(l.clone()),
                                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                            )
                        })
                        .or_else(|| {
                            LayoutInfo::from_config(
                                &config_options.layout_dir,
                                &config_options.default_layout,
                            )
                        })
                },
                terminal_window_size: full_screen_ws,
                data_dir: cli_args.data_dir.clone(),
                is_debug: cli_args.debug,
                max_panes: cli_args.max_panes,
                force_run_layout_commands: false,
                cwd: None,
            };
            (
                ClientToServerMsg::AttachClient {
                    cli_assets,
                    tab_position_to_focus,
                    pane_to_focus: pane_id_to_focus.map(|(pane_id, is_plugin)| {
                        zellij_utils::ipc::PaneReference { pane_id, is_plugin }
                    }),
                    is_web_client,
                },
                ipc_pipe,
            )
        },
        ClientInfo::Watch(name, _config_options) => {
            envs::set_session_name(name.clone());
            os_input.update_session_name(name);
            let ipc_pipe = create_ipc_pipe(Some(terminal_teardown));
            let is_web_client = false;

            (
                ClientToServerMsg::AttachWatcherClient {
                    terminal_size: full_screen_ws,
                    is_web_client,
                },
                ipc_pipe,
            )
        },
        ClientInfo::Resurrect(name, path_to_layout, force_run_commands, cwd) => {
            envs::set_session_name(name.clone());

            let cli_assets = CliAssets {
                config_file_path: Config::config_file_path(&cli_args),
                config_dir: cli_args.config_dir.clone(),
                should_ignore_config: cli_args.is_setup_clean(),
                configuration_options: Some(config_options.clone()),
                layout: Some(LayoutInfo::File(
                    path_to_layout.display().to_string(),
                    LayoutMetadata::default(),
                )),
                terminal_window_size: full_screen_ws,
                data_dir: cli_args.data_dir.clone(),
                is_debug: cli_args.debug,
                max_panes: cli_args.max_panes,
                force_run_layout_commands: force_run_commands,
                cwd,
            };

            os_input.update_session_name(name);
            let ipc_pipe = create_ipc_pipe(Some(terminal_teardown));

            if let Err(e) = os_input.spawn_server(&*ipc_pipe, cli_args.debug) {
                exit_after_startup_error(Some(terminal_teardown), spawn_server_error_message(e));
            }
            if should_start_web_server {
                if let Err(e) = spawn_web_server(&cli_args) {
                    log::error!("Failed to start web server: {}", e);
                }
            }

            let is_web_client = false;

            (
                ClientToServerMsg::FirstClientConnected {
                    cli_assets,
                    is_web_client,
                },
                ipc_pipe,
            )
        },
        ClientInfo::New(name, layout_info, layout_cwd) => {
            envs::set_session_name(name.clone());

            let cli_assets = CliAssets {
                config_file_path: Config::config_file_path(&cli_args),
                config_dir: cli_args.config_dir.clone(),
                should_ignore_config: cli_args.is_setup_clean(),
                configuration_options: Some(config_options.clone()),
                layout: layout_info.or_else(|| {
                    cli_args
                        .layout
                        .as_ref()
                        .and_then(|l| {
                            LayoutInfo::from_cli(
                                &config_options.layout_dir,
                                &Some(l.clone()),
                                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                            )
                        })
                        .or_else(|| {
                            LayoutInfo::from_config(
                                &config_options.layout_dir,
                                &config_options.default_layout,
                            )
                        })
                }),
                terminal_window_size: full_screen_ws,
                data_dir: cli_args.data_dir.clone(),
                is_debug: cli_args.debug,
                max_panes: cli_args.max_panes,
                force_run_layout_commands: false,
                cwd: layout_cwd,
            };

            os_input.update_session_name(name);
            let ipc_pipe = create_ipc_pipe(Some(terminal_teardown));

            if let Err(e) = os_input.spawn_server(&*ipc_pipe, cli_args.debug) {
                exit_after_startup_error(Some(terminal_teardown), spawn_server_error_message(e));
            }
            if should_start_web_server {
                if let Err(e) = spawn_web_server(&cli_args) {
                    log::error!("Failed to start web server: {}", e);
                }
            }

            let is_web_client = false;

            (
                ClientToServerMsg::FirstClientConnected {
                    cli_assets,
                    is_web_client,
                },
                ipc_pipe,
            )
        },
    };

    os_input.connect_to_server(&*ipc_pipe);
    os_input.send_to_server(first_msg);

    let mut command_is_executing = CommandIsExecuting::new();

    os_input.set_raw_mode();
    let mut stdout = os_input.get_stdout_writer();
    stdout.write_all(ENABLE_BRACKETED_PASTE.as_bytes()).unwrap();
    let nested_reannounce = if is_nested_inside_zellij_pane {
        let announce = nested_session::NestedSessionMessage::Announce {
            session_name: own_session_name.clone(),
            capabilities: vec![nested_session::NestedSessionCapability::NestedControl],
        };
        stdout
            .write_all(&nested_session::encode_frame(&announce))
            .unwrap();
        let _ = stdout.flush();
        Some(crate::nested_reannounce::NestedReannounce::spawn(
            os_input.clone(),
            own_session_name.clone(),
        ))
    } else {
        None
    };

    let (send_client_instructions, receive_client_instructions): ChannelWithContext<
        ClientInstruction,
    > = channels::bounded(50);
    let send_client_instructions = SenderWithContext::new(send_client_instructions);

    let (send_input_instructions, receive_input_instructions): ChannelWithContext<
        InputInstruction,
    > = channels::bounded(50);
    let send_input_instructions = SenderWithContext::new(send_input_instructions);

    if os_input.should_install_panic_hook() {
        std::panic::set_hook({
            use zellij_utils::errors::handle_panic;
            let send_client_instructions = send_client_instructions.clone();
            let os_input = os_input.clone();
            Box::new(move |info| {
                os_input.disable_mouse().non_fatal();
                os_input.restore_console_mode();
                if let Ok(()) = os_input.unset_raw_mode() {
                    handle_panic(info, Some(&send_client_instructions));
                }
            })
        });
    }

    let on_force_close = config_options.on_force_close.unwrap_or_default();
    let stdin_ansi_parser = Arc::new(Mutex::new(StdinAnsiParser::new()));

    let (resize_sender, resize_receiver) = std::sync::mpsc::channel::<()>();

    let _stdin_thread = thread::Builder::new()
        .name("stdin_handler".to_string())
        .spawn({
            let os_input = os_input.clone();
            let send_input_instructions = send_input_instructions.clone();
            let stdin_ansi_parser = stdin_ansi_parser.clone();
            move || {
                stdin_loop(
                    os_input,
                    send_input_instructions,
                    stdin_ansi_parser,
                    explicitly_disable_kitty_keyboard_protocol,
                    support_kitty_graphics_protocol,
                    Some(resize_sender),
                )
            }
        });

    // Apps running inside Zellij panes can issue a whitelisted set
    // of queries to the host terminal (bg/fg colour, palette
    // registers, window pixel dimensions). Each query opens a
    // "forward slot" on the client: we write the query + a
    // Primary-DA barrier to stdout, then collect any reply bytes
    // that arrive on stdin until the barrier reply closes the slot.
    // The pane that asked gets the captured bytes piped to its pty.
    //
    // If the host never answers, we must close the slot anyway so
    // the server can dispatch the next queued forward. A per-slot
    // timer task enforces that deadline: opening a forward spawns
    // an async sleep on `forward_timeout_runtime()`; on wake it
    // tries to close the slot for that specific token. If the
    // barrier (or a later forward) closed the slot first, the
    // timer's close call is a no-op — the token-guard makes
    // cancellation implicit. Spawn site: the
    // `ClientInstruction::ForwardQueryToHost` handler below.

    let _input_thread = thread::Builder::new()
        .name("input_handler".to_string())
        .spawn({
            let send_client_instructions = send_client_instructions.clone();
            let command_is_executing = command_is_executing.clone();
            let os_input = os_input.clone();
            let default_mode = config_options.default_mode.unwrap_or_default();
            let nested_reannounce = nested_reannounce.clone();
            move || {
                input_loop(
                    os_input,
                    config,
                    config_options,
                    command_is_executing,
                    send_client_instructions,
                    default_mode,
                    receive_input_instructions,
                    nested_reannounce,
                )
            }
        });

    let _signal_thread = thread::Builder::new()
        .name("signal_listener".to_string())
        .spawn({
            let os_input = os_input.clone();
            move || {
                os_input.handle_signals(
                    Box::new({
                        let os_api = os_input.clone();
                        move || {
                            os_api.send_to_server(ClientToServerMsg::TerminalResize {
                                new_size: os_api.get_terminal_size(),
                            });
                            #[cfg(not(windows))]
                            let _ = os_api
                                .get_stdout_writer()
                                .write(crate::stdin_handler::PIXEL_SIZE_QUERY.as_bytes());
                        }
                    }),
                    Box::new({
                        let os_api = os_input.clone();
                        move || {
                            os_api.send_to_server(ClientToServerMsg::Action {
                                action: on_force_close.into(),
                                terminal_id: None,
                                client_id: None,
                                is_cli_client: false,
                            });
                        }
                    }),
                    Some(resize_receiver),
                );
            }
        })
        .unwrap();

    let router_thread = thread::Builder::new()
        .name("router".to_string())
        .spawn({
            let os_input = os_input.clone();
            let mut should_break = false;
            let mut consecutive_unknown_messages_received = 0;
            move || loop {
                match os_input.recv_from_server() {
                    Some((instruction, err_ctx)) => {
                        consecutive_unknown_messages_received = 0;
                        err_ctx.update_thread_ctx();
                        if let ServerToClientMsg::Exit { .. } = instruction {
                            should_break = true;
                        }
                        send_client_instructions.send(instruction.into()).unwrap();
                        if should_break {
                            break;
                        }
                    },
                    None => {
                        consecutive_unknown_messages_received += 1;
                        send_client_instructions
                            .send(ClientInstruction::UnblockInputThread)
                            .unwrap();
                        log::error!("Received unknown message from server");
                        if consecutive_unknown_messages_received >= 1000 {
                            send_client_instructions
                                .send(ClientInstruction::Error(
                                    "Received empty unknown from server".to_string(),
                                ))
                                .unwrap();
                            break;
                        }
                    },
                }
            }
        })
        .unwrap();

    let handle_error = |backtrace: String| {
        os_input.disable_mouse().non_fatal();
        os_input.unset_raw_mode().unwrap();
        os_input.restore_console_mode();
        let error = terminal_teardown_message(
            &backtrace,
            full_screen_ws.rows,
            !explicitly_disable_kitty_keyboard_protocol,
        );
        let mut stdout = os_input.get_stdout_writer();
        stdout.write_all(error.as_bytes()).unwrap();
        stdout.flush().unwrap();
        std::process::exit(1);
    };

    let mut exit_msg = String::new();
    let mut synchronised_output = match os_input.env_variable("TERM").as_deref() {
        Some("alacritty") => Some(SyncOutput::DCS),
        _ => None,
    };

    loop {
        let (client_instruction, mut err_ctx) = receive_client_instructions
            .recv()
            .expect("failed to receive app instruction on channel");

        err_ctx.add_call(ContextType::Client((&client_instruction).into()));

        match client_instruction {
            ClientInstruction::Exit(reason) => {
                os_input.send_to_server(ClientToServerMsg::ClientExited);

                if let ExitReason::Error(_) = reason {
                    handle_error(reason.to_string());
                }
                exit_msg = reason.to_string();
                break;
            },
            ClientInstruction::Error(backtrace) => {
                handle_error(backtrace);
            },
            ClientInstruction::Render(output) => {
                let mut stdout = os_input.get_stdout_writer();
                if let Some(sync) = synchronised_output {
                    stdout
                        .write_all(sync.start_seq())
                        .expect("cannot write to stdout");
                }
                stdout
                    .write_all(output.as_bytes())
                    .expect("cannot write to stdout");
                if let Some(sync) = synchronised_output {
                    stdout
                        .write_all(sync.end_seq())
                        .expect("cannot write to stdout");
                }
                stdout.flush().expect("could not flush");
            },
            ClientInstruction::UnblockInputThread => {
                command_is_executing.unblock_input_thread();
            },
            ClientInstruction::Log(lines_to_log) => {
                for line in lines_to_log {
                    log::info!("{line}");
                }
            },
            ClientInstruction::LogError(lines_to_log) => {
                for line in lines_to_log {
                    log::error!("{line}");
                }
            },
            ClientInstruction::SwitchSession(connect_to_session) => {
                reconnect_to_session = Some(connect_to_session);
                os_input.send_to_server(ClientToServerMsg::ClientExited);
                break;
            },
            ClientInstruction::SetSynchronizedOutput(enabled) => {
                synchronised_output = enabled;
            },
            ClientInstruction::QueryTerminalSize => {
                os_input.send_to_server(ClientToServerMsg::TerminalResize {
                    new_size: os_input.get_terminal_size(),
                });
            },
            ClientInstruction::StartWebServer => {
                let web_server_base_url = web_server_base_url(
                    web_server_ip,
                    web_server_port,
                    has_certificate,
                    enforce_https_for_localhost,
                );
                match spawn_web_server(&cli_args) {
                    Ok(_) => {
                        let _ = os_input.send_to_server(ClientToServerMsg::WebServerStarted {
                            base_url: web_server_base_url,
                        });
                    },
                    Err(e) => {
                        log::error!("Failed to start web_server: {}", e);
                        let _ = os_input
                            .send_to_server(ClientToServerMsg::FailedToStartWebServer { error: e });
                    },
                }
            },
            ClientInstruction::ForwardQueryToHost { token, query_bytes } => {
                // 1. Open a forwarding window on the parser so any reply
                //    events that arrive before the barrier are captured.
                //    A slot may still be open here: the server's backstop
                //    timeout can give up on the previous token and dispatch
                //    this one before this client's per-slot timer got to
                //    run. Hand that slot over instead of clobbering it.
                let stale_forward = {
                    let mut stdin_ansi_parser = stdin_ansi_parser.lock().unwrap();
                    let stale_forward = stdin_ansi_parser.take_active_forward();
                    stdin_ansi_parser.open_forward(token);
                    stale_forward
                };
                if let Some((stale_token, stale_reply_bytes)) = stale_forward {
                    log::warn!(
                        "forward slot for token {} was still open when token {} was dispatched \
                         ({} accumulated bytes); closing it out",
                        stale_token,
                        token,
                        stale_reply_bytes.len(),
                    );
                    let _ = send_input_instructions.send(
                        InputInstruction::ForwardedReplyFromHostComplete {
                            token: stale_token,
                            reply_bytes: stale_reply_bytes,
                        },
                    );
                }
                // 2. Spawn a per-forward timer on the dedicated async
                //    runtime. When the deadline fires, the task closes
                //    the slot (if it's still open for this token) and
                //    relays `ForwardedReplyFromHostComplete` so the
                //    server releases `forward_in_flight` and dispatches
                //    the next queued forward.
                let runtime = stdin_ansi_parser::forward_timeout_runtime();
                let parser_for_timer = stdin_ansi_parser.clone();
                let sender_for_timer = send_input_instructions.clone();
                stdin_ansi_parser::schedule_forward_timeout(
                    runtime.handle(),
                    parser_for_timer,
                    token,
                    std::time::Duration::from_millis(500),
                    move |token, reply_bytes| {
                        let _ = sender_for_timer.send(
                            InputInstruction::ForwardedReplyFromHostComplete { token, reply_bytes },
                        );
                    },
                );
                // 3. Write the query + Primary-DA barrier in a single
                //    write_all. The barrier closes the window on the
                //    parser side when its reply arrives — the timer
                //    task's eventual wake-up finds an empty slot for
                //    this token and no-ops.
                let mut blob = query_bytes;
                blob.extend_from_slice(b"\x1b[c");
                let mut out = os_input.get_stdout_writer();
                let _ = out.write_all(&blob);
                let _ = out.flush();
            },
            ClientInstruction::EmitNestedSessionFrame(payload_bytes) => {
                if is_nested_inside_zellij_pane {
                    let frame = nested_session::encode_frame_from_payload(&payload_bytes);
                    let mut out = os_input.get_stdout_writer();
                    let _ = out.write_all(&frame);
                    let _ = out.flush();
                }
            },
            _ => {},
        }
    }

    if let Some(nested_reannounce) = &nested_reannounce {
        nested_reannounce.stop();
    }

    router_thread.join().unwrap();

    if is_nested_inside_zellij_pane {
        let mut stdout = os_input.get_stdout_writer();
        let _ = stdout.write_all(&nested_session::encode_frame(
            &nested_session::NestedSessionMessage::Bye,
        ));
        let _ = stdout.flush();
    }

    if reconnect_to_session.is_none() {
        let goodbye_message = terminal_teardown_message(
            &exit_msg,
            full_screen_ws.rows,
            !explicitly_disable_kitty_keyboard_protocol,
        );

        os_input.disable_mouse().non_fatal();
        info!("{}", exit_msg);
        os_input.unset_raw_mode().unwrap();
        os_input.restore_console_mode();
        let mut stdout = os_input.get_stdout_writer();
        stdout.write_all(goodbye_message.as_bytes()).unwrap();
        stdout.flush().unwrap();
    } else {
        let clear_screen = "\u{1b}[2J";
        let mut stdout = os_input.get_stdout_writer();
        stdout.write_all(clear_screen.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }

    let _ = send_input_instructions.send(InputInstruction::Exit);

    reconnect_to_session
}

pub fn start_server_detached(
    mut os_input: Box<dyn ClientOsApi>,
    cli_args: CliArgs,
    config: Config,
    config_options: Options,
    info: ClientInfo,
) {
    envs::set_zellij("0".to_string());
    config.env.set_vars();

    let should_start_web_server = config_options.web_server.map(|w| w).unwrap_or(false);

    let (first_msg, ipc_pipe) = match info {
        ClientInfo::Resurrect(name, path_to_layout, force_run_commands, cwd) => {
            envs::set_session_name(name.clone());

            let cli_assets = CliAssets {
                config_file_path: Config::config_file_path(&cli_args),
                config_dir: cli_args.config_dir.clone(),
                should_ignore_config: cli_args.is_setup_clean(),
                configuration_options: Some(config_options.clone()),
                layout: Some(LayoutInfo::File(
                    path_to_layout.display().to_string(),
                    LayoutMetadata::default(),
                )),
                terminal_window_size: Size { cols: 50, rows: 50 }, // static number until a
                // client connects
                data_dir: cli_args.data_dir.clone(),
                is_debug: cli_args.debug,
                max_panes: cli_args.max_panes,
                force_run_layout_commands: force_run_commands,
                cwd,
            };

            os_input.update_session_name(name);
            let ipc_pipe = create_ipc_pipe(None);

            if let Err(e) = os_input.spawn_server(&*ipc_pipe, cli_args.debug) {
                exit_after_startup_error(None, spawn_server_error_message(e));
            }
            if should_start_web_server {
                if let Err(e) = spawn_web_server(&cli_args) {
                    log::error!("Failed to start web server: {}", e);
                }
            }

            let is_web_client = false;

            (
                ClientToServerMsg::FirstClientConnected {
                    cli_assets,
                    is_web_client,
                },
                ipc_pipe,
            )
        },
        ClientInfo::New(name, layout_info, layout_cwd) => {
            envs::set_session_name(name.clone());

            let cli_assets = CliAssets {
                config_file_path: Config::config_file_path(&cli_args),
                config_dir: cli_args.config_dir.clone(),
                should_ignore_config: cli_args.is_setup_clean(),
                configuration_options: cli_args.options(),
                layout: layout_info.or_else(|| {
                    cli_args
                        .layout
                        .as_ref()
                        .and_then(|l| {
                            LayoutInfo::from_cli(
                                &config_options.layout_dir,
                                &Some(l.clone()),
                                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                            )
                        })
                        .or_else(|| {
                            LayoutInfo::from_config(
                                &config_options.layout_dir,
                                &config_options.default_layout,
                            )
                        })
                }),
                terminal_window_size: Size { cols: 50, rows: 50 }, // static number until a
                // client connects
                data_dir: cli_args.data_dir.clone(),
                is_debug: cli_args.debug,
                max_panes: cli_args.max_panes,
                force_run_layout_commands: false,
                cwd: layout_cwd,
            };

            os_input.update_session_name(name);
            let ipc_pipe = create_ipc_pipe(None);

            if let Err(e) = os_input.spawn_server(&*ipc_pipe, cli_args.debug) {
                exit_after_startup_error(None, spawn_server_error_message(e));
            }
            if should_start_web_server {
                if let Err(e) = spawn_web_server(&cli_args) {
                    log::error!("Failed to start web server: {}", e);
                }
            }
            let is_web_client = false;

            (
                ClientToServerMsg::FirstClientConnected {
                    cli_assets,
                    is_web_client,
                },
                ipc_pipe,
            )
        },
        _ => {
            eprintln!("Session already exists");
            std::process::exit(1);
        },
    };

    os_input.connect_to_server(&*ipc_pipe);
    os_input.send_to_server(first_msg);
}

fn terminal_teardown_message(message: &str, rows: usize, include_kitty_exit: bool) -> String {
    let goto_start_of_last_line = format!("\u{1b}[{};{}H", rows, 1);
    let kitty_exit = if include_kitty_exit {
        EXIT_KITTY_KEYBOARD_MODE
    } else {
        ""
    };
    format!(
        "{}{}{}{}{}{}{}\n",
        kitty_exit,
        DISABLE_HOST_THEME_NOTIFY,
        EXIT_ALTERNATE_SCREEN,
        RESET_STYLE,
        SHOW_CURSOR,
        goto_start_of_last_line,
        message
    )
}

#[cfg(test)]
mod unit;

