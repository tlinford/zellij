use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use zellij_browser_bridge::protocol::DisplayConfig;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use zellij_utils::input::{config::Config, options::Options};
use zellij_browser_bridge::SessionLink;

pub use zellij_browser_bridge::control_frame::ControlFrame;
pub use zellij_browser_bridge::factory::{
    list_web_sessions, LocalSessionSource, SessionLinkFactory, SessionSource, WebSessionInfo,
};
pub use zellij_browser_bridge::{BrowserBridge, ViewerId};

#[derive(Debug, Clone)]
pub struct RealClientOsApiFactory;

impl SessionLinkFactory for RealClientOsApiFactory {
    fn create(&self) -> Result<Box<dyn SessionLink>, Box<dyn std::error::Error>> {
        crate::os_input_output::get_client_os_input()
            .map(|os_input| Box::new(os_input) as Box<dyn SessionLink>)
            .map_err(|e| format!("Failed to create client OS API: {:?}", e).into())
    }
}

pub const MAX_PENDING_WELCOME_SESSIONS: usize = 256;
pub const PENDING_WELCOME_SESSION_TTL: Duration = Duration::from_secs(300);

pub type PendingWelcomeSessions = Arc<Mutex<VecDeque<(String, Instant)>>>;

pub fn record_pending_welcome_session(pending: &PendingWelcomeSessions, session_name: &str) {
    let mut pending = pending.lock().unwrap();
    let now = Instant::now();
    pending.retain(|(_, created_at)| now.duration_since(*created_at) < PENDING_WELCOME_SESSION_TTL);
    while pending.len() >= MAX_PENDING_WELCOME_SESSIONS {
        pending.pop_front();
    }
    pending.push_back((session_name.to_owned(), now));
}

pub fn take_pending_welcome_session(pending: &PendingWelcomeSessions, session_name: &str) -> bool {
    let mut pending = pending.lock().unwrap();
    let now = Instant::now();
    pending.retain(|(_, created_at)| now.duration_since(*created_at) < PENDING_WELCOME_SESSION_TTL);
    match pending.iter().position(|(name, _)| name == session_name) {
        Some(index) => {
            pending.remove(index);
            true
        },
        None => false,
    }
}

#[derive(Clone)]
pub struct AppState {
    pub bridge: Arc<BrowserBridge>,
    pub config: Arc<Mutex<Config>>,
    pub config_options: Options,
    pub config_file_path: PathBuf,
    pub client_os_api_factory: Arc<dyn SessionLinkFactory>,
    pub e2e_keys: Arc<Mutex<HashMap<ViewerId, [u8; 32]>>>,
    pub is_https: bool,
    pub pending_welcome_sessions: PendingWelcomeSessions,
    /// Whether E2E encryption is enabled for local web clients. Sourced
    /// from `Options.encrypt_web_sharing`. When `true`, `serve_html`
    /// stamps `EXPECTED_E2E=true` into the challenge page and
    /// `create_new_client` derives + stores a per-client AES key.
    pub encrypt_web_sharing: bool,
    /// Session-local HKDF `info` parameter. Generated once at web-server
    /// startup so the key the browser derives matches the server's even
    /// when the option is toggled on an existing session (the browser
    /// reads it from the login page — see Step 6).
    pub local_tunnel_id: String,
}

#[derive(Serialize)]
pub struct CreateClientIdResponse {
    pub web_client_id: String,
    pub is_read_only: bool,
    pub session_name: String,
    pub config: DisplayConfig,

    /// Whether the server will encrypt terminal frames on this
    /// connection. Must match the `EXPECTED_E2E` value the challenge page
    /// served; the browser JS refuses to proceed on mismatch.
    pub e2e_encrypted: bool,
    /// HKDF `info` parameter used when deriving the per-client E2E key.
    /// Present regardless of the `e2e_encrypted` flag so the browser can
    /// always cache it (cheaply) and only use it when encryption is on.
    pub tunnel_id: String,
    pub session_rows: u32,
    pub session_cols: u32,
}

#[derive(Deserialize)]
pub struct SessionQuery {
    pub session: Option<String>,
    pub welcome: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct SessionListResponse {
    pub sessions: Vec<WebSessionInfo>,
}

#[derive(Deserialize)]
pub struct TerminalParams {
    pub web_client_id: String,
    pub rows: Option<u16>,
    pub cols: Option<u16>,
    pub cell_width: Option<u16>,
    pub cell_height: Option<u16>,
}

#[derive(Deserialize)]
pub struct ControlParams {
    pub web_client_id: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub auth_token: String,
    pub remember_me: Option<bool>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
}
