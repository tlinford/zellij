use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zellij_utils::input::layout::Layout;
use zellij_utils::ipc::ClientToServerMsg;
use crate::virtual_client::SessionLink;

use crate::session_management::spawn_new_session;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WebSessionInfo {
    pub name: String,
    pub web_clients_allowed: bool,
    pub tab_count: usize,
    pub pane_count: usize,
    pub connected_clients: usize,
    pub creation_secs_ago: u64,
}

/// Snapshot of the live sessions on this host, as served to the browser by
/// `GET /session-list` and used to populate the mobile session menu.
pub fn list_web_sessions() -> Vec<WebSessionInfo> {
    zellij_utils::sessions::read_live_session_states_default_dirs("")
        .into_values()
        .map(|info| WebSessionInfo {
            name: info.name,
            web_clients_allowed: info.web_clients_allowed,
            tab_count: info.tabs.len(),
            pane_count: info.panes.panes.values().map(|panes| panes.len()).sum(),
            connected_clients: info.connected_clients,
            creation_secs_ago: info.creation_time.as_secs(),
        })
        .collect()
}

pub trait SessionLinkFactory: Send + Sync + std::fmt::Debug {
    fn create(&self) -> Result<Box<dyn SessionLink>, Box<dyn std::error::Error>>;
}

pub trait SessionSource: Send + Sync + std::fmt::Debug {
    fn session_exists(&self, session_name: &str) -> Result<bool, Box<dyn std::error::Error>>;
    fn list_sessions(&self) -> Vec<WebSessionInfo> {
        list_web_sessions()
    }
    fn get_resurrection_layout(&self, session_name: &str) -> Option<Layout>;
    fn spawn_session_if_needed(
        &self,
        session_name: &str,
        os_input: Box<dyn SessionLink>,
        session_exists: bool,
        zellij_ipc_pipe: &PathBuf,
        first_message: ClientToServerMsg,
    );
}

#[derive(Debug, Clone)]
pub struct LocalSessionSource;

impl SessionSource for LocalSessionSource {
    fn session_exists(&self, session_name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        zellij_utils::sessions::session_exists(session_name)
            .map_err(|e| format!("Session check failed: {:?}", e).into())
    }

    fn get_resurrection_layout(&self, session_name: &str) -> Option<Layout> {
        zellij_utils::sessions::resurrection_layout(session_name)
            .ok()
            .flatten()
    }

    fn spawn_session_if_needed(
        &self,
        session_name: &str,
        os_input: Box<dyn SessionLink>,
        session_exists: bool,
        zellij_ipc_pipe: &PathBuf,
        first_message: ClientToServerMsg,
    ) {
        if !session_exists {
            spawn_new_session(session_name, os_input.clone(), zellij_ipc_pipe);
        }
        os_input.connect_to_server(&zellij_ipc_pipe);
        os_input.send_to_server(first_message);
    }
}
