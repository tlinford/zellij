use std::collections::HashMap;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::control_frame::ControlFrame;
use crate::protocol::{control_payload_to_server_msg, FromBrowser, ToBrowser};
use crate::virtual_client::SessionLink;

const CLOSE_CODE_NORMAL: u16 = 1000;
const CLOSE_CODE_DO_NOT_RECONNECT: u16 = 4001;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ViewerId(pub String);

impl ViewerId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ViewerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct Viewer {
    pub id: ViewerId,
    pub read_only: bool,
    link: Box<dyn SessionLink>,
    control_out: Option<UnboundedSender<ControlFrame>>,
    terminal_out: Option<UnboundedSender<String>>,
    terminal_cancellation: Option<CancellationToken>,
    should_not_reconnect: Arc<AtomicBool>,
}

impl Viewer {
    fn new(id: ViewerId, link: Box<dyn SessionLink>, read_only: bool) -> Self {
        Viewer {
            id,
            read_only,
            link,
            control_out: None,
            terminal_out: None,
            terminal_cancellation: None,
            should_not_reconnect: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn link(&self) -> Box<dyn SessionLink> {
        self.link.box_clone()
    }

    pub fn send(&self, msg: ToBrowser) {
        match &self.control_out {
            Some(tx) => {
                let frame = ControlFrame::Text(serde_json::to_string(&msg).unwrap());
                let _ = tx.send(frame);
            },
            None => log::error!("Failed to send control message to viewer {} (no sink)", self.id),
        }
    }

    pub fn send_stdout(&self, stdout: String) {
        match &self.terminal_out {
            Some(tx) => {
                let _ = tx.send(stdout);
            },
            None => log::error!("Failed to send STDOUT to viewer {} (no sink)", self.id),
        }
    }

    pub fn feed_control(&self, json: &str) {
        let msg: FromBrowser = match serde_json::from_str(json) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to deserialize control message: {:?}", e);
                return;
            },
        };
        let Some(client_msg) = control_payload_to_server_msg(msg.payload) else {
            return;
        };
        self.link.send_to_server(client_msg);
    }
}

#[derive(Debug, Default, Clone)]
pub struct ViewerRoster {
    viewers: HashMap<ViewerId, Viewer>,
    token_hash: HashMap<ViewerId, String>,
}

impl ViewerRoster {
    pub fn admit(
        &mut self,
        id: ViewerId,
        link: Box<dyn SessionLink>,
        read_only: bool,
        token_hash: String,
    ) {
        self.viewers
            .insert(id.clone(), Viewer::new(id.clone(), link, read_only));
        self.token_hash.insert(id, token_hash);
    }

    pub fn verify_ownership(&self, id: &ViewerId, token_hash: &str) -> bool {
        self.token_hash
            .get(id)
            .map(|hash| hash == token_hash)
            .unwrap_or(false)
    }

    pub fn read_only(&self, id: &ViewerId) -> bool {
        self.viewers.get(id).map(|v| v.read_only).unwrap_or(false)
    }

    pub fn set_control_out(&mut self, id: &ViewerId, tx: UnboundedSender<ControlFrame>) {
        if let Some(v) = self.viewers.get_mut(id) {
            v.control_out = Some(tx);
        }
    }

    pub fn set_terminal_out(&mut self, id: &ViewerId, tx: UnboundedSender<String>) {
        if let Some(v) = self.viewers.get_mut(id) {
            v.terminal_out = Some(tx);
        }
    }

    pub fn set_terminal_cancellation(&mut self, id: &ViewerId, token: CancellationToken) {
        if let Some(v) = self.viewers.get_mut(id) {
            v.terminal_cancellation = Some(token);
        }
    }

    pub fn link_for(&self, id: &ViewerId) -> Option<Box<dyn SessionLink>> {
        self.viewers.get(id).map(|v| v.link())
    }

    pub fn control_out(&self, id: &ViewerId) -> Option<UnboundedSender<ControlFrame>> {
        self.viewers.get(id).and_then(|v| v.control_out.clone())
    }

    pub fn should_not_reconnect_flag(&self, id: &ViewerId) -> Option<Arc<AtomicBool>> {
        self.viewers.get(id).map(|v| v.should_not_reconnect.clone())
    }

    pub fn ids(&self) -> Vec<ViewerId> {
        self.viewers.keys().cloned().collect()
    }

    pub fn send(&self, id: &ViewerId, msg: ToBrowser) {
        if let Some(v) = self.viewers.get(id) {
            v.send(msg);
        }
    }

    pub fn send_stdout(&self, id: &ViewerId, stdout: String) {
        if let Some(v) = self.viewers.get(id) {
            v.send_stdout(stdout);
        }
    }

    pub fn feed_control(&self, id: &ViewerId, json: &str) {
        match self.viewers.get(id) {
            Some(v) => v.feed_control(json),
            None => log::error!("Unknown viewer id for control message: {}", id),
        }
    }

    pub fn remove(&mut self, id: &ViewerId) {
        if let Some(mut v) = self.viewers.remove(id) {
            if let Some(token) = v.terminal_cancellation.take() {
                token.cancel();
            }
        }
        self.token_hash.remove(id);
    }

    pub fn close(&mut self, id: &ViewerId) {
        let should_not_reconnect = self
            .viewers
            .get(id)
            .map(|v| v.should_not_reconnect.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false);
        let code = if should_not_reconnect {
            CLOSE_CODE_DO_NOT_RECONNECT
        } else {
            CLOSE_CODE_NORMAL
        };
        if let Some(tx) = self.control_out(id) {
            let _ = tx.send(ControlFrame::Close {
                code,
                reason: "Connection closed".to_string(),
            });
        }
        self.remove(id);
    }

    pub fn close_kicked(&mut self, id: &ViewerId) {
        if let Some(v) = self.viewers.get(id) {
            v.should_not_reconnect
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.close(id);
    }
}
