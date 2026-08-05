//! Transport-agnostic WebSocket control frame. The connection table stores
//! control-channel senders typed on this enum so the bridging machinery has
//! no dependency on a concrete WebSocket implementation (axum / tungstenite).
//! Each transport converts to/from `ControlFrame` at its own socket boundary.

#[derive(Debug, Clone)]
pub enum ControlFrame {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close { code: u16, reason: String },
}

impl From<String> for ControlFrame {
    fn from(s: String) -> Self {
        ControlFrame::Text(s)
    }
}

impl From<&str> for ControlFrame {
    fn from(s: &str) -> Self {
        ControlFrame::Text(s.to_string())
    }
}
