use std::path::Path;

use zellij_utils::data::Palette;
use zellij_utils::errors::ErrorContext;
use zellij_utils::ipc::{ClientToServerMsg, ServerToClientMsg};
use zellij_utils::pane_size::Size;

pub trait SessionLink: Send + Sync + std::fmt::Debug {
    fn send_to_server(&self, msg: ClientToServerMsg);
    fn recv_from_server(&self) -> Option<(ServerToClientMsg, ErrorContext)>;
    fn connect_to_server(&self, path: &Path);
    fn get_terminal_size(&self) -> Size;
    fn load_palette(&self) -> Palette;
    fn update_session_name(&mut self, new_session_name: String);
    fn spawn_server(&self, socket_path: &Path, debug: bool) -> Result<(), std::io::Error>;
    fn box_clone(&self) -> Box<dyn SessionLink>;
}

impl Clone for Box<dyn SessionLink> {
    fn clone(&self) -> Box<dyn SessionLink> {
        self.box_clone()
    }
}
