use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot;

use zellij_utils::input::{config::Config, options::Options};
use zellij_utils::pane_size::{Size, SizeInPixels};

use crate::connection_table::{ViewerId, ViewerRoster};
use crate::control_frame::ControlFrame;
use crate::factory::SessionSource;
use crate::server_listener::Downlink;
use crate::virtual_client::SessionLink;

pub struct ViewerSink {
    pub control_out: UnboundedSender<ControlFrame>,
    pub terminal_out: UnboundedSender<String>,
}

pub struct AttachSpec {
    pub id: ViewerId,
    pub link: Box<dyn SessionLink>,
    pub sink: ViewerSink,
    pub read_only: bool,
    pub relay_fanout: bool,
    pub token_hash: String,
    pub config: Config,
    pub config_options: Options,
    pub config_file_path: Option<PathBuf>,
    pub session_name: Option<String>,
}

pub struct BrowserBridge {
    roster: Arc<Mutex<ViewerRoster>>,
    source: Arc<dyn SessionSource>,
}

impl BrowserBridge {
    pub fn new(source: Arc<dyn SessionSource>) -> Arc<Self> {
        Arc::new(BrowserBridge {
            roster: Arc::new(Mutex::new(ViewerRoster::default())),
            source,
        })
    }

    pub fn roster(&self) -> Arc<Mutex<ViewerRoster>> {
        self.roster.clone()
    }

    pub fn source(&self) -> Arc<dyn SessionSource> {
        self.source.clone()
    }

    pub fn admit(
        &self,
        id: ViewerId,
        link: Box<dyn SessionLink>,
        read_only: bool,
        token_hash: String,
    ) {
        self.roster
            .lock()
            .unwrap()
            .admit(id, link, read_only, token_hash);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_downlink(
        &self,
        id: &ViewerId,
        config: Config,
        config_options: Options,
        config_file_path: Option<PathBuf>,
        session_name: Option<String>,
        relay_fanout: bool,
        is_welcome_session: bool,
        client_size: Option<Size>,
        client_pixel_dims: Option<SizeInPixels>,
    ) -> oneshot::Receiver<()> {
        let link = self
            .roster
            .lock()
            .unwrap()
            .link_for(id)
            .expect("start_downlink for unknown viewer");
        let (tx, rx) = oneshot::channel();
        Downlink::start(
            link,
            self.roster.clone(),
            id.clone(),
            self.source.clone(),
            config,
            config_options,
            config_file_path,
            session_name,
            relay_fanout,
            Some(tx),
            is_welcome_session,
            client_size,
            client_pixel_dims,
        );
        rx
    }

    pub fn attach(&self, spec: AttachSpec) -> oneshot::Receiver<()> {
        let AttachSpec {
            id,
            link,
            sink,
            read_only,
            relay_fanout,
            token_hash,
            config,
            config_options,
            config_file_path,
            session_name,
        } = spec;
        {
            let mut roster = self.roster.lock().unwrap();
            roster.admit(id.clone(), link, read_only, token_hash);
            roster.set_control_out(&id, sink.control_out);
            roster.set_terminal_out(&id, sink.terminal_out);
        }
        self.start_downlink(
            &id,
            config,
            config_options,
            config_file_path,
            session_name,
            relay_fanout,
            false,
            None,
            None,
        )
    }

    pub fn kick(&self, id: &ViewerId) {
        self.roster.lock().unwrap().close_kicked(id);
    }
}
