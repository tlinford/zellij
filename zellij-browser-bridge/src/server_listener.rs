use crate::connection_table::{ViewerId, ViewerRoster};
use crate::factory::SessionSource;
use crate::host_query_seed::build_host_query_seed_msgs;
use crate::protocol::{DisplayConfig, ToBrowser};
use crate::session_management::{build_initial_connection, create_first_message, create_ipc_pipe};
use crate::virtual_client::SessionLink;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use zellij_utils::{
    cli::CliArgs,
    data::Style,
    input::{config::Config, options::Options},
    ipc::{ClientToServerMsg, ExitReason, PixelDimensions, ServerToClientMsg},
    pane_size::{Size, SizeInPixels},
    sessions::generate_unique_session_name,
    setup::Setup,
};

fn terminal_init_messages() -> Vec<&'static str> {
    let clear_client_terminal_attributes = "\u{1b}[?1l\u{1b}=\u{1b}[r\u{1b}[?1000l\u{1b}[?1002l\u{1b}[?1003l\u{1b}[?1005l\u{1b}[?1006l\u{1b}[?12l";
    let enter_alternate_screen = "\u{1b}[?1049h";
    let bracketed_paste = "\u{1b}[?2004h";
    let enter_kitty_keyboard_mode = "\u{1b}[>1u";
    let enable_mouse_mode = "\u{1b}[?1000h\u{1b}[?1002h\u{1b}[?1015h\u{1b}[?1006h";
    vec![
        clear_client_terminal_attributes,
        enter_alternate_screen,
        bracketed_paste,
        enter_kitty_keyboard_mode,
        enable_mouse_mode,
    ]
}

pub struct Downlink;

impl Downlink {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        link: Box<dyn SessionLink>,
        roster: Arc<Mutex<ViewerRoster>>,
        id: ViewerId,
        source: Arc<dyn SessionSource>,
        mut config: Config,
        mut config_options: Options,
        config_file_path: Option<PathBuf>,
        session_name: Option<String>,
        relay_fanout: bool,
        attachment_complete_tx: Option<tokio::sync::oneshot::Sender<()>>,
        is_welcome_session: bool,
        client_size: Option<Size>,
        client_pixel_dims: Option<SizeInPixels>,
    ) -> Downlink {
        let _downlink_thread = std::thread::Builder::new()
            .name("downlink".to_string())
            .spawn(move || {
                let mut reconnect_to_session =
                    match build_initial_connection(session_name, is_welcome_session, &config) {
                        Ok(initial_session_connection) => initial_session_connection,
                        Err(e) => {
                            log::error!("{}", e);
                            return;
                        },
                    };
                let mut attachment_complete_tx = attachment_complete_tx;
                'reconnect_loop: loop {
                    let reconnect_info = reconnect_to_session.take();
                    let initial_layout = reconnect_info.as_ref().and_then(|r| r.layout.clone());
                    let path = {
                        let Some(session_name) = reconnect_info
                            .as_ref()
                            .and_then(|r| r.name.clone())
                            .or_else(generate_unique_session_name)
                        else {
                            log::error!("Failed to generate unique session name, bailing.");
                            roster.lock().unwrap().close(&id);
                            return;
                        };
                        let mut sock_dir = zellij_utils::consts::ZELLIJ_SOCK_DIR.clone();
                        if let Err(e) = zellij_utils::sessions::validate_session_name(&session_name)
                        {
                            log::error!("Invalid session name: {}", e);
                            roster.lock().unwrap().close(&id);
                            return;
                        }
                        sock_dir.push(session_name.clone());
                        sock_dir.to_str().unwrap().to_owned()
                    };

                    reload_config_from_disk(&mut config, &mut config_options, &config_file_path);

                    let full_screen_ws = client_size.unwrap_or_else(|| link.get_terminal_size());
                    let mut sent_init_messages = false;

                    let palette = config
                        .theme_config(config_options.theme.as_ref())
                        .unwrap_or_else(|| link.load_palette().into());
                    let client_attributes = zellij_utils::ipc::ClientAttributes {
                        size: full_screen_ws,
                        style: Style {
                            colors: palette,
                            rounded_corners: config.ui.pane_frames.rounded_corners,
                            hide_session_name: config.ui.pane_frames.hide_session_name,
                        },
                    };

                    let session_name = PathBuf::from(path.clone())
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned();

                    let is_read_only = roster.lock().unwrap().read_only(&id);

                    let session_exists = source.session_exists(&session_name).unwrap_or(false);

                    if is_read_only && !session_exists {
                        log::error!("Read only tokens cannot create new sessions.");
                        roster.lock().unwrap().close(&id);
                        return;
                    }

                    let should_create_new_session = !session_exists;
                    let first_message = create_first_message(
                        is_read_only,
                        relay_fanout,
                        config_file_path.clone(),
                        client_attributes.clone(),
                        config_options.clone(),
                        should_create_new_session,
                        &session_name,
                        initial_layout,
                    );
                    let zellij_ipc_pipe = create_ipc_pipe(&session_name);

                    source.spawn_session_if_needed(
                        &session_name,
                        link.clone(),
                        session_exists,
                        &zellij_ipc_pipe,
                        first_message,
                    );

                    if let Some(pixel_dims) = client_pixel_dims {
                        link.send_to_server(ClientToServerMsg::TerminalPixelDimensions {
                            pixel_dimensions: PixelDimensions {
                                text_area_size: client_size.map(|size| SizeInPixels {
                                    width: size.cols * pixel_dims.width,
                                    height: size.rows * pixel_dims.height,
                                }),
                                character_cell_size: Some(pixel_dims),
                            },
                        });
                    }

                    for seed in build_host_query_seed_msgs(&config, &config_options) {
                        link.send_to_server(seed);
                    }

                    if let Some(tx) = attachment_complete_tx.take() {
                        let _ = tx.send(());
                    }

                    roster.lock().unwrap().send(
                        &id,
                        ToBrowser::SwitchedSession {
                            new_session_name: session_name.clone(),
                        },
                    );

                    let mut unknown_message_count = 0;
                    loop {
                        let msg = link.recv_from_server();
                        if msg.is_some() {
                            unknown_message_count = 0;
                        } else {
                            unknown_message_count += 1;
                        }
                        match msg.map(|m| m.0) {
                            Some(ServerToClientMsg::UnblockInputThread) => {},
                            Some(ServerToClientMsg::Connected) => {},
                            Some(ServerToClientMsg::CliPipeOutput { .. }) => {},
                            Some(ServerToClientMsg::UnblockCliPipeInput { .. }) => {},
                            Some(ServerToClientMsg::StartWebServer { .. }) => {},
                            Some(ServerToClientMsg::Exit { exit_reason }) => {
                                handle_exit_reason(&roster, &id, exit_reason);
                                link.send_to_server(ClientToServerMsg::ClientExited);
                                break;
                            },
                            Some(ServerToClientMsg::Render { content: bytes }) => {
                                if !sent_init_messages {
                                    for message in terminal_init_messages() {
                                        roster
                                            .lock()
                                            .unwrap()
                                            .send_stdout(&id, message.to_owned());
                                    }
                                    sent_init_messages = true;
                                }
                                roster.lock().unwrap().send_stdout(&id, bytes);
                            },
                            Some(ServerToClientMsg::SwitchSession { connect_to_session }) => {
                                reconnect_to_session = Some(connect_to_session);
                                continue 'reconnect_loop;
                            },
                            Some(ServerToClientMsg::QueryTerminalSize) => {
                                roster.lock().unwrap().send(&id, ToBrowser::QueryTerminalSize);
                            },
                            Some(ServerToClientMsg::SetSoftKeyboard { on }) => {
                                roster
                                    .lock()
                                    .unwrap()
                                    .send(&id, ToBrowser::SetSoftKeyboard { on });
                            },
                            Some(ServerToClientMsg::MobileState { payload }) => {
                                roster
                                    .lock()
                                    .unwrap()
                                    .send(&id, ToBrowser::MobileState { payload });
                            },
                            Some(ServerToClientMsg::EmitNestedSessionFrame { .. }) => {},
                            Some(ServerToClientMsg::Log { lines }) => {
                                roster.lock().unwrap().send(&id, ToBrowser::Log { lines });
                            },
                            Some(ServerToClientMsg::LogError { lines }) => {
                                roster.lock().unwrap().send(&id, ToBrowser::LogError { lines });
                            },
                            Some(ServerToClientMsg::RenamedSession {
                                name: new_session_name,
                            }) => {
                                roster
                                    .lock()
                                    .unwrap()
                                    .send(&id, ToBrowser::SwitchedSession { new_session_name });
                            },
                            Some(ServerToClientMsg::ConfigFileUpdated) => {
                                if let Some(config_file_path) = &config_file_path {
                                    if let Ok(new_config) =
                                        Config::from_path(config_file_path, Some(config.clone()))
                                    {
                                        for seed in
                                            build_host_query_seed_msgs(&new_config, &config_options)
                                        {
                                            link.send_to_server(seed);
                                        }
                                        let set_config_payload = DisplayConfig::from(&new_config);
                                        let config_message =
                                            ToBrowser::SetConfig(set_config_payload);
                                        let config_msg_json =
                                            match serde_json::to_string(&config_message) {
                                                Ok(json) => json,
                                                Err(e) => {
                                                    log::error!(
                                                        "Failed to serialize config message: {}",
                                                        e
                                                    );
                                                    continue;
                                                },
                                            };

                                        let viewer_ids = roster.lock().unwrap().ids();
                                        for viewer_id in viewer_ids {
                                            if let Some(control_tx) =
                                                roster.lock().unwrap().control_out(&viewer_id)
                                            {
                                                if let Err(e) =
                                                    control_tx.send(config_msg_json.clone().into())
                                                {
                                                    log::error!(
                                                        "Failed to send config update to viewer {}: {}",
                                                        viewer_id,
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            Some(ServerToClientMsg::PaneRenderUpdate { .. }) => {},
                            Some(ServerToClientMsg::SubscribedPaneClosed { .. }) => {},
                            Some(ServerToClientMsg::ForwardQueryToHost { token, .. }) => {
                                link.send_to_server(ClientToServerMsg::ForwardedReplyFromHost {
                                    token,
                                    reply_bytes: Vec::new(),
                                });
                            },
                            Some(ServerToClientMsg::SessionSize { rows, cols }) => {
                                roster
                                    .lock()
                                    .unwrap()
                                    .send(&id, ToBrowser::SessionSizeChanged { rows, cols });
                            },
                            None => {
                                if unknown_message_count >= 1000 {
                                    log::error!("Error: Received more than 1000 consecutive unknown server messages, disconnecting.");
                                    break;
                                }
                            },
                        }
                    }
                    if reconnect_to_session.is_none() {
                        break;
                    }
                }
            });
        Downlink
    }
}

fn handle_exit_reason(roster: &Arc<Mutex<ViewerRoster>>, id: &ViewerId, exit_reason: ExitReason) {
    match exit_reason {
        ExitReason::KickedByHost => {
            roster.lock().unwrap().close_kicked(id);
            return;
        },
        ExitReason::WebClientsForbidden => {
            roster.lock().unwrap().send_stdout(
                id,
                format!("\u{1b}[2J\n Web Clients are not allowed to attach to this session."),
            );
        },
        ExitReason::Error(e) => {
            let goto_start_of_last_line = format!("\u{1b}[{};{}H", 1, 1);
            let clear_client_terminal_attributes = "\u{1b}[?1l\u{1b}=\u{1b}[r\u{1b}[?1000l\u{1b}[?1002l\u{1b}[?1003l\u{1b}[?1005l\u{1b}[?1006l\u{1b}[?12l";
            let disable_mouse = "\u{1b}[?1006l\u{1b}[?1015l\u{1b}[?1003l\u{1b}[?1002l\u{1b}[?1000l";
            let error = format!(
                "{}{}\n{}{}\n",
                disable_mouse,
                clear_client_terminal_attributes,
                goto_start_of_last_line,
                e.to_string().replace("\n", "\n\r")
            );
            roster
                .lock()
                .unwrap()
                .send_stdout(id, format!("\u{1b}[2J\n{}", error));
        },
        _ => {},
    }
    roster.lock().unwrap().close(id);
}

fn reload_config_from_disk(
    config_without_layout: &mut Config,
    config_options_without_layout: &mut Options,
    config_file_path: &Option<PathBuf>,
) {
    let mut cli_args = CliArgs::default();
    cli_args.config = config_file_path.clone();
    match Setup::from_cli_args(&cli_args) {
        Ok((_, _, _, reloaded_config_without_layout, reloaded_config_options_without_layout)) => {
            *config_without_layout = reloaded_config_without_layout;
            *config_options_without_layout = reloaded_config_options_without_layout;
        },
        Err(e) => {
            log::error!("Failed to reload config: {}", e);
        },
    };
}
