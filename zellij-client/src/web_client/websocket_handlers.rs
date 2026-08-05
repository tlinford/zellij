use crate::web_client::authentication::SessionTokenHash;
use crate::web_client::local_heartbeat::{
    now_millis, spawn_local_ws_heartbeat, HEARTBEAT_TIMEOUT_SECS,
};
use crate::web_client::message_handlers::{render_to_client, send_control_messages_to_client};
use crate::web_client::types::{
    take_pending_welcome_session, AppState, ControlFrame, ControlParams, TerminalParams, ViewerId,
};
use zellij_browser_bridge::protocol::{
    control_payload_to_server_msg, DisplayConfig, FromBrowser, ToBrowser,
};
use zellij_browser_bridge::Uplink;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path as AxumPath, Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tokio_util::sync::CancellationToken;
use zellij_relay_protocol::crypto;
use zellij_utils::{
    ipc::ClientToServerMsg,
    pane_size::{Size, SizeInPixels},
};

pub async fn ws_handler_control(
    ws: WebSocketUpgrade,
    _path: Option<AxumPath<String>>,
    Query(params): Query<ControlParams>,
    State(state): State<AppState>,
    axum::Extension(session_token_hash): axum::Extension<SessionTokenHash>,
) -> Response {
    let viewer_id = ViewerId(params.web_client_id.clone());
    if !state
        .bridge
        .roster()
        .lock()
        .unwrap()
        .verify_ownership(&viewer_id, &session_token_hash.0)
    {
        log::error!(
            "Control WebSocket: client does not own web_client_id {}",
            viewer_id
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    ws.on_upgrade(move |socket| handle_ws_control(socket, params, state, session_token_hash))
}

pub async fn ws_handler_terminal(
    ws: WebSocketUpgrade,
    session_name: Option<AxumPath<String>>,
    Query(params): Query<TerminalParams>,
    State(state): State<AppState>,
    axum::Extension(session_token_hash): axum::Extension<SessionTokenHash>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| {
        handle_ws_terminal(socket, session_name, params, state, session_token_hash)
    })
}

async fn handle_ws_control(
    socket: WebSocket,
    params: ControlParams,
    state: AppState,
    session_token_hash: SessionTokenHash,
) {
    let web_client_id = params.web_client_id;
    let payload = DisplayConfig::from(&*state.config.lock().unwrap());
    let set_config_msg = ToBrowser::SetConfig(payload);

    let (control_socket_tx, mut control_socket_rx) = socket.split();

    let (control_channel_tx, control_channel_rx) = tokio::sync::mpsc::unbounded_channel();
    send_control_messages_to_client(control_channel_rx, control_socket_tx);

    let _ = control_channel_tx.send(ControlFrame::Text(
        serde_json::to_string(&set_config_msg).unwrap(),
    ));

    log::info!("[hb-local-control] wiring heartbeat for incoming /ws/control connection");
    let last_activity = Arc::new(AtomicU64::new(now_millis()));
    let (hb_handle, mut hb_tripped) = spawn_local_ws_heartbeat(
        control_channel_tx.clone(),
        || ControlFrame::Ping(b"hb".to_vec()),
        last_activity.clone(),
        "control",
    );

    let roster = state.bridge.roster();
    roster
        .lock()
        .unwrap()
        .set_control_out(&ViewerId(web_client_id.clone()), control_channel_tx.clone());

    loop {
        let msg = tokio::select! {
            next = control_socket_rx.next() => match next {
                Some(Ok(msg)) => msg,
                _ => break,
            },
            _ = &mut hb_tripped => {
                log::warn!(
                    "local control ws silent >{}s — closing",
                    HEARTBEAT_TIMEOUT_SECS
                );
                break;
            }
        };
        last_activity.store(now_millis(), Ordering::Relaxed);
        match msg {
            Message::Ping(payload) => {
                log::info!(
                    "[hb-local-control] inbound PING ({} bytes) — queueing PONG",
                    payload.len()
                );
                let _ = control_channel_tx.send(ControlFrame::Pong(payload.to_vec()));
                continue;
            },
            Message::Pong(payload) => {
                log::info!(
                    "[hb-local-control] inbound PONG ({} bytes) — last_activity refreshed",
                    payload.len()
                );
                continue;
            },
            Message::Text(text) => {
                let deserialized_msg = match serde_json::from_str::<FromBrowser>(&text) {
                    Ok(msg) => msg,
                    Err(e) => {
                        log::error!("Failed to deserialize client msg: {:?}", e);
                        continue;
                    },
                };
                if deserialized_msg.web_client_id != web_client_id {
                    log::error!(
                        "Client attempted to use web_client_id {} that does not belong to their connection",
                        deserialized_msg.web_client_id
                    );
                    break;
                }
                let viewer_id = ViewerId(deserialized_msg.web_client_id.clone());
                if !roster
                    .lock()
                    .unwrap()
                    .verify_ownership(&viewer_id, &session_token_hash.0)
                {
                    log::error!(
                        "Client attempted to use web_client_id {} that does not belong to their session",
                        viewer_id
                    );
                    break;
                }
                let Some(link) = roster.lock().unwrap().link_for(&viewer_id) else {
                    log::error!("Unknown web_client_id: {}", viewer_id);
                    continue;
                };
                if let Some(client_msg) = control_payload_to_server_msg(deserialized_msg.payload) {
                    link.send_to_server(client_msg);
                }
            },
            Message::Close(_) => {
                break;
            },
            _ => {
                log::error!("Unsupported messagetype : {:?}", msg);
            },
        }
    }
    hb_handle.abort();
}

async fn handle_ws_terminal(
    socket: WebSocket,
    session_name: Option<AxumPath<String>>,
    params: TerminalParams,
    state: AppState,
    session_token_hash: SessionTokenHash,
) {
    let client_size = match (params.rows, params.cols) {
        (Some(rows), Some(cols)) if rows > 0 && cols > 0 => Some(Size {
            rows: rows as usize,
            cols: cols as usize,
        }),
        _ => None,
    };
    let client_pixel_dims = match (params.cell_width, params.cell_height) {
        (Some(width), Some(height)) if width > 0 && height > 0 => Some(SizeInPixels {
            width: width as usize,
            height: height as usize,
        }),
        _ => None,
    };
    let viewer_id = ViewerId(params.web_client_id);
    let roster = state.bridge.roster();

    if !roster
        .lock()
        .unwrap()
        .verify_ownership(&viewer_id, &session_token_hash.0)
    {
        log::error!(
            "Terminal WebSocket: client does not own web_client_id {}",
            viewer_id
        );
        return;
    }

    let Some(link) = roster.lock().unwrap().link_for(&viewer_id) else {
        log::error!("Unknown web_client_id: {}", viewer_id);
        return;
    };

    let (client_terminal_channel_tx, mut client_terminal_channel_rx) = socket.split();
    let (stdout_channel_tx, stdout_channel_rx) = tokio::sync::mpsc::unbounded_channel();
    let e2e_key = state.e2e_keys.lock().unwrap().get(&viewer_id).copied();
    roster
        .lock()
        .unwrap()
        .set_terminal_out(&viewer_id, stdout_channel_tx);

    let session_name = session_name.map(|p| p.0);
    let is_welcome_session = session_name
        .as_ref()
        .map(|name| take_pending_welcome_session(&state.pending_welcome_sessions, name))
        .unwrap_or(true);

    let attachment_complete_rx = state.bridge.start_downlink(
        &viewer_id,
        state.config.lock().unwrap().clone(),
        state.config_options.clone(),
        Some(state.config_file_path.clone()),
        session_name,
        false,
        is_welcome_session,
        client_size,
        client_pixel_dims,
    );

    let terminal_channel_cancellation_token = CancellationToken::new();
    let should_not_reconnect = roster
        .lock()
        .unwrap()
        .should_not_reconnect_flag(&viewer_id)
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

    log::info!("[hb-local-terminal] wiring heartbeat for incoming /ws/terminal connection");
    let (terminal_ping_tx, terminal_ping_rx) =
        tokio::sync::mpsc::unbounded_channel::<Message>();
    let terminal_last_activity = Arc::new(AtomicU64::new(now_millis()));
    let (terminal_hb_handle, mut terminal_hb_tripped) = spawn_local_ws_heartbeat(
        terminal_ping_tx.clone(),
        || Message::Ping(b"hb".to_vec().into()),
        terminal_last_activity.clone(),
        "terminal",
    );

    render_to_client(
        stdout_channel_rx,
        client_terminal_channel_tx,
        terminal_channel_cancellation_token.clone(),
        should_not_reconnect,
        e2e_key,
        terminal_ping_rx,
    );
    roster
        .lock()
        .unwrap()
        .set_terminal_cancellation(&viewer_id, terminal_channel_cancellation_token);

    let explicitly_disable_kitty_keyboard_protocol = state
        .config
        .lock()
        .unwrap()
        .options
        .support_kitty_keyboard_protocol
        .map(|e| !e)
        .unwrap_or(false);
    let read_only = roster.lock().unwrap().read_only(&viewer_id);

    let _ = attachment_complete_rx.await;

    let mut uplink = Uplink::new(link.clone(), read_only, explicitly_disable_kitty_keyboard_protocol);
    let finalize_idle = std::time::Duration::from_millis(50);
    loop {
        let result = if uplink.pending_finalize() {
            tokio::select! {
                msg = client_terminal_channel_rx.next() => Some(msg),
                _ = tokio::time::sleep(finalize_idle) => None,
                _ = &mut terminal_hb_tripped => {
                    log::warn!(
                        "local terminal ws silent >{}s — closing",
                        HEARTBEAT_TIMEOUT_SECS
                    );
                    break;
                }
            }
        } else {
            tokio::select! {
                msg = client_terminal_channel_rx.next() => Some(msg),
                _ = &mut terminal_hb_tripped => {
                    log::warn!(
                        "local terminal ws silent >{}s — closing",
                        HEARTBEAT_TIMEOUT_SECS
                    );
                    break;
                }
            }
        };
        let msg = match result {
            Some(Some(Ok(m))) => m,
            Some(_) => break,
            None => {
                uplink.finalize_idle();
                continue;
            },
        };
        terminal_last_activity.store(now_millis(), Ordering::Relaxed);
        match msg {
            Message::Ping(p) => {
                log::info!(
                    "[hb-local-terminal] inbound PING ({} bytes) — queueing PONG",
                    p.len()
                );
                let _ = terminal_ping_tx.send(Message::Pong(p));
                continue;
            },
            Message::Pong(p) => {
                log::info!(
                    "[hb-local-terminal] inbound PONG ({} bytes) — last_activity refreshed",
                    p.len()
                );
                continue;
            },
            Message::Binary(buf) => {
                let parsed: Vec<u8> = match &e2e_key {
                    Some(key) => match crypto::decrypt(key, &buf) {
                        Ok(plaintext) => plaintext,
                        Err(e) => {
                            log::warn!(
                                "local e2e decrypt failed for client {}: {} — dropping frame",
                                viewer_id, e
                            );
                            continue;
                        }
                    },
                    None => buf.to_vec(),
                };
                uplink.feed_terminal(&parsed);
            },
            Message::Text(text) => {
                if e2e_key.is_some() {
                    log::warn!(
                        "got plaintext Text frame from client {} while E2E is on — dropping",
                        viewer_id
                    );
                    continue;
                }
                uplink.feed_terminal(text.as_bytes());
            },
            Message::Close(_) => {
                roster.lock().unwrap().remove(&viewer_id);
                break;
            },
        }
    }
    terminal_hb_handle.abort();
    state.e2e_keys.lock().unwrap().remove(&viewer_id);
    link.send_to_server(ClientToServerMsg::ClientExited);
}
