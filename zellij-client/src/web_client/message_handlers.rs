use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::{prelude::stream::SplitSink, SinkExt};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_util::sync::CancellationToken;
use zellij_relay_protocol::crypto;

use zellij_browser_bridge::control_frame::ControlFrame;

/// Convert a transport-agnostic `ControlFrame` (produced by the bridging
/// crate) into the axum WebSocket `Message` written to the browser socket.
fn control_frame_to_ws(frame: ControlFrame) -> Message {
    match frame {
        ControlFrame::Text(s) => Message::Text(s.into()),
        ControlFrame::Binary(b) => Message::Binary(b.into()),
        ControlFrame::Ping(p) => Message::Ping(p.into()),
        ControlFrame::Pong(p) => Message::Pong(p.into()),
        ControlFrame::Close { code, reason } => Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
    }
}

pub fn render_to_client(
    mut stdout_channel_rx: UnboundedReceiver<String>,
    mut client_channel_tx: SplitSink<WebSocket, Message>,
    cancellation_token: CancellationToken,
    should_not_reconnect: Arc<AtomicBool>,
    e2e_key: Option<[u8; 32]>,
    mut ping_channel_rx: UnboundedReceiver<Message>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    let code = if should_not_reconnect.load(Ordering::Relaxed) {
                        4001u16
                    } else {
                        axum::extract::ws::close_code::NORMAL
                    };
                    let close_frame = CloseFrame {
                        code,
                        reason: "Connection closed".into(),
                    };
                    let close_message = Message::Close(Some(close_frame));
                    if client_channel_tx
                        .send(close_message)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    break;
                }
                // Phase 6 (Session A): heartbeat Ping / Pong frames
                // routed through this dedicated channel so the existing
                // stdout pipeline can stay `String`-typed.
                ping = ping_channel_rx.recv() => {
                    match ping {
                        Some(msg) => {
                            match &msg {
                                Message::Ping(p) => log::info!(
                                    "[hb-local-terminal] forwarding PING to socket sink ({} bytes)",
                                    p.len()
                                ),
                                Message::Pong(p) => log::info!(
                                    "[hb-local-terminal] forwarding PONG to socket sink ({} bytes)",
                                    p.len()
                                ),
                                _ => {},
                            }
                            if let Err(e) = client_channel_tx.send(msg).await {
                                log::warn!(
                                    "[hb-local-terminal] socket sink send error ({:?}) — exiting render_to_client",
                                    e
                                );
                                break;
                            }
                        }
                        None => {
                            log::info!("[hb-local-terminal] ping channel closed — exiting render_to_client");
                            break;
                        },
                    }
                }
                result = stdout_channel_rx.recv() => {
                    match result {
                        Some(rendered_bytes) => {
                            // With E2E on, encrypt the rendered bytes and
                            // send as Binary; without E2E, Text preserves
                            // the pre-Phase-3 behaviour unchanged.
                            let frame = match &e2e_key {
                                Some(key) => match crypto::encrypt(key, rendered_bytes.as_bytes()) {
                                    Ok(ct) => Message::Binary(ct.into()),
                                    Err(e) => {
                                        log::error!("local e2e encrypt failed: {} — dropping frame", e);
                                        continue;
                                    }
                                },
                                None => Message::Text(rendered_bytes.into()),
                            };
                            if client_channel_tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });
}

pub fn send_control_messages_to_client(
    mut control_channel_rx: UnboundedReceiver<ControlFrame>,
    mut socket_channel_tx: SplitSink<WebSocket, Message>,
) {
    tokio::spawn(async move {
        while let Some(frame) = control_channel_rx.recv().await {
            let message = control_frame_to_ws(frame);
            // Phase 6 diagnostic log: prove the Ping actually reaches
            // the socket writer.
            if let Message::Ping(ref p) = message {
                log::info!(
                    "[hb-local-control] forwarding PING to socket sink ({} bytes)",
                    p.len()
                );
            }
            if let Message::Pong(ref p) = message {
                log::info!(
                    "[hb-local-control] forwarding PONG to socket sink ({} bytes)",
                    p.len()
                );
            }
            if let Err(e) = socket_channel_tx.send(message).await {
                log::warn!(
                    "[hb-local-control] socket sink send error ({:?}) — exiting forwarder",
                    e
                );
                break;
            }
        }
        log::info!("[hb-local-control] forwarder exited (channel closed)");
    });
}
