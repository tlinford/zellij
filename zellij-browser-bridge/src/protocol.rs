use serde::{Deserialize, Serialize};
use zellij_utils::{
    data::{DeviceScope, PaneId},
    input::{actions::Action, config::Config},
    ipc::{ClientToServerMsg, MobileStatePayload, PixelDimensions},
    pane_size::{Size, SizeInPixels},
};

/// Translate a browser control message into the `ClientToServerMsg` it maps
/// to, or `None` when the message is handled locally (relay control channel,
/// device enrolment) and must not be forwarded to the zellij server.
pub fn control_payload_to_server_msg(
    payload: WebClientToWebServerControlMessagePayload,
) -> Option<ClientToServerMsg> {
    use WebClientToWebServerControlMessagePayload as Payload;
    let client_msg = match payload {
        Payload::TerminalResize(size) => ClientToServerMsg::TerminalResize { new_size: size },
        Payload::TerminalMetrics(metrics) => terminal_metrics_to_ipc(metrics),
        Payload::SoftKeyboardVisibilityChanged { visible } => {
            ClientToServerMsg::SoftKeyboardVisibilityChanged { visible }
        },
        Payload::NestedSessionFrameFromHost { payload_bytes } => {
            ClientToServerMsg::NestedSessionFrameFromHost { payload_bytes }
        },
        Payload::RequestSessionList => ClientToServerMsg::RequestSessionList,
        Payload::FocusPane { pane_id, is_plugin } => {
            let pane_id = if is_plugin {
                PaneId::Plugin(pane_id)
            } else {
                PaneId::Terminal(pane_id)
            };
            ClientToServerMsg::Action {
                action: Action::FocusPaneByPaneId { pane_id },
                terminal_id: None,
                client_id: None,
                is_cli_client: false,
            }
        },
        Payload::NewPaneInTab { .. } => ClientToServerMsg::Action {
            action: Action::NewTiledPane {
                direction: None,
                command: None,
                pane_name: None,
                near_current_pane: false,
                no_focus: false,
                borderless: None,
                tab_id: None,
            },
            terminal_id: None,
            client_id: None,
            is_cli_client: false,
        },
        Payload::NewTab => ClientToServerMsg::Action {
            action: Action::NewTab {
                tiled_layout: None,
                floating_layouts: vec![],
                swap_tiled_layouts: None,
                swap_floating_layouts: None,
                tab_name: None,
                should_change_focus_to_new_tab: true,
                cwd: None,
                initial_panes: None,
                first_pane_unblock_condition: None,
            },
            terminal_id: None,
            client_id: None,
            is_cli_client: false,
        },
        Payload::SetMobileRenderPreferences { single_pane, fit } => {
            ClientToServerMsg::SetMobileRenderPreferences { single_pane, fit }
        },
        Payload::ClientReady
        | Payload::VersionRequest
        | Payload::DeviceEnrollRequest { .. }
        | Payload::EnrollComplete
        | Payload::DeviceAuthRequest
        | Payload::DeviceAuthResponse { .. }
        | Payload::Ping => return None,
        Payload::Unknown => {
            log::warn!("Ignoring unknown control message type from web client");
            return None;
        },
    };
    Some(client_msg)
}

/// Convert browser-reported terminal pixel metrics into the IPC message the
/// server caches for OSC pixel-dimension queries.
pub fn terminal_metrics_to_ipc(metrics: TerminalMetrics) -> ClientToServerMsg {
    ClientToServerMsg::TerminalPixelDimensions {
        pixel_dimensions: PixelDimensions {
            text_area_size: Some(SizeInPixels {
                width: metrics.text_area_pixel_width,
                height: metrics.text_area_pixel_height,
            }),
            character_cell_size: Some(SizeInPixels {
                width: metrics.cell_pixel_width,
                height: metrics.cell_pixel_height,
            }),
        },
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FromBrowser {
    pub web_client_id: String,
    pub payload: WebClientToWebServerControlMessagePayload,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum WebClientToWebServerControlMessagePayload {
    TerminalResize(Size),
    TerminalMetrics(TerminalMetrics),
    SoftKeyboardVisibilityChanged {
        visible: bool,
    },
    NestedSessionFrameFromHost {
        payload_bytes: Vec<u8>,
    },
    RequestSessionList,
    FocusPane {
        pane_id: u32,
        is_plugin: bool,
    },
    NewPaneInTab {
        tab_id: usize,
    },
    NewTab,
    SetMobileRenderPreferences {
        single_pane: bool,
        fit: bool,
    },
    ClientReady,
    VersionRequest,
    DeviceEnrollRequest {
        pubkey_alg: String,
        pubkey: Vec<u8>,
        requested_label: Option<String>,
    },
    EnrollComplete,
    DeviceAuthRequest,
    DeviceAuthResponse {
        signature: Vec<u8>,
    },
    Ping,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TerminalMetrics {
    pub cell_pixel_width: usize,
    pub cell_pixel_height: usize,
    pub text_area_pixel_width: usize,
    pub text_area_pixel_height: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum ToBrowser {
    SetConfig(DisplayConfig),
    QueryTerminalSize,
    Log { lines: Vec<String> },
    LogError { lines: Vec<String> },
    SwitchedSession { new_session_name: String },
    SetSoftKeyboard { on: bool },
    MobileState { payload: MobileStatePayload },
    /// Sharer-side session viewport size, forwarded to r/o viewers so the
    /// browser clipper can re-emit at the new dimensions.
    SessionSizeChanged { rows: u32, cols: u32 },
    VersionAnnounce {
        zellij_version: String,
        app_bundle_sha384: String,
    },
    Admitted {
        #[serde(default)]
        enroll: bool,
    },
    Rejected {
        reason: String,
    },
    DeviceEnrollAck {
        device_id: Vec<u8>,
        device_secret: String,
        scope: DeviceScope,
        host_id: Option<String>,
        access_read_only: bool,
    },
    DeviceAuthChallenge {
        nonce: Vec<u8>,
    },
    Pong,
    Exit {
        reason: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DisplayConfig {
    pub font: String,
    pub theme: SetConfigPayloadTheme,
    pub cursor_blink: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_inactive_style: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_style: Option<String>,
    pub mac_option_is_meta: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<u16>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct SetConfigPayloadTheme {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreground: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub black: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_black: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_blue: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_cyan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_green: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_magenta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_red: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_white: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bright_yellow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor_accent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cyan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub green: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magenta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub red: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_background: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_foreground: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_inactive_background: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub white: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yellow: Option<String>,
}

impl From<&Config> for DisplayConfig {
    fn from(config: &Config) -> Self {
        let font = config.web_client.font.clone();

        let palette = config.theme_config(config.options.theme.as_ref());
        let web_client_theme_from_config = config.web_client.theme.as_ref();

        let mut theme = SetConfigPayloadTheme::default();

        theme.background = web_client_theme_from_config
            .and_then(|theme| theme.background.clone())
            .or_else(|| palette.map(|p| p.text_unselected.background.as_rgb_str()));
        theme.foreground = web_client_theme_from_config
            .and_then(|theme| theme.foreground.clone())
            .or_else(|| palette.map(|p| p.text_unselected.base.as_rgb_str()));
        theme.black = web_client_theme_from_config.and_then(|theme| theme.black.clone());
        theme.blue = web_client_theme_from_config.and_then(|theme| theme.blue.clone());
        theme.bright_black =
            web_client_theme_from_config.and_then(|theme| theme.bright_black.clone());
        theme.bright_blue =
            web_client_theme_from_config.and_then(|theme| theme.bright_blue.clone());
        theme.bright_cyan =
            web_client_theme_from_config.and_then(|theme| theme.bright_cyan.clone());
        theme.bright_green =
            web_client_theme_from_config.and_then(|theme| theme.bright_green.clone());
        theme.bright_magenta =
            web_client_theme_from_config.and_then(|theme| theme.bright_magenta.clone());
        theme.bright_red = web_client_theme_from_config.and_then(|theme| theme.bright_red.clone());
        theme.bright_white =
            web_client_theme_from_config.and_then(|theme| theme.bright_white.clone());
        theme.bright_yellow =
            web_client_theme_from_config.and_then(|theme| theme.bright_yellow.clone());
        theme.cursor = web_client_theme_from_config.and_then(|theme| theme.cursor.clone());
        theme.cursor_accent =
            web_client_theme_from_config.and_then(|theme| theme.cursor_accent.clone());
        theme.cyan = web_client_theme_from_config.and_then(|theme| theme.cyan.clone());
        theme.green = web_client_theme_from_config.and_then(|theme| theme.green.clone());
        theme.magenta = web_client_theme_from_config.and_then(|theme| theme.magenta.clone());
        theme.red = web_client_theme_from_config.and_then(|theme| theme.red.clone());
        theme.selection_background = web_client_theme_from_config
            .and_then(|theme| theme.selection_background.clone())
            .or_else(|| palette.map(|p| p.text_selected.background.as_rgb_str()));
        theme.selection_foreground = web_client_theme_from_config
            .and_then(|theme| theme.selection_foreground.clone())
            .or_else(|| palette.map(|p| p.text_selected.base.as_rgb_str()));
        theme.selection_inactive_background = web_client_theme_from_config
            .and_then(|theme| theme.selection_inactive_background.clone());
        theme.white = web_client_theme_from_config.and_then(|theme| theme.white.clone());
        theme.yellow = web_client_theme_from_config.and_then(|theme| theme.yellow.clone());

        let cursor_blink = config.web_client.cursor_blink;
        let mac_option_is_meta = config.web_client.mac_option_is_meta;
        let cursor_style = config
            .web_client
            .cursor_style
            .as_ref()
            .map(|s| s.to_string());
        let cursor_inactive_style = config
            .web_client
            .cursor_inactive_style
            .as_ref()
            .map(|s| s.to_string());

        let font_size = config.web_client.font_size;

        DisplayConfig {
            font,
            theme,
            cursor_blink,
            mac_option_is_meta,
            cursor_style,
            cursor_inactive_style,
            font_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zellij_utils::ipc::ClientToServerMsg;

    #[test]
    fn terminal_metrics_to_ipc_preserves_all_dimensions() {
        let metrics = TerminalMetrics {
            cell_pixel_width: 9,
            cell_pixel_height: 18,
            text_area_pixel_width: 80 * 9,
            text_area_pixel_height: 24 * 18,
        };
        let msg = terminal_metrics_to_ipc(metrics);
        match msg {
            ClientToServerMsg::TerminalPixelDimensions { pixel_dimensions } => {
                let cell = pixel_dimensions
                    .character_cell_size
                    .expect("cell size missing");
                let area = pixel_dimensions
                    .text_area_size
                    .expect("text area size missing");
                assert_eq!(cell.width, 9);
                assert_eq!(cell.height, 18);
                assert_eq!(area.width, 720);
                assert_eq!(area.height, 432);
            },
            other => panic!("expected TerminalPixelDimensions, got {:?}", other),
        }
    }

    #[test]
    fn terminal_metrics_round_trips_through_json_payload() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "TerminalMetrics",
                "cell_pixel_width": 7,
                "cell_pixel_height": 14,
                "text_area_pixel_width": 560,
                "text_area_pixel_height": 336,
            }
        });
        let parsed: FromBrowser =
            serde_json::from_value(raw).expect("parse");
        let metrics = match parsed.payload {
            WebClientToWebServerControlMessagePayload::TerminalMetrics(m) => m,
            other => panic!("expected TerminalMetrics, got {:?}", other),
        };
        assert_eq!(metrics.cell_pixel_width, 7);
        assert_eq!(metrics.cell_pixel_height, 14);
        assert_eq!(metrics.text_area_pixel_width, 560);
        assert_eq!(metrics.text_area_pixel_height, 336);
    }

    #[test]
    fn version_request_round_trips_through_json_payload() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": { "type": "VersionRequest" }
        });
        let parsed: FromBrowser = serde_json::from_value(raw).expect("parse");
        match parsed.payload {
            WebClientToWebServerControlMessagePayload::VersionRequest => {},
            other => panic!("expected VersionRequest, got {:?}", other),
        }
    }

    #[test]
    fn version_announce_serializes_with_type_tag() {
        let msg = ToBrowser::VersionAnnounce {
            zellij_version: "0.45.0".to_string(),
            app_bundle_sha384: "sha384-deadbeef".to_string(),
        };
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "type": "VersionAnnounce",
                "zellij_version": "0.45.0",
                "app_bundle_sha384": "sha384-deadbeef",
            })
        );
    }

    #[test]
    fn terminal_resize_still_deserializes_after_adding_variant() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "TerminalResize",
                "rows": 24,
                "cols": 80,
            }
        });
        let parsed: FromBrowser =
            serde_json::from_value(raw).expect("parse");
        match parsed.payload {
            WebClientToWebServerControlMessagePayload::TerminalResize(size) => {
                assert_eq!(size.rows, 24);
                assert_eq!(size.cols, 80);
            },
            other => panic!("expected TerminalResize, got {:?}", other),
        }
    }

    #[test]
    fn focus_pane_payload_deserializes() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "FocusPane",
                "pane_id": 7,
                "is_plugin": true,
            }
        });
        let parsed: FromBrowser = serde_json::from_value(raw).expect("parse");
        match parsed.payload {
            WebClientToWebServerControlMessagePayload::FocusPane { pane_id, is_plugin } => {
                assert_eq!(pane_id, 7);
                assert!(is_plugin);
            },
            other => panic!("expected FocusPane, got {:?}", other),
        }
    }

    #[test]
    fn new_pane_in_tab_payload_deserializes() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "NewPaneInTab",
                "tab_id": 2,
            }
        });
        let parsed: FromBrowser = serde_json::from_value(raw).expect("parse");
        match parsed.payload {
            WebClientToWebServerControlMessagePayload::NewPaneInTab { tab_id } => {
                assert_eq!(tab_id, 2);
            },
            other => panic!("expected NewPaneInTab, got {:?}", other),
        }
    }

    #[test]
    fn new_tab_payload_deserializes() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": { "type": "NewTab" }
        });
        let parsed: FromBrowser = serde_json::from_value(raw).expect("parse");
        assert!(matches!(
            parsed.payload,
            WebClientToWebServerControlMessagePayload::NewTab
        ));
    }

    #[test]
    fn set_mobile_render_preferences_payload_deserializes() {
        let raw = serde_json::json!({
            "web_client_id": "abc",
            "payload": {
                "type": "SetMobileRenderPreferences",
                "single_pane": false,
                "fit": true,
            }
        });
        let parsed: FromBrowser = serde_json::from_value(raw).expect("parse");
        match parsed.payload {
            WebClientToWebServerControlMessagePayload::SetMobileRenderPreferences {
                single_pane,
                fit,
            } => {
                assert!(!single_pane);
                assert!(fit);
            },
            other => panic!("expected SetMobileRenderPreferences, got {:?}", other),
        }
    }

    #[test]
    fn new_pane_in_tab_is_routed_to_the_requesting_client() {
        let client_msg = control_payload_to_server_msg(
            WebClientToWebServerControlMessagePayload::NewPaneInTab { tab_id: 2 },
        )
        .expect("message dropped");
        match client_msg {
            ClientToServerMsg::Action {
                action:
                    Action::NewTiledPane {
                        tab_id, no_focus, ..
                    },
                ..
            } => {
                assert_eq!(
                    tab_id, None,
                    "The pane is opened in the client's own tab so that it is focused for it, \
                     keeping single-pane mode attached to the new pane"
                );
                assert!(!no_focus, "The new pane takes focus");
            },
            other => panic!("expected a NewTiledPane action, got {:?}", other),
        }
    }

    #[test]
    fn unknown_control_message_is_dropped() {
        assert!(
            control_payload_to_server_msg(WebClientToWebServerControlMessagePayload::Unknown)
                .is_none()
        );
    }

    #[test]
    fn relay_control_channel_messages_are_not_forwarded_to_the_server() {
        for payload in [
            WebClientToWebServerControlMessagePayload::ClientReady,
            WebClientToWebServerControlMessagePayload::VersionRequest,
            WebClientToWebServerControlMessagePayload::EnrollComplete,
            WebClientToWebServerControlMessagePayload::DeviceAuthRequest,
            WebClientToWebServerControlMessagePayload::Ping,
        ] {
            assert!(
                control_payload_to_server_msg(payload.clone()).is_none(),
                "expected {:?} to be handled locally",
                payload
            );
        }
    }
}
