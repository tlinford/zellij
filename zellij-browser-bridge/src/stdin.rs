use zellij_utils::{
    input::{actions::Action, cast_termwiz_key, from_termwiz, mouse::MouseEvent},
    ipc::ClientToServerMsg,
    keyboard_parser::{KittyKeyboardParser, KittyParseOutcome},
    vendored::termwiz::input::{InputEvent, InputParser},
};
use crate::virtual_client::SessionLink;

pub const BRACKETED_PASTE_START: [u8; 6] = [27, 91, 50, 48, 48, 126];
pub const BRACKETED_PASTE_END: [u8; 6] = [27, 91, 50, 48, 49, 126];

pub struct Uplink {
    link: Box<dyn SessionLink>,
    read_only: bool,
    kitty_parser: KittyKeyboardParser,
    input_parser: InputParser,
    explicitly_disable_kitty_keyboard_protocol: bool,
    pending_finalize: bool,
    mouse_old_event: MouseEvent,
}

impl Uplink {
    pub fn new(
        link: Box<dyn SessionLink>,
        read_only: bool,
        explicitly_disable_kitty_keyboard_protocol: bool,
    ) -> Self {
        Uplink {
            link,
            read_only,
            kitty_parser: KittyKeyboardParser::new(),
            input_parser: InputParser::new(),
            explicitly_disable_kitty_keyboard_protocol,
            pending_finalize: false,
            mouse_old_event: MouseEvent::new(),
        }
    }

    pub fn pending_finalize(&self) -> bool {
        self.pending_finalize
    }

    pub fn clear_pending_finalize(&mut self) {
        self.pending_finalize = false;
    }

    pub fn finalize_idle(&mut self) {
        if self.read_only {
            self.pending_finalize = false;
            return;
        }
        let mut events = vec![];
        self.input_parser.parse(
            &[],
            |input_event: InputEvent| {
                events.push(input_event);
            },
            false,
        );
        for input_event in events {
            dispatch_termwiz_event(&*self.link, &mut self.mouse_old_event, input_event, &[]);
        }
        self.pending_finalize = false;
    }

    pub fn feed_terminal(&mut self, buf: &[u8]) {
        if self.read_only {
            return;
        }
        if !self.explicitly_disable_kitty_keyboard_protocol {
            match self.kitty_parser.feed(buf) {
                KittyParseOutcome::Complete(key_with_modifier) => {
                    self.link.send_to_server(ClientToServerMsg::Key {
                        key: key_with_modifier.clone(),
                        raw_bytes: buf.to_vec(),
                        is_kitty_keyboard_protocol: true,
                    });
                    return;
                },
                KittyParseOutcome::Incomplete | KittyParseOutcome::NoMatch => {},
            }
        }

        let maybe_more = true;
        let mut events = vec![];
        self.input_parser.parse(
            buf,
            |input_event: InputEvent| {
                events.push(input_event);
            },
            maybe_more,
        );

        let single_event = events.len() == 1;
        for input_event in events.into_iter() {
            match input_event {
                InputEvent::Key(key_event) => {
                    let raw_bytes = if single_event {
                        buf.to_vec()
                    } else {
                        use zellij_utils::vendored::termwiz::input::{KeyCode, Modifiers};
                        match (&key_event.key, key_event.modifiers) {
                            (KeyCode::Char(c), m) if m == Modifiers::NONE => {
                                let mut char_buf = [0u8; 4];
                                c.encode_utf8(&mut char_buf).as_bytes().to_vec()
                            },
                            _ => buf.to_vec(),
                        }
                    };
                    let key = cast_termwiz_key(key_event.clone(), &raw_bytes, None);
                    self.link.send_to_server(ClientToServerMsg::Key {
                        key: key.clone(),
                        raw_bytes,
                        is_kitty_keyboard_protocol: false,
                    });
                },
                other => {
                    dispatch_termwiz_event(&*self.link, &mut self.mouse_old_event, other, buf);
                },
            }
        }

        self.pending_finalize = true;
    }
}

fn dispatch_termwiz_event(
    link: &dyn SessionLink,
    mouse_old_event: &mut MouseEvent,
    input_event: InputEvent,
    raw_bytes: &[u8],
) {
    match input_event {
        InputEvent::Key(key_event) => {
            let raw_bytes_vec = raw_bytes.to_vec();
            let key = cast_termwiz_key(key_event.clone(), &raw_bytes_vec, None);
            link.send_to_server(ClientToServerMsg::Key {
                key: key.clone(),
                raw_bytes: raw_bytes_vec,
                is_kitty_keyboard_protocol: false,
            });
        },
        InputEvent::Mouse(mouse_event) => {
            let mouse_event = from_termwiz(mouse_old_event, mouse_event);
            let action = Action::MouseEvent { event: mouse_event };
            link.send_to_server(ClientToServerMsg::Action {
                action,
                terminal_id: None,
                client_id: None,
                is_cli_client: false,
            });
        },
        InputEvent::Paste(pasted_text) => {
            link.send_to_server(ClientToServerMsg::Action {
                action: Action::Write {
                    key_with_modifier: None,
                    bytes: BRACKETED_PASTE_START.to_vec(),
                    is_kitty_keyboard_protocol: false,
                },
                terminal_id: None,
                client_id: None,
                is_cli_client: false,
            });
            link.send_to_server(ClientToServerMsg::Action {
                action: Action::Write {
                    key_with_modifier: None,
                    bytes: pasted_text.as_bytes().to_vec(),
                    is_kitty_keyboard_protocol: false,
                },
                terminal_id: None,
                client_id: None,
                is_cli_client: false,
            });
            link.send_to_server(ClientToServerMsg::Action {
                action: Action::Write {
                    key_with_modifier: None,
                    bytes: BRACKETED_PASTE_END.to_vec(),
                    is_kitty_keyboard_protocol: false,
                },
                terminal_id: None,
                client_id: None,
                is_cli_client: false,
            });
        },
        _ => {
            log::error!("Unsupported event: {:#?}", input_event);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::Uplink;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use zellij_utils::{
        data::Palette,
        errors::ErrorContext,
        ipc::{ClientToServerMsg, ServerToClientMsg},
        pane_size::Size,
    };
    use crate::virtual_client::SessionLink;

    #[derive(Clone, Debug, Default)]
    struct RecordingLink {
        sent_messages: Arc<Mutex<Vec<ClientToServerMsg>>>,
    }

    impl RecordingLink {
        fn take_sent_messages(&self) -> Vec<ClientToServerMsg> {
            self.sent_messages.lock().unwrap().clone()
        }
    }

    impl SessionLink for RecordingLink {
        fn send_to_server(&self, msg: ClientToServerMsg) {
            self.sent_messages.lock().unwrap().push(msg);
        }
        fn recv_from_server(&self) -> Option<(ServerToClientMsg, ErrorContext)> {
            None
        }
        fn connect_to_server(&self, _path: &Path) {}
        fn get_terminal_size(&self) -> Size {
            Size::default()
        }
        fn load_palette(&self) -> Palette {
            Palette::default()
        }
        fn update_session_name(&mut self, _new_session_name: String) {}
        fn spawn_server(&self, _socket_path: &Path, _debug: bool) -> Result<(), std::io::Error> {
            Ok(())
        }
        fn box_clone(&self) -> Box<dyn SessionLink> {
            Box::new(self.clone())
        }
    }

    #[test]
    fn ime_multi_char_input_uses_per_char_raw_bytes() {
        let link = RecordingLink::default();
        let mut uplink = Uplink::new(Box::new(link.clone()), false, false);

        uplink.feed_terminal("你好".as_bytes());

        let sent_messages = link.take_sent_messages();
        assert_eq!(sent_messages.len(), 2);

        let raw_bytes: Vec<Vec<u8>> = sent_messages
            .into_iter()
            .map(|message| match message {
                ClientToServerMsg::Key { raw_bytes, .. } => raw_bytes,
                other => panic!("expected key message, got {other:?}"),
            })
            .collect();

        assert_eq!(
            raw_bytes,
            vec!["你".as_bytes().to_vec(), "好".as_bytes().to_vec()]
        );
    }

    #[test]
    fn single_char_input_keeps_original_raw_bytes() {
        let link = RecordingLink::default();
        let mut uplink = Uplink::new(Box::new(link.clone()), false, false);

        uplink.feed_terminal("a".as_bytes());

        let sent_messages = link.take_sent_messages();
        assert_eq!(sent_messages.len(), 1);

        match &sent_messages[0] {
            ClientToServerMsg::Key { raw_bytes, .. } => {
                assert_eq!(raw_bytes, &b"a".to_vec());
            },
            other => panic!("expected key message, got {other:?}"),
        }
    }

    #[test]
    fn fragmented_kitty_sequence_resolves_across_frames() {
        use zellij_utils::data::{BareKey, KeyWithModifier};
        let link = RecordingLink::default();
        let mut uplink = Uplink::new(Box::new(link.clone()), false, false);

        uplink.feed_terminal(b"\x1b[97;");
        assert!(
            link.take_sent_messages().is_empty(),
            "incomplete Kitty prefix must not emit a key on frame 1"
        );

        uplink.feed_terminal(b"5u");
        let sent = link.take_sent_messages();
        assert_eq!(
            sent.len(),
            1,
            "exactly one Kitty key event after both frames; got {:?}",
            sent
        );
        match &sent[0] {
            ClientToServerMsg::Key {
                key,
                is_kitty_keyboard_protocol,
                ..
            } => {
                assert!(*is_kitty_keyboard_protocol);
                assert_eq!(
                    *key,
                    KeyWithModifier::new(BareKey::Char('a')).with_ctrl_modifier()
                );
            },
            other => panic!("expected Key message, got {other:?}"),
        }
    }

    #[test]
    fn non_kitty_bytes_pass_through_to_termwiz_path() {
        let link = RecordingLink::default();
        let mut uplink = Uplink::new(Box::new(link.clone()), false, false);

        uplink.feed_terminal(b"ab");

        let sent = link.take_sent_messages();
        assert_eq!(sent.len(), 2);
        for msg in &sent {
            match msg {
                ClientToServerMsg::Key {
                    is_kitty_keyboard_protocol,
                    ..
                } => assert!(!*is_kitty_keyboard_protocol),
                other => panic!("expected Key, got {other:?}"),
            }
        }
    }

    #[test]
    fn read_only_uplink_drops_input() {
        let link = RecordingLink::default();
        let mut uplink = Uplink::new(Box::new(link.clone()), true, false);

        uplink.feed_terminal(b"a");

        assert!(link.take_sent_messages().is_empty());
    }
}
