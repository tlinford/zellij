mod admissions_screen;
mod guest_links_screen;
mod main_screen;
mod my_devices_screen;
mod online_tab;
mod token_management_screen;
mod token_screen;
mod ui_components;

use std::net::IpAddr;
use zellij_tile::prelude::*;

use std::collections::{BTreeMap, HashMap};

use main_screen::MainScreen;
use token_management_screen::TokenManagementScreen;
use token_screen::TokenScreen;

static MESSAGE_DISMISS_DURATION: f64 = 3.0;

#[derive(Debug, Default)]
struct App {
    web_server: WebServerState,
    ui: UIState,
    tokens: TokenManager,
    guest_links: GuestLinkManager,
    admissions: AdmissionManager,
    devices: DeviceManager,
    state: AppState,
}

register_plugin!(App);

impl ZellijPlugin for App {
    fn load(&mut self, _configuration: BTreeMap<String, String>) {
        self.initialize();
    }

    fn update(&mut self, event: Event) -> bool {
        if !self.web_server.capability && !matches!(event, Event::ModeUpdate(_)) {
            return false;
        }

        let should_render = match event {
            Event::Timer(_) => self.handle_message_dismissal(),
            Event::ModeUpdate(mode_info) => self.handle_mode_update(mode_info),
            Event::WebServerStatus(status) => self.handle_web_server_status(status),
            Event::Key(key) => self.handle_key_input(key),
            Event::Mouse(mouse_event) => self.handle_mouse_event(mouse_event),
            Event::RunCommandResult(exit_code, _stdout, _stderr, context) => {
                self.handle_command_result(exit_code, context)
            },
            Event::FailedToStartWebServer(error) => self.handle_web_server_error(error),
            Event::PastedText(text) => self.handle_pasted_text(text),
            _ => false,
        };
        self.arm_message_timer_if_needed();
        should_render
    }

    fn pipe(&mut self, pipe_message: PipeMessage) -> bool {
        let should_render = match pipe_message.name.as_str() {
            "share_admission_pending" => self.handle_admission_pending_pipe(),
            "share_devices_changed" => self.handle_devices_changed_pipe(),
            _ => false,
        };
        self.arm_message_timer_if_needed();
        should_render
    }

    fn render(&mut self, rows: usize, cols: usize) {
        if !self.web_server.capability {
            self.render_no_capability_message(rows, cols);
            return;
        }

        self.ui.reset_render_state();
        match &self.state.current_screen {
            Screen::Main => self.render_main_screen(rows, cols),
            Screen::Token(token) => self.render_token_screen(rows, cols, token),
            Screen::ManageTokens => self.render_manage_tokens_screen(rows, cols),
            Screen::GuestLinks => self.render_guest_links_screen(rows, cols),
            Screen::Admissions => self.render_admissions_screen(rows, cols),
            Screen::MyDevices => self.render_my_devices_screen(rows, cols),
        }
    }
}

impl App {
    fn initialize(&mut self) {
        self.subscribe_to_events();
        self.state.own_plugin_id = Some(get_plugin_ids().plugin_id);
        self.retrieve_token_list();
        self.query_link_executable();
        self.set_plugin_title();
    }

    fn subscribe_to_events(&self) {
        subscribe(&[
            EventType::Key,
            EventType::ModeUpdate,
            EventType::WebServerStatus,
            EventType::Mouse,
            EventType::RunCommandResult,
            EventType::FailedToStartWebServer,
            EventType::Timer,
            EventType::PastedText,
        ]);
    }

    fn set_plugin_title(&self) {
        if let Some(plugin_id) = self.state.own_plugin_id {
            rename_plugin_pane(plugin_id, "Share Session");
        }
    }

    fn has_message(&self) -> bool {
        self.state.info.is_some() || self.web_server.error.is_some()
    }

    fn arm_message_timer_if_needed(&mut self) {
        if self.has_message() && !self.state.message_timer_armed {
            self.state.message_timer_armed = true;
            set_timeout(MESSAGE_DISMISS_DURATION);
        }
    }

    fn handle_message_dismissal(&mut self) -> bool {
        self.state.message_timer_armed = false;
        if self.has_message() {
            self.state.info = None;
            self.web_server.error = None;
            return true;
        }
        false
    }

    fn handle_admission_pending_pipe(&mut self) -> bool {
        self.refresh_pending_admissions();
        if self.admissions.list.is_empty() {
            return false;
        }
        if !self.admissions.presented {
            self.admissions.presented = true;
            if self.admissions.selected_index.is_none() {
                self.admissions.selected_index = Some(0);
            }
            if !matches!(self.state.current_screen, Screen::Admissions) {
                self.state.previous_screen = Some(self.state.current_screen.clone());
            }
            self.state.current_screen = Screen::Admissions;
        }
        true
    }

    fn handle_devices_changed_pipe(&mut self) -> bool {
        let mut should_render = false;
        if matches!(self.state.current_screen, Screen::MyDevices) {
            self.retrieve_devices_list();
            should_render = true;
        }
        if matches!(self.state.current_screen, Screen::GuestLinks) {
            self.retrieve_guest_links_list();
            should_render = true;
        }
        should_render
    }

    fn refresh_pending_admissions(&mut self) {
        if !self.relay_share_is_live() {
            return;
        }
        let admissions = match relay_list_pending_admissions() {
            Ok(a) => a,
            Err(_) => return,
        };
        let has = !admissions.is_empty();
        self.admissions.list = admissions;
        self.admissions.adjust_selection_after_list_change();
        if !has {
            self.admissions.presented = false;
            if matches!(self.state.current_screen, Screen::Admissions) {
                self.change_to_main_screen();
            }
        }
    }

    fn render_admissions_screen(&mut self, rows: usize, cols: usize) {
        let message = if let Some(err) = &self.web_server.error {
            Some((err.as_str(), true))
        } else {
            self.state.info.as_deref().map(|info| (info, false))
        };
        admissions_screen::render_admissions_screen(
            rows,
            cols,
            &self.admissions.list,
            self.admissions.selected_index,
            message,
        );
    }

    fn handle_admissions_keys(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Esc if key.has_no_modifiers() => {
                self.change_to_main_screen();
                true
            },
            BareKey::Down if key.has_no_modifiers() => self.admissions.navigate_down(),
            BareKey::Up if key.has_no_modifiers() => self.admissions.navigate_up(),
            BareKey::Char('a') if key.has_no_modifiers() => {
                if let Some(admission) = self.admissions.get_selected() {
                    let client_id = admission.client_id;
                    let code_confirmed = !admission.read_only;
                    self.resolve_admission(client_id, true, code_confirmed);
                    return true;
                }
                false
            },
            BareKey::Char('r') if key.has_no_modifiers() => {
                if let Some(admission) = self.admissions.get_selected() {
                    let client_id = admission.client_id;
                    self.resolve_admission(client_id, false, false);
                    return true;
                }
                false
            },
            _ => false,
        }
    }

    fn resolve_admission(&mut self, client_id: u32, admit: bool, code_confirmed: bool) {
        match relay_resolve_admission(client_id, admit, code_confirmed) {
            Ok(()) => {
                self.state.info = Some(
                    if admit {
                        "Admitted."
                    } else {
                        "Rejected."
                    }
                    .to_owned(),
                );
                if let Ok(a) = relay_list_pending_admissions() {
                    self.admissions.list = a;
                    self.admissions.adjust_selection_after_list_change();
                }
                if self.admissions.list.is_empty() {
                    self.admissions.presented = false;
                    if matches!(self.state.current_screen, Screen::Admissions) {
                        self.change_to_main_screen();
                    }
                }
            },
            Err(e) => self.web_server.error = Some(e),
        }
    }

    fn handle_mode_update(&mut self, mode_info: ModeInfo) -> bool {
        let mut should_render = false;

        self.state.session_name = mode_info.session_name;

        if let Some(web_clients_allowed) = mode_info.web_clients_allowed {
            self.web_server.clients_allowed = web_clients_allowed;
            should_render = true;
        }

        if let Some(web_sharing) = mode_info.web_sharing {
            self.web_server.sharing = web_sharing;
            should_render = true;
        }

        if let Some(web_server_ip) = mode_info.web_server_ip {
            self.web_server.ip = Some(web_server_ip);
            should_render = true;
        }

        if let Some(web_server_port) = mode_info.web_server_port {
            self.web_server.port = Some(web_server_port);
            should_render = true;
        }

        if let Some(web_server_capability) = mode_info.web_server_capability {
            let gained_capability = web_server_capability && !self.web_server.capability;
            self.web_server.capability = web_server_capability;
            if gained_capability {
                query_web_server_status();
                self.retrieve_token_list();
            }
            should_render = true;
        }

        if self.web_server.relay_share_status != mode_info.relay_share_status {
            self.web_server.relay_share_status = mode_info.relay_share_status;
            should_render = true;
        }

        should_render
    }

    fn handle_web_server_status(&mut self, status: WebServerStatus) -> bool {
        match status {
            WebServerStatus::Online(base_url) => {
                self.web_server.base_url = base_url;
                self.web_server.started = true;
                self.web_server.different_version_error = None;
            },
            WebServerStatus::Offline => {
                self.web_server.started = false;
                self.web_server.different_version_error = None;
            },
            WebServerStatus::DifferentVersion(version) => {
                self.web_server.started = false;
                self.web_server.different_version_error = Some(version);
            },
        }
        true
    }

    fn handle_key_input(&mut self, key: KeyWithModifier) -> bool {
        let has_message = self.web_server.error.is_some() || self.state.info.is_some();

        if has_message && key.bare_key == BareKey::Esc && key.has_no_modifiers() {
            self.clear_error_or_info();
            return true;
        }

        let cleared = self.clear_error_or_info();

        let handled = match self.state.current_screen {
            Screen::Main => self.handle_main_screen_keys(key),
            Screen::Token(_) => self.handle_token_screen_keys(key),
            Screen::ManageTokens => self.handle_manage_tokens_keys(key),
            Screen::GuestLinks => self.handle_guest_links_keys(key),
            Screen::Admissions => self.handle_admissions_keys(key),
            Screen::MyDevices => self.handle_my_devices_keys(key),
        };

        handled || cleared
    }

    fn clear_error_or_info(&mut self) -> bool {
        let cleared =
            self.web_server.error.take().is_some() || self.state.info.take().is_some();
        if cleared {
            self.state.message_timer_armed = false;
        }
        cleared
    }

    fn handle_main_screen_keys(&mut self, key: KeyWithModifier) -> bool {
        // When the inline relay-auth-token prompt is open, keystrokes are
        // captured by the prompt — typing, backspace, Enter (submit),
        // Esc (cancel). Other keys fall through.
        if self.state.entering_relay_tunnel_auth_token.is_some() {
            return self.handle_relay_token_prompt_key(key);
        }

        // `<TAB>` switches between the Online and Local tabs.
        if key.bare_key == BareKey::Tab && key.has_no_modifiers() {
            self.state.tab = match self.state.tab {
                ShareTab::Online => ShareTab::Local,
                ShareTab::Local => ShareTab::Online,
            };
            return true;
        }

        // Keys shared by both tabs: web-server lifecycle (the local web
        // server backs both local and relay sharing) and closing the plugin.
        match key.bare_key {
            BareKey::Enter if key.has_no_modifiers() && !self.web_server.started => {
                start_web_server();
                return false;
            },
            BareKey::Char('c') if key.has_modifiers(&[KeyModifier::Ctrl]) => {
                stop_web_server();
                return false;
            },
            BareKey::Esc if key.has_no_modifiers() => {
                close_self();
                return false;
            },
            _ => {},
        }

        match self.state.tab {
            ShareTab::Online => self.handle_online_tab_keys(key),
            ShareTab::Local => self.handle_local_tab_keys(key),
        }
    }

    /// Relay (public) sharing keys — active on the Online tab.
    fn handle_online_tab_keys(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char('l') if key.has_no_modifiers() => {
                self.handle_share_to_relay_key();
                true
            },
            BareKey::Char('g') if key.has_no_modifiers() && self.relay_share_is_live() => {
                self.change_to_guest_links_screen();
                true
            },
            BareKey::Char('d') if key.has_no_modifiers() && self.relay_share_is_live() => {
                self.change_to_my_devices_screen();
                true
            },
            _ => false,
        }
    }

    /// Local web-server sharing keys — active on the Local tab.
    fn handle_local_tab_keys(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char(' ') if key.has_no_modifiers() => {
                self.toggle_session_sharing();
                false
            },
            BareKey::Char('t') if key.has_no_modifiers() => {
                self.handle_token_action();
                true
            },
            _ => false,
        }
    }

    fn handle_share_to_relay_key(&mut self) {
        if self.relay_share_is_live() {
            stop_sharing_current_session_from_relay();
        } else if self.relay_auth_rejected() {
            self.open_relay_auth_token_prompt();
        } else {
            share_current_session_to_relay();
        }
    }

    fn relay_share_is_live(&self) -> bool {
        match &self.web_server.relay_share_status {
            Some(RelayShareStatus::Connected { url }) => url.is_some(),
            _ => false,
        }
    }

    fn relay_auth_rejected(&self) -> bool {
        matches!(
            &self.web_server.relay_share_status,
            Some(RelayShareStatus::Failed {
                reason: RelayFailureReason::AuthRejected,
                ..
            })
        )
    }

    fn open_relay_auth_token_prompt(&mut self) {
        self.state.entering_relay_tunnel_auth_token = Some(String::new());
    }

    /// Keystroke dispatch while the inline relay-auth-token prompt is
    /// active. Returns `true` whenever the plugin should re-render.
    fn handle_relay_token_prompt_key(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char(c) if key.has_no_modifiers() => {
                if let Some(buf) = self.state.entering_relay_tunnel_auth_token.as_mut() {
                    buf.push(c);
                }
                true
            },
            BareKey::Backspace if key.has_no_modifiers() => {
                if let Some(buf) = self.state.entering_relay_tunnel_auth_token.as_mut() {
                    buf.pop();
                }
                true
            },
            BareKey::Enter if key.has_no_modifiers() => {
                if let Some(token) = self.state.entering_relay_tunnel_auth_token.take() {
                    let trimmed = token.trim().to_owned();
                    if trimmed.is_empty() {
                        // Empty submit is treated as a cancel but
                        // surfaced as info so the user knows nothing
                        // was persisted.
                        self.state.info =
                            Some("Relay tunnel auth token not changed.".to_owned());
                    } else {
                        set_relay_tunnel_auth_token(trimmed);
                        share_current_session_to_relay();
                    }
                }
                true
            },
            BareKey::Esc if key.has_no_modifiers() => {
                self.state.entering_relay_tunnel_auth_token = None;
                true
            },
            _ => false,
        }
    }

    fn toggle_session_sharing(&self) {
        match self.web_server.sharing {
            WebSharing::Disabled => {},
            WebSharing::On => stop_sharing_current_session(),
            WebSharing::Off => share_current_session(),
        }
    }

    fn handle_token_action(&mut self) {
        if self.tokens.list.is_empty() {
            self.generate_new_token(None, false);
        } else {
            self.change_to_manage_tokens_screen();
        }
    }

    fn handle_token_screen_keys(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Esc if key.has_no_modifiers() => {
                self.change_to_previous_screen();
                true
            },
            _ => false,
        }
    }

    fn handle_manage_tokens_keys(&mut self, key: KeyWithModifier) -> bool {
        if self.tokens.handle_text_input(&key) {
            return true;
        }

        match key.bare_key {
            BareKey::Esc if key.has_no_modifiers() => self.handle_escape_key(),
            BareKey::Down if key.has_no_modifiers() => self.tokens.navigate_down(),
            BareKey::Up if key.has_no_modifiers() => self.tokens.navigate_up(),
            BareKey::Char('n') if key.has_no_modifiers() => {
                self.tokens.start_new_token_input();
                true
            },
            BareKey::Char('o') if key.has_no_modifiers() => {
                self.tokens.start_new_read_only_token_input();
                true
            },
            BareKey::Enter if key.has_no_modifiers() => self.handle_enter_key(),
            BareKey::Char('r') if key.has_no_modifiers() => {
                self.tokens.start_rename_input();
                true
            },
            BareKey::Char('x') if key.has_no_modifiers() => self.revoke_selected_token(),
            BareKey::Char('x') if key.has_modifiers(&[KeyModifier::Ctrl]) => {
                self.revoke_all_tokens();
                true
            },
            _ => false,
        }
    }

    fn handle_escape_key(&mut self) -> bool {
        let was_editing = self.tokens.cancel_input();

        if !was_editing {
            self.change_to_main_screen();
        }
        true
    }

    fn handle_enter_key(&mut self) -> bool {
        if let Some(token_name) = self.tokens.finish_new_token_input() {
            self.generate_new_token(token_name, false);
            return true;
        }

        if let Some(token_name) = self.tokens.finish_new_read_only_token_input() {
            self.generate_new_token(token_name, true);
            return true;
        }

        if let Some(new_name) = self.tokens.finish_rename_input() {
            self.rename_current_token(new_name);
            return true;
        }

        false
    }

    fn generate_new_token(&mut self, name: Option<String>, read_only: bool) {
        match generate_web_login_token(name, read_only) {
            Ok(token) => self.change_to_token_screen(token),
            Err(e) => self.web_server.error = Some(e),
        }
    }

    fn rename_current_token(&mut self, new_name: String) {
        if let Some(current_token) = self.tokens.get_selected_token() {
            match rename_web_token(&current_token.0, &new_name) {
                Ok(_) => {
                    self.retrieve_token_list();
                    if self.tokens.adjust_selection_after_list_change() {
                        self.change_to_main_screen();
                    }
                },
                Err(e) => self.web_server.error = Some(e),
            }
        }
    }

    fn revoke_selected_token(&mut self) -> bool {
        if let Some(token) = self.tokens.get_selected_token() {
            match revoke_web_login_token(&token.0) {
                Ok(_) => {
                    self.retrieve_token_list();
                    if self.tokens.adjust_selection_after_list_change() {
                        self.change_to_main_screen();
                    }
                    self.state.info = Some("Revoked. Connected clients not affected.".to_owned());
                },
                Err(e) => self.web_server.error = Some(e),
            }
            return true;
        }
        false
    }

    fn revoke_all_tokens(&mut self) {
        match revoke_all_web_tokens() {
            Ok(_) => {
                self.retrieve_token_list();
                if self.tokens.adjust_selection_after_list_change() {
                    self.change_to_main_screen();
                }
                self.state.info = Some("Revoked. Connected clients not affected.".to_owned());
            },
            Err(e) => self.web_server.error = Some(e),
        }
    }

    fn handle_mouse_event(&mut self, event: Mouse) -> bool {
        match event {
            Mouse::LeftClick(line, column) => self.handle_link_click(line, column),
            Mouse::Hover(line, column) => {
                self.ui.hover_coordinates = Some((column, line as usize));
                true
            },
            _ => false,
        }
    }

    fn handle_link_click(&mut self, line: isize, column: usize) -> bool {
        for (coordinates, url) in &self.ui.clickable_urls {
            if coordinates.contains(column, line as usize) {
                if let Some(executable) = self.ui.link_executable {
                    run_command(&[executable, url], Default::default());
                }
                return true;
            }
        }
        false
    }

    fn handle_command_result(
        &mut self,
        exit_code: Option<i32>,
        context: BTreeMap<String, String>,
    ) -> bool {
        if context.contains_key("xdg_open_cli") && exit_code == Some(0) {
            self.ui.link_executable = Some("xdg-open");
        } else if context.contains_key("open_cli") && exit_code == Some(0) {
            self.ui.link_executable = Some("open");
        }
        false
    }

    fn handle_web_server_error(&mut self, error: String) -> bool {
        self.web_server.error = Some(error);
        true
    }

    /// Bracketed-paste handler. When the relay-auth-token prompt is
    /// open, the pasted string is appended to the input buffer verbatim
    /// (newlines stripped — tokens are single-line). Outside the prompt
    /// pastes are ignored.
    fn handle_pasted_text(&mut self, text: String) -> bool {
        if let Some(buf) = self.state.entering_relay_tunnel_auth_token.as_mut() {
            for c in text.chars() {
                if c == '\n' || c == '\r' {
                    continue;
                }
                buf.push(c);
            }
            return true;
        }
        false
    }

    fn query_link_executable(&self) {
        let mut xdg_context = BTreeMap::new();
        xdg_context.insert("xdg_open_cli".to_owned(), String::new());
        run_command(&["xdg-open", "--help"], xdg_context);

        let mut open_context = BTreeMap::new();
        open_context.insert("open_cli".to_owned(), String::new());
        run_command(&["open", "--help"], open_context);
    }

    fn render_no_capability_message(&self, rows: usize, cols: usize) {
        let full_text = "This version of Zellij was compiled without web sharing capabilities";
        let short_text = "No web server capabilities";
        let text = if cols >= full_text.chars().count() {
            full_text
        } else {
            short_text
        };

        let text_element = Text::new(text).color_range(3, ..);
        let text_x = cols.saturating_sub(text.chars().count()) / 2;
        let text_y = rows / 2;
        print_text_with_coordinates(text_element, text_x, text_y, None, None);
    }

    fn change_to_token_screen(&mut self, token: String) {
        self.retrieve_token_list();
        set_self_mouse_selection_support(true);
        self.state.previous_screen = Some(self.state.current_screen.clone());
        self.state.current_screen = Screen::Token(token);
    }

    fn change_to_manage_tokens_screen(&mut self) {
        self.retrieve_token_list();
        set_self_mouse_selection_support(false);
        self.tokens.selected_index = Some(0);
        self.state.previous_screen = None;
        self.state.current_screen = Screen::ManageTokens;
    }

    fn change_to_main_screen(&mut self) {
        self.retrieve_token_list();
        set_self_mouse_selection_support(false);
        self.state.previous_screen = None;
        self.state.current_screen = Screen::Main;
    }

    fn change_to_previous_screen(&mut self) {
        self.retrieve_token_list();
        match self.state.previous_screen.take() {
            Some(Screen::ManageTokens) => self.change_to_manage_tokens_screen(),
            _ => self.change_to_main_screen(),
        }
    }

    fn render_main_screen(&mut self, rows: usize, cols: usize) {
        self.render_share_tabs();
        match self.state.tab {
            ShareTab::Local => self.render_local_tab(rows, cols),
            ShareTab::Online => self.render_online_tab(rows, cols),
        }
    }

    /// Top tab ribbon (`<TAB>` switches), mirroring the configuration plugin.
    fn render_share_tabs(&self) {
        let switch_key = Text::new("<TAB>").color_range(3, ..);
        print_text_with_coordinates(switch_key, 0, 0, None, None);
        let mut online = Text::new("Online");
        let mut local = Text::new("Local");
        match self.state.tab {
            ShareTab::Online => online = online.selected(),
            ShareTab::Local => local = local.selected(),
        }
        print_ribbon_with_coordinates(online, 6, 0, None, None);
        print_ribbon_with_coordinates(local, 16, 0, None, None);
    }

    /// Local web-server sharing (everything except the relay/public rows).
    fn render_local_tab(&mut self, rows: usize, cols: usize) {
        let state_changes = MainScreen::new(
            self.tokens.list.is_empty(),
            self.web_server.started,
            &self.web_server.error,
            &self.web_server.different_version_error,
            &self.web_server.base_url,
            self.web_server.ip,
            self.web_server.port,
            &self.state.session_name,
            self.web_server.sharing,
            self.ui.hover_coordinates,
            &self.state.info,
            &self.ui.link_executable,
        )
        .render(rows, cols);

        self.ui.currently_hovering_over_link = state_changes.currently_hovering_over_link;
        self.ui.currently_hovering_over_unencrypted =
            state_changes.currently_hovering_over_unencrypted;
        self.ui.clickable_urls = state_changes.clickable_urls;
    }

    fn render_online_tab(&mut self, rows: usize, cols: usize) {
        let logged_in = self.relay_share_is_live();
        self.ui.currently_hovering_over_link = online_tab::render_online_tab(
            rows,
            cols,
            self.ui.hover_coordinates,
            &mut self.ui.clickable_urls,
            logged_in,
        );
    }

    fn render_token_screen(&self, rows: usize, cols: usize, token: &str) {
        let token_screen =
            TokenScreen::new(token.to_string(), self.web_server.error.clone(), rows, cols);
        token_screen.render();
    }

    fn render_manage_tokens_screen(&self, rows: usize, cols: usize) {
        // Pass whichever token input field is active (normal or read-only)
        let entering_new_token_name = if self.tokens.entering_new_name.is_some() {
            &self.tokens.entering_new_name
        } else {
            &self.tokens.entering_new_read_only_name
        };

        TokenManagementScreen::new(
            &self.tokens.list,
            self.tokens.selected_index,
            &self.tokens.renaming_token,
            entering_new_token_name,
            &self.web_server.error,
            &self.state.info,
            rows,
            cols,
        )
        .render();
    }

    fn retrieve_token_list(&mut self) {
        if let Err(e) = self.tokens.retrieve_list() {
            self.web_server.error = Some(e);
        }
    }

    fn change_to_guest_links_screen(&mut self) {
        self.clear_messages();
        self.retrieve_guest_links_list();
        set_self_mouse_selection_support(false);
        self.guest_links.selected_index = Some(0);
        self.guest_links.display = None;
        self.state.previous_screen = None;
        self.state.current_screen = Screen::GuestLinks;
    }

    fn clear_messages(&mut self) {
        self.state.info = None;
        self.web_server.error = None;
        self.state.message_timer_armed = false;
    }

    fn render_guest_links_screen(&mut self, rows: usize, cols: usize) {
        let message = if let Some(err) = &self.web_server.error {
            Some((err.as_str(), true))
        } else {
            self.state.info.as_deref().map(|info| (info, false))
        };
        guest_links_screen::render_guest_links_screen(
            rows,
            cols,
            &self.guest_links.list,
            self.guest_links.selected_index,
            self.guest_links.entering_label.clone(),
            self.guest_links.pending_read_only,
            self.guest_links.display_link(),
            message,
            self.ui.hover_coordinates,
            &mut self.ui.clickable_urls,
        );
    }

    fn handle_guest_links_keys(&mut self, key: KeyWithModifier) -> bool {
        if self.guest_links.display.is_some() {
            return self.handle_display_link_keys(key);
        }

        if self.guest_links.handle_text_input(&key) {
            return true;
        }

        match key.bare_key {
            BareKey::Esc if key.has_no_modifiers() => {
                if !self.guest_links.cancel_input() {
                    self.change_to_main_screen();
                }
                true
            },
            BareKey::Down if key.has_no_modifiers() => self.guest_links.navigate_down(),
            BareKey::Up if key.has_no_modifiers() => self.guest_links.navigate_up(),
            BareKey::Char('n') if key.has_no_modifiers() => {
                self.guest_links.start_new_input(false);
                true
            },
            BareKey::Char('o') if key.has_no_modifiers() => {
                self.guest_links.start_new_input(true);
                true
            },
            BareKey::Enter if key.has_no_modifiers() => self.submit_guest_link_input(),
            BareKey::Char('c') if key.has_no_modifiers() => {
                if let Some(link) = self.guest_links.get_selected() {
                    if !link.active {
                        copy_to_clipboard(link.url.clone());
                        self.state.info = Some("Link copied to clipboard.".to_owned());
                        self.state.message_timer_armed = false;
                    }
                }
                true
            },
            BareKey::Char('d') if key.has_no_modifiers() => {
                if let Some(index) = self.guest_links.selected_index {
                    if let Some(link) = self.guest_links.list.get(index) {
                        if !link.active {
                            self.guest_links.start_display(index);
                        }
                    }
                }
                true
            },
            BareKey::Char('x') if key.has_no_modifiers() => self.revoke_selected_guest_link(),
            _ => false,
        }
    }

    fn handle_display_link_keys(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char('d') if key.has_no_modifiers() => {
                self.guest_links.reveal_display();
                true
            },
            BareKey::Char('c') if key.has_no_modifiers() => {
                if let Some((link, _)) = self.guest_links.display_link() {
                    copy_to_clipboard(link.url.clone());
                    self.state.info = Some("Link copied to clipboard.".to_owned());
                    self.state.message_timer_armed = false;
                }
                self.guest_links.cancel_display();
                true
            },
            BareKey::Esc if key.has_no_modifiers() => {
                self.guest_links.cancel_display();
                true
            },
            _ => true,
        }
    }

    fn submit_guest_link_input(&mut self) -> bool {
        if let Some((read_only, label)) = self.guest_links.finish_new_input() {
            let label = if label.trim().is_empty() {
                generate_random_name()
            } else {
                label
            };
            self.mint_guest_link(read_only, label, false);
            return true;
        }
        false
    }

    fn mint_guest_link(&mut self, read_only: bool, label: String, enroll: bool) {
        match relay_mint_guest_link(read_only, label, enroll) {
            Ok(link) => {
                self.retrieve_guest_links_list();
                if !enroll {
                    self.guest_links.select_by_link_id(&link.link_id);
                }
                if enroll {
                    self.state.info = Some("Device-enrollment link minted.".to_owned());
                }
            },
            Err(e) => self.web_server.error = Some(e),
        }
    }

    fn revoke_selected_guest_link(&mut self) -> bool {
        if let Some(link) = self.guest_links.get_selected() {
            let link_id = link.link_id.clone();
            match relay_revoke_guest_link(link_id) {
                Ok(_) => {
                    self.retrieve_guest_links_list();
                    self.guest_links.adjust_selection_after_list_change();
                    self.state.info = Some("Guest link revoked.".to_owned());
                    self.state.message_timer_armed = false;
                },
                Err(e) => self.web_server.error = Some(e),
            }
            return true;
        }
        false
    }

    fn retrieve_guest_links_list(&mut self) {
        if let Err(e) = self.guest_links.retrieve_list() {
            self.web_server.error = Some(e);
        }
    }

    fn change_to_my_devices_screen(&mut self) {
        self.clear_messages();
        self.retrieve_devices_list();
        set_self_mouse_selection_support(false);
        self.devices.selected_index = Some(0);
        self.devices.display = None;
        self.devices.adjust_selection_after_list_change();
        self.state.previous_screen = None;
        self.state.current_screen = Screen::MyDevices;
    }

    fn render_my_devices_screen(&mut self, rows: usize, cols: usize) {
        let message = if let Some(err) = &self.web_server.error {
            Some((err.as_str(), true))
        } else {
            self.state.info.as_deref().map(|info| (info, false))
        };

        let devices: Vec<my_devices_screen::DeviceRowView> = self
            .devices
            .list
            .iter()
            .map(|d| my_devices_screen::DeviceRowView {
                label: d.label.as_str(),
                read_only: d.read_only,
                connected: d.connected,
                ever_connected: d.last_used.is_some(),
            })
            .collect();

        let links: Vec<my_devices_screen::EnrollmentLinkView> = self
            .devices
            .enrollment_links
            .iter()
            .map(|l| my_devices_screen::EnrollmentLinkView {
                label: l.label.as_str(),
                read_only: l.read_only,
            })
            .collect();

        let display_link = self
            .devices
            .display_link()
            .map(|(link, revealed)| (link.label.as_str(), link.url.as_str(), revealed));

        my_devices_screen::render_my_devices_screen(
            rows,
            cols,
            &devices,
            &links,
            self.devices.selected_index,
            self.devices.entering_label.clone(),
            self.devices.pending_read_only,
            display_link,
            message,
            self.ui.hover_coordinates,
            &mut self.ui.clickable_urls,
        );
    }

    fn handle_my_devices_keys(&mut self, key: KeyWithModifier) -> bool {
        if self.devices.display.is_some() {
            return self.handle_device_display_link_keys(key);
        }

        if self.devices.handle_text_input(&key) {
            return true;
        }
        match key.bare_key {
            BareKey::Esc if key.has_no_modifiers() => {
                if !self.devices.cancel_input() {
                    self.change_to_main_screen();
                }
                true
            },
            BareKey::Down if key.has_no_modifiers() => self.devices.navigate_down(),
            BareKey::Up if key.has_no_modifiers() => self.devices.navigate_up(),
            BareKey::Char('n') if key.has_no_modifiers() => {
                self.devices.start_new_input(false);
                true
            },
            BareKey::Char('o') if key.has_no_modifiers() => {
                self.devices.start_new_input(true);
                true
            },
            BareKey::Enter if key.has_no_modifiers() => {
                if let Some((read_only, label)) = self.devices.finish_new_input() {
                    let label = if label.trim().is_empty() {
                        generate_random_name()
                    } else {
                        label
                    };
                    self.mint_enrollment_link(read_only, label);
                    return true;
                }
                false
            },
            BareKey::Char('c') if key.has_no_modifiers() => {
                if let Some(link_index) = self.devices.selected_link_index() {
                    if let Some(link) = self.devices.enrollment_links.get(link_index) {
                        copy_to_clipboard(link.url.clone());
                        self.state.info = Some("Link copied to clipboard.".to_owned());
                        self.state.message_timer_armed = false;
                    }
                }
                true
            },
            BareKey::Char('d') if key.has_no_modifiers() => {
                if let Some(link_index) = self.devices.selected_link_index() {
                    self.devices.start_display(link_index);
                }
                true
            },
            BareKey::Char('x') if key.has_no_modifiers() => self.revoke_selected_device(),
            _ => false,
        }
    }

    fn handle_device_display_link_keys(&mut self, key: KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char('d') if key.has_no_modifiers() => {
                self.devices.reveal_display();
                true
            },
            BareKey::Char('c') if key.has_no_modifiers() => {
                if let Some((link, _)) = self.devices.display_link() {
                    copy_to_clipboard(link.url.clone());
                    self.state.info = Some("Link copied to clipboard.".to_owned());
                    self.state.message_timer_armed = false;
                }
                self.devices.cancel_display();
                true
            },
            BareKey::Esc if key.has_no_modifiers() => {
                self.devices.cancel_display();
                true
            },
            _ => true,
        }
    }

    fn mint_enrollment_link(&mut self, read_only: bool, label: String) {
        match relay_mint_guest_link(read_only, label, true) {
            Ok(link) => {
                self.retrieve_devices_list();
                self.devices.select_by_link_id(&link.link_id);
                self.state.info =
                    Some("Device-enrollment link minted. Hand it to the new device.".to_owned());
            },
            Err(e) => self.web_server.error = Some(e),
        }
    }

    fn revoke_selected_device(&mut self) -> bool {
        let outcome = match self.devices.get_selected() {
            Some(DeviceRow::Device(d)) => Some(relay_revoke_device(d.device_id.clone()).map(|_| "Device revoked.")),
            Some(DeviceRow::EnrollmentLink(l)) => {
                Some(relay_revoke_guest_link(l.link_id.clone()).map(|_| "Enrollment link revoked."))
            },
            None => None,
        };
        match outcome {
            Some(Ok(msg)) => {
                self.retrieve_devices_list();
                self.devices.adjust_selection_after_list_change();
                self.state.info = Some(msg.to_owned());
                true
            },
            Some(Err(e)) => {
                self.web_server.error = Some(e);
                true
            },
            None => false,
        }
    }

    fn retrieve_devices_list(&mut self) {
        if let Err(e) = self.devices.retrieve_list() {
            self.web_server.error = Some(e);
        }
    }
}

#[derive(Debug, Default)]
struct WebServerState {
    started: bool,
    sharing: WebSharing,
    clients_allowed: bool,
    error: Option<String>,
    different_version_error: Option<String>,
    ip: Option<IpAddr>,
    port: Option<u16>,
    base_url: String,
    capability: bool,
    pub relay_share_status: Option<RelayShareStatus>,
}

#[derive(Debug, Default)]
struct UIState {
    hover_coordinates: Option<(usize, usize)>,
    clickable_urls: HashMap<CoordinatesInLine, String>,
    link_executable: Option<&'static str>,
    currently_hovering_over_link: bool,
    currently_hovering_over_unencrypted: bool,
}

impl UIState {
    fn reset_render_state(&mut self) {
        self.currently_hovering_over_link = false;
        self.clickable_urls.clear();
    }
}

#[derive(Debug, Default)]
struct TokenManager {
    list: Vec<(String, String, bool)>, // bool -> is_read_only
    selected_index: Option<usize>,
    entering_new_name: Option<String>,
    entering_new_read_only_name: Option<String>,
    renaming_token: Option<String>,
}

impl TokenManager {
    fn retrieve_list(&mut self) -> Result<(), String> {
        match list_web_login_tokens() {
            Ok(tokens) => {
                self.list = tokens;
                Ok(())
            },
            Err(e) => Err(format!("Failed to retrieve login tokens: {}", e)),
        }
    }

    fn get_selected_token(&self) -> Option<&(String, String, bool)> {
        self.selected_index.and_then(|i| self.list.get(i))
    }

    fn adjust_selection_after_list_change(&mut self) -> bool {
        if self.list.is_empty() {
            self.selected_index = None;
            true // indicates should change to main screen
        } else if self.selected_index >= Some(self.list.len()) {
            self.selected_index = Some(self.list.len().saturating_sub(1));
            false
        } else {
            false
        }
    }

    fn navigate_down(&mut self) -> bool {
        if let Some(ref mut index) = self.selected_index {
            *index = if *index < self.list.len().saturating_sub(1) {
                *index + 1
            } else {
                0
            };
            return true;
        }
        false
    }

    fn navigate_up(&mut self) -> bool {
        if let Some(ref mut index) = self.selected_index {
            *index = if *index == 0 {
                self.list.len().saturating_sub(1)
            } else {
                *index - 1
            };
            return true;
        }
        false
    }

    fn start_new_token_input(&mut self) {
        self.entering_new_name = Some(String::new());
    }

    fn start_new_read_only_token_input(&mut self) {
        self.entering_new_read_only_name = Some(String::new());
    }

    fn start_rename_input(&mut self) {
        self.renaming_token = Some(String::new());
    }

    fn handle_text_input(&mut self, key: &KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char(c) if key.has_no_modifiers() => {
                if let Some(ref mut name) = self.entering_new_name {
                    name.push(c);
                    return true;
                }
                if let Some(ref mut name) = self.entering_new_read_only_name {
                    name.push(c);
                    return true;
                }
                if let Some(ref mut name) = self.renaming_token {
                    name.push(c);
                    return true;
                }
            },
            BareKey::Backspace if key.has_no_modifiers() => {
                if let Some(ref mut name) = self.entering_new_name {
                    name.pop();
                    return true;
                }
                if let Some(ref mut name) = self.entering_new_read_only_name {
                    name.pop();
                    return true;
                }
                if let Some(ref mut name) = self.renaming_token {
                    name.pop();
                    return true;
                }
            },
            _ => {},
        }
        false
    }

    fn finish_new_token_input(&mut self) -> Option<Option<String>> {
        self.entering_new_name
            .take()
            .map(|name| if name.is_empty() { None } else { Some(name) })
    }

    fn finish_new_read_only_token_input(&mut self) -> Option<Option<String>> {
        self.entering_new_read_only_name
            .take()
            .map(|name| if name.is_empty() { None } else { Some(name) })
    }

    fn finish_rename_input(&mut self) -> Option<String> {
        self.renaming_token.take()
    }

    fn cancel_input(&mut self) -> bool {
        self.entering_new_name.take().is_some()
            || self.entering_new_read_only_name.take().is_some()
            || self.renaming_token.take().is_some()
    }
}

#[derive(Debug, Default)]
struct GuestLinkManager {
    list: Vec<GuestLink>,
    selected_index: Option<usize>,
    entering_label: Option<String>,
    pending_read_only: bool,
    display: Option<DisplayLinkView>,
}

#[derive(Debug, Clone)]
struct DisplayLinkView {
    index: usize,
    revealed: bool,
}

impl GuestLinkManager {
    fn select_by_link_id(&mut self, link_id: &[u8]) {
        if let Some(index) = self.list.iter().position(|l| l.link_id == link_id) {
            self.selected_index = Some(index);
        }
    }

    fn start_display(&mut self, index: usize) {
        self.display = Some(DisplayLinkView {
            index,
            revealed: false,
        });
    }

    fn reveal_display(&mut self) {
        if let Some(ref mut display) = self.display {
            display.revealed = true;
        }
    }

    fn cancel_display(&mut self) -> bool {
        self.display.take().is_some()
    }

    fn display_link(&self) -> Option<(&GuestLink, bool)> {
        self.display
            .as_ref()
            .and_then(|d| self.list.get(d.index).map(|link| (link, d.revealed)))
    }

    fn retrieve_list(&mut self) -> Result<(), String> {
        match relay_list_guest_links() {
            Ok(links) => {
                self.list = links.into_iter().filter(|l| !l.enroll).collect();
                Ok(())
            },
            Err(e) => Err(format!("Failed to retrieve guest links: {}", e)),
        }
    }

    fn get_selected(&self) -> Option<&GuestLink> {
        self.selected_index.and_then(|i| self.list.get(i))
    }

    fn adjust_selection_after_list_change(&mut self) {
        if self.list.is_empty() {
            self.selected_index = None;
        } else if self.selected_index >= Some(self.list.len()) {
            self.selected_index = Some(self.list.len().saturating_sub(1));
        }
    }

    fn navigate_down(&mut self) -> bool {
        if self.list.is_empty() {
            return false;
        }
        if let Some(ref mut index) = self.selected_index {
            *index = if *index < self.list.len().saturating_sub(1) {
                *index + 1
            } else {
                0
            };
            return true;
        }
        self.selected_index = Some(0);
        true
    }

    fn navigate_up(&mut self) -> bool {
        if self.list.is_empty() {
            return false;
        }
        if let Some(ref mut index) = self.selected_index {
            *index = if *index == 0 {
                self.list.len().saturating_sub(1)
            } else {
                *index - 1
            };
            return true;
        }
        self.selected_index = Some(self.list.len().saturating_sub(1));
        true
    }

    fn start_new_input(&mut self, read_only: bool) {
        self.entering_label = Some(String::new());
        self.pending_read_only = read_only;
    }

    fn handle_text_input(&mut self, key: &KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char(c) if key.has_no_modifiers() => {
                if let Some(ref mut label) = self.entering_label {
                    label.push(c);
                    return true;
                }
            },
            BareKey::Backspace if key.has_no_modifiers() => {
                if let Some(ref mut label) = self.entering_label {
                    label.pop();
                    return true;
                }
            },
            _ => {},
        }
        false
    }

    fn finish_new_input(&mut self) -> Option<(bool, String)> {
        self.entering_label
            .take()
            .map(|label| (self.pending_read_only, label))
    }

    fn cancel_input(&mut self) -> bool {
        self.entering_label.take().is_some()
    }
}

enum DeviceRow<'a> {
    Device(&'a EnrolledDevice),
    EnrollmentLink(&'a GuestLink),
}

#[derive(Debug, Default)]
struct DeviceManager {
    list: Vec<EnrolledDevice>,
    enrollment_links: Vec<GuestLink>,
    selected_index: Option<usize>,
    entering_label: Option<String>,
    pending_read_only: bool,
    display: Option<DisplayLinkView>,
}

impl DeviceManager {
    fn select_by_link_id(&mut self, link_id: &[u8]) {
        if let Some(index) = self
            .enrollment_links
            .iter()
            .position(|l| l.link_id == link_id)
        {
            self.selected_index = Some(self.list.len() + index);
        }
    }

    fn start_display(&mut self, link_index: usize) {
        self.display = Some(DisplayLinkView {
            index: link_index,
            revealed: false,
        });
    }

    fn reveal_display(&mut self) {
        if let Some(ref mut display) = self.display {
            display.revealed = true;
        }
    }

    fn cancel_display(&mut self) -> bool {
        self.display.take().is_some()
    }

    fn display_link(&self) -> Option<(&GuestLink, bool)> {
        self.display
            .as_ref()
            .and_then(|d| self.enrollment_links.get(d.index).map(|link| (link, d.revealed)))
    }

    /// Index into `enrollment_links` for the current selection, if the selected
    /// row is an enrollment link (rows past the devices list).
    fn selected_link_index(&self) -> Option<usize> {
        let i = self.selected_index?;
        if i < self.list.len() {
            None
        } else {
            let link_index = i - self.list.len();
            if link_index < self.enrollment_links.len() {
                Some(link_index)
            } else {
                None
            }
        }
    }

    fn retrieve_list(&mut self) -> Result<(), String> {
        let devices =
            relay_list_devices().map_err(|e| format!("Failed to retrieve devices: {}", e))?;
        let links = relay_list_guest_links()
            .map_err(|e| format!("Failed to retrieve enrollment links: {}", e))?;
        self.list = devices;
        self.enrollment_links = links
            .into_iter()
            .filter(|l| l.enroll)
            .collect();
        Ok(())
    }

    fn total_rows(&self) -> usize {
        self.list.len() + self.enrollment_links.len()
    }

    fn get_selected(&self) -> Option<DeviceRow<'_>> {
        let i = self.selected_index?;
        if i < self.list.len() {
            Some(DeviceRow::Device(&self.list[i]))
        } else {
            self.enrollment_links
                .get(i - self.list.len())
                .map(DeviceRow::EnrollmentLink)
        }
    }

    fn adjust_selection_after_list_change(&mut self) {
        let total = self.total_rows();
        if total == 0 {
            self.selected_index = None;
        } else if self.selected_index >= Some(total) {
            self.selected_index = Some(total.saturating_sub(1));
        } else if self.selected_index.is_none() {
            self.selected_index = Some(0);
        }
    }

    fn navigate_down(&mut self) -> bool {
        let total = self.total_rows();
        if let Some(ref mut index) = self.selected_index {
            if total == 0 {
                return false;
            }
            *index = if *index < total.saturating_sub(1) {
                *index + 1
            } else {
                0
            };
            return true;
        }
        false
    }

    fn navigate_up(&mut self) -> bool {
        let total = self.total_rows();
        if let Some(ref mut index) = self.selected_index {
            if total == 0 {
                return false;
            }
            *index = if *index == 0 {
                total.saturating_sub(1)
            } else {
                *index - 1
            };
            return true;
        }
        false
    }

    fn handle_text_input(&mut self, key: &KeyWithModifier) -> bool {
        match key.bare_key {
            BareKey::Char(c) if key.has_no_modifiers() => {
                if let Some(ref mut label) = self.entering_label {
                    label.push(c);
                    return true;
                }
            },
            BareKey::Backspace if key.has_no_modifiers() => {
                if let Some(ref mut label) = self.entering_label {
                    label.pop();
                    return true;
                }
            },
            _ => {},
        }
        false
    }

    fn cancel_input(&mut self) -> bool {
        self.entering_label.take().is_some()
    }

    fn start_new_input(&mut self, read_only: bool) {
        self.entering_label = Some(String::new());
        self.pending_read_only = read_only;
    }

    fn finish_new_input(&mut self) -> Option<(bool, String)> {
        self.entering_label
            .take()
            .map(|label| (self.pending_read_only, label))
    }
}

#[derive(Debug, Default)]
struct AdmissionManager {
    list: Vec<PendingAdmission>,
    selected_index: Option<usize>,
    presented: bool,
}

impl AdmissionManager {
    fn get_selected(&self) -> Option<&PendingAdmission> {
        self.selected_index.and_then(|i| self.list.get(i))
    }

    fn adjust_selection_after_list_change(&mut self) {
        if self.list.is_empty() {
            self.selected_index = None;
        } else if self.selected_index >= Some(self.list.len()) {
            self.selected_index = Some(self.list.len().saturating_sub(1));
        } else if self.selected_index.is_none() {
            self.selected_index = Some(0);
        }
    }

    fn navigate_down(&mut self) -> bool {
        if let Some(ref mut index) = self.selected_index {
            if self.list.is_empty() {
                return false;
            }
            *index = if *index < self.list.len().saturating_sub(1) {
                *index + 1
            } else {
                0
            };
            return true;
        }
        false
    }

    fn navigate_up(&mut self) -> bool {
        if let Some(ref mut index) = self.selected_index {
            if self.list.is_empty() {
                return false;
            }
            *index = if *index == 0 {
                self.list.len().saturating_sub(1)
            } else {
                *index - 1
            };
            return true;
        }
        false
    }
}

#[derive(Debug, Default)]
struct AppState {
    session_name: Option<String>,
    own_plugin_id: Option<u32>,
    current_screen: Screen,
    previous_screen: Option<Screen>,
    info: Option<String>,
    message_timer_armed: bool,
    /// Phase 6 Session C: when `Some`, the main screen renders an inline
    /// text-prompt instead of the normal public-URL row. Typing pushes
    /// into the string, Enter submits + opens the tunnel, Esc aborts.
    entering_relay_tunnel_auth_token: Option<String>,
    /// Which top-level tab is active on the main screen. `<TAB>` toggles it;
    /// "Online" (relay sharing) is the default.
    tab: ShareTab,
}

/// Top-level tabs of the share plugin's main screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ShareTab {
    /// Relay (public, end-to-end-encrypted) sharing — read/write + read-only.
    #[default]
    Online,
    /// Local web-server sharing on this machine/network.
    Local,
}

#[derive(Debug, Clone)]
enum Screen {
    Main,
    Token(String),
    ManageTokens,
    GuestLinks,
    Admissions,
    MyDevices,
}

impl Default for Screen {
    fn default() -> Self {
        Screen::Main
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct CoordinatesInLine {
    x: usize,
    y: usize,
    width: usize,
}

impl CoordinatesInLine {
    pub fn new(x: usize, y: usize, width: usize) -> Self {
        CoordinatesInLine { x, y, width }
    }

    pub fn contains(&self, x: usize, y: usize) -> bool {
        x >= self.x && x <= self.x + self.width && self.y == y
    }
}

