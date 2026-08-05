use std::collections::HashMap;
use zellij_tile::prelude::*;

use crate::ui_components;
use crate::CoordinatesInLine;

const TITLE: &str = "Share Session Online";
const DESC_LINE1: &str =
    "Invite others to join this session over the Internet, using robust authentication,";
const URL: &str = "https://zellij.online";
const DESC_LINE2: &str = "end-to-end encrypted through https://zellij.online - a service \
    run by the Zellij maintainers.";
const PARA2: &str =
    "Each invitation link can either be read-only or enable full control of the session.";
pub const ACTIONS_LOGGED_OUT: &str = "<s> - Sign Up, <l> - Login, <?> - Learn more";
pub const ACTIONS_LOGGED_IN: &str = "<l> - Logout, <g> - Guest links, <d> - My devices, <?> - Learn more";

pub fn word_wrap(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return vec![String::new()];
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in words {
        let wc = word.chars().count();
        if current.is_empty() {
            current = word.to_string();
        } else if current.chars().count() + 1 + wc <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

pub fn color_action_keys(line: &str) -> Text {
    let mut text = Text::new(line);
    for marker in &["<s>", "<l>", "<?>", "<g>", "<d>", "<TAB>"] {
        if let Some(start) = line.find(marker) {
            let end = start + marker.chars().count();
            text = text.color_range(3, start..end);
        }
    }
    text
}

fn render_title(base_x: usize, y: usize) {
    print_text_with_coordinates(
        Text::new(TITLE).color_range(2, ..),
        base_x,
        y,
        None,
        None,
    );
}

fn render_description(
    lines: &[String],
    base_x: usize,
    rows: usize,
    mut y: usize,
) -> usize {
    for line in lines {
        if y >= rows.saturating_sub(1) {
            break;
        }
        print_text_with_coordinates(Text::new(line), base_x, y, None, None);
        y += 1;
    }
    y
}

fn render_url_line(
    line: &str,
    base_x: usize,
    y: usize,
    rows: usize,
    hover_coordinates: Option<(usize, usize)>,
    clickable_urls: &mut HashMap<CoordinatesInLine, String>,
) -> (usize, bool) {
    if y >= rows.saturating_sub(1) {
        return (y, false);
    }

    let mut hovering = false;
    if let Some(url_start) = line.find(URL) {
        let url_end = url_start + URL.chars().count();
        let text = Text::new(line).color_range(1, url_start..url_end);
        let url_screen_x = base_x + url_start;
        let url_screen_width = url_end - url_start;
        clickable_urls.insert(
            CoordinatesInLine::new(url_screen_x, y, url_screen_width),
            URL.to_string(),
        );
        print_text_with_coordinates(text, base_x, y, None, None);
        if ui_components::hovering_on_line(
            url_screen_x,
            y,
            url_screen_width,
            hover_coordinates,
        ) {
            hovering = true;
            ui_components::render_text_with_underline(url_screen_x, y, URL);
        }
    } else {
        print_text_with_coordinates(Text::new(line), base_x, y, None, None);
    }
    (y + 1, hovering)
}

fn render_access_modes(
    lines: &[String],
    base_x: usize,
    rows: usize,
    mut y: usize,
) -> usize {
    for line in lines {
        if y >= rows.saturating_sub(1) {
            break;
        }
        let mut text = Text::new(line);
        for word in &["read-only", "full control"] {
            if let Some(start) = line.find(word) {
                let end = start + word.chars().count();
                text = text.color_range(0, start..end);
            }
        }
        print_text_with_coordinates(text, base_x, y, None, None);
        y += 1;
    }
    y
}

fn render_actions(
    lines: &[String],
    base_x: usize,
    rows: usize,
    mut y: usize,
) -> usize {
    for line in lines {
        if y >= rows {
            break;
        }
        let text = color_action_keys(line);
        print_text_with_coordinates(text, base_x, y, None, None);
        y += 1;
    }
    y
}

pub fn render_online_tab(
    rows: usize,
    cols: usize,
    hover_coordinates: Option<(usize, usize)>,
    clickable_urls: &mut HashMap<CoordinatesInLine, String>,
    logged_in: bool,
) -> bool {
    clickable_urls.clear();

    let actions = if logged_in { ACTIONS_LOGGED_IN } else { ACTIONS_LOGGED_OUT };
    let status_text = if logged_in { "Status: ONLINE" } else { "Status: OFFLINE" };

    let available = cols.saturating_sub(2);
    let desc1_wrapped = word_wrap(DESC_LINE1, available);
    let desc2_wrapped = word_wrap(DESC_LINE2, available);
    let para2_wrapped = word_wrap(PARA2, available);
    let actions_wrapped = word_wrap(actions, available);

    let desc_lines = desc1_wrapped.len() + desc2_wrapped.len();
    let total_height = (2 + desc_lines + 1 + para2_wrapped.len() + 1 + 1 + 1 + actions_wrapped.len()).min(rows);
    let base_y = rows.saturating_sub(total_height) / 2;
    let mut y = base_y;

    let max_unwrapped = TITLE.chars().count()
        .max(DESC_LINE1.chars().count())
        .max(DESC_LINE2.chars().count())
        .max(PARA2.chars().count())
        .max(actions.chars().count());
    let base_x = available.saturating_sub(max_unwrapped) / 2;

    render_title(base_x, y);
    y += 2;

    y = render_description(&desc1_wrapped, base_x, rows, y);

    let mut hovering = false;
    for line in &desc2_wrapped {
        let (new_y, line_hovering) = render_url_line(
            line,
            base_x,
            y,
            rows,
            hover_coordinates,
            clickable_urls,
        );
        if line_hovering {
            hovering = true;
        }
        y = new_y;
    }

    y = y.saturating_add(1);
    y = render_access_modes(&para2_wrapped, base_x, rows, y);
    y = y.saturating_add(1);

    if y < rows.saturating_sub(1) {
        let mut text = Text::new(status_text);
        if logged_in {
            text = text.success_color_range(8..);
        } else {
            text = text.error_color_range(8..);
        }
        print_text_with_coordinates(
            text,
            base_x,
            y,
            None,
            None,
        );
        y = y.saturating_add(1);
    }

    y = y.saturating_add(1);
    let _y = render_actions(&actions_wrapped, base_x, rows, y);

    hovering
}
