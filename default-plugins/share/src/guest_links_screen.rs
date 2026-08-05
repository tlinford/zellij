use std::collections::HashMap;
use zellij_tile::prelude::*;

use crate::online_tab::word_wrap;
use crate::ui_components::render_secret_link_screen;
use crate::CoordinatesInLine;

const TITLE: &str = "Guest links";
const READ_ONLY: &str = "Read-only";
const FULL_CONTROL: &str = "FULL CONTROL";
const ACTIVE: &str = "[Active]";
const PENDING: &str = "[Pending]";
const CONTROLS_WIDE: &str = "<c> - Copy link, <d> - Display link";
const CONTROLS_MEDIUM: &str = "<c> - Copy, <d> - Display";
const CONTROLS_NARROW: &str = "<c>/<d>";
const DESCRIPTION: &str = "Guest share links are single-use. They contain shared secrets, so must be sent over a secure medium. When a user connects, their identity can be verified before admission using a 6 digit PIN derived from this secret.";
const USAGE_LINE1: &str = "Usage from remote: zellij attach <LINK> (most secure).";
const USAGE_LINE2: &str = "                   Or paste into a browser.";
const USAGE_EMPHASIS: &str = "zellij attach <LINK>";

const HELP_WIDE_1: &str = "Help: <n> - New full-control, <o> - New read-only";
const HELP_WIDE_2: &str = "      <x> - Revoke, <Esc> - Back";
const HELP_MED_1: &str = "Help: <n> - New, <o> - Read-only";
const HELP_MED_2: &str = "      <x> - Revoke, <Esc> - Back";
const HELP_NARROW_1: &str = "<n>/<o>";
const HELP_NARROW_2: &str = "<x>/<Esc>";

const HELP_EMPTY_WIDE: &str = "Help: <n> - New full-control, <o> - New read-only, <Esc> - Back";
const HELP_EMPTY_MED: &str = "Help: <n> - New, <o> - Read-only, <Esc> - Back";
const HELP_EMPTY_NARROW: &str = "<n>/<o>/<Esc>";

fn render_title(base_x: usize, y: usize) {
    print_text_with_coordinates(
        Text::new(TITLE).color_all(2),
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

fn render_usage(
    base_x: usize,
    rows: usize,
    mut y: usize,
) {
    if y >= rows.saturating_sub(1) {
        return;
    }
    let mut text = Text::new(USAGE_LINE1);
    if let Some(start) = USAGE_LINE1.find(USAGE_EMPHASIS) {
        let end = start + USAGE_EMPHASIS.chars().count();
        text = text.color_range(0, start..end);
    }
    print_text_with_coordinates(text, base_x, y, None, None);
    y += 1;

    if y >= rows.saturating_sub(1) {
        return;
    }
    print_text_with_coordinates(Text::new(USAGE_LINE2), base_x, y, None, None);
}

fn render_table(
    links: &[GuestLink],
    selected_index: Option<usize>,
    base_x: usize,
    y: usize,
    available_rows: usize,
    max_cols: usize,
    controls_text: &str,
) -> usize {
    let mut table = Table::new().add_row(vec![" ", " ", " ", " "]);

    for (i, link) in links.iter().enumerate() {
        let is_selected = Some(i) == selected_index;
        let label = link.label.clone();
        let access_cell = if link.read_only { Text::new(READ_ONLY).success_color_all() } else { Text::new(FULL_CONTROL).error_color_all() };
        let status = if link.active { ACTIVE } else { PENDING };

        let name_cell = Text::new(label).color_all(1);
        let mut status_cell = Text::new(status);
        if link.active {
            status_cell = status_cell.success_color_all();
        }

        let controls_cell = if link.active {
            Text::new(" ".repeat(controls_text.chars().count()))
        } else {
            Text::new(controls_text)
                .color_substring(3, "<c>")
                .color_substring(3, "<d>")
        };

        if is_selected {
            table = table.add_styled_row(vec![
                name_cell.selected(),
                access_cell.selected(),
                status_cell.selected(),
                controls_cell.selected(),
            ]);
        } else {
            table = table.add_styled_row(vec![name_cell, access_cell, status_cell, Text::new(" ")]);
        }
    }

    print_table_with_coordinates(table, base_x, y, Some(max_cols), Some(available_rows));
    (1 + links.len()).min(available_rows)
}

const RANDOM_NAME_HINT: &str = " (<ENTER> - random name)";

fn render_prompt(
    pending_read_only: bool,
    label: &str,
    base_x: usize,
    y: usize,
) {
    let kind = if pending_read_only { "READ-ONLY" } else { "FULL-CONTROL" };
    let prefix = format!("New {} link label: ", kind);
    let show_hint = label.trim().is_empty();
    let hint = if show_hint { RANDOM_NAME_HINT } else { "" };
    let full = format!("{}{}_{}", prefix, label, hint);
    let prefix_len = prefix.chars().count();
    let label_len = label.chars().count();
    let cursor_pos = prefix_len + label_len;
    let mut text = Text::new(&full);
    text = text.color_all(1);
    text = text.color_range(3, cursor_pos..cursor_pos + 1);
    if pending_read_only {
        text = text.success_color_substring(kind);
    } else {
        text = text.error_color_substring(kind);
    }
    if show_hint {
        text = text.color_substring(3, "<ENTER>");
    }
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn render_help_wide(base_x: usize, y: usize) {
    let help_text = Text::new(HELP_WIDE_1)
        .color_substring(3, "<n>")
        .color_substring(3, "<o>")
        .color_substring(3, "<x>")
        .color_substring(3, "<Esc>");
    print_text_with_coordinates(help_text, base_x, y, None, None);
    let shortcuts_text = Text::new(HELP_WIDE_2)
        .color_substring(3, "<x>")
        .color_substring(3, "<Esc>");
    print_text_with_coordinates(shortcuts_text, base_x, y + 1, None, None);
}

fn render_help_med(base_x: usize, y: usize) {
    let help_text = Text::new(HELP_MED_1)
        .color_substring(3, "<n>")
        .color_substring(3, "<o>");
    print_text_with_coordinates(help_text, base_x, y, None, None);
    let shortcuts_text = Text::new(HELP_MED_2)
        .color_substring(3, "<x>")
        .color_substring(3, "<Esc>");
    print_text_with_coordinates(shortcuts_text, base_x, y + 1, None, None);
}

fn render_help_narrow(base_x: usize, y: usize) {
    let text1 = Text::new(HELP_NARROW_1)
        .color_substring(3, "<n>")
        .color_substring(3, "<o>");
    print_text_with_coordinates(text1, base_x, y, None, None);
    let text2 = Text::new(HELP_NARROW_2)
        .color_substring(3, "<x>")
        .color_substring(3, "<Esc>");
    print_text_with_coordinates(text2, base_x, y + 1, None, None);
}

fn render_message(base_x: usize, y: usize, message: &str, is_error: bool) {
    let text = if is_error {
        Text::new(message).error_color_all()
    } else {
        Text::new(message).success_color_all()
    };
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn render_help_empty(base_x: usize, y: usize, tier: usize) {
    let text = match tier {
        2 => Text::new(HELP_EMPTY_WIDE)
            .color_substring(3, "<n>")
            .color_substring(3, "<o>")
            .color_substring(3, "<Esc>"),
        1 => Text::new(HELP_EMPTY_MED)
            .color_substring(3, "<n>")
            .color_substring(3, "<o>")
            .color_substring(3, "<Esc>"),
        _ => Text::new(HELP_EMPTY_NARROW)
            .color_substring(3, "<n>")
            .color_substring(3, "<o>")
            .color_substring(3, "<Esc>"),
    };
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn help_empty_width(available_cols: usize) -> usize {
    let wide_w = HELP_EMPTY_WIDE.chars().count();
    if available_cols >= wide_w {
        return wide_w;
    }
    let med_w = HELP_EMPTY_MED.chars().count();
    if available_cols >= med_w {
        return med_w;
    }
    let narrow_w = HELP_EMPTY_NARROW.chars().count();
    if available_cols >= narrow_w {
        return narrow_w;
    }
    0
}

fn help_empty_tier(available_cols: usize) -> Option<usize> {
    let wide_w = HELP_EMPTY_WIDE.chars().count();
    if available_cols >= wide_w {
        return Some(2);
    }
    let med_w = HELP_EMPTY_MED.chars().count();
    if available_cols >= med_w {
        return Some(1);
    }
    let narrow_w = HELP_EMPTY_NARROW.chars().count();
    if available_cols >= narrow_w {
        return Some(0);
    }
    None
}

fn max_label_width(links: &[GuestLink]) -> usize {
    links.iter()
        .map(|l| l.label.chars().count())
        .max()
        .unwrap_or(0)
}

fn table_content_width(links: &[GuestLink], controls_text: &str) -> usize {
    let name_width = max_label_width(links);
    let access_width = FULL_CONTROL.chars().count();
    let status_width = PENDING.chars().count();
    let controls_width = controls_text.chars().count();
    name_width.saturating_add(access_width).saturating_add(status_width).saturating_add(controls_width).saturating_add(5)
}

fn pick_controls_text(available_cols: usize, links: &[GuestLink]) -> &'static str {
    let name_width = max_label_width(links);
    let access_width = FULL_CONTROL.chars().count();
    let status_width = PENDING.chars().count();
    let base_width = name_width.saturating_add(access_width).saturating_add(status_width).saturating_add(5);
    let remaining = available_cols.saturating_sub(base_width);

    if remaining >= CONTROLS_WIDE.chars().count() {
        CONTROLS_WIDE
    } else if remaining >= CONTROLS_MEDIUM.chars().count() {
        CONTROLS_MEDIUM
    } else {
        CONTROLS_NARROW
    }
}

fn help_width(available_cols: usize) -> usize {
    let wide_w = HELP_WIDE_1.chars().count().max(HELP_WIDE_2.chars().count());
    if available_cols >= wide_w {
        return wide_w;
    }
    let med_w = HELP_MED_1.chars().count().max(HELP_MED_2.chars().count());
    if available_cols >= med_w {
        return med_w;
    }
    let narrow_w = HELP_NARROW_1.chars().count().max(HELP_NARROW_2.chars().count());
    if available_cols >= narrow_w {
        return narrow_w;
    }
    0
}

fn help_tier(available_cols: usize) -> Option<usize> {
    let wide_w = HELP_WIDE_1.chars().count().max(HELP_WIDE_2.chars().count());
    if available_cols >= wide_w {
        return Some(2);
    }
    let med_w = HELP_MED_1.chars().count().max(HELP_MED_2.chars().count());
    if available_cols >= med_w {
        return Some(1);
    }
    let narrow_w = HELP_NARROW_1.chars().count().max(HELP_NARROW_2.chars().count());
    if available_cols >= narrow_w {
        return Some(0);
    }
    None
}

fn prompt_width(pending_read_only: bool, label: &str) -> usize {
    let kind = if pending_read_only { "read-only" } else { "full-control" };
    let hint = if label.trim().is_empty() { RANDOM_NAME_HINT } else { "" };
    format!("New {} link label: {}_{}", kind, label, hint).chars().count()
}

pub fn render_guest_links_screen(
    rows: usize,
    cols: usize,
    links: &[GuestLink],
    selected_index: Option<usize>,
    entering_label: Option<String>,
    pending_read_only: bool,
    display_link: Option<(&GuestLink, bool)>,
    message: Option<(&str, bool)>,
    hover_coordinates: Option<(usize, usize)>,
    clickable_urls: &mut HashMap<CoordinatesInLine, String>,
) {
    if let Some((link, revealed)) = display_link {
        render_secret_link_screen(
            rows,
            cols,
            "Guest link:",
            &link.label,
            &link.url,
            revealed,
            hover_coordinates,
            clickable_urls,
        );
        return;
    }

    let show_no_links = links.is_empty() && entering_label.is_none();
    let available_cols = cols.saturating_sub(2);

    let message_w = message.map(|(m, _)| m.chars().count()).unwrap_or(0);

    if show_no_links {
        let title_w = TITLE.chars().count();
        let help_w = help_empty_width(available_cols);
        let usage_w = USAGE_LINE1.chars().count().max(USAGE_LINE2.chars().count());

        let max_w = title_w.max(help_w).max(usage_w);
        let effective_width = max_w.max(1).min(available_cols);
        let base_x = available_cols.saturating_sub(effective_width) / 2;

        let desc_wrapped = word_wrap(DESCRIPTION, effective_width);
        let desc_lines = desc_wrapped.len();

        let help_rows = if help_w > 0 { 1 } else { 0 };
        let total_height = 1 + 1 + desc_lines + 1 + 2 + 1 + help_rows;
        let base_y = rows.saturating_sub(total_height.min(rows)) / 2;

        let title_y = base_y;
        let desc_start_y = base_y + 2;
        let usage_start_y = desc_start_y + desc_lines + 1;
        let help_y = usage_start_y + 2 + 1;

        render_title(base_x, title_y);
        let _ = render_description(&desc_wrapped, base_x, rows, desc_start_y);
        render_usage(base_x, rows, usage_start_y);

        if let Some(tier) = help_empty_tier(available_cols) {
            render_help_empty(base_x, help_y, tier);
        }

        if let Some((text, is_error)) = message {
            render_message(base_x, help_y + help_rows + 1, text, is_error);
        }
        return;
    }

    let entering = entering_label.is_some();
    let has_links = !links.is_empty();

    let controls_text = pick_controls_text(available_cols, links);

    let title_w = TITLE.chars().count();
    let table_w = table_content_width(links, controls_text);
    let help_w = if entering {
        help_empty_width(available_cols)
    } else {
        help_width(available_cols)
    };
    let prompt_w = entering_label.as_ref().map(|buf| prompt_width(pending_read_only, buf)).unwrap_or(0);

    let content_w = table_w;

    let mut max_w = title_w.max(content_w);
    max_w = max_w.max(help_w);
    max_w = max_w.max(prompt_w);
    max_w = max_w.max(message_w);

    let effective_width = max_w.min(available_cols);
    let base_x = available_cols.saturating_sub(effective_width) / 2;
    let max_cols = effective_width.min(cols);

    let desc_wrapped = word_wrap(DESCRIPTION, effective_width);
    let desc_lines = desc_wrapped.len();

    let help_rows = if help_w > 0 {
        if entering { 1 } else { 2 }
    } else {
        0
    };
    let prompt_extra_rows = if entering { 2 } else { 0 };

    let fixed_height = 1 + 1 + desc_lines + prompt_extra_rows + 1 + 2 + 1 + help_rows;
    let available_for_content = rows.saturating_sub(fixed_height).max(1);

    let content_rows = if has_links {
        (1 + links.len()).min(available_for_content)
    } else {
        0
    };

    let total_height = 1 + 1 + desc_lines + content_rows + prompt_extra_rows + 1 + 2 + 1 + help_rows;
    let base_y = rows.saturating_sub(total_height.min(rows)) / 2;

    let title_y = base_y;
    let desc_start_y = base_y + 2;
    let content_y = desc_start_y + desc_lines;
    let after_content_y = content_y + content_rows;
    let prompt_y = after_content_y + 1;
    let usage_start_y = if entering {
        prompt_y + 1 + 1
    } else {
        after_content_y + 1
    };
    let help_y = usage_start_y + 2 + 1;

    render_title(base_x, title_y);
    let _ = render_description(&desc_wrapped, base_x, rows, desc_start_y);

    if has_links {
        let _ = render_table(
            links,
            selected_index,
            base_x,
            content_y,
            available_for_content,
            max_cols,
            controls_text,
        );
    }

    if let Some(ref buf) = entering_label {
        render_prompt(pending_read_only, buf, base_x, prompt_y);
    }

    render_usage(base_x, rows, usage_start_y);

    if entering {
        if let Some(tier) = help_empty_tier(available_cols) {
            render_help_empty(base_x, help_y, tier);
        }
    } else if let Some(tier) = help_tier(available_cols) {
        match tier {
            2 => render_help_wide(base_x, help_y),
            1 => render_help_med(base_x, help_y),
            0 => render_help_narrow(base_x, help_y),
            _ => {},
        }
    }

    if let Some((text, is_error)) = message {
        render_message(base_x, help_y + help_rows + 1, text, is_error);
    }
}
