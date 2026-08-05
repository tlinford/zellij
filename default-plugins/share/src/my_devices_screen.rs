use std::collections::HashMap;
use zellij_tile::prelude::*;

use crate::online_tab::word_wrap;
use crate::ui_components::render_secret_link_screen;
use crate::CoordinatesInLine;

const TITLE: &str = "Permanently Enrolled Devices";
const READ_ONLY: &str = "Read-only";
const FULL_CONTROL: &str = "FULL CONTROL";
const CONNECTED: &str = "[Connected]";
const NOT_CONNECTED: &str = "[Not connected]";
const NEVER_CONNECTED: &str = "[Never connected]";
const PENDING: &str = "[Pending]";
const UNLABELLED_DEVICE: &str = "(unlabelled device)";
const UNLABELLED_LINK: &str = "(unlabelled)";

const CONTROLS_WIDE: &str = "<c> - Copy link, <d> - Display link";
const CONTROLS_MEDIUM: &str = "<c> - Copy, <d> - Display";
const CONTROLS_NARROW: &str = "<c>/<d>";

const DESCRIPTION: &str = "Enrolled devices can reconnect to this machine without re-admission. Enrollment links are single-use and contain shared secrets, so must be sent over a secure medium. Each link grants the device the access level shown until revoked.";
const USAGE_LINE1: &str = "Usage from remote: zellij attach <LINK> (most secure).";
const USAGE_LINE2: &str = "                   Or paste into a browser.";
const USAGE_EMPHASIS: &str = "zellij attach <LINK>";

const HELP_WIDE_1: &str = "Help: <n> - Enroll full-control, <o> - Enroll read-only";
const HELP_WIDE_2: &str = "      <x> - Revoke, <Esc> - Back";
const HELP_MED_1: &str = "Help: <n> - Enroll, <o> - Read-only";
const HELP_MED_2: &str = "      <x> - Revoke, <Esc> - Back";
const HELP_NARROW_1: &str = "<n>/<o>";
const HELP_NARROW_2: &str = "<x>/<Esc>";

const HELP_EMPTY_WIDE: &str = "Help: <n> - Enroll full-control, <o> - Enroll read-only, <Esc> - Back";
const HELP_EMPTY_MED: &str = "Help: <n> - Enroll, <o> - Read-only, <Esc> - Back";
const HELP_EMPTY_NARROW: &str = "<n>/<o>/<Esc>";

const RANDOM_NAME_HINT: &str = " (<ENTER> - random name)";

pub struct DeviceRowView<'a> {
    pub label: &'a str,
    pub read_only: bool,
    pub connected: bool,
    pub ever_connected: bool,
}

pub struct EnrollmentLinkView<'a> {
    pub label: &'a str,
    pub read_only: bool,
}

fn render_title(base_x: usize, y: usize) {
    print_text_with_coordinates(Text::new(TITLE).color_all(2), base_x, y, None, None);
}

fn render_description(lines: &[String], base_x: usize, rows: usize, mut y: usize) -> usize {
    for line in lines {
        if y >= rows.saturating_sub(1) {
            break;
        }
        print_text_with_coordinates(Text::new(line), base_x, y, None, None);
        y += 1;
    }
    y
}

fn render_usage(base_x: usize, rows: usize, mut y: usize) {
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

fn access_cell(read_only: bool) -> Text {
    if read_only {
        Text::new(READ_ONLY).success_color_all()
    } else {
        Text::new(FULL_CONTROL).error_color_all()
    }
}

fn device_status(view: &DeviceRowView) -> (&'static str, bool) {
    if view.connected {
        (CONNECTED, true)
    } else if view.ever_connected {
        (NOT_CONNECTED, false)
    } else {
        (NEVER_CONNECTED, false)
    }
}

fn render_table(
    devices: &[DeviceRowView],
    links: &[EnrollmentLinkView],
    selected_index: Option<usize>,
    base_x: usize,
    y: usize,
    available_rows: usize,
    max_cols: usize,
    controls_text: &str,
) -> usize {
    let mut table = Table::new().add_row(vec![" ", " ", " ", " "]);

    for (i, device) in devices.iter().enumerate() {
        let is_selected = Some(i) == selected_index;
        let label = if device.label.is_empty() {
            UNLABELLED_DEVICE
        } else {
            device.label
        };
        let name_cell = Text::new(label).color_all(1);
        let access = access_cell(device.read_only);
        let (status, connected) = device_status(device);
        let mut status_cell = Text::new(status);
        if connected {
            status_cell = status_cell.success_color_all();
        }
        let spacer = Text::new(" ".repeat(controls_text.chars().count()));

        if is_selected {
            table = table.add_styled_row(vec![
                name_cell.selected(),
                access.selected(),
                status_cell.selected(),
                spacer.selected(),
            ]);
        } else {
            table = table.add_styled_row(vec![name_cell, access, status_cell, spacer]);
        }
    }

    let offset = devices.len();
    for (i, link) in links.iter().enumerate() {
        let row_index = offset + i;
        let is_selected = Some(row_index) == selected_index;
        let label = if link.label.is_empty() {
            UNLABELLED_LINK
        } else {
            link.label
        };
        let name_cell = Text::new(label).color_all(1);
        let access = access_cell(link.read_only);
        let status_cell = Text::new(PENDING);
        let controls_cell = Text::new(controls_text)
            .color_substring(3, "<c>")
            .color_substring(3, "<d>");

        if is_selected {
            table = table.add_styled_row(vec![
                name_cell.selected(),
                access.selected(),
                status_cell.selected(),
                controls_cell.selected(),
            ]);
        } else {
            table = table.add_styled_row(vec![name_cell, access, status_cell, Text::new(" ")]);
        }
    }

    print_table_with_coordinates(table, base_x, y, Some(max_cols), Some(available_rows));
    (1 + devices.len() + links.len()).min(available_rows)
}

fn render_prompt(read_only: bool, label: &str, base_x: usize, y: usize) {
    let kind = if read_only { "READ-ONLY" } else { "FULL-CONTROL" };
    let prefix = format!("New {} enrollment link label: ", kind);
    let show_hint = label.trim().is_empty();
    let hint = if show_hint { RANDOM_NAME_HINT } else { "" };
    let full = format!("{}{}_{}", prefix, label, hint);
    let prefix_len = prefix.chars().count();
    let label_len = label.chars().count();
    let cursor_pos = prefix_len + label_len;
    let mut text = Text::new(&full);
    text = text.color_all(1);
    text = text.color_range(3, cursor_pos..cursor_pos + 1);
    if read_only {
        text = text.success_color_substring(kind);
    } else {
        text = text.error_color_substring(kind);
    }
    if show_hint {
        text = text.color_substring(3, "<ENTER>");
    }
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn prompt_width(read_only: bool, label: &str) -> usize {
    let kind = if read_only { "READ-ONLY" } else { "FULL-CONTROL" };
    let hint = if label.trim().is_empty() {
        RANDOM_NAME_HINT
    } else {
        ""
    };
    format!("New {} enrollment link label: {}_{}", kind, label, hint)
        .chars()
        .count()
}

fn render_help_wide(base_x: usize, y: usize) {
    let help_text = Text::new(HELP_WIDE_1)
        .color_substring(3, "<n>")
        .color_substring(3, "<o>");
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

fn render_help_empty(base_x: usize, y: usize, tier: usize) {
    let text = match tier {
        2 => Text::new(HELP_EMPTY_WIDE),
        1 => Text::new(HELP_EMPTY_MED),
        _ => Text::new(HELP_EMPTY_NARROW),
    }
    .color_substring(3, "<n>")
    .color_substring(3, "<o>")
    .color_substring(3, "<Esc>");
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn render_message(base_x: usize, y: usize, message: &str, is_error: bool) {
    let text = if is_error {
        Text::new(message).error_color_all()
    } else {
        Text::new(message).success_color_all()
    };
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn max_label_width(devices: &[DeviceRowView], links: &[EnrollmentLinkView]) -> usize {
    let device_w = devices
        .iter()
        .map(|d| {
            if d.label.is_empty() {
                UNLABELLED_DEVICE.chars().count()
            } else {
                d.label.chars().count()
            }
        })
        .max()
        .unwrap_or(0);
    let link_w = links
        .iter()
        .map(|l| {
            if l.label.is_empty() {
                UNLABELLED_LINK.chars().count()
            } else {
                l.label.chars().count()
            }
        })
        .max()
        .unwrap_or(0);
    device_w.max(link_w)
}

fn table_content_width(
    devices: &[DeviceRowView],
    links: &[EnrollmentLinkView],
    controls_text: &str,
) -> usize {
    let name_width = max_label_width(devices, links);
    let access_width = FULL_CONTROL.chars().count();
    let status_width = NEVER_CONNECTED.chars().count();
    let controls_width = controls_text.chars().count();
    name_width
        .saturating_add(access_width)
        .saturating_add(status_width)
        .saturating_add(controls_width)
        .saturating_add(5)
}

fn pick_controls_text(
    available_cols: usize,
    devices: &[DeviceRowView],
    links: &[EnrollmentLinkView],
) -> &'static str {
    let name_width = max_label_width(devices, links);
    let access_width = FULL_CONTROL.chars().count();
    let status_width = NEVER_CONNECTED.chars().count();
    let base_width = name_width
        .saturating_add(access_width)
        .saturating_add(status_width)
        .saturating_add(5);
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

pub fn render_my_devices_screen(
    rows: usize,
    cols: usize,
    devices: &[DeviceRowView],
    links: &[EnrollmentLinkView],
    selected_index: Option<usize>,
    entering_label: Option<String>,
    pending_read_only: bool,
    display_link: Option<(&str, &str, bool)>,
    message: Option<(&str, bool)>,
    hover_coordinates: Option<(usize, usize)>,
    clickable_urls: &mut HashMap<CoordinatesInLine, String>,
) {
    if let Some((label, url, revealed)) = display_link {
        render_secret_link_screen(
            rows,
            cols,
            "Enrollment link:",
            label,
            url,
            revealed,
            hover_coordinates,
            clickable_urls,
        );
        return;
    }

    let entering = entering_label.is_some();
    let has_rows = !devices.is_empty() || !links.is_empty();
    let show_empty = !has_rows && !entering;
    let available_cols = cols.saturating_sub(2);

    let message_w = message.map(|(m, _)| m.chars().count()).unwrap_or(0);

    if show_empty {
        let title_w = TITLE.chars().count();
        let help_w = help_empty_width(available_cols);
        let usage_w = USAGE_LINE1.chars().count().max(USAGE_LINE2.chars().count());

        let max_w = title_w.max(help_w).max(usage_w).max(message_w);
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

    let controls_text = pick_controls_text(available_cols, devices, links);

    let title_w = TITLE.chars().count();
    let table_w = table_content_width(devices, links, controls_text);
    let help_w = if entering {
        help_empty_width(available_cols)
    } else {
        help_width(available_cols)
    };
    let prompt_w = entering_label
        .as_ref()
        .map(|buf| prompt_width(pending_read_only, buf))
        .unwrap_or(0);
    let usage_w = USAGE_LINE1.chars().count().max(USAGE_LINE2.chars().count());

    let mut max_w = title_w.max(table_w);
    max_w = max_w.max(help_w);
    max_w = max_w.max(prompt_w);
    max_w = max_w.max(usage_w);
    max_w = max_w.max(message_w);

    let effective_width = max_w.min(available_cols);
    let base_x = available_cols.saturating_sub(effective_width) / 2;
    let max_cols = effective_width.min(cols);

    let desc_wrapped = word_wrap(DESCRIPTION, effective_width);
    let desc_lines = desc_wrapped.len();

    let help_rows = if help_w > 0 {
        if entering {
            1
        } else {
            2
        }
    } else {
        0
    };
    let prompt_extra_rows = if entering { 2 } else { 0 };

    let fixed_height = 1 + 1 + desc_lines + prompt_extra_rows + 1 + 2 + 1 + help_rows;
    let available_for_content = rows.saturating_sub(fixed_height).max(1);

    let content_rows = if has_rows {
        (1 + devices.len() + links.len()).min(available_for_content)
    } else {
        0
    };

    let total_height =
        1 + 1 + desc_lines + content_rows + prompt_extra_rows + 1 + 2 + 1 + help_rows;
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

    if has_rows {
        let _ = render_table(
            devices,
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
