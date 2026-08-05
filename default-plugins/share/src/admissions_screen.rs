use zellij_tile::prelude::*;

use crate::online_tab::word_wrap;

const TITLE_SINGLE_PREFIX: &str = "Someone wants to join this session with link ";
const TITLE_MULTIPLE: &str = "Multiple people want to join this session";

const DESC_ACCESS_PREFIX: &str = "Admitting them will grant them ";
const DESC_ACCESS_FULL: &str = "FULL CONTROL";
const DESC_ACCESS_READ_ONLY: &str = "read-only access";
const DESC_ACCESS_SUFFIX_FULL: &str = " of this machine.";
const DESC_ACCESS_SUFFIX_READ_ONLY: &str = " to this session.";

const DESC_PIN: &str = "Following is a PIN derived from the shared secret. Make sure an identical PIN appears on the joiner's screen. If it differs, this connection is insecure and should be aborted.";

const DESC_PIN_MULTIPLE: &str = "Below is a PIN for each joiner, derived from their shared secret. Make sure each PIN matches the one shown on the corresponding joiner's screen. If any differs, that connection is insecure and should be aborted.";

const COMPROMISE_WARNING: &str = "WARNING: more than one person is joining with a single-use link. The link may have been compromised — verify each PIN carefully.";

const UNLABELLED: &str = "(unlabelled link)";

const HELP_WIDE_1: &str = "Help: <a> - Admit, <r> - Reject, <Esc> - Back";
const HELP_WIDE_2: &str = "      <Up/Down> - Select";
const HELP_MED_1: &str = "Help: <a> - Admit, <r> - Reject, <Esc> - Back";
const HELP_MED_2: &str = "      <Up/Down> - Select";
const HELP_NARROW_1: &str = "<a>/<r>/<Esc>";
const HELP_NARROW_2: &str = "<Up/Down>";

const HELP_SINGLE_WIDE: &str = "Help: <a> - Admit, <r> - Reject, <Esc> - Back";
const HELP_SINGLE_NARROW: &str = "<a>/<r>/<Esc>";

fn link_name_of(admission: &PendingAdmission) -> String {
    if admission.label.is_empty() {
        UNLABELLED.to_owned()
    } else {
        admission.label.clone()
    }
}

fn render_single_title(base_x: usize, y: usize, name: &str, seconds_remaining: u32) {
    let timer = format!("  ({}s left)", seconds_remaining);
    let full = format!("{}{}{}", TITLE_SINGLE_PREFIX, name, timer);
    let prefix_len = TITLE_SINGLE_PREFIX.chars().count();
    let name_len = name.chars().count();
    let name_end = prefix_len + name_len;
    let timer_end = name_end + timer.chars().count();
    let text = Text::new(&full)
        .color_range(2, 0..prefix_len)
        .color_range(1, prefix_len..name_end)
        .color_range(3, name_end..timer_end);
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn render_multiple_title(base_x: usize, y: usize) {
    print_text_with_coordinates(Text::new(TITLE_MULTIPLE).color_all(2), base_x, y, None, None);
}

fn render_access_description(read_only: bool, base_x: usize, y: usize) {
    let (text, _) = access_description_text(read_only, 0);
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn access_description_text(read_only: bool, indent: usize) -> (Text, usize) {
    access_description_text_padded(read_only, indent, 0)
}

fn access_description_text_padded(read_only: bool, indent: usize, width: usize) -> (Text, usize) {
    let (access, suffix) = if read_only {
        (DESC_ACCESS_READ_ONLY, DESC_ACCESS_SUFFIX_READ_ONLY)
    } else {
        (DESC_ACCESS_FULL, DESC_ACCESS_SUFFIX_FULL)
    };
    let pad: String = " ".repeat(indent);
    let core = format!("{}{}{}{}", pad, DESC_ACCESS_PREFIX, access, suffix);
    let right_pad = width.saturating_sub(core.chars().count());
    let full = format!("{}{}", core, " ".repeat(right_pad));
    let access_start = indent + DESC_ACCESS_PREFIX.chars().count();
    let access_end = access_start + access.chars().count();
    let mut text = Text::new(&full);
    if read_only {
        text = text.success_color_range(access_start..access_end);
    } else {
        text = text.error_color_range(access_start..access_end);
    }
    (text, full.chars().count())
}

fn render_paragraph(lines: &[String], base_x: usize, rows: usize, mut y: usize) -> usize {
    for line in lines {
        if y >= rows.saturating_sub(1) {
            break;
        }
        print_text_with_coordinates(Text::new(line), base_x, y, None, None);
        y += 1;
    }
    y
}

fn render_pin(base_x: usize, y: usize, width: usize, pin: &str) {
    let prefix = "PIN: ";
    let prefix_len = prefix.chars().count();
    let pin_len = pin.chars().count();
    let full = format!("{}{}", prefix, pin);
    let full_len = prefix_len + pin_len;
    let pin_x = base_x + width.saturating_sub(full_len) / 2;
    let text = Text::new(&full).color_range(0, prefix_len..full_len);
    print_text_with_coordinates(text, pin_x, y, None, None);
}

fn pin_text_full_width(width: usize, pin: &str) -> Text {
    let prefix = "PIN: ";
    let prefix_len = prefix.chars().count();
    let pin_len = pin.chars().count();
    let content_len = prefix_len + pin_len;
    let left = width.saturating_sub(content_len) / 2;
    let right = width.saturating_sub(left + content_len);
    let full = format!(
        "{}{}{}{}",
        " ".repeat(left),
        prefix,
        pin,
        " ".repeat(right)
    );
    let pin_start = left + prefix_len;
    let pin_end = pin_start + pin_len;
    Text::new(&full).color_range(0, pin_start..pin_end)
}

fn render_message(base_x: usize, y: usize, message: &str, is_error: bool) {
    let text = if is_error {
        Text::new(message).error_color_all()
    } else {
        Text::new(message).success_color_all()
    };
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn render_help_single(base_x: usize, y: usize, tier: usize) {
    let text = match tier {
        1 | 2 => Text::new(HELP_SINGLE_WIDE)
            .color_substring(3, "<a>")
            .color_substring(3, "<r>")
            .color_substring(3, "<Esc>"),
        _ => Text::new(HELP_SINGLE_NARROW)
            .color_substring(3, "<a>")
            .color_substring(3, "<r>")
            .color_substring(3, "<Esc>"),
    };
    print_text_with_coordinates(text, base_x, y, None, None);
}

fn render_help_multiple(base_x: usize, y: usize, tier: usize) {
    let (line1, line2) = match tier {
        2 => (HELP_WIDE_1, HELP_WIDE_2),
        1 => (HELP_MED_1, HELP_MED_2),
        _ => (HELP_NARROW_1, HELP_NARROW_2),
    };
    let text1 = Text::new(line1)
        .color_substring(3, "<a>")
        .color_substring(3, "<r>")
        .color_substring(3, "<Esc>");
    print_text_with_coordinates(text1, base_x, y, None, None);
    let text2 = Text::new(line2).color_substring(3, "<Up/Down>");
    print_text_with_coordinates(text2, base_x, y + 1, None, None);
}

fn help_single_tier(available_cols: usize) -> usize {
    if available_cols >= HELP_SINGLE_WIDE.chars().count() {
        2
    } else {
        0
    }
}

fn help_single_width(available_cols: usize) -> usize {
    match help_single_tier(available_cols) {
        2 => HELP_SINGLE_WIDE.chars().count(),
        _ => HELP_SINGLE_NARROW.chars().count(),
    }
}

fn help_multiple_tier(available_cols: usize) -> usize {
    let wide_w = HELP_WIDE_1.chars().count().max(HELP_WIDE_2.chars().count());
    if available_cols >= wide_w {
        return 2;
    }
    let med_w = HELP_MED_1.chars().count().max(HELP_MED_2.chars().count());
    if available_cols >= med_w {
        return 1;
    }
    0
}

fn help_multiple_width(available_cols: usize) -> usize {
    match help_multiple_tier(available_cols) {
        2 => HELP_WIDE_1.chars().count().max(HELP_WIDE_2.chars().count()),
        1 => HELP_MED_1.chars().count().max(HELP_MED_2.chars().count()),
        _ => HELP_NARROW_1.chars().count().max(HELP_NARROW_2.chars().count()),
    }
}

fn single_title_width(name: &str, seconds_remaining: u32) -> usize {
    let timer = format!("  ({}s left)", seconds_remaining);
    TITLE_SINGLE_PREFIX.chars().count() + name.chars().count() + timer.chars().count()
}

fn access_description_width(read_only: bool) -> usize {
    let (access, suffix) = if read_only {
        (DESC_ACCESS_READ_ONLY, DESC_ACCESS_SUFFIX_READ_ONLY)
    } else {
        (DESC_ACCESS_FULL, DESC_ACCESS_SUFFIX_FULL)
    };
    DESC_ACCESS_PREFIX.chars().count() + access.chars().count() + suffix.chars().count()
}

fn pin_width(admission: &PendingAdmission) -> usize {
    "PIN: ".chars().count() + admission.sas.chars().count()
}

fn name_with_timer_width(admission: &PendingAdmission) -> usize {
    let name = link_name_of(admission);
    let timer = format!("  ({}s left)", admission.seconds_remaining);
    name.chars().count() + timer.chars().count()
}

fn render_single(
    rows: usize,
    available_cols: usize,
    admission: &PendingAdmission,
    message: Option<(&str, bool)>,
) {
    let name = link_name_of(admission);
    let message_w = message.map(|(m, _)| m.chars().count()).unwrap_or(0);

    let title_w = single_title_width(&name, admission.seconds_remaining);
    let access_w = access_description_width(admission.read_only);
    let help_w = help_single_width(available_cols);
    let pin_w = pin_width(admission);

    let max_w = title_w
        .max(access_w)
        .max(help_w)
        .max(pin_w)
        .max(message_w);
    let effective_width = max_w.max(1).min(available_cols);
    let base_x = available_cols.saturating_sub(effective_width) / 2;

    let pin_para = word_wrap(DESC_PIN, effective_width);
    let pin_para_lines = pin_para.len();

    let total_height = 1 + 1 + 1 + 1 + pin_para_lines + 1 + 1 + 1 + 1;
    let base_y = rows.saturating_sub(total_height.min(rows)) / 2;

    let title_y = base_y;
    let access_y = title_y + 2;
    let pin_para_y = access_y + 2;
    let pin_y = pin_para_y + pin_para_lines + 1;
    let help_y = pin_y + 2;

    render_single_title(base_x, title_y, &name, admission.seconds_remaining);
    render_access_description(admission.read_only, base_x, access_y);
    let _ = render_paragraph(&pin_para, base_x, rows, pin_para_y);
    if pin_y < rows.saturating_sub(1) {
        render_pin(base_x, pin_y, effective_width, &admission.sas);
    }
    if help_y < rows {
        render_help_single(base_x, help_y, help_single_tier(available_cols));
    }

    if let Some((text, is_error)) = message {
        render_message(base_x, help_y + 1 + 1, text, is_error);
    }
}

fn block_line_count() -> usize {
    1 + 1 + 1 + 1 + 1
}

fn render_multiple(
    rows: usize,
    available_cols: usize,
    admissions: &[PendingAdmission],
    selected_index: Option<usize>,
    message: Option<(&str, bool)>,
) {
    let message_w = message.map(|(m, _)| m.chars().count()).unwrap_or(0);

    let title_w = TITLE_MULTIPLE.chars().count();
    let help_w = help_multiple_width(available_cols);
    let name_w = admissions
        .iter()
        .map(name_with_timer_width)
        .max()
        .unwrap_or(0);
    let access_w = access_description_width(false).max(access_description_width(true));
    let pin_w = admissions.iter().map(pin_width).max().unwrap_or(0);

    let max_w = title_w
        .max(help_w)
        .max(name_w)
        .max(access_w)
        .max(pin_w)
        .max(message_w);
    let effective_width = max_w.max(1).min(available_cols);
    let base_x = available_cols.saturating_sub(effective_width) / 2;

    let contested = admissions.iter().any(|a| a.contested);
    let warning_wrapped = if contested {
        word_wrap(COMPROMISE_WARNING, effective_width)
    } else {
        Vec::new()
    };
    let warning_lines = warning_wrapped.len();
    let warning_block = if warning_lines > 0 { warning_lines + 1 } else { 0 };
    let pin_para = word_wrap(DESC_PIN_MULTIPLE, effective_width);
    let pin_para_lines = pin_para.len();

    let per_block = block_line_count();
    let blocks_height = per_block * admissions.len();

    let total_height = 1 + 1 + pin_para_lines + 1 + warning_block + blocks_height + 1 + 2;
    let base_y = rows.saturating_sub(total_height.min(rows)) / 2;

    let mut y = base_y;
    render_multiple_title(base_x, y);
    y += 2;

    let _ = render_paragraph(&pin_para, base_x, rows, y);
    y += pin_para_lines + 1;

    if warning_lines > 0 {
        for line in &warning_wrapped {
            if y >= rows.saturating_sub(1) {
                break;
            }
            print_text_with_coordinates(Text::new(line).error_color_all(), base_x, y, None, None);
            y += 1;
        }
        y += 1;
    }

    for (i, admission) in admissions.iter().enumerate() {
        if y + per_block >= rows {
            break;
        }
        let is_selected = Some(i) == selected_index;
        let name = link_name_of(admission);

        let timer = format!("  ({}s left)", admission.seconds_remaining);
        let core = format!("{}{}", name, timer);
        let right_pad = effective_width.saturating_sub(core.chars().count());
        let name_full = format!("{}{}", core, " ".repeat(right_pad));
        let name_end = name.chars().count();
        let timer_end = name_end + timer.chars().count();
        let mut name_text = Text::new(&name_full)
            .color_range(1, 0..name_end)
            .color_range(3, name_end..timer_end);

        let (mut access_text, access_len) =
            access_description_text_padded(admission.read_only, 0, effective_width);
        let _ = access_len;
        let mut pin_text = pin_text_full_width(effective_width, &admission.sas);
        let mut blank_text = Text::new(&" ".repeat(effective_width));
        let mut blank_text2 = Text::new(&" ".repeat(effective_width));

        if is_selected {
            name_text = name_text.selected();
            access_text = access_text.selected();
            pin_text = pin_text.selected();
            blank_text = blank_text.selected();
            blank_text2 = blank_text2.selected();
        }

        print_text_with_coordinates(name_text, base_x, y, None, None);
        y += 1;
        print_text_with_coordinates(access_text, base_x, y, None, None);
        y += 1;
        print_text_with_coordinates(blank_text, base_x, y, None, None);
        y += 1;
        print_text_with_coordinates(pin_text, base_x, y, None, None);
        y += 1;
        print_text_with_coordinates(blank_text2, base_x, y, None, None);
        y += 1;
    }

    let help_y = y + 1;
    if help_y < rows {
        render_help_multiple(base_x, help_y, help_multiple_tier(available_cols));
    }

    if let Some((text, is_error)) = message {
        render_message(base_x, help_y + 2 + 1, text, is_error);
    }
}

pub fn render_admissions_screen(
    rows: usize,
    cols: usize,
    admissions: &[PendingAdmission],
    selected_index: Option<usize>,
    message: Option<(&str, bool)>,
) {
    let available_cols = cols.saturating_sub(2);

    match admissions.len() {
        0 => {},
        1 => render_single(rows, available_cols, &admissions[0], message),
        _ => render_multiple(rows, available_cols, admissions, selected_index, message),
    }
}
