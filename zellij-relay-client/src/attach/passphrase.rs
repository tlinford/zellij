use std::path::Path;

use console::{style, Key, Term};

const MIN_LEN: usize = 8;
const WEAK_SCORE: u8 = 2;
const ATTACKER_GUESSES_PER_SEC: f64 = 100_000.0;
const PASSPHRASE_ENV: &str = "ZELLIJ_DEVICE_PASSPHRASE";
const ASKPASS_ENV: &str = "ZELLIJ_DEVICE_ASKPASS";
const MASK: &str = "•";

pub struct Strength {
    pub score: u8,
    pub guesses: u64,
    pub label: &'static str,
}

pub fn strength(passphrase: &str) -> Strength {
    let entropy = zxcvbn::zxcvbn(passphrase, &[]);
    let score = u8::from(entropy.score());
    Strength {
        score,
        guesses: entropy.guesses(),
        label: score_label(score),
    }
}

fn score_label(score: u8) -> &'static str {
    match score {
        0 => "very weak",
        1 => "weak",
        2 => "fair",
        3 => "good",
        _ => "strong",
    }
}

pub fn is_weak(passphrase: &str) -> bool {
    passphrase.chars().count() < MIN_LEN || strength(passphrase).score < WEAK_SCORE
}

pub fn estimate_offline_crack(guesses: u64) -> String {
    humanize_duration(guesses as f64 / ATTACKER_GUESSES_PER_SEC)
}

fn humanize_duration(seconds: f64) -> String {
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 60.0 * MINUTE;
    const DAY: f64 = 24.0 * HOUR;
    const YEAR: f64 = 365.0 * DAY;
    if seconds < 1.0 {
        "less than a second".to_string()
    } else if seconds < MINUTE {
        format!("{} seconds", seconds.round() as u64)
    } else if seconds < HOUR {
        format!("{} minutes", (seconds / MINUTE).round() as u64)
    } else if seconds < DAY {
        format!("{} hours", (seconds / HOUR).round() as u64)
    } else if seconds < YEAR {
        format!("{} days", (seconds / DAY).round() as u64)
    } else {
        let years = seconds / YEAR;
        if years >= 1_000_000_000.0 {
            "billions of years".to_string()
        } else if years >= 1_000_000.0 {
            "millions of years".to_string()
        } else if years >= 1_000.0 {
            format!("{} thousand years", (years / 1_000.0).round() as u64)
        } else {
            format!("{} years", years.round() as u64)
        }
    }
}

pub fn resolve_supplied_passphrase() -> Option<String> {
    resolve_supplied_from(
        std::env::var(PASSPHRASE_ENV).ok(),
        std::env::var(ASKPASS_ENV).ok(),
        run_askpass,
    )
}

fn resolve_supplied_from(
    literal: Option<String>,
    askpass: Option<String>,
    run: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    if let Some(value) = literal {
        if !value.is_empty() {
            return Some(value);
        }
    }
    let command = askpass?;
    let output = run(&command)?;
    let line = first_line(&output);
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

fn first_line(output: &str) -> String {
    output.lines().next().unwrap_or("").to_string()
}

fn run_askpass(command: &str) -> Option<String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

pub fn prompt_new_passphrase(key_path: &Path) -> Option<String> {
    let term = Term::stdout();
    if !term.is_term() {
        return prompt_new_passphrase_basic();
    }
    print_threat_header(&term, key_path);
    loop {
        let passphrase = read_with_meter(&term)?;
        let confirm = read_masked(&term, "Confirm passphrase: ")?;
        if confirm == passphrase {
            return Some(passphrase);
        }
        let _ = term.write_line("Passphrases do not match — try again.");
    }
}

fn print_threat_header(term: &Term, key_path: &Path) {
    let _ = term.write_line("");
    let _ = term.write_line("Admitted. This device is now enrolled on the remote server.");
    let _ = term.write_line(&format!(
        "A secret key for this device will now be created and saved to {}",
        key_path.display()
    ));
    let _ = term.write_line("Please select a passphrase that will be used to decrypt this key.");
    let _ = term.write_line(
        "If someone steals this device or obtains this secret key, this passphrase is the only",
    );
    let _ =
        term.write_line("protection until the device's enrollment can be revoked.");
    let _ = term.write_line("");
    let _ = term
        .write_line("The strength estimate below assumes a well-resourced attacker on current hardware.");
    let _ = term.write_line("");
}

fn read_with_meter(term: &Term) -> Option<String> {
    let prompt = "New passphrase: ";
    let mut buffer = String::new();
    let mut rejected = false;
    redraw(term, prompt, &buffer, rejected);
    loop {
        let key = term.read_key().ok()?;
        match key {
            Key::Char(c) => {
                buffer.push(c);
                rejected = false;
            },
            Key::Backspace => {
                buffer.pop();
                rejected = false;
            },
            Key::Enter => {
                if is_weak(&buffer) {
                    rejected = true;
                } else {
                    let _ = term.move_cursor_down(1);
                    let _ = term.write_line("");
                    return Some(buffer);
                }
            },
            Key::Escape => return None,
            _ => continue,
        }
        redraw(term, prompt, &buffer, rejected);
    }
}

fn redraw(term: &Term, prompt: &str, buffer: &str, rejected: bool) {
    let _ = term.clear_line();
    let _ = term.write_str(&format!("{}{}", prompt, MASK.repeat(buffer.chars().count())));
    let _ = term.write_str("\n");
    let _ = term.clear_line();
    let _ = term.write_str(&meter_line(buffer, rejected));
    let _ = term.move_cursor_up(1);
    let _ = term.write_str("\r");
    let width = prompt.chars().count() + buffer.chars().count();
    if width > 0 {
        let _ = term.move_cursor_right(width);
    }
}

fn meter_line(buffer: &str, rejected: bool) -> String {
    if buffer.is_empty() {
        return "  strength: —".to_string();
    }
    let s = strength(buffer);
    let body = format!(
        "{} · offline crack if stolen ≈ {}",
        s.label,
        estimate_offline_crack(s.guesses)
    );
    let colored = match s.score {
        0 | 1 => style(body).red(),
        2 => style(body).yellow(),
        _ => style(body).green(),
    };
    let note = if rejected {
        style(" — too weak, keep typing").red().to_string()
    } else {
        String::new()
    };
    format!("  strength: {}{}", colored, note)
}

fn read_masked(term: &Term, prompt: &str) -> Option<String> {
    let mut buffer = String::new();
    let _ = term.write_str(prompt);
    loop {
        let key = term.read_key().ok()?;
        match key {
            Key::Char(c) => {
                buffer.push(c);
                let _ = term.write_str(MASK);
            },
            Key::Backspace => {
                if buffer.pop().is_some() {
                    let _ = term.clear_chars(1);
                }
            },
            Key::Enter => {
                let _ = term.write_line("");
                return Some(buffer);
            },
            Key::Escape => return None,
            _ => continue,
        }
    }
}

fn prompt_new_passphrase_basic() -> Option<String> {
    use dialoguer::Password;
    loop {
        let passphrase = Password::new()
            .with_prompt("Set a passphrase to protect this device on disk")
            .with_confirmation("Confirm passphrase", "Passphrases do not match")
            .interact()
            .ok()?;
        if is_weak(&passphrase) {
            eprintln!("Passphrase too weak — choose a longer, less predictable one.");
            continue;
        }
        return Some(passphrase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_common() {
        assert!(is_weak("short"));
        assert!(is_weak("password"));
        assert!(is_weak("12345678"));
    }

    #[test]
    fn accepts_a_strong_passphrase() {
        assert!(!is_weak("correct horse battery staple"));
    }

    #[test]
    fn crack_estimate_grows_with_guesses() {
        let small = estimate_offline_crack(1);
        let big = estimate_offline_crack(u64::MAX);
        assert_eq!(small, "less than a second");
        assert!(big.contains("years"));
    }

    #[test]
    fn humanize_covers_ranges() {
        assert_eq!(humanize_duration(0.5), "less than a second");
        assert_eq!(humanize_duration(90.0), "2 minutes");
        assert_eq!(humanize_duration(3.0 * 3600.0), "3 hours");
        assert_eq!(humanize_duration(2.0 * 86400.0), "2 days");
    }

    #[test]
    fn literal_env_takes_precedence() {
        let out = resolve_supplied_from(
            Some("from-literal".to_string()),
            Some("ignored".to_string()),
            |_| Some("from-command".to_string()),
        );
        assert_eq!(out.as_deref(), Some("from-literal"));
    }

    #[test]
    fn empty_literal_falls_through_to_askpass() {
        let out = resolve_supplied_from(
            Some(String::new()),
            Some("cmd".to_string()),
            |_| Some("secret\ntrailing".to_string()),
        );
        assert_eq!(out.as_deref(), Some("secret"));
    }

    #[test]
    fn no_source_resolves_none() {
        let out = resolve_supplied_from(None, None, |_| Some("x".to_string()));
        assert_eq!(out, None);
    }

    #[test]
    fn blank_command_output_resolves_none() {
        let out = resolve_supplied_from(None, Some("cmd".to_string()), |_| Some("\n".to_string()));
        assert_eq!(out, None);
    }
}
