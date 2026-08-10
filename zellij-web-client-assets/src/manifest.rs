use sha2::{Digest, Sha384};

pub const HANDSHAKE_CORE_ASSET_NAMES: &[&str] = &[
    "utils.js",
    "integrity.js",
    "crypto.js",
    "relay_crypto.wasm",
    "auth.js",
    "connection.js",
    "modals.js",
    "style.css",
    "core-bootstrap.js",
    "core-control.js",
    "device-store.js",
    "favicon.ico",
    "manifest.webmanifest",
    "icon-192.png",
];

pub const HANDSHAKE_CLASSIC_SCRIPT_NAMES: &[&str] = &["modals.js"];

pub const HANDSHAKE_MODULE_SCRIPT_NAMES: &[&str] = &[
    "utils.js",
    "integrity.js",
    "crypto.js",
    "connection.js",
    "auth.js",
    "core-control.js",
    "core-bootstrap.js",
];

pub const HANDSHAKE_STYLESHEET_NAMES: &[&str] = &["style.css"];

pub const HANDSHAKE_HEAD_LINK_NAMES: &[&str] =
    &["favicon.ico", "manifest.webmanifest", "icon-192.png"];

pub const HANDSHAKE_RUNTIME_LOADED_NAMES: &[&str] = &["relay_crypto.wasm", "device-store.js"];

pub const APPLICATION_ASSET_NAMES: &[&str] = &[
    "app.js",
    "clip.wasm",
    "xterm.js",
    "xterm.css",
    "addon-fit.js",
    "addon-clipboard.js",
    "addon-web-links.js",
    "addon-webgl.js",
];

pub fn per_asset_integrity_b64(bytes: &[u8]) -> String {
    let digest = Sha384::digest(bytes);
    format!("sha384-{}", base64_std(&digest))
}

pub fn manifest_line(name: &str, integrity: &str) -> String {
    format!("{}  {}", name, integrity)
}

pub fn rolled_up_from_lines(sorted_lines: &[String]) -> String {
    let mut text = sorted_lines.join("\n");
    text.push('\n');
    let digest = Sha384::digest(text.as_bytes());
    format!("sha384-{}", base64_std(&digest))
}

fn base64_symbol(value: usize) -> u8 {
    match value {
        0..=25 => b'A' + value as u8,
        26..=51 => b'a' + (value - 26) as u8,
        52..=61 => b'0' + (value - 52) as u8,
        62 => 43,
        _ => 47,
    }
}

fn base64_std(bytes: &[u8]) -> String {
    const PAD: u8 = 61;
    let mut out: Vec<u8> = Vec::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(base64_symbol(b0 >> 2));
        out.push(base64_symbol(((b0 & 0x03) << 4) | (b1 >> 4)));
        out.push(if chunk.len() > 1 {
            base64_symbol(((b1 & 0x0f) << 2) | (b2 >> 6))
        } else {
            PAD
        });
        out.push(if chunk.len() > 2 {
            base64_symbol(b2 & 0x3f)
        } else {
            PAD
        });
    }
    String::from_utf8(out).expect("base64 alphabet is ascii")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn handshake_core_partition_is_disjoint_and_complete() {
        let groups: &[&[&str]] = &[
            HANDSHAKE_CLASSIC_SCRIPT_NAMES,
            HANDSHAKE_MODULE_SCRIPT_NAMES,
            HANDSHAKE_STYLESHEET_NAMES,
            HANDSHAKE_HEAD_LINK_NAMES,
            HANDSHAKE_RUNTIME_LOADED_NAMES,
        ];
        let mut union: HashSet<&str> = HashSet::new();
        let mut total = 0;
        for group in groups {
            for name in *group {
                assert!(union.insert(name), "asset '{}' classified twice", name);
                total += 1;
            }
        }
        let core: HashSet<&str> = HANDSHAKE_CORE_ASSET_NAMES.iter().copied().collect();
        assert_eq!(total, HANDSHAKE_CORE_ASSET_NAMES.len());
        assert_eq!(union, core);
    }
}
