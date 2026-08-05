use include_dir::{include_dir, Dir};
use std::sync::LazyLock;

pub mod manifest;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub static ASSETS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/assets");

static APP_BUNDLE_SHA384: LazyLock<String> = LazyLock::new(|| {
    let mut lines: Vec<String> = manifest::APPLICATION_ASSET_NAMES
        .iter()
        .map(|name| {
            let bytes = lookup(name).expect("application asset embedded").contents;
            manifest::manifest_line(name, &manifest::per_asset_integrity_b64(bytes))
        })
        .collect();
    lines.sort();
    manifest::rolled_up_from_lines(&lines)
});

pub fn app_bundle_sha384() -> &'static str {
    &APP_BUNDLE_SHA384
}

/// The raw HTML shell served by the web client. Consumers are expected to
/// substitute `BASE_URL` and `IS_AUTHENTICATED` placeholders before
/// returning to the browser.
pub static INDEX_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html"));

/// Result of a successful asset lookup.
pub struct AssetResponse {
    pub content_type: &'static str,
    pub contents: &'static [u8],
}

/// When the `clip_wasm_from_target` feature is enabled, bundle the live
/// `zellij-ansi-clip` build artifact instead of the committed blob so edits
/// to the crate are picked up without a commit. Release builds + CI always
/// use the committed `assets/clip.wasm`.
#[cfg(feature = "clip_wasm_from_target")]
static CLIP_WASM_FROM_TARGET: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/wasm32-unknown-unknown/release/zellij_ansi_clip.wasm"
));

fn clip_wasm_override() -> Option<&'static [u8]> {
    #[cfg(feature = "clip_wasm_from_target")]
    {
        Some(CLIP_WASM_FROM_TARGET)
    }
    #[cfg(not(feature = "clip_wasm_from_target"))]
    {
        None
    }
}

/// Resolve an asset by relative path (e.g. `"index.js"` or `"xterm.css"`).
/// Returns the bytes alongside the resolved MIME type. Returns `None` when
/// the path does not match a bundled asset.
pub fn lookup(path: &str) -> Option<AssetResponse> {
    let trimmed = path.trim_start_matches('/');
    if trimmed == "clip.wasm" {
        if let Some(bytes) = clip_wasm_override() {
            return Some(AssetResponse {
                content_type: "application/wasm",
                contents: bytes,
            });
        }
    }
    let file = ASSETS_DIR.get_file(trimmed)?;
    let ext = file.path().extension().and_then(|ext| ext.to_str());
    Some(AssetResponse {
        content_type: mime_type_for_extension(ext),
        contents: file.contents(),
    })
}

/// Resolve the MIME type for a file extension. Matches the small set of
/// content types served by the local web server; everything else falls
/// back to `text/plain`.
pub fn mime_type_for_extension(ext: Option<&str>) -> &'static str {
    match ext {
        None => "text/plain",
        Some(ext) => match ext {
            "html" => "text/html",
            "css" => "text/css",
            "js" => "application/javascript",
            "wasm" => "application/wasm",
            "png" => "image/png",
            "ico" => "image/x-icon",
            "svg" => "image/svg+xml",
            "webmanifest" => "application/manifest+json",
            _ => "text/plain",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_bundle_sha384_is_stable() {
        assert_eq!(app_bundle_sha384(), app_bundle_sha384());
        assert!(app_bundle_sha384().starts_with("sha384-"));
    }

    #[test]
    fn app_bundle_sha384_matches_hand_recompute_over_application_assets() {
        let mut lines: Vec<String> = manifest::APPLICATION_ASSET_NAMES
            .iter()
            .map(|name| {
                let bytes = lookup(name).expect("application asset embedded").contents;
                manifest::manifest_line(name, &manifest::per_asset_integrity_b64(bytes))
            })
            .collect();
        lines.sort();
        assert_eq!(app_bundle_sha384(), manifest::rolled_up_from_lines(&lines));
    }

    #[test]
    fn every_named_asset_is_embedded() {
        for name in manifest::HANDSHAKE_CORE_ASSET_NAMES
            .iter()
            .chain(manifest::APPLICATION_ASSET_NAMES.iter())
        {
            assert!(lookup(name).is_some(), "asset {} not embedded", name);
        }
    }
}
