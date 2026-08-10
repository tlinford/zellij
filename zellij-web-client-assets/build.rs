use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");

    if std::env::var_os("CARGO_FEATURE_CLIP_WASM_FROM_TARGET").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().to_path_buf();
    let target_dir = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => workspace_root.join("target"),
    };
    let clip_wasm = target_dir
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("zellij_ansi_clip.wasm");

    println!("cargo:rerun-if-changed={}", clip_wasm.display());
    println!("cargo:rustc-env=ZELLIJ_CLIP_WASM_PATH={}", clip_wasm.display());
}
