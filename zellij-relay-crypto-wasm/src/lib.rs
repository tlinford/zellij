//! C-ABI `wasm32-unknown-unknown` shim exposing the relay E2E crypto
//! (SPAKE2 handshake + key confirmation + per-viewer key derivation) to the
//! browser viewer. Built as a raw wasm module — no wasm-bindgen — mirroring
//! `zellij-ansi-clip`'s `clip.wasm`. AES-256-GCM stays in the browser's
//! WebCrypto, keyed by the 32-byte key this module derives, so the wire
//! crypto is byte-for-byte identical to the Rust sharer (same `spake2`
//! crate, same `crypto.rs`).
//!
//! Randomness: SPAKE2's blinding scalar (and AES nonces, were they used
//! here) come from `OsRng` → `getrandom`. On `wasm32-unknown-unknown` there
//! is no default `getrandom` backend, so we register a custom one that calls
//! the JS-supplied `js_fill_random` import (backed by `crypto.getRandomValues`).

use core::cell::RefCell;
use std::mem;

use zellij_relay_protocol::crypto::{
    self, PakeState, CONFIRM_LEN, DEVICE_PUBKEY_LEN, DEVICE_SEED_LEN, DEVICE_SIGNATURE_LEN, KEY_LEN,
};

// The JS-imported RNG + custom `getrandom` backend only make sense on the
// `wasm32-unknown-unknown` target (the only place there is no OS backend and
// the `js_fill_random` import is resolved by the browser loader). On the host
// — where this crate is still compiled as part of a `--workspace` build — the
// real `getrandom` backend is used and the import is omitted, so the cdylib
// links cleanly without an undefined symbol.
#[cfg(target_arch = "wasm32")]
extern "C" {
    /// Imported from JS: fill `len` bytes at `ptr` with CSPRNG output.
    fn js_fill_random(ptr: *mut u8, len: usize);
}

#[cfg(target_arch = "wasm32")]
fn custom_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    if !dest.is_empty() {
        unsafe { js_fill_random(dest.as_mut_ptr(), dest.len()) };
    }
    Ok(())
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(custom_getrandom);

thread_local! {
    /// SPAKE2 state held between `pake_start` and `pake_finish`.
    static PAKE_STATE: RefCell<Option<PakeState>> = const { RefCell::new(None) };
    /// Confirmed SPAKE2 key, set by `pake_finish`, consumed by the
    /// confirmation + key-derivation calls.
    static PAKE_KEY: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Allocate `len` bytes inside the wasm linear memory; the JS side owns the
/// pointer until it calls [`crypto_free`].
#[no_mangle]
pub extern "C" fn crypto_alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    ptr
}

/// Free a buffer previously returned by [`crypto_alloc`] or a wasm function.
#[no_mangle]
pub unsafe extern "C" fn crypto_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let _ = Vec::from_raw_parts(ptr, 0, len);
    }
}

/// Begin the SPAKE2 exchange. Returns a heap pointer to the viewer's
/// outbound message and writes its length to `out_len`; the state is held
/// for the matching [`pake_finish`].
#[no_mangle]
pub unsafe extern "C" fn pake_start(
    secret: *const u8,
    secret_len: usize,
    slug: *const u8,
    slug_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let secret = core::slice::from_raw_parts(secret, secret_len);
    let slug_bytes = core::slice::from_raw_parts(slug, slug_len);
    let slug = core::str::from_utf8(slug_bytes).unwrap_or("");
    let (state, msg) = crypto::pake_start(secret, slug);
    PAKE_STATE.with(|s| *s.borrow_mut() = Some(state));
    let len = msg.len();
    let mut boxed = msg.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    mem::forget(boxed);
    *out_len = len;
    ptr
}

/// Consume the peer's SPAKE2 message and stash the resulting key. Returns
/// `0` on success, `-1` if no handshake is in progress or the message is
/// malformed.
#[no_mangle]
pub unsafe extern "C" fn pake_finish(peer: *const u8, peer_len: usize) -> i32 {
    let peer = core::slice::from_raw_parts(peer, peer_len);
    let state = PAKE_STATE.with(|s| s.borrow_mut().take());
    let Some(state) = state else {
        return -1;
    };
    match crypto::pake_finish(state, peer) {
        Ok(key) => {
            PAKE_KEY.with(|k| *k.borrow_mut() = Some(key));
            0
        },
        Err(_) => -1,
    }
}

/// Write a `CONFIRM_LEN`-byte key-confirmation tag for `label` over the
/// transcript into `out`. Returns `0` on success, `-1` if no key is set.
#[no_mangle]
pub unsafe extern "C" fn confirmation_tag(
    label: u8,
    viewer_msg: *const u8,
    viewer_len: usize,
    sharer_msg: *const u8,
    sharer_len: usize,
    out: *mut u8,
) -> i32 {
    let viewer_msg = core::slice::from_raw_parts(viewer_msg, viewer_len);
    let sharer_msg = core::slice::from_raw_parts(sharer_msg, sharer_len);
    let key = PAKE_KEY.with(|k| k.borrow().clone());
    let Some(key) = key else {
        return -1;
    };
    let tag = crypto::confirmation_tag(&key, label, viewer_msg, sharer_msg);
    core::ptr::copy_nonoverlapping(tag.as_ptr(), out, CONFIRM_LEN);
    0
}

/// Verify a peer's confirmation tag. Returns `1` if valid, `0` if invalid,
/// `-1` if no key is set.
#[no_mangle]
pub unsafe extern "C" fn verify_confirmation(
    label: u8,
    tag: *const u8,
    viewer_msg: *const u8,
    viewer_len: usize,
    sharer_msg: *const u8,
    sharer_len: usize,
) -> i32 {
    let tag = core::slice::from_raw_parts(tag, CONFIRM_LEN);
    let viewer_msg = core::slice::from_raw_parts(viewer_msg, viewer_len);
    let sharer_msg = core::slice::from_raw_parts(sharer_msg, sharer_len);
    let key = PAKE_KEY.with(|k| k.borrow().clone());
    let Some(key) = key else {
        return -1;
    };
    if crypto::verify_confirmation(tag, &key, label, viewer_msg, sharer_msg) {
        1
    } else {
        0
    }
}

/// Derive the per-viewer AES-256 session key from the confirmed SPAKE2 key
/// and write the `KEY_LEN` bytes into `out`. Returns `0` on success, `-1` if
/// no key is set.
#[no_mangle]
pub unsafe extern "C" fn derive_session_key(
    tunnel_id: *const u8,
    tunnel_len: usize,
    client_id: u32,
    out: *mut u8,
) -> i32 {
    let tunnel_bytes = core::slice::from_raw_parts(tunnel_id, tunnel_len);
    let tunnel = core::str::from_utf8(tunnel_bytes).unwrap_or("");
    let key = PAKE_KEY.with(|k| k.borrow().clone());
    let Some(key) = key else {
        return -1;
    };
    let sk = crypto::derive_session_key(&key, tunnel, client_id);
    core::ptr::copy_nonoverlapping(sk.as_ptr(), out, KEY_LEN);
    0
}

#[no_mangle]
pub unsafe extern "C" fn derive_sas(
    viewer_msg: *const u8,
    viewer_len: usize,
    sharer_msg: *const u8,
    sharer_len: usize,
    out: *mut u8,
) -> i32 {
    let viewer_msg = core::slice::from_raw_parts(viewer_msg, viewer_len);
    let sharer_msg = core::slice::from_raw_parts(sharer_msg, sharer_len);
    let key = PAKE_KEY.with(|k| k.borrow().clone());
    let Some(key) = key else {
        return -1;
    };
    let sas = crypto::derive_sas(&key, viewer_msg, sharer_msg);
    let bytes = sas.as_bytes();
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    0
}

#[no_mangle]
pub unsafe extern "C" fn derive_frame_key(
    tunnel_id: *const u8,
    tunnel_len: usize,
    client_id: u32,
    frame_type: u8,
    direction: u8,
    out: *mut u8,
) -> i32 {
    let tunnel_bytes = core::slice::from_raw_parts(tunnel_id, tunnel_len);
    let tunnel = core::str::from_utf8(tunnel_bytes).unwrap_or("");
    let key = PAKE_KEY.with(|k| k.borrow().clone());
    let Some(key) = key else {
        return -1;
    };
    let fk = crypto::derive_frame_key(&key, tunnel, client_id, frame_type, direction);
    core::ptr::copy_nonoverlapping(fk.as_ptr(), out, KEY_LEN);
    0
}

#[no_mangle]
pub unsafe extern "C" fn sign_device_challenge(
    seed: *const u8,
    challenge: *const u8,
    challenge_len: usize,
    out: *mut u8,
) -> i32 {
    let seed_slice = core::slice::from_raw_parts(seed, DEVICE_SEED_LEN);
    let Ok(seed_arr) = <[u8; DEVICE_SEED_LEN]>::try_from(seed_slice) else {
        return -1;
    };
    let challenge = core::slice::from_raw_parts(challenge, challenge_len);
    let sig = crypto::sign_device_challenge(&seed_arr, challenge);
    core::ptr::copy_nonoverlapping(sig.as_ptr(), out, DEVICE_SIGNATURE_LEN);
    0
}

#[no_mangle]
pub unsafe extern "C" fn verify_device_challenge(
    pubkey: *const u8,
    challenge: *const u8,
    challenge_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    let pubkey_slice = core::slice::from_raw_parts(pubkey, DEVICE_PUBKEY_LEN);
    let Ok(pubkey_arr) = <[u8; DEVICE_PUBKEY_LEN]>::try_from(pubkey_slice) else {
        return -1;
    };
    let challenge = core::slice::from_raw_parts(challenge, challenge_len);
    let signature = core::slice::from_raw_parts(signature, signature_len);
    if crypto::verify_device_challenge(&pubkey_arr, challenge, signature) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_value(key: &str) -> String {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../zellij-relay-protocol/tests/fixtures/e2e_test_vectors.json"
        ));
        let needle = format!("\"{}\"", key);
        let start = raw.find(&needle).expect("fixture key present");
        let after = &raw[start + needle.len()..];
        let colon = after.find(':').expect("colon after key");
        let rest = &after[colon + 1..];
        let open = rest.find('"').expect("open quote");
        let tail = &rest[open + 1..];
        let close = tail.find('"').expect("close quote");
        tail[..close].to_string()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn wasm_device_exports_match_fixture() {
        let seed = unhex(&fixture_value("device_seed_hex"));
        let challenge = unhex(&fixture_value("device_challenge_hex"));
        let pubkey = unhex(&fixture_value("device_pubkey_hex"));
        let expected_sig = fixture_value("device_signature_hex");

        let mut sig = [0u8; DEVICE_SIGNATURE_LEN];
        let rc = unsafe {
            sign_device_challenge(
                seed.as_ptr(),
                challenge.as_ptr(),
                challenge.len(),
                sig.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(hex(&sig), expected_sig);

        let ok = unsafe {
            verify_device_challenge(
                pubkey.as_ptr(),
                challenge.as_ptr(),
                challenge.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        assert_eq!(ok, 1);
    }
}
