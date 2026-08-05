//! End-to-end crypto helper shared between the Zellij tunnel client, the
//! browser viewer (mirrored in JS/WASM), and the Rust attach client.
//!
//! The viewer and the sharer establish a per-viewer session key with a
//! **SPAKE2** password-authenticated key exchange driven by the shared
//! secret (the PIN / passphrase). The raw secret is never sent anywhere —
//! the relay only forwards the opaque SPAKE2 messages — so the relay cannot
//! derive the key, and it cannot offline-grind even a short secret. A
//! [`confirmation_tag`] over the handshake transcript detects a relay that
//! tampers with (MITM) the exchange before any data flows.
//!
//! # Primitives
//!
//! * SPAKE2 over Ed25519 (symmetric) from the `spake2` crate: [`pake_start`]
//!   → exchange messages through the relay → [`pake_finish`] → raw shared key.
//! * HMAC-SHA256 key confirmation ([`confirmation_tag`] / [`verify_confirmation`])
//!   keyed by the SPAKE2 key over the full message transcript.
//! * HKDF-SHA256 ([`derive_session_key`]) with a fixed salt of `b"zellij-e2e-v1"`
//!   and an `info` of `tunnel_id || client_id`, mapping the confirmed SPAKE2
//!   key to a distinct per-viewer AES-256 key.
//! * AES-256-GCM with a 12-byte random nonce generated via `rand::rngs::OsRng`.
//!   `encrypt` returns `nonce || ciphertext` as a single `Vec<u8>`; `decrypt`
//!   expects the same layout.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Fixed HKDF salt. A version suffix is baked in so a future migration can
/// rotate the salt while keeping the old path decryptable during a
/// transition window.
pub const HKDF_SALT: &[u8] = b"zellij-e2e-v1";

/// AES-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;

/// Length of a key-confirmation tag (HMAC-SHA256 output).
pub const CONFIRM_LEN: usize = 32;

/// Transcript label identifying the sharer's key-confirmation tag.
pub const CONFIRM_LABEL_SHARER: u8 = b'S';
/// Transcript label identifying the viewer's key-confirmation tag.
pub const CONFIRM_LABEL_VIEWER: u8 = b'V';
pub const SAS_LABEL: u8 = b'A';

pub const SAS_DIGITS: u32 = 6;
const SAS_MODULUS: u32 = 1_000_000;

pub const FRAME_TYPE_TERMINAL: u8 = b'T';
pub const FRAME_TYPE_CONTROL: u8 = b'C';

pub const DIRECTION_SHARER_TO_VIEWER: u8 = b'>';
pub const DIRECTION_VIEWER_TO_SHARER: u8 = b'<';

pub const NONCE_PREFIX: [u8; 4] = *b"ze2e";

pub const DEVICE_AUTH_PREFIX: &[u8] = b"zellij-device-auth:v1";
pub const DEVICE_SEED_LEN: usize = 32;
pub const DEVICE_PUBKEY_LEN: usize = 32;
pub const DEVICE_SIGNATURE_LEN: usize = 64;
pub const DEVICE_CHALLENGE_LEN: usize = 32;

const SEQ_AAD_LEN: usize = 1 + 1 + 8;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ciphertext too short (expected >= {expected} bytes, got {actual})")]
    TooShort { expected: usize, actual: usize },
    #[error("aead decryption failed")]
    Decrypt,
    #[error("aead encryption failed")]
    Encrypt,
    #[error("pake handshake failed")]
    Pake,
}

/// Derive a 32-byte AES-256 key from the raw auth token plus the tunnel id.
///
/// `tunnel_id` is included as the HKDF `info` parameter so a single token
/// reused across reconnections produces a fresh key per tunnel — mitigating
/// nonce-reuse risk if a token is ever reused against a different relay
/// allocation.
pub fn derive_key(raw_token: &str, tunnel_id: &str) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), raw_token.as_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(tunnel_id.as_bytes(), &mut okm)
        .expect("HKDF output length is valid");
    okm
}

/// Retained SPAKE2 state between [`pake_start`] and [`pake_finish`].
///
/// The handshake spans a network round-trip: a side calls [`pake_start`],
/// sends the returned message to its peer (the relay forwards it opaquely),
/// holds this state, and later calls [`pake_finish`] with the peer's message.
pub struct PakeState {
    inner: Spake2<Ed25519Group>,
}

/// Bind the SPAKE2 exchange to a slug so a message captured on one share
/// cannot be replayed against another.
fn pake_identity(slug: &str) -> String {
    format!("zellij-relay:{slug}")
}

/// Begin a symmetric SPAKE2 exchange from the shared secret (the raw PIN /
/// passphrase — never sent to the relay). Returns the state to retain and the
/// outbound message to hand to the peer through the relay.
pub fn pake_start(secret: &[u8], slug: &str) -> (PakeState, Vec<u8>) {
    let (inner, msg) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(secret),
        &Identity::new(pake_identity(slug).as_bytes()),
    );
    (PakeState { inner }, msg)
}

/// Consume the peer's SPAKE2 message, returning the raw shared key.
///
/// SPAKE2 does **not** authenticate by itself: a wrong secret yields a
/// *different* key rather than an error. Callers MUST run key confirmation
/// (`confirmation_tag` / `verify_confirmation`) before trusting the key.
pub fn pake_finish(state: PakeState, peer_msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    state.inner.finish(peer_msg).map_err(|_| CryptoError::Pake)
}

fn confirmation_mac(pake_key: &[u8], label: u8, viewer_msg: &[u8], sharer_msg: &[u8]) -> HmacSha256 {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(pake_key).expect("HMAC accepts any key length");
    mac.update(&[label]);
    mac.update(&(viewer_msg.len() as u64).to_be_bytes());
    mac.update(viewer_msg);
    mac.update(&(sharer_msg.len() as u64).to_be_bytes());
    mac.update(sharer_msg);
    mac
}

/// Compute a key-confirmation tag over the full handshake transcript (both
/// SPAKE2 messages), keyed by the SPAKE2 key. `label` is `CONFIRM_LABEL_*`,
/// distinguishing the two directions so a tag cannot be reflected.
pub fn confirmation_tag(
    pake_key: &[u8],
    label: u8,
    viewer_msg: &[u8],
    sharer_msg: &[u8],
) -> [u8; CONFIRM_LEN] {
    let bytes = confirmation_mac(pake_key, label, viewer_msg, sharer_msg).finalize().into_bytes();
    let mut tag = [0u8; CONFIRM_LEN];
    tag.copy_from_slice(&bytes);
    tag
}

/// Constant-time verification of a peer's key-confirmation tag. A mismatch
/// means a wrong secret or a tampering relay (MITM): the handshake must abort.
pub fn verify_confirmation(
    tag: &[u8],
    pake_key: &[u8],
    label: u8,
    viewer_msg: &[u8],
    sharer_msg: &[u8],
) -> bool {
    confirmation_mac(pake_key, label, viewer_msg, sharer_msg)
        .verify_slice(tag)
        .is_ok()
}

pub fn derive_sas(pake_key: &[u8], viewer_msg: &[u8], sharer_msg: &[u8]) -> String {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), pake_key);
    let mut info = Vec::with_capacity(1 + 16 + viewer_msg.len() + sharer_msg.len());
    info.push(SAS_LABEL);
    info.extend_from_slice(&(viewer_msg.len() as u64).to_be_bytes());
    info.extend_from_slice(viewer_msg);
    info.extend_from_slice(&(sharer_msg.len() as u64).to_be_bytes());
    info.extend_from_slice(sharer_msg);
    let mut okm = [0u8; 4];
    hk.expand(&info, &mut okm)
        .expect("HKDF output length is valid");
    let value = u32::from_be_bytes(okm) % SAS_MODULUS;
    format!("{:0width$}", value, width = SAS_DIGITS as usize)
}

/// Derive the per-viewer AES-256 session key from a confirmed SPAKE2 key.
///
/// `client_id` (unique per viewer) is folded into the HKDF `info` alongside
/// `tunnel_id` for domain separation; SPAKE2's per-handshake randomness
/// already makes each viewer's key distinct.
pub fn derive_session_key(pake_key: &[u8], tunnel_id: &str, client_id: u32) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), pake_key);
    let mut info = Vec::with_capacity(tunnel_id.len() + 4);
    info.extend_from_slice(tunnel_id.as_bytes());
    info.extend_from_slice(&client_id.to_be_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("HKDF output length is valid");
    okm
}

#[derive(Clone)]
pub struct ViewerKeys {
    pub terminal_s2v: [u8; KEY_LEN],
    pub terminal_v2s: [u8; KEY_LEN],
    pub control_s2v: [u8; KEY_LEN],
    pub control_v2s: [u8; KEY_LEN],
}

pub fn derive_frame_key(
    pake_key: &[u8],
    tunnel_id: &str,
    client_id: u32,
    frame_type: u8,
    direction: u8,
) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), pake_key);
    let mut info = Vec::with_capacity(tunnel_id.len() + 4 + 2);
    info.extend_from_slice(tunnel_id.as_bytes());
    info.extend_from_slice(&client_id.to_be_bytes());
    info.push(frame_type);
    info.push(direction);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("HKDF output length is valid");
    okm
}

pub fn derive_viewer_keys(pake_key: &[u8], tunnel_id: &str, client_id: u32) -> ViewerKeys {
    ViewerKeys {
        terminal_s2v: derive_frame_key(
            pake_key,
            tunnel_id,
            client_id,
            FRAME_TYPE_TERMINAL,
            DIRECTION_SHARER_TO_VIEWER,
        ),
        terminal_v2s: derive_frame_key(
            pake_key,
            tunnel_id,
            client_id,
            FRAME_TYPE_TERMINAL,
            DIRECTION_VIEWER_TO_SHARER,
        ),
        control_s2v: derive_frame_key(
            pake_key,
            tunnel_id,
            client_id,
            FRAME_TYPE_CONTROL,
            DIRECTION_SHARER_TO_VIEWER,
        ),
        control_v2s: derive_frame_key(
            pake_key,
            tunnel_id,
            client_id,
            FRAME_TYPE_CONTROL,
            DIRECTION_VIEWER_TO_SHARER,
        ),
    }
}

fn seq_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(&NONCE_PREFIX);
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn seq_aad(frame_type: u8, direction: u8, seq: u64) -> [u8; SEQ_AAD_LEN] {
    let mut aad = [0u8; SEQ_AAD_LEN];
    aad[0] = frame_type;
    aad[1] = direction;
    aad[2..].copy_from_slice(&seq.to_be_bytes());
    aad
}

pub fn encrypt_seq(
    key: &[u8; KEY_LEN],
    seq: u64,
    frame_type: u8,
    direction: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = seq_nonce(seq);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = seq_aad(frame_type, direction, seq);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_seq(
    key: &[u8; KEY_LEN],
    frame_type: u8,
    direction: u8,
    nonce_and_ct: &[u8],
) -> Result<(u64, Vec<u8>), CryptoError> {
    if nonce_and_ct.len() < NONCE_LEN {
        return Err(CryptoError::TooShort {
            expected: NONCE_LEN,
            actual: nonce_and_ct.len(),
        });
    }
    let (nonce_bytes, ct) = nonce_and_ct.split_at(NONCE_LEN);
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&nonce_bytes[4..]);
    let seq = u64::from_be_bytes(seq_bytes);
    let aad = seq_aad(frame_type, direction, seq);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| CryptoError::Decrypt)?;
    Ok((seq, pt))
}

#[derive(Default)]
pub struct ReplayWindow {
    last_seen: Option<u64>,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { last_seen: None }
    }

    pub fn accept(&mut self, seq: u64) -> bool {
        match self.last_seen {
            Some(last) if seq <= last => false,
            _ => {
                self.last_seen = Some(seq);
                true
            },
        }
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    OsRng.fill_bytes(&mut out);
    out
}

/// Encrypt `plaintext` with AES-256-GCM, returning `nonce || ciphertext`.
///
/// A fresh 12-byte random nonce is generated per call. `OsRng` is the
/// cryptographically-secure system RNG; a panic here would indicate an OS
/// RNG failure and is treated as unrecoverable.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext` payload produced by [`encrypt`].
///
/// Returns `CryptoError::TooShort` when `nonce_and_ct` is shorter than a
/// single nonce, and `CryptoError::Decrypt` on AEAD auth-tag mismatch
/// (tampering, wrong key, or truncation).
pub fn decrypt(key: &[u8; KEY_LEN], nonce_and_ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce_and_ct.len() < NONCE_LEN {
        return Err(CryptoError::TooShort {
            expected: NONCE_LEN,
            actual: nonce_and_ct.len(),
        });
    }
    let (nonce_bytes, ct) = nonce_and_ct.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|_| CryptoError::Decrypt)
}

fn device_auth_message(challenge: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DEVICE_AUTH_PREFIX.len() + challenge.len());
    msg.extend_from_slice(DEVICE_AUTH_PREFIX);
    msg.extend_from_slice(challenge);
    msg
}

pub fn generate_device_keypair() -> ([u8; DEVICE_SEED_LEN], [u8; DEVICE_PUBKEY_LEN]) {
    let mut seed = [0u8; DEVICE_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    (seed, verifying.to_bytes())
}

pub fn device_public_key(seed: &[u8; DEVICE_SEED_LEN]) -> [u8; DEVICE_PUBKEY_LEN] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn sign_device_challenge(
    seed: &[u8; DEVICE_SEED_LEN],
    challenge: &[u8],
) -> [u8; DEVICE_SIGNATURE_LEN] {
    let signing = SigningKey::from_bytes(seed);
    signing.sign(&device_auth_message(challenge)).to_bytes()
}

pub fn verify_device_challenge(
    pubkey: &[u8; DEVICE_PUBKEY_LEN],
    challenge: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(verifying) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; DEVICE_SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_bytes);
    verifying
        .verify_strict(&device_auth_message(challenge), &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn derive_key_is_deterministic() {
        let k1 = derive_key("some-token", "tunnel-abc");
        let k2 = derive_key("some-token", "tunnel-abc");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_depends_on_token() {
        let k1 = derive_key("token-a", "tunnel-abc");
        let k2 = derive_key("token-b", "tunnel-abc");
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_key_depends_on_tunnel_id() {
        let k1 = derive_key("same-token", "tunnel-1");
        let k2 = derive_key("same-token", "tunnel-2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn roundtrip_preserves_plaintext() {
        let key = derive_key("my-token", "t-123");
        let plaintext = b"hello, end-to-end world";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_preserves_empty_plaintext() {
        let key = derive_key("tok", "t");
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = derive_key("my-token", "t-123");
        let mut encrypted = encrypt(&key, b"confidential").unwrap();
        let tamper_idx = encrypted.len() - 1;
        encrypted[tamper_idx] ^= 0x01;
        let err = decrypt(&key, &encrypted).expect_err("should fail");
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = derive_key("token-a", "t");
        let key_b = derive_key("token-b", "t");
        let encrypted = encrypt(&key_a, b"secret").unwrap();
        let err = decrypt(&key_b, &encrypted).expect_err("should fail");
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = derive_key("tok", "t");
        let encrypted = encrypt(&key, b"secret").unwrap();
        let err = decrypt(&key, &encrypted[..5]).expect_err("should fail");
        assert!(matches!(err, CryptoError::TooShort { .. }));
    }

    #[test]
    fn nonces_are_unique_across_many_encrypts() {
        // Sample a moderate number of encrypts; we care about catching a
        // constant-nonce bug, not about exhaustively validating OsRng.
        let key = derive_key("tok", "t");
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let encrypted = encrypt(&key, b"x").unwrap();
            let nonce = encrypted[..NONCE_LEN].to_vec();
            assert!(seen.insert(nonce), "duplicate nonce");
        }
    }

    #[test]
    fn pake_handshake_succeeds_with_matching_secret() {
        let slug = "abc123";
        let (v_state, v_msg) = pake_start(b"483921", slug);
        let (s_state, s_msg) = pake_start(b"483921", slug);
        let v_key = pake_finish(v_state, &s_msg).unwrap();
        let s_key = pake_finish(s_state, &v_msg).unwrap();

        let s_tag = confirmation_tag(&s_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg);
        assert!(verify_confirmation(&s_tag, &v_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg));
        let v_tag = confirmation_tag(&v_key, CONFIRM_LABEL_VIEWER, &v_msg, &s_msg);
        assert!(verify_confirmation(&v_tag, &s_key, CONFIRM_LABEL_VIEWER, &v_msg, &s_msg));

        let sk_v = derive_session_key(&v_key, "tunnel-1", 7);
        let sk_s = derive_session_key(&s_key, "tunnel-1", 7);
        assert_eq!(sk_v, sk_s);
        let ct = encrypt(&sk_s, b"end to end").unwrap();
        assert_eq!(decrypt(&sk_v, &ct).unwrap(), b"end to end");
    }

    #[test]
    fn pake_confirmation_fails_on_wrong_secret() {
        let slug = "abc123";
        let (v_state, v_msg) = pake_start(b"111111", slug);
        let (s_state, s_msg) = pake_start(b"999999", slug);
        let v_key = pake_finish(v_state, &s_msg).unwrap();
        let s_key = pake_finish(s_state, &v_msg).unwrap();
        let s_tag = confirmation_tag(&s_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg);
        assert!(!verify_confirmation(&s_tag, &v_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg));
    }

    #[test]
    fn pake_key_depends_on_slug_identity() {
        let (v_state, v_msg) = pake_start(b"483921", "slug-a");
        let (s_state, s_msg) = pake_start(b"483921", "slug-b");
        let v_key = pake_finish(v_state, &s_msg).unwrap();
        let s_key = pake_finish(s_state, &v_msg).unwrap();
        let s_tag = confirmation_tag(&s_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg);
        assert!(!verify_confirmation(&s_tag, &v_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg));
    }

    #[test]
    fn pake_confirmation_fails_on_tampered_message() {
        // A relay that substitutes/garbles the sharer's message must not be
        // able to make confirmation pass: either finish errors, or the
        // viewer's key diverges and the sharer's tag fails to verify.
        let slug = "xyz";
        let (v_state, v_msg) = pake_start(b"483921", slug);
        let (s_state, s_msg) = pake_start(b"483921", slug);
        let s_key = pake_finish(s_state, &v_msg).unwrap();
        let mut tampered = s_msg.clone();
        let idx = tampered.len() / 2;
        tampered[idx] ^= 0x01;
        match pake_finish(v_state, &tampered) {
            Err(_) => {},
            Ok(v_key) => {
                let s_tag = confirmation_tag(&s_key, CONFIRM_LABEL_SHARER, &v_msg, &s_msg);
                assert!(!verify_confirmation(
                    &s_tag,
                    &v_key,
                    CONFIRM_LABEL_SHARER,
                    &v_msg,
                    &tampered
                ));
            },
        }
    }

    #[test]
    fn derive_sas_is_six_digits_and_deterministic() {
        let s1 = derive_sas(b"shared-pake-key", b"viewer-msg", b"sharer-msg");
        let s2 = derive_sas(b"shared-pake-key", b"viewer-msg", b"sharer-msg");
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), SAS_DIGITS as usize);
        assert!(s1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn derive_sas_diverges_on_transcript_and_key() {
        let base = derive_sas(b"pk", b"v", b"s");
        assert_ne!(base, derive_sas(b"pk2", b"v", b"s"));
        assert_ne!(base, derive_sas(b"pk", b"v2", b"s"));
        assert_ne!(base, derive_sas(b"pk", b"v", b"s2"));
    }

    #[test]
    fn derive_sas_matches_between_confirmed_peers() {
        let slug = "abc123";
        let (v_state, v_msg) = pake_start(b"483921", slug);
        let (s_state, s_msg) = pake_start(b"483921", slug);
        let v_key = pake_finish(v_state, &s_msg).unwrap();
        let s_key = pake_finish(s_state, &v_msg).unwrap();
        let viewer_sas = derive_sas(&v_key, &v_msg, &s_msg);
        let sharer_sas = derive_sas(&s_key, &v_msg, &s_msg);
        assert_eq!(viewer_sas, sharer_sas);
    }

    #[test]
    fn derive_frame_key_separates_plane_and_direction() {
        let pake = b"shared-pake-key";
        let ts = derive_frame_key(pake, "t", 1, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER);
        let tv = derive_frame_key(pake, "t", 1, FRAME_TYPE_TERMINAL, DIRECTION_VIEWER_TO_SHARER);
        let cs = derive_frame_key(pake, "t", 1, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER);
        let cv = derive_frame_key(pake, "t", 1, FRAME_TYPE_CONTROL, DIRECTION_VIEWER_TO_SHARER);
        let all = [ts, tv, cs, cv];
        let unique: HashSet<_> = all.iter().collect();
        assert_eq!(unique.len(), 4, "all four labelled keys must differ");
    }

    #[test]
    fn derive_viewer_keys_matches_individual_derivations() {
        let pake = b"shared-pake-key";
        let keys = derive_viewer_keys(pake, "tunnel-9", 42);
        assert_eq!(
            keys.terminal_s2v,
            derive_frame_key(pake, "tunnel-9", 42, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER)
        );
        assert_eq!(
            keys.control_v2s,
            derive_frame_key(pake, "tunnel-9", 42, FRAME_TYPE_CONTROL, DIRECTION_VIEWER_TO_SHARER)
        );
        let four = [keys.terminal_s2v, keys.terminal_v2s, keys.control_s2v, keys.control_v2s];
        assert_eq!(four.iter().collect::<HashSet<_>>().len(), 4);
    }

    #[test]
    fn derive_viewer_keys_depends_on_client_id() {
        let pake = b"shared-pake-key";
        let a = derive_viewer_keys(pake, "t", 1);
        let b = derive_viewer_keys(pake, "t", 2);
        assert_ne!(a.terminal_s2v, b.terminal_s2v);
    }

    #[test]
    fn encrypt_seq_roundtrips_and_recovers_seq() {
        let key = derive_frame_key(b"pk", "t", 1, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER);
        let pt = b"control plane payload";
        let ct =
            encrypt_seq(&key, 7, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER, pt).unwrap();
        let (seq, decrypted) =
            decrypt_seq(&key, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER, &ct).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn encrypt_seq_nonce_is_deterministic_and_unique_per_seq() {
        let key = derive_frame_key(b"pk", "t", 1, FRAME_TYPE_TERMINAL, DIRECTION_VIEWER_TO_SHARER);
        let c0 = encrypt_seq(&key, 0, FRAME_TYPE_TERMINAL, DIRECTION_VIEWER_TO_SHARER, b"x").unwrap();
        let c0b = encrypt_seq(&key, 0, FRAME_TYPE_TERMINAL, DIRECTION_VIEWER_TO_SHARER, b"x").unwrap();
        let c1 = encrypt_seq(&key, 1, FRAME_TYPE_TERMINAL, DIRECTION_VIEWER_TO_SHARER, b"x").unwrap();
        assert_eq!(c0, c0b);
        assert_ne!(c0[..NONCE_LEN], c1[..NONCE_LEN]);
        assert_eq!(&c0[..4], &NONCE_PREFIX);
    }

    #[test]
    fn decrypt_seq_rejects_frame_type_mismatch() {
        let key = derive_frame_key(b"pk", "t", 1, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER);
        let ct = encrypt_seq(&key, 3, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER, b"hi").unwrap();
        let err = decrypt_seq(&key, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER, &ct)
            .expect_err("AAD mismatch must fail");
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn decrypt_seq_rejects_direction_mismatch() {
        let key = derive_frame_key(b"pk", "t", 1, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER);
        let ct = encrypt_seq(&key, 3, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER, b"hi").unwrap();
        let err = decrypt_seq(&key, FRAME_TYPE_CONTROL, DIRECTION_VIEWER_TO_SHARER, &ct)
            .expect_err("direction mismatch must fail");
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn decrypt_seq_rejects_tampered_seq_in_nonce() {
        let key = derive_frame_key(b"pk", "t", 1, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER);
        let mut ct = encrypt_seq(&key, 5, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER, b"hi").unwrap();
        ct[NONCE_LEN - 1] ^= 0x01;
        let err = decrypt_seq(&key, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER, &ct)
            .expect_err("tampered seq must fail");
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn replay_window_rejects_replay_and_reorder() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(1));
        assert!(!w.accept(1), "replay of last seq rejected");
        assert!(!w.accept(0), "reorder below high-water rejected");
        assert!(w.accept(2));
        assert!(w.accept(10), "gaps allowed (drops do not block progress)");
        assert!(!w.accept(5), "below high-water after a gap rejected");
    }

    #[test]
    fn sharer_viewer_control_roundtrips_both_directions() {
        let pake = b"confirmed-spake2-key";
        let sharer = derive_viewer_keys(pake, "tid", 4);
        let viewer = derive_viewer_keys(pake, "tid", 4);

        let mut viewer_in = ReplayWindow::new();
        for (seq, msg) in [(0u64, &b"setconfig"[..]), (1, b"resize-request")] {
            let wire = encrypt_seq(
                &sharer.control_s2v,
                seq,
                FRAME_TYPE_CONTROL,
                DIRECTION_SHARER_TO_VIEWER,
                msg,
            )
            .unwrap();
            let (got_seq, pt) = decrypt_seq(
                &viewer.control_s2v,
                FRAME_TYPE_CONTROL,
                DIRECTION_SHARER_TO_VIEWER,
                &wire,
            )
            .unwrap();
            assert_eq!(got_seq, seq);
            assert!(viewer_in.accept(got_seq));
            assert_eq!(pt, msg);
        }

        let mut sharer_in = ReplayWindow::new();
        let wire = encrypt_seq(
            &viewer.control_v2s,
            0,
            FRAME_TYPE_CONTROL,
            DIRECTION_VIEWER_TO_SHARER,
            b"viewer-resize",
        )
        .unwrap();
        let (seq, pt) = decrypt_seq(
            &sharer.control_v2s,
            FRAME_TYPE_CONTROL,
            DIRECTION_VIEWER_TO_SHARER,
            &wire,
        )
        .unwrap();
        assert!(sharer_in.accept(seq));
        assert_eq!(pt, b"viewer-resize");
    }

    #[test]
    fn relay_replay_and_reorder_are_rejected() {
        let pake = b"confirmed-spake2-key";
        let sharer = derive_viewer_keys(pake, "tid", 9);
        let viewer = derive_viewer_keys(pake, "tid", 9);

        let frame = |seq: u64| {
            encrypt_seq(
                &sharer.terminal_s2v,
                seq,
                FRAME_TYPE_TERMINAL,
                DIRECTION_SHARER_TO_VIEWER,
                b"frame",
            )
            .unwrap()
        };
        let recv = |wire: &[u8]| {
            decrypt_seq(
                &viewer.terminal_s2v,
                FRAME_TYPE_TERMINAL,
                DIRECTION_SHARER_TO_VIEWER,
                wire,
            )
            .unwrap()
        };

        let mut window = ReplayWindow::new();
        let f0 = frame(0);
        let f1 = frame(1);
        let (s0, _) = recv(&f0);
        assert!(window.accept(s0));
        let (s1, _) = recv(&f1);
        assert!(window.accept(s1));
        let (dup, _) = recv(&f1);
        assert!(!window.accept(dup), "relay duplicate rejected");
        let (reordered, _) = recv(&f0);
        assert!(!window.accept(reordered), "relay reorder rejected");
    }

    #[test]
    fn device_signature_roundtrips() {
        let (seed, pubkey) = generate_device_keypair();
        let challenge = random_bytes(DEVICE_CHALLENGE_LEN);
        let sig = sign_device_challenge(&seed, &challenge);
        assert!(verify_device_challenge(&pubkey, &challenge, &sig));
    }

    #[test]
    fn device_public_key_is_stable_for_seed() {
        let (seed, pubkey) = generate_device_keypair();
        assert_eq!(device_public_key(&seed), pubkey);
    }

    #[test]
    fn device_signature_fails_on_fresh_challenge() {
        let (seed, pubkey) = generate_device_keypair();
        let first = random_bytes(DEVICE_CHALLENGE_LEN);
        let second = random_bytes(DEVICE_CHALLENGE_LEN);
        let sig = sign_device_challenge(&seed, &first);
        assert!(!verify_device_challenge(&pubkey, &second, &sig));
    }

    #[test]
    fn device_signature_fails_under_wrong_pubkey() {
        let (seed, _) = generate_device_keypair();
        let (_, other_pubkey) = generate_device_keypair();
        let challenge = random_bytes(DEVICE_CHALLENGE_LEN);
        let sig = sign_device_challenge(&seed, &challenge);
        assert!(!verify_device_challenge(&other_pubkey, &challenge, &sig));
    }

    #[test]
    fn device_signature_is_domain_separated() {
        let (seed, pubkey) = generate_device_keypair();
        let challenge = random_bytes(DEVICE_CHALLENGE_LEN);
        let signing = SigningKey::from_bytes(&seed);
        let raw = signing.sign(&challenge).to_bytes();
        assert!(!verify_device_challenge(&pubkey, &challenge, &raw));
    }

    #[test]
    fn device_verify_rejects_malformed_signature() {
        let (_, pubkey) = generate_device_keypair();
        let challenge = random_bytes(DEVICE_CHALLENGE_LEN);
        assert!(!verify_device_challenge(&pubkey, &challenge, b"too-short"));
    }

    #[test]
    fn relay_tampered_control_frame_fails_aead() {
        let pake = b"confirmed-spake2-key";
        let sharer = derive_viewer_keys(pake, "tid", 1);
        let viewer = derive_viewer_keys(pake, "tid", 1);
        let mut wire = encrypt_seq(
            &sharer.control_s2v,
            0,
            FRAME_TYPE_CONTROL,
            DIRECTION_SHARER_TO_VIEWER,
            b"secret-control",
        )
        .unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let err = decrypt_seq(
            &viewer.control_s2v,
            FRAME_TYPE_CONTROL,
            DIRECTION_SHARER_TO_VIEWER,
            &wire,
        )
        .expect_err("tampered ciphertext must fail");
        assert!(matches!(err, CryptoError::Decrypt));
    }
}
