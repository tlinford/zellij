/**
 * End-to-end crypto helpers mirroring `zellij-relay-protocol/src/crypto.rs`.
 *
 * Both sides must produce identical AES-256-GCM keys: the Zellij server
 * derives `HKDF(auth_token_hash, salt="zellij-e2e-v1", info=tunnel_id)`;
 * the browser does the same, taking the SHA-256 of the raw auth token the
 * user typed so it never transmits the raw token to the server after
 * login.
 *
 * Nonces are 12 bytes random per encrypt; payload wire format is
 * `nonce || ciphertext`.
 */

import { getBaseUrl, isRelayMode } from "./utils.js";
import { WASM_INTEGRITY } from "./integrity.js";

const HKDF_SALT = new TextEncoder().encode("zellij-e2e-v1");
const NONCE_LEN = 12;
const KEY_LEN = 32;
const NONCE_PREFIX = new Uint8Array([0x7a, 0x65, 0x32, 0x65]);
const SEQ_AAD_LEN = 10;

export const FRAME_TYPE_TERMINAL = 84;
export const FRAME_TYPE_CONTROL = 67;
export const DIRECTION_SHARER_TO_VIEWER = 62;
export const DIRECTION_VIEWER_TO_SHARER = 60;

/** Convert a hex string to a Uint8Array. */
function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

/** Convert a Uint8Array to a lowercase hex string. */
function bytesToHex(bytes) {
    let out = "";
    for (const b of bytes) {
        out += b.toString(16).padStart(2, "0");
    }
    return out;
}

/** SHA-256 of a UTF-8 string, returned as lowercase hex. */
export async function sha256Hex(utf8) {
    const buf = new TextEncoder().encode(utf8);
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return bytesToHex(new Uint8Array(digest));
}

/**
 * Derive a 32-byte AES-256 key via HKDF-SHA256.
 *
 * `keyMaterial` is the hex string Zellij stores for the token
 * (SHA-256(raw_token) lowercased). `tunnelId` is the value the server
 * returned on /session — used as the HKDF `info` parameter so reused
 * tokens across reconnections produce a fresh key per tunnel.
 */
export async function deriveKey(keyMaterialHex, tunnelId) {
    // HKDF input is the token-hash bytes (match Zellij's
    // `derive_key(token_hash.as_bytes(), tunnel_id)`).
    const ikm = new TextEncoder().encode(keyMaterialHex);
    const ikmKey = await crypto.subtle.importKey(
        "raw",
        ikm,
        { name: "HKDF" },
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: HKDF_SALT,
            info: new TextEncoder().encode(tunnelId),
        },
        ikmKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

/**
 * Encrypt a Uint8Array or ArrayBuffer with the derived key. Output
 * layout: `nonce(12) || ciphertext`.
 */
export async function encrypt(key, plaintext) {
    const pt = plaintext instanceof Uint8Array
        ? plaintext
        : new Uint8Array(plaintext);
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ctBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        key,
        pt
    );
    const ct = new Uint8Array(ctBuf);
    const out = new Uint8Array(NONCE_LEN + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_LEN);
    return out;
}

/**
 * Decrypt a `nonce || ciphertext` payload. Throws on AEAD tag mismatch.
 */
export async function decrypt(key, nonceAndCt) {
    const buf = nonceAndCt instanceof Uint8Array
        ? nonceAndCt
        : new Uint8Array(nonceAndCt);
    if (buf.length < NONCE_LEN) {
        throw new Error("ciphertext too short");
    }
    const nonce = buf.subarray(0, NONCE_LEN);
    const ct = buf.subarray(NONCE_LEN);
    const ptBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce },
        key,
        ct
    );
    return new Uint8Array(ptBuf);
}

// The seq-AEAD framing below (nonce prefix, AAD layout, frame/direction tags)
// is the frozen handshake-core contract. It is pinned byte-for-byte by
// zellij-relay-protocol/tests/cross_language_vectors.rs; the core/application
// split only relocates which file calls encryptSeq/decryptSeq, not the bytes.
// Do not change it without regenerating that fixture and bumping the protocol.
function seqAad(frameType, direction, seq) {
    const aad = new Uint8Array(SEQ_AAD_LEN);
    aad[0] = frameType;
    aad[1] = direction;
    new DataView(aad.buffer).setBigUint64(2, BigInt(seq), false);
    return aad;
}

export async function encryptSeq(key, seq, frameType, direction, plaintext) {
    const pt = plaintext instanceof Uint8Array
        ? plaintext
        : new Uint8Array(plaintext);
    const nonce = new Uint8Array(NONCE_LEN);
    nonce.set(NONCE_PREFIX, 0);
    new DataView(nonce.buffer).setBigUint64(4, BigInt(seq), false);
    const aad = seqAad(frameType, direction, seq);
    const ctBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        key,
        pt
    );
    const ct = new Uint8Array(ctBuf);
    const out = new Uint8Array(NONCE_LEN + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_LEN);
    return out;
}

export async function decryptSeq(key, frameType, direction, nonceAndCt) {
    const buf = nonceAndCt instanceof Uint8Array
        ? nonceAndCt
        : new Uint8Array(nonceAndCt);
    if (buf.length < NONCE_LEN) {
        throw new Error("ciphertext too short");
    }
    const nonce = buf.subarray(0, NONCE_LEN);
    const ct = buf.subarray(NONCE_LEN);
    const seq = Number(
        new DataView(nonce.buffer, nonce.byteOffset, NONCE_LEN).getBigUint64(4, false)
    );
    const aad = seqAad(frameType, direction, seq);
    const ptBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        key,
        ct
    );
    return { seq, plaintext: new Uint8Array(ptBuf) };
}

export { NONCE_LEN, KEY_LEN };

/**
 * Relay E2E (SPAKE2) helpers, backed by the `relay_crypto.wasm` module.
 *
 * Only the relay viewer path uses these; the local web server keeps the
 * token-hash `deriveKey` path above. The wasm module is the same Rust
 * `spake2`/`crypto.rs` the sharer runs, so the handshake is byte-for-byte
 * compatible. AES-256-GCM stays here in WebCrypto, keyed by the 32-byte
 * session key the module derives.
 */

// Transcript labels — must match `crypto::CONFIRM_LABEL_*` (ASCII 'S'/'V').
export const CONFIRM_LABEL_SHARER = 83;
export const CONFIRM_LABEL_VIEWER = 86;

export const SAS_DIGITS = 6;

let pakeWasm = null;
let pakeWasmMemory = null;

function base64FromBytes(bytes) {
    let s = "";
    for (const b of bytes) {
        s += String.fromCharCode(b);
    }
    return btoa(s);
}

/**
 * Verify fetched wasm bytes against the digest baked into the staged
 * `integrity.js` before instantiation. The relay never serves this code —
 * it comes from the app origin — and SRI cannot ride a `fetch()`, so the
 * check is done here. An empty manifest is tolerated only outside relay
 * mode (dev / local web server); on the relay path it refuses to run.
 */
export async function verifyWasmDigest(expected, name, bytes) {
    if (!expected) {
        if (isRelayMode()) {
            throw new Error(`integrity check unavailable for ${name}; refusing to run`);
        }
        return;
    }
    const digest = await crypto.subtle.digest("SHA-384", bytes);
    const actual = "sha384-" + base64FromBytes(new Uint8Array(digest));
    if (actual !== expected) {
        throw new Error(`integrity check failed for ${name}; refusing to run`);
    }
}

export async function verifyWasmIntegrity(name, bytes) {
    return verifyWasmDigest(WASM_INTEGRITY[name], name, bytes);
}

export async function sha384Base64(bytes) {
    const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await crypto.subtle.digest("SHA-384", buf);
    return base64FromBytes(new Uint8Array(digest));
}

async function loadPakeWasm() {
    if (pakeWasm) return pakeWasm;
    const root = getBaseUrl().replace(/\/$/, "");
    const resp = await fetch(`${root}/assets/relay_crypto.wasm`);
    if (!resp.ok) {
        throw new Error(`relay_crypto.wasm fetch failed: ${resp.status}`);
    }
    const buf = await resp.arrayBuffer();
    await verifyWasmIntegrity("relay_crypto.wasm", buf);
    const imports = {
        env: {
            // SPAKE2's blinding scalar needs CSPRNG bytes; the wasm module
            // has no OS to read from, so it imports this.
            js_fill_random: (ptr, len) => {
                const view = new Uint8Array(pakeWasmMemory.buffer, ptr, len);
                crypto.getRandomValues(view);
            },
        },
    };
    const mod = await WebAssembly.instantiate(buf, imports);
    pakeWasm = mod.instance.exports;
    pakeWasmMemory = pakeWasm.memory;
    return pakeWasm;
}

function pakeWrite(w, bytes) {
    const ptr = w.crypto_alloc(bytes.length);
    new Uint8Array(w.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
}

/** Begin the SPAKE2 exchange; returns the viewer's outbound message bytes. */
export async function pakeStart(secretStr, slug) {
    const w = await loadPakeWasm();
    const secret = new TextEncoder().encode(secretStr);
    const slugBytes = new TextEncoder().encode(slug);
    const secretPtr = pakeWrite(w, secret);
    const slugPtr = pakeWrite(w, slugBytes);
    const outLenPtr = w.crypto_alloc(4);
    const msgPtr = w.pake_start(secretPtr, secret.length, slugPtr, slugBytes.length, outLenPtr);
    const msgLen = new Uint32Array(w.memory.buffer, outLenPtr, 1)[0];
    const msg = new Uint8Array(w.memory.buffer, msgPtr, msgLen).slice();
    w.crypto_free(secretPtr, secret.length);
    w.crypto_free(slugPtr, slugBytes.length);
    w.crypto_free(outLenPtr, 4);
    w.crypto_free(msgPtr, msgLen);
    return msg;
}

/** Consume the peer's SPAKE2 message; returns true on success. */
export async function pakeFinish(peerMsg) {
    const w = await loadPakeWasm();
    const ptr = pakeWrite(w, peerMsg);
    const rc = w.pake_finish(ptr, peerMsg.length);
    w.crypto_free(ptr, peerMsg.length);
    return rc === 0;
}

/** Compute a key-confirmation tag; returns Uint8Array(32) or null. */
export async function confirmationTag(label, viewerMsg, sharerMsg) {
    const w = await loadPakeWasm();
    const vptr = pakeWrite(w, viewerMsg);
    const sptr = pakeWrite(w, sharerMsg);
    const outPtr = w.crypto_alloc(KEY_LEN);
    const rc = w.confirmation_tag(label, vptr, viewerMsg.length, sptr, sharerMsg.length, outPtr);
    const tag = rc === 0 ? new Uint8Array(w.memory.buffer, outPtr, KEY_LEN).slice() : null;
    w.crypto_free(vptr, viewerMsg.length);
    w.crypto_free(sptr, sharerMsg.length);
    w.crypto_free(outPtr, KEY_LEN);
    return tag;
}

/** Verify the peer's confirmation tag. */
export async function verifyConfirmation(label, tag, viewerMsg, sharerMsg) {
    const w = await loadPakeWasm();
    const tptr = pakeWrite(w, tag);
    const vptr = pakeWrite(w, viewerMsg);
    const sptr = pakeWrite(w, sharerMsg);
    const rc = w.verify_confirmation(label, tptr, vptr, viewerMsg.length, sptr, sharerMsg.length);
    w.crypto_free(tptr, tag.length);
    w.crypto_free(vptr, viewerMsg.length);
    w.crypto_free(sptr, sharerMsg.length);
    return rc === 1;
}

/** Derive the per-viewer AES key; returns Uint8Array(32) or null. */
export async function deriveSessionKey(tunnelId, clientId) {
    const w = await loadPakeWasm();
    const t = new TextEncoder().encode(tunnelId);
    const tptr = pakeWrite(w, t);
    const outPtr = w.crypto_alloc(KEY_LEN);
    const rc = w.derive_session_key(tptr, t.length, clientId >>> 0, outPtr);
    const key = rc === 0 ? new Uint8Array(w.memory.buffer, outPtr, KEY_LEN).slice() : null;
    w.crypto_free(tptr, t.length);
    w.crypto_free(outPtr, KEY_LEN);
    return key;
}

export async function deriveFrameKey(tunnelId, clientId, frameType, direction) {
    const w = await loadPakeWasm();
    const t = new TextEncoder().encode(tunnelId);
    const tptr = pakeWrite(w, t);
    const outPtr = w.crypto_alloc(KEY_LEN);
    const rc = w.derive_frame_key(tptr, t.length, clientId >>> 0, frameType, direction, outPtr);
    const key = rc === 0 ? new Uint8Array(w.memory.buffer, outPtr, KEY_LEN).slice() : null;
    w.crypto_free(tptr, t.length);
    w.crypto_free(outPtr, KEY_LEN);
    return key;
}

export async function deriveSas(viewerMsg, sharerMsg) {
    const w = await loadPakeWasm();
    const vptr = pakeWrite(w, viewerMsg);
    const sptr = pakeWrite(w, sharerMsg);
    const outPtr = w.crypto_alloc(SAS_DIGITS);
    const rc = w.derive_sas(vptr, viewerMsg.length, sptr, sharerMsg.length, outPtr);
    const sas =
        rc === 0
            ? new TextDecoder().decode(new Uint8Array(w.memory.buffer, outPtr, SAS_DIGITS).slice())
            : null;
    w.crypto_free(vptr, viewerMsg.length);
    w.crypto_free(sptr, sharerMsg.length);
    w.crypto_free(outPtr, SAS_DIGITS);
    return sas;
}

/** Import 32 raw key bytes as an AES-256-GCM CryptoKey for encrypt/decrypt. */
export async function importAesKey(rawBytes) {
    return crypto.subtle.importKey(
        "raw",
        rawBytes,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

export const DEVICE_AUTH_PREFIX = new TextEncoder().encode("zellij-device-auth:v1");
export const DEVICE_PUBKEY_ALG = "ed25519";

export async function generateDeviceKey() {
    const pair = await crypto.subtle.generateKey(
        { name: "Ed25519" },
        false,
        ["sign", "verify"]
    );
    const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return { privateKey: pair.privateKey, pubkey: rawPub };
}

export async function signDeviceChallenge(privateKey, nonce) {
    const n = nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce);
    const msg = new Uint8Array(DEVICE_AUTH_PREFIX.length + n.length);
    msg.set(DEVICE_AUTH_PREFIX, 0);
    msg.set(n, DEVICE_AUTH_PREFIX.length);
    const sig = await crypto.subtle.sign("Ed25519", privateKey, msg);
    return new Uint8Array(sig);
}
