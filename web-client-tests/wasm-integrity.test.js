import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installBrowserEnvironment } from "./relay-harness.js";
import {
    verifyWasmDigest,
    verifyWasmIntegrity,
    sha384Base64,
    pakeStart,
} from "../zellij-web-client-assets/assets/crypto.js";

installBrowserEnvironment();

const assetsDir = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "zellij-web-client-assets",
    "assets"
);

function setAuthMode(mode) {
    document.getElementById("zellij-auth-mode").value = mode;
}

test("relay mode refuses a wasm whose expected digest is absent", async () => {
    await assert.rejects(
        verifyWasmIntegrity("relay_crypto.wasm", new Uint8Array([1, 2, 3])),
        /integrity check unavailable for relay_crypto\.wasm; refusing to run/
    );
});

test("relay mode refuses to start the pake before instantiating unverified wasm", async () => {
    const wasmBytes = fs.readFileSync(path.join(assetsDir, "relay_crypto.wasm"));
    defineFetchReturning(wasmBytes);
    await assert.rejects(
        pakeStart("secret", "testslug"),
        /integrity check unavailable for relay_crypto\.wasm; refusing to run/
    );
});

function defineFetchReturning(bytes) {
    const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    Object.defineProperty(globalThis, "fetch", {
        value: async () => ({ ok: true, arrayBuffer: async () => buffer }),
        configurable: true,
        writable: true,
    });
}

test("a matching digest passes and a byte-flip is refused", async () => {
    const bytes = new Uint8Array(fs.readFileSync(path.join(assetsDir, "relay_crypto.wasm")));
    const expected = "sha384-" + (await sha384Base64(bytes));
    await verifyWasmDigest(expected, "relay_crypto.wasm", bytes);
    bytes[0] ^= 1;
    await assert.rejects(
        verifyWasmDigest(expected, "relay_crypto.wasm", bytes),
        /integrity check failed for relay_crypto\.wasm; refusing to run/
    );
});

test("local mode still permits a missing digest", async () => {
    setAuthMode("local");
    try {
        await verifyWasmIntegrity("relay_crypto.wasm", new Uint8Array([1, 2, 3]));
    } finally {
        setAuthMode("relay");
    }
});
