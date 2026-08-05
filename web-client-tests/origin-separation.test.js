import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import {
    deriveRelayHost,
    relayHostCollidesWithAppHost,
    getRelayIsolation,
} from "../zellij-web-client-assets/assets/utils.js";

const assetsDir = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "zellij-web-client-assets",
    "assets"
);

function defineGlobal(name, value) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}

function installPageAt(url, authMode = "relay") {
    const page = new JSDOM(
        `<!DOCTYPE html><html><body><input id="zellij-auth-mode" value="${authMode}"></body></html>`,
        { url }
    );
    defineGlobal("window", page.window);
    defineGlobal("document", page.window.document);
    defineGlobal("location", page.window.location);
    return page;
}

function pageRunningModals(url, authMode) {
    const modalsSource = fs.readFileSync(path.join(assetsDir, "modals.js"), "utf8");
    const page = new JSDOM(
        `<!DOCTYPE html><html><body>
            <input id="zellij-auth-mode" value="${authMode}" hidden>
            <input id="zellij-expected-e2e" value="true" hidden>
        </body></html>`,
        { url, runScripts: "dangerously" }
    );
    const script = page.window.document.createElement("script");
    script.textContent = modalsSource;
    page.window.document.body.appendChild(script);
    return page;
}

test("a same-host app and relay deployment is detected", () => {
    assert.equal(
        relayHostCollidesWithAppHost("relay.example.com", deriveRelayHost("relay.example.com")),
        true
    );
    assert.equal(relayHostCollidesWithAppHost("relay.example.com:8443", "relay.example.com"), true);
    installPageAt("http://relay.example.test/r/testslug#k=x");
    const isolation = getRelayIsolation();
    assert.equal(isolation.sameHost, true);
    assert.equal(isolation.relayHost, "relay.example.test");
});

test("a split app and relay deployment is clean", () => {
    assert.equal(deriveRelayHost("app.example.com"), "relay.app.example.com");
    assert.equal(
        relayHostCollidesWithAppHost("app.example.com", deriveRelayHost("app.example.com")),
        false
    );
    installPageAt("http://app.example.test/r/testslug#k=x");
    const isolation = getRelayIsolation();
    assert.equal(isolation.sameHost, false);
    assert.equal(isolation.appHost, "app.example.test");
    assert.equal(isolation.relayHost, "relay.app.example.test");
});

test("the join modal shows the serving origin in relay mode", () => {
    const page = pageRunningModals("http://app.example.test/r/testslug", "relay");
    page.window.getSecurityToken();
    const origin = page.window.document.querySelector(".origin-indicator");
    assert.ok(origin);
    assert.equal(
        origin.textContent.trim(),
        "Your session code is handled by code from app.example.test."
    );
    page.window.document.querySelector("#cancel").click();
    assert.equal(page.window.document.querySelector(".origin-indicator"), null);
});

test("local mode shows no origin row and keeps the remember checkbox", () => {
    const page = pageRunningModals("http://localhost:8082/", "local");
    page.window.getSecurityToken();
    assert.equal(page.window.document.querySelector(".origin-indicator"), null);
    assert.ok(page.window.document.querySelector("#remember"));
    page.window.document.querySelector("#cancel").click();
});

test("the same-host warning is acknowledgeable and continues", async () => {
    const page = pageRunningModals("http://relay.example.test/r/testslug", "relay");
    const acknowledged = page.window.showSecurityWarningModal(
        "Security warning",
        "app and relay share a host"
    );
    const modal = page.window.document.querySelector(".security-modal.warning");
    assert.ok(modal);
    assert.equal(modal.querySelector(".dismiss-btn").textContent, "Continue anyway");
    assert.equal(
        modal.querySelector(".warning-description").textContent,
        "app and relay share a host"
    );
    modal.querySelector("#dismiss").click();
    await acknowledged;
    assert.equal(page.window.document.querySelector(".security-modal.warning"), null);
});
