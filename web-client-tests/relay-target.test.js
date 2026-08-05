import test from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { deriveRelayHost, getRelayTarget } from "../zellij-web-client-assets/assets/utils.js";

function defineGlobal(name, value) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}

function installPageAt(url) {
    const page = new JSDOM(
        '<!DOCTYPE html><html><body><input id="zellij-auth-mode" value="relay"></body></html>',
        { url }
    );
    defineGlobal("window", page.window);
    defineGlobal("document", page.window.document);
    defineGlobal("location", page.window.location);
}

test("the relay host is derived from the page host with the port appended", () => {
    installPageAt("https://app.example.test:8443/r/slug#k=x");
    const target = getRelayTarget();
    assert.equal(target.relayHost, "relay.app.example.test:8443");
    assert.equal(target.httpBase, "https://relay.app.example.test:8443/r/slug");
    assert.equal(target.wsBase, "wss://relay.app.example.test:8443/r/slug");
});

test("a host already starting with relay. is kept unchanged", () => {
    assert.equal(deriveRelayHost("relay.example.com"), "relay.example.com");
});

test("an ip literal host passes through without a relay prefix", () => {
    assert.equal(deriveRelayHost("127.0.0.1"), "127.0.0.1");
    assert.equal(deriveRelayHost("[::1]"), "[::1]");
    installPageAt("http://127.0.0.1:9000/r/slug#k=x");
    assert.equal(getRelayTarget().relayHost, "127.0.0.1:9000");
});

test("a fragment r= override is ignored and the secret still parses", () => {
    installPageAt("http://app.example.test/r/slug#k=x&r=evil.example.net");
    const target = getRelayTarget();
    assert.equal(target.relayHost, "relay.app.example.test");
    assert.equal(target.secret, "x");
});

test("http pages derive ws bases and https pages derive wss bases", () => {
    installPageAt("http://app.example.test/r/slug#k=x");
    assert.equal(getRelayTarget().wsBase, "ws://relay.app.example.test/r/slug");
    installPageAt("https://app.example.test/r/slug#k=x");
    assert.equal(getRelayTarget().wsBase, "wss://relay.app.example.test/r/slug");
});
