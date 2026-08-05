import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";
import { openControlAndAwaitVersion } from "../zellij-web-client-assets/assets/core-control.js";
import { loadDeviceRecord } from "../zellij-web-client-assets/assets/device-store.js";
import {
    importAesKey,
    encryptSeq,
    decryptSeq,
    FRAME_TYPE_CONTROL,
    DIRECTION_SHARER_TO_VIEWER,
    DIRECTION_VIEWER_TO_SHARER,
    DEVICE_AUTH_PREFIX,
} from "../zellij-web-client-assets/assets/crypto.js";

const RELAY_SERVER_URL = "http://relay.example.test/r/testslug";
const RECONNECT_CHALLENGE_NONCE = [3, 1, 4, 1, 5, 9, 2, 6];

function defineGlobal(name, value) {
    try {
        Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    } catch (_) {
        globalThis[name] = value;
    }
}

let domInstalled = false;

export function installBrowserEnvironment() {
    if (!domInstalled) {
        const page = new JSDOM(
            '<!DOCTYPE html><html><head><base href="http://app.example.test/"></head>' +
                '<body><input id="zellij-auth-mode" value="relay"></body></html>',
            { url: "http://app.example.test/r/testslug#k=deadbeefdeadbeefdeadbeefdeadbeef&l=00112233445566778899aabbccddeeff" }
        );
        defineGlobal("window", page.window);
        defineGlobal("document", page.window.document);
        defineGlobal("location", page.window.location);
        defineGlobal("navigator", page.window.navigator);
        defineGlobal("crypto", webcrypto);
        defineGlobal("showErrorModal", async () => {});
        defineGlobal("showReconnectionModal", async () => ({ action: "cancel" }));
        defineGlobal("showAdmissionWaitingModal", () => ({ close() {} }));
        domInstalled = true;
    }
    globalThis.indexedDB = new IDBFactory();
}

let mostRecentlyOpenedConnection = null;

class FakeRelayConnection {
    constructor(url) {
        this.url = url;
        this._state = FakeRelayConnection.CONNECTING;
        this.binaryType = "blob";
        this.framesSentByViewer = [];
        this.onmessage = null;
        this.onopen = null;
        this.onclose = null;
        this.onerror = null;
        this.onViewerSend = null;
        this._openListeners = [];
        mostRecentlyOpenedConnection = this;
    }

    get readyState() {
        return this._state;
    }

    get isClosed() {
        return this._state === FakeRelayConnection.CLOSED;
    }

    addEventListener(type, callback) {
        if (type !== "open") return;
        if (this._state === FakeRelayConnection.OPEN) callback();
        else this._openListeners.push(callback);
    }

    removeEventListener() {}

    send(bytes) {
        if (this._state !== FakeRelayConnection.OPEN) {
            throw new Error("the viewer sent a frame before the relay connection was open");
        }
        this.framesSentByViewer.push(bytes);
        if (this.onViewerSend) this.onViewerSend(bytes);
    }

    close() {
        this._state = FakeRelayConnection.CLOSED;
    }

    becomesEstablished() {
        if (this._state !== FakeRelayConnection.CONNECTING) return;
        this._state = FakeRelayConnection.OPEN;
        for (const listener of this._openListeners.splice(0)) listener();
        if (this.onopen) this.onopen();
    }

    deliverToViewer(bytes) {
        if (this.onmessage) this.onmessage({ data: bytes.slice().buffer });
    }

    deliverRawToViewer(data) {
        if (this.onmessage) this.onmessage({ data });
    }
}
FakeRelayConnection.CONNECTING = 0;
FakeRelayConnection.OPEN = 1;
FakeRelayConnection.CLOSING = 2;
FakeRelayConnection.CLOSED = 3;

function useFakeRelayTransport() {
    mostRecentlyOpenedConnection = null;
    defineGlobal("WebSocket", FakeRelayConnection);
}

function theConnectionTheViewerJustOpened() {
    return mostRecentlyOpenedConnection;
}

function durationToMs(text) {
    let total = 0;
    for (const [, value, unit] of text.matchAll(/(\d+)(ms|s|m)/g)) {
        const n = Number(value);
        total += unit === "ms" ? n : unit === "s" ? n * 1000 : n * 60000;
    }
    return total;
}

function installManualClock() {
    const realTimers = {
        setInterval: globalThis.setInterval,
        clearInterval: globalThis.clearInterval,
        setTimeout: globalThis.setTimeout,
        clearTimeout: globalThis.clearTimeout,
        now: Date.now,
    };

    let currentTimeMs = 0;
    let nextTimerId = 1;
    const scheduled = new Map();

    function schedule(callback, delayMs, repeating) {
        const id = nextTimerId++;
        const delay = Math.max(0, delayMs || 0);
        scheduled.set(id, { id, callback, delay, fireAt: currentTimeMs + delay, repeating });
        return id;
    }

    Date.now = () => currentTimeMs;
    globalThis.setInterval = (callback, delayMs) => schedule(callback, delayMs, true);
    globalThis.setTimeout = (callback, delayMs) => schedule(callback, delayMs, false);
    globalThis.clearInterval = (id) => scheduled.delete(id);
    globalThis.clearTimeout = (id) => scheduled.delete(id);

    function earliestTimerDueBy(deadline) {
        let earliest = null;
        for (const timer of scheduled.values()) {
            if (timer.fireAt <= deadline && (earliest === null || timer.fireAt < earliest.fireAt)) {
                earliest = timer;
            }
        }
        return earliest;
    }

    const drainMicrotasks = () => new Promise((resolve) => realTimers.setTimeout(resolve, 0));

    async function letReactionsComplete() {
        for (let i = 0; i < 25; i++) await drainMicrotasks();
    }

    async function advance(ms) {
        const deadline = currentTimeMs + ms;
        let timer;
        while ((timer = earliestTimerDueBy(deadline))) {
            currentTimeMs = timer.fireAt;
            if (timer.repeating) timer.fireAt += timer.delay;
            else scheduled.delete(timer.id);
            timer.callback();
            await letReactionsComplete();
        }
        currentTimeMs = deadline;
        await letReactionsComplete();
    }

    async function pumpUntil(condition, tries = 400) {
        for (let i = 0; i < tries; i++) {
            if (condition()) return;
            await advance(0);
        }
        if (!condition()) throw new Error("harness: expected condition was never reached");
    }

    function uninstall() {
        globalThis.setInterval = realTimers.setInterval;
        globalThis.clearInterval = realTimers.clearInterval;
        globalThis.setTimeout = realTimers.setTimeout;
        globalThis.clearTimeout = realTimers.clearTimeout;
        Date.now = realTimers.now;
    }

    return { advance, pumpUntil, uninstall };
}

const frameEncoder = new TextEncoder();
const frameDecoder = new TextDecoder();

async function freshViewerKeys() {
    const random = () => {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return bytes;
    };
    return {
        controlV2s: await importAesKey(random()),
        controlS2v: await importAesKey(random()),
        terminalV2s: await importAesKey(random()),
        terminalS2v: await importAesKey(random()),
    };
}

class SharerControlChannel {
    constructor(connection, viewerKeys) {
        this.connection = connection;
        this.viewerKeys = viewerKeys;
        this.nextOutboundSeq = 0;
    }

    async sendToViewer(frame, seqOverride) {
        const seq = seqOverride === undefined ? this.nextOutboundSeq++ : seqOverride;
        const sealed = await encryptSeq(
            this.viewerKeys.controlS2v,
            seq,
            FRAME_TYPE_CONTROL,
            DIRECTION_SHARER_TO_VIEWER,
            frameEncoder.encode(JSON.stringify(frame))
        );
        this.connection.deliverToViewer(sealed);
    }

    onFrameFromViewer(handleFrame) {
        let inOrder = Promise.resolve();
        this.connection.onViewerSend = (sealed) => {
            inOrder = inOrder.then(async () => {
                const { plaintext } = await decryptSeq(
                    this.viewerKeys.controlV2s,
                    FRAME_TYPE_CONTROL,
                    DIRECTION_VIEWER_TO_SHARER,
                    sealed
                );
                await handleFrame(JSON.parse(frameDecoder.decode(plaintext)));
            });
        };
    }
}

async function deviceSignatureIsValid(pinnedPublicKey, challengeNonce, signature) {
    if (!pinnedPublicKey) return false;
    const publicKey = await crypto.subtle.importKey("raw", pinnedPublicKey, { name: "Ed25519" }, false, ["verify"]);
    const nonce = Uint8Array.from(challengeNonce);
    const signedMessage = new Uint8Array(DEVICE_AUTH_PREFIX.length + nonce.length);
    signedMessage.set(DEVICE_AUTH_PREFIX, 0);
    signedMessage.set(nonce, DEVICE_AUTH_PREFIX.length);
    return crypto.subtle.verify("Ed25519", publicKey, Uint8Array.from(signature), signedMessage);
}

class Sharer {
    constructor({ enrollsDevices, clock }) {
        this.enrollsDevices = enrollsDevices;
        this.clock = clock;
        this.pinnedDevicePublicKey = null;
        this.deviceRevoked = false;
        this.answersHeartbeats = true;
        this.connectedViewers = [];
    }

    revokesTheDevice() {
        this.deviceRevoked = true;
    }

    stopsAnsweringHeartbeats() {
        this.answersHeartbeats = false;
    }

    async endsSession() {
        for (const viewer of this.connectedViewers) {
            if (viewer.status === "connected") await viewer.channel.sendToViewer({ type: "Exit" });
        }
    }

    replaysAnEarlierFrameTo(viewer) {
        viewer.channel.sendToViewer({ type: "Exit" }, 0);
    }

    deliversAMalformedFrameTo(viewer) {
        viewer.channel.connection.deliverRawToViewer("not-a-binary-frame");
    }

    async acceptViewer(viewer, { returning }) {
        const session = await this._sessionFor({ returning });
        const attaching = openControlAndAwaitVersion(session);
        const connection = theConnectionTheViewerJustOpened();
        const channel = new SharerControlChannel(connection, session.e2e.relay);

        viewer.beginAttaching(channel, attaching);
        this.connectedViewers.push(viewer);
        channel.onFrameFromViewer((frame) => this._respondTo(viewer, frame));

        connection.becomesEstablished();
        if (!returning) {
            await channel.sendToViewer({ type: "Admitted", enroll: this.enrollsDevices });
        }
        await this.clock.pumpUntil(() => viewer.status !== "connecting");
    }

    async _sessionFor({ returning }) {
        const relayKeys = await freshViewerKeys();
        const rememberedDevice = returning ? await loadDeviceRecord(RELAY_SERVER_URL) : null;
        return {
            handshake: "test-handshake",
            sas: "123456",
            e2e: { relay: relayKeys },
            device: { serverUrl: RELAY_SERVER_URL, reconnect: returning, record: rememberedDevice },
        };
    }

    _respondTo(viewer, frame) {
        switch (frame.type) {
            case "DeviceAuthRequest":
                return this._answerReconnectAttempt(viewer);
            case "DeviceAuthResponse":
                return this._admitIfSignatureValid(viewer, frame);
            case "DeviceEnrollRequest":
                return this._enrollDevice(viewer, frame);
            case "VersionRequest":
                return this._announceVersion(viewer);
            case "Ping":
                return this._answerHeartbeat(viewer);
            default:
                return undefined;
        }
    }

    _answerReconnectAttempt(viewer) {
        if (this.deviceRevoked) {
            return viewer.channel.sendToViewer({ type: "Rejected", reason: "access revoked" });
        }
        viewer.lastChallengeNonce = RECONNECT_CHALLENGE_NONCE;
        return viewer.channel.sendToViewer({ type: "DeviceAuthChallenge", nonce: RECONNECT_CHALLENGE_NONCE });
    }

    async _admitIfSignatureValid(viewer, frame) {
        const valid = await deviceSignatureIsValid(this.pinnedDevicePublicKey, viewer.lastChallengeNonce, frame.signature);
        if (!valid) {
            return viewer.channel.sendToViewer({ type: "Rejected", reason: "invalid device signature" });
        }
        viewer.reconnectedBySignature = true;
        return viewer.channel.sendToViewer({ type: "Admitted" });
    }

    _enrollDevice(viewer, frame) {
        this.pinnedDevicePublicKey = Uint8Array.from(frame.pubkey);
        return viewer.channel.sendToViewer({
            type: "DeviceEnrollAck",
            device_id: [1, 2, 3, 4],
            device_secret: "device-secret",
            scope: "session",
            access_read_only: false,
            host_id: "host-1",
        });
    }

    _announceVersion(viewer) {
        return viewer.channel.sendToViewer({
            type: "VersionAnnounce",
            zellij_version: "1.0.0-test",
            app_bundle_sha384: "sha384-test",
        });
    }

    _answerHeartbeat(viewer) {
        if (this.answersHeartbeats) return viewer.channel.sendToViewer({ type: "Pong" });
        return undefined;
    }
}

class Viewer {
    constructor(sharer) {
        this.sharer = sharer;
        this.channel = null;
        this.reconnectedBySignature = false;
        this._outcome = "idle";
    }

    async connects() {
        await this.sharer.acceptViewer(this, { returning: false });
        return this;
    }

    async reconnects() {
        await this.sharer.acceptViewer(this, { returning: true });
        return this;
    }

    get status() {
        if (this._outcome === "refused") return "refused";
        if (this._outcome === "connected") return this.channel.connection.isClosed ? "disconnected" : "connected";
        return this._outcome === "idle" ? "idle" : "connecting";
    }

    async remembersDevice() {
        return (await loadDeviceRecord(RELAY_SERVER_URL)) !== null;
    }

    async deviceKeyCanBeExported() {
        const device = await loadDeviceRecord(RELAY_SERVER_URL);
        if (!device || !device.privateKey) return false;
        try {
            await crypto.subtle.exportKey("pkcs8", device.privateKey);
            return true;
        } catch (_) {
            return false;
        }
    }

    async becomesDisconnected() {
        await this.sharer.clock.pumpUntil(() => this.status === "disconnected");
    }

    beginAttaching(channel, attaching) {
        this.channel = channel;
        this._outcome = "connecting";
        this.reconnectedBySignature = false;
        attaching.then(
            () => { this._outcome = "connected"; },
            () => { this._outcome = "refused"; }
        );
    }
}

let activeClock = null;

export function shareSession({ enrollsDevices = false } = {}) {
    installBrowserEnvironment();
    useFakeRelayTransport();
    activeClock = installManualClock();
    return new Sharer({ enrollsDevices, clock: activeClock });
}

export function openViewer(sharer) {
    return new Viewer(sharer);
}

export async function timePasses(duration) {
    await activeClock.advance(durationToMs(duration));
}

export function endHarness() {
    if (activeClock) {
        activeClock.uninstall();
        activeClock = null;
    }
}
