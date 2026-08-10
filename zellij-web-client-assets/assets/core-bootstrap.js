import { initConnectionHandlers } from "./connection.js";
import {
    initAuthentication,
    deviceReconnectSession,
    fetchSessionList,
} from "./auth.js";
import { isRelayMode, getRelayTarget, getRelayIsolation } from "./utils.js";
import { sha384Base64 } from "./crypto.js";
import { openControlAndAwaitVersion } from "./core-control.js";
import { loadDeviceRecord, deleteDeviceRecord } from "./device-store.js";

const CLASSIC_LIBRARY_SCRIPTS = [
    "xterm.js",
    "addon-fit.js",
    "addon-clipboard.js",
    "addon-web-links.js",
    "addon-webgl.js",
];

function fail(title, message) {
    if (typeof showErrorModal === "function") {
        showErrorModal(title, message);
    }
    return new Error(message);
}

function surfaceFatal(message) {
    if (typeof showErrorModal === "function") {
        showErrorModal("Connection failed", message);
        return;
    }
    const pre = document.createElement("pre");
    pre.style.cssText =
        "color:#fff;background:#000;padding:16px;white-space:pre-wrap;font-size:14px;";
    pre.textContent = `Connection failed: ${message}`;
    document.body.replaceChildren(pre);
}

window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason;
    if (reason && reason.handled) {
        return;
    }
    event.preventDefault();
    surfaceFatal((reason && reason.message) || String(reason));
});

function versionedBase(version) {
    return `/v/${encodeURIComponent(version)}`;
}

async function fetchAndVerifyManifest(version, attestedRolledUp) {
    const res = await fetch(`${versionedBase(version)}/app-manifest.json`);
    if (res.status === 404) {
        throw fail(
            "Update Zellij",
            "This Zellij version is not hosted by the app origin — update Zellij."
        );
    }
    if (!res.ok) {
        throw fail("Error", `Could not fetch the application manifest (${res.status}).`);
    }
    const manifest = await res.json();
    const lines = manifest.map((e) => `${e.name}  ${e.integrity}`).sort();
    const text = lines.join("\n") + "\n";
    const rolledUp = "sha384-" + (await sha384Base64(new TextEncoder().encode(text)));
    if (rolledUp !== attestedRolledUp) {
        throw fail(
            "Refused",
            "The app-origin bundle does not match the shared session — refusing to connect."
        );
    }
    return manifest;
}

function injectStylesheet(href, integrity) {
    return new Promise((resolve, reject) => {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = href;
        if (integrity) {
            link.integrity = integrity;
            link.crossOrigin = "anonymous";
        }
        link.onload = () => resolve();
        link.onerror = () => reject(new Error(`failed to load ${href}`));
        document.head.appendChild(link);
    });
}

function injectClassicScript(src, integrity) {
    return new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = src;
        if (integrity) {
            script.integrity = integrity;
            script.crossOrigin = "anonymous";
        }
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`failed to load ${src}`));
        document.head.appendChild(script);
    });
}

function injectModulePreload(href, integrity) {
    return new Promise((resolve, reject) => {
        const link = document.createElement("link");
        link.rel = "modulepreload";
        link.href = href;
        if (integrity) {
            link.integrity = integrity;
            link.crossOrigin = "anonymous";
        }
        link.onload = () => resolve();
        link.onerror = () => reject(new Error(`failed to preload ${href}`));
        document.head.appendChild(link);
    });
}

async function loadLocalLibraries() {
    await injectStylesheet("/assets/xterm.css");
    for (const name of CLASSIC_LIBRARY_SCRIPTS) {
        await injectClassicScript(`/assets/${name}`);
    }
}

async function loadApplicationBundle(version, manifest) {
    const integrity = {};
    for (const entry of manifest) {
        integrity[entry.name] = entry.integrity;
    }
    const base = `${versionedBase(version)}/assets`;

    await injectStylesheet(`${base}/xterm.css`, integrity["xterm.css"]);

    for (const name of CLASSIC_LIBRARY_SCRIPTS) {
        await injectClassicScript(`${base}/${name}`, integrity[name]);
    }

    const moduleNames = manifest
        .map((entry) => entry.name)
        .filter((name) => name.endsWith(".js") && !CLASSIC_LIBRARY_SCRIPTS.includes(name));
    await Promise.all(
        moduleNames.map((name) => injectModulePreload(`${base}/${name}`, integrity[name]))
    );

    return import(`${base}/app.js`);
}

async function resolveLocalWelcome(sessionFromPath) {
    if (sessionFromPath) {
        return true;
    }
    const mobileUi = await import("./app.js");
    if (!mobileUi.shouldUseStandaloneMenu()) {
        return true;
    }
    document.title = "Zellij";
    await mobileUi.showStandaloneSessionMenu({ fetchSessions: fetchSessionList });
    return false;
}

document.addEventListener("DOMContentLoaded", async () => {
    initConnectionHandlers();

    let session = null;
    let serverUrl = null;
    let deviceReconnect = false;
    let deviceRecord = null;
    const sessionFromPath = isRelayMode()
        ? null
        : location.pathname.split("/").pop();
    let welcome = true;
    if (isRelayMode()) {
        serverUrl = getRelayTarget().httpBase;
        const isolation = getRelayIsolation();
        if (isolation.sameHost && typeof showSecurityWarningModal === "function") {
            await showSecurityWarningModal(
                "Security warning",
                `This page's code and the relay are both served from ${isolation.relayHost}. ` +
                    "End-to-end encryption cannot protect the session from that host. " +
                    "The connection will continue."
            );
        }
        try {
            deviceRecord = await loadDeviceRecord(serverUrl);
        } catch (err) {
            deviceRecord = null;
        }
        if (deviceRecord) {
            try {
                session = await deviceReconnectSession(deviceRecord);
            } catch (err) {
                session = null;
            }
            if (session) {
                deviceReconnect = true;
            } else {
                await deleteDeviceRecord(serverUrl);
                deviceRecord = null;
            }
        }
    } else {
        welcome = await resolveLocalWelcome(sessionFromPath);
    }
    if (!session) {
        try {
            session = await initAuthentication({ session: sessionFromPath, welcome });
        } catch (err) {
            if (!(err && err.handled)) {
                surfaceFatal((err && err.message) || "Authentication failed.");
            }
            return;
        }
    }
    if (!isRelayMode() && session.sessionName) {
        if (!location.pathname.endsWith(`/${session.sessionName}`)) {
            history.replaceState(null, "", session.sessionName);
        }
    }
    if (isRelayMode()) {
        session.device = {
            serverUrl,
            reconnect: deviceReconnect,
            record: deviceReconnect ? deviceRecord : null,
        };
        let controlChannel = null;
        try {
            const negotiated = await openControlAndAwaitVersion(session);
            controlChannel = negotiated.controlChannel;
            const { zellijVersion, appBundleSha384, bufferedControl } = negotiated;
            const manifest = await fetchAndVerifyManifest(zellijVersion, appBundleSha384);
            const app = await loadApplicationBundle(zellijVersion, manifest);
            await app.start({ session, controlChannel, bufferedControl });
        } catch (err) {
            if (controlChannel) {
                controlChannel.close();
            }
            if (typeof showErrorModal === "function") {
                await showErrorModal(
                    "Not admitted",
                    (err && err.message) || "The host did not admit this session."
                );
            }
        }
    } else {
        await loadLocalLibraries();
        const app = await import("./app.js");
        await app.start({ session });
    }
});
