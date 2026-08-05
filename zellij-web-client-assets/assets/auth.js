/**
 * Authentication logic and token management
 */

import { getBaseUrl, getRelayTarget } from "./utils.js";
import {
    sha256Hex,
    deriveKey,
    pakeStart,
    pakeFinish,
    confirmationTag,
    verifyConfirmation,
    deriveFrameKey,
    deriveSas,
    importAesKey,
    CONFIRM_LABEL_SHARER,
    CONFIRM_LABEL_VIEWER,
    FRAME_TYPE_TERMINAL,
    FRAME_TYPE_CONTROL,
    DIRECTION_SHARER_TO_VIEWER,
    DIRECTION_VIEWER_TO_SHARER,
} from "./crypto.js";

/**
 * Relay-mode authentication: a SPAKE2 password-authenticated key exchange
 * driven by the secret carried in the URL fragment (`#k=`), run over the two
 * cross-origin auth POSTs to the relay. The relay
 * only forwards opaque SPAKE2 blobs; the secret never leaves the browser.
 * The handshake id from `/command/login` binds the two round-trips and the
 * viewer WebSockets — it replaces the former cross-origin cookie. Returns
 * the same shape as `getClientId` or null on failure.
 */
async function getClientIdRelay(token, expectedE2e, opts) {
    const target = getRelayTarget();
    const slug = target.slug;
    const httpBase = target.httpBase;
    const silent = !!(opts && opts.silent);
    const linkId = (opts && opts.linkId) || target.linkId;
    const fail = async (title, message) => {
        if (!silent) {
            await showErrorModal(title, message);
        }
        return null;
    };

    let viewerMsg;
    try {
        viewerMsg = await pakeStart(token, slug);
    } catch (e) {
        return fail("Error", `Could not initialise encryption: ${e.message}`);
    }

    const loginRequest = { viewer_msg: Array.from(viewerMsg) };
    if (linkId) {
        loginRequest.link_id = Array.from(linkId);
    }
    let loginRes = await fetch(`${httpBase}/command/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(loginRequest),
    });
    if (loginRes.status === 401) {
        return fail("Error", "Incorrect or expired secret.");
    } else if (!loginRes.ok) {
        return fail("Error", `Error ${loginRes.status} connecting to relay.`);
    }
    const loginBody = await loginRes.json();
    const sharerMsg = new Uint8Array(loginBody.sharer_msg || []);
    const sharerConfirm = new Uint8Array(loginBody.sharer_confirm || []);
    const handshake = loginBody.handshake;
    if (!handshake || typeof handshake !== "string") {
        return fail("Error", "Relay did not return a handshake id.");
    }

    if (!(await pakeFinish(sharerMsg))) {
        return fail("Error", "Key exchange failed.");
    }
    const sharerOk = await verifyConfirmation(
        CONFIRM_LABEL_SHARER,
        sharerConfirm,
        viewerMsg,
        sharerMsg
    );
    if (!sharerOk) {
        // Wrong secret or a tampering relay (MITM): the tag keyed by the shared
        // secret did not verify. Refuse before sending anything further.
        return fail(
            "Refused",
            "Key confirmation failed — wrong secret or a tampering relay. Refusing to connect."
        );
    }

    const viewerConfirm = await confirmationTag(
        CONFIRM_LABEL_VIEWER,
        viewerMsg,
        sharerMsg
    );
    if (!viewerConfirm) {
        return fail("Error", "Key exchange failed.");
    }

    const sas = await deriveSas(viewerMsg, sharerMsg);
    let sessRes = await fetch(`${httpBase}/session`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-Zellij-Handshake": handshake,
        },
        body: JSON.stringify({ viewer_confirm: Array.from(viewerConfirm) }),
    });
    if (sessRes.status === 401) {
        return fail("Error", "Incorrect or expired secret.");
    } else if (!sessRes.ok) {
        return fail("Error", `Error ${sessRes.status} connecting to relay.`);
    }
    const body = await sessRes.json();
    if (expectedE2e && body.e2e_encrypted !== true) {
        return fail(
            "Refused",
            "This session was advertised as end-to-end encrypted, but the relay does not confirm it. Refusing to connect."
        );
    }
    if (!body.tunnel_id || typeof body.tunnel_id !== "string") {
        return fail("Error", "Relay did not return a tunnel id.");
    }
    const cid = Number(body.client_id) || 0;
    const rawTerminalS2v = await deriveFrameKey(body.tunnel_id, cid, FRAME_TYPE_TERMINAL, DIRECTION_SHARER_TO_VIEWER);
    const rawTerminalV2s = await deriveFrameKey(body.tunnel_id, cid, FRAME_TYPE_TERMINAL, DIRECTION_VIEWER_TO_SHARER);
    const rawControlS2v = await deriveFrameKey(body.tunnel_id, cid, FRAME_TYPE_CONTROL, DIRECTION_SHARER_TO_VIEWER);
    const rawControlV2s = await deriveFrameKey(body.tunnel_id, cid, FRAME_TYPE_CONTROL, DIRECTION_VIEWER_TO_SHARER);
    if (!rawTerminalS2v || !rawTerminalV2s || !rawControlS2v || !rawControlV2s) {
        return fail("Error", "Could not derive the session keys.");
    }
    const relay = {
        terminalS2v: await importAesKey(rawTerminalS2v),
        terminalV2s: await importAesKey(rawTerminalV2s),
        controlS2v: await importAesKey(rawControlS2v),
        controlV2s: await importAesKey(rawControlV2s),
    };
    return {
        webClientId: body.web_client_id,
        e2e: { relay },
        isReadOnly: body.is_read_only === true,
        sessionRows: 0,
        sessionCols: 0,
        handshake,
        sas,
    };
}

export async function deviceReconnectSession(deviceRecord) {
    if (getAuthMode() !== "relay") {
        return null;
    }
    const expectedE2e = readExpectedE2e();
    return getClientIdRelay(deviceRecord.deviceSecret, expectedE2e, {
        linkId: deviceRecord.deviceId,
        silent: true,
    });
}

/**
 * Hosts that always operate behind an E2E-enforcing relay. Any URL whose
 * hostname (or a subdomain thereof) matches one of these entries has its
 * `expectedE2e` flag forced to `true`, independent of the hidden form
 * field on the challenge page. A compromised relay serving
 * `EXPECTED_E2E=false` is therefore caught before any STDIN is sent.
 */
const KNOWN_RELAY_HOSTS = ["zellij.online"];

/**
 * Returns true if the current page's URL is a known-relay URL. Exact
 * match or `.<host>` suffix so `relay.zellij.online` and `my.zellij.online`
 * are recognised but an unrelated `zellij.online.evil.com` is not.
 */
function pageIsOnKnownRelay() {
    const host = location.hostname.toLowerCase();
    for (const r of KNOWN_RELAY_HOSTS) {
        if (host === r || host.endsWith("." + r)) {
            return true;
        }
    }
    return false;
}

/** Read the challenge-page `expectedE2e` claim, forcing true on known relays. */
function readExpectedE2e() {
    if (pageIsOnKnownRelay()) {
        return true;
    }
    const el = document.getElementById("zellij-expected-e2e");
    if (!el) return false;
    return el.value === "true";
}

/**
 * Read the server-asserted auth-flow profile from the
 * `zellij-auth-mode` hidden input. Returns "relay" or "local";
 * defaults to "local" when the value is missing or unrecognised.
 */
function getAuthMode() {
    const el = document.getElementById("zellij-auth-mode");
    const v = el && el.value;
    return v === "relay" ? "relay" : "local";
}

/**
 * Wait for user to provide a security token
 * @returns {Promise<{token: string, remember: boolean}>}
 */
async function waitForSecurityToken() {
    let token = null;
    let remember = false;

    while (!token) {
        let result = await getSecurityToken();
        if (result) {
            token = result.token;
            remember = !!result.remember;
        } else {
            await showErrorModal(
                "Error",
                "Must provide security token in order to log in."
            );
        }
    }

    return { token, remember };
}

/**
 * Persist a successful credential in the browser's password manager.
 * On Chromium this is the imperative path; on Safari / Firefox the
 * form-submit heuristic in `getSecurityToken` produces the same
 * "Save password?" prompt, so this is a no-op there.
 */
async function saveCredential(token) {
    if (typeof PasswordCredential === "undefined" ||
        !navigator.credentials ||
        !navigator.credentials.store) {
        return;
    }
    try {
        const cred = new PasswordCredential({
            id: getCredentialId(),
            password: token,
        });
        await navigator.credentials.store(cred);
    } catch (_) {
        // Best-effort: failures are silent.
    }
}

/**
 * Get client ID from server after authentication
 * @param {string} token - Authentication token
 * @param {boolean} rememberMe - Local-mode Remember-me preference; ignored in relay mode
 * @param {boolean} hasAuthenticationCookie - Whether auth cookie exists
 * @returns {Promise<{webClientId: string, e2e: ?{key: CryptoKey}} | null>} null on failure
 */
export async function getClientId(token, rememberMe, hasAuthenticationCookie, expectedE2e) {
    const baseUrl = getBaseUrl();

    // Relay mode uses a SPAKE2 handshake (the secret never reaches the relay).
    // It is inherently a fresh two-round-trip exchange every time, so the
    // cookie-resume shortcut does not apply.
    if (getAuthMode() === "relay") {
        return getClientIdRelay(token, expectedE2e);
    }

    if (!hasAuthenticationCookie) {
        // In relay mode `remember_me` has no server-side effect (no
        // persistent cookie path) and the field is not part of the relay
        // login contract, so it is omitted entirely. In local mode the
        // flag is forwarded so the standalone web-client can issue a
        // persistent cookie when requested.
        const loginBody = getAuthMode() === "local"
            ? { auth_token: token, remember_me: !!rememberMe }
            : { auth_token: token };
        let login_res = await fetch(`${baseUrl}/command/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(loginBody),
            credentials: "include",
        });

        if (login_res.status === 401) {
            await showErrorModal(
                "Error",
                "Unauthorized or revoked login token."
            );
            return null;
        } else if (!login_res.ok) {
            await showErrorModal(
                "Error",
                `Error ${login_res.status} connecting to server.`
            );
            return null;
        }
    }

    let data = await fetch(`${baseUrl}/session`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
    });

    if (data.status === 401) {
        await showErrorModal("Error", "Unauthorized or revoked login token.");
        return null;
    } else if (!data.ok) {
        await showErrorModal(
            "Error",
            `Error ${data.status} connecting to server.`
        );
        return null;
    }

    let body = await data.json();
    const serverE2e = body.e2e_encrypted === true;

    // Cross-check: the server's claim must not be weaker than what the
    // page (or known-relay override) advertised. Stronger is allowed so
    // clients can opportunistically upgrade.
    if (expectedE2e && !serverE2e) {
        await showErrorModal(
            "Refused",
            "This session was advertised as end-to-end encrypted, but the server does not confirm it. Refusing to connect."
        );
        return null;
    }

    let e2e = null;
    if (serverE2e) {
        // Derive the same key the server derived: HKDF over the
        // hex-encoded SHA-256 of the raw token, with info=tunnel_id.
        if (!body.tunnel_id || typeof body.tunnel_id !== "string") {
            await showErrorModal(
                "Error",
                "Server did not return a tunnel id; cannot enable encryption."
            );
            return null;
        }
        const tokenHashHex = await sha256Hex(token);
        const key = await deriveKey(tokenHashHex, body.tunnel_id);
        e2e = { key };
    }

    return {
        webClientId: body.web_client_id,
        e2e,
        isReadOnly: body.is_read_only === true,
        sessionRows: Number(body.session_rows) || 0,
        sessionCols: Number(body.session_cols) || 0,
    };
}

/**
 * Initialize authentication flow and return client ID
 * @returns {Promise<{webClientId: string, e2e: ?{key: CryptoKey}}>}
 */
export async function initAuthentication() {
    const expectedE2e = readExpectedE2e();
    if (getAuthMode() === "relay") {
        return await initRelayAuthentication(expectedE2e);
    }
    return await initLocalAuthentication(expectedE2e);
}

async function initRelayAuthentication(expectedE2e) {
    const fragmentSecret = getRelayTarget().secret;
    if (!fragmentSecret) {
        await showErrorModal(
            "Error",
            "This share link is missing its secret. Ask the host for a fresh guest link.",
        );
        throw new Error("relay share link has no fragment secret");
    }
    const session = await getClientId(fragmentSecret, false, false, expectedE2e);
    if (!session) {
        throw new Error("relay authentication rejected");
    }
    return session;
}

async function initLocalAuthentication(expectedE2e) {
    let token = null;
    let remember = false;
    let hasAuthenticationCookie = document.body.dataset.authenticated === "true";
    // Gates the imperative `navigator.credentials.store` call so the
    // password manager is only asked to save tokens that came from a
    // real user gesture, not from a silent autofill.
    let tokenFromUserEntry = false;

    if (!hasAuthenticationCookie) {
        const tokenResult = await waitForSecurityToken();
        token = tokenResult.token;
        remember = tokenResult.remember;
        tokenFromUserEntry = true;
    }

    let session;

    while (!session) {
        session = await getClientId(
            token,
            remember,
            hasAuthenticationCookie,
            expectedE2e,
        );
        if (!session) {
            // Login rejected (revoked / wrong token) — drop any cookie
            // assumption and prompt the user manually. The modal's
            // form-submit then lets the password manager offer to
            // update the saved credential.
            hasAuthenticationCookie = false;
            const tokenResult = await waitForSecurityToken();
            token = tokenResult.token;
            remember = tokenResult.remember;
            tokenFromUserEntry = true;
        }
    }

    if (token && tokenFromUserEntry) {
        await saveCredential(token);
    }

    return session;
}
