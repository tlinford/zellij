import { getWsApiBase } from "./utils.js";
import { handleReconnection, handleDisconnected } from "./connection.js";
import {
    encryptSeq,
    decryptSeq,
    FRAME_TYPE_CONTROL,
    DIRECTION_SHARER_TO_VIEWER,
    DIRECTION_VIEWER_TO_SHARER,
    generateDeviceKey,
    signDeviceChallenge,
    DEVICE_PUBKEY_ALG,
} from "./crypto.js";
import { saveDeviceRecord, deleteDeviceRecord } from "./device-store.js";

const HEARTBEAT_INTERVAL_MS = 30000;
const HEARTBEAT_TIMEOUT_MS = 60000;
const DEVICE_ADMISSION_TIMEOUT_MS = 35000;
const ENROLL_TIMEOUT_MS = 125000;

function makeReplayWindow() {
    let last = -1;
    return (seq) => {
        if (seq <= last) {
            return false;
        }
        last = seq;
        return true;
    };
}

function createControlChannel(ws, relay, coreHandler) {
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();
    let outSeq = 0;
    let sendChain = new Promise((resolve) => {
        if (ws.readyState === WebSocket.OPEN) {
            resolve();
        } else {
            ws.addEventListener("open", () => resolve(), { once: true });
        }
    });
    let recvChain = Promise.resolve();
    const inWindow = makeReplayWindow();
    let handler = null;
    const buffer = [];

    const send = (obj) => {
        const json = JSON.stringify(obj);
        sendChain = sendChain.then(async () => {
            try {
                const ct = await encryptSeq(
                    relay.controlV2s,
                    outSeq,
                    FRAME_TYPE_CONTROL,
                    DIRECTION_VIEWER_TO_SHARER,
                    textEncoder.encode(json)
                );
                outSeq += 1;
                ws.send(ct);
            } catch (err) {
                console.error("e2e control encrypt failed:", err);
            }
        });
    };

    const dispatch = (msg) => {
        if (handler) {
            handler(msg);
        } else {
            buffer.push(msg);
        }
    };

    ws.onmessage = (event) => {
        recvChain = recvChain.then(async () => {
            if (!(event.data instanceof ArrayBuffer)) {
                console.error("received plaintext control frame under E2E");
                return;
            }
            try {
                const { seq, plaintext } = await decryptSeq(
                    relay.controlS2v,
                    FRAME_TYPE_CONTROL,
                    DIRECTION_SHARER_TO_VIEWER,
                    event.data
                );
                if (!inWindow(seq)) {
                    return;
                }
                const obj = JSON.parse(textDecoder.decode(plaintext));
                if (coreHandler) {
                    let consumed = false;
                    try {
                        consumed = await coreHandler(obj, { send });
                    } catch (e) {
                        console.error("device control handler failed:", e);
                    }
                    if (consumed) {
                        return;
                    }
                }
                dispatch(obj);
            } catch (err) {
                console.error("e2e control decrypt failed:", err);
            }
        });
    };

    return {
        ws,
        send,
        onFrame(cb) {
            handler = cb;
            const pending = buffer.splice(0, buffer.length);
            for (const msg of pending) {
                cb(msg);
            }
        },
        detachHandler() {
            handler = null;
        },
        bufferFrame(msg) {
            buffer.push(msg);
        },
        snapshotBuffered() {
            return buffer.slice();
        },
        close() {
            handler = null;
            buffer.length = 0;
            ws.onmessage = null;
            ws.onclose = null;
            ws.onerror = null;
            try {
                ws.close();
            } catch (_) {}
        },
    };
}

function makeDeviceCore(session, serverUrl, onExit) {
    const record = session.device && session.device.record;
    let lastPong = Date.now();
    return {
        setLastPongNow() {
            lastPong = Date.now();
        },
        lastPong() {
            return lastPong;
        },
        async handle(msg, channel) {
            if (!msg || typeof msg.type !== "string") {
                return false;
            }
            switch (msg.type) {
                case "DeviceAuthChallenge": {
                    if (record && record.privateKey) {
                        const nonce = Uint8Array.from(msg.nonce || []);
                        const sig = await signDeviceChallenge(record.privateKey, nonce);
                        channel.send({
                            type: "DeviceAuthResponse",
                            signature: Array.from(sig),
                        });
                    }
                    return true;
                }
                case "Pong": {
                    lastPong = Date.now();
                    return true;
                }
                case "Exit": {
                    onExit();
                    return true;
                }
                case "MobileState": {
                    if (msg.payload) {
                        window.__zjLastMobileState = msg.payload;
                    }
                    return false;
                }
                default:
                    return false;
            }
        },
    };
}

function awaitDeviceAdmission(ws, channel) {
    return new Promise((resolve, reject) => {
        let settled = false;
        let admissionTimeout = null;
        const finish = (fn, value) => {
            if (settled) {
                return;
            }
            settled = true;
            if (admissionTimeout !== null) {
                clearTimeout(admissionTimeout);
            }
            fn(value);
        };
        channel.onFrame((msg) => {
            if (settled) {
                return;
            }
            if (msg && msg.type === "Admitted") {
                channel.detachHandler();
                finish(resolve, undefined);
            } else if (msg && msg.type === "Rejected") {
                channel.detachHandler();
                finish(reject, new Error(msg.reason || "the host did not admit this device"));
            } else {
                channel.bufferFrame(msg);
            }
        });
        ws.onerror = () => {
            finish(reject, new Error("control channel error before device admission"));
        };
        ws.onclose = (event) => {
            finish(reject, new Error("control channel closed before device admission"));
        };
        channel.send({ type: "DeviceAuthRequest" });
        admissionTimeout = setTimeout(() => {
            finish(reject, new Error("timed out waiting for device admission"));
        }, DEVICE_ADMISSION_TIMEOUT_MS);
    });
}

async function enrollDevice(ws, channel, serverUrl) {
    const key = await generateDeviceKey();
    channel.send({
        type: "DeviceEnrollRequest",
        pubkey_alg: DEVICE_PUBKEY_ALG,
        pubkey: Array.from(key.pubkey),
        requested_label: null,
    });
    return new Promise((resolve, reject) => {
        let settled = false;
        let enrollTimeout = null;
        const finish = (fn, value) => {
            if (settled) {
                return;
            }
            settled = true;
            if (enrollTimeout !== null) {
                clearTimeout(enrollTimeout);
            }
            fn(value);
        };
        channel.onFrame(async (msg) => {
            if (settled) {
                return;
            }
            if (msg && msg.type === "DeviceEnrollAck") {
                channel.detachHandler();
                if (serverUrl) {
                    await saveDeviceRecord({
                        serverUrl,
                        privateKey: key.privateKey,
                        pubkey: key.pubkey,
                        deviceId: Uint8Array.from(msg.device_id || []),
                        deviceSecret: msg.device_secret,
                        scope: msg.scope,
                        readOnly: msg.access_read_only === true,
                        hostId: msg.host_id || null,
                    });
                }
                channel.send({ type: "EnrollComplete" });
                finish(resolve, undefined);
            } else if (msg && msg.type === "Rejected") {
                channel.detachHandler();
                finish(reject, new Error(msg.reason || "the host did not complete enrollment"));
            } else {
                channel.bufferFrame(msg);
            }
        });
        ws.onerror = () => {
            finish(reject, new Error("control channel error during enrollment"));
        };
        ws.onclose = (event) => {
            finish(reject, new Error("control channel closed during enrollment"));
        };
        enrollTimeout = setTimeout(() => {
            finish(reject, new Error("timed out during enrollment"));
        }, ENROLL_TIMEOUT_MS);
    });
}

function startHeartbeat(channel, deviceCore, onDead) {
    deviceCore.setLastPongNow();
    const timer = setInterval(() => {
        channel.send({ type: "Ping" });
        if (Date.now() - deviceCore.lastPong() > HEARTBEAT_TIMEOUT_MS) {
            clearInterval(timer);
            onDead();
        }
    }, HEARTBEAT_INTERVAL_MS);
    return () => clearInterval(timer);
}

export async function openControlAndAwaitVersion(session) {
    const relay = session.e2e && session.e2e.relay;
    if (!relay) {
        throw new Error("relay session keys missing");
    }
    const device = session.device || null;
    const reconnect = !!(device && device.reconnect);
    const serverUrl = device && device.serverUrl;

    let channel = null;
    let heartbeatStop = null;
    let teardownDone = false;
    const teardown = () => {
        if (teardownDone) {
            return;
        }
        teardownDone = true;
        if (heartbeatStop) {
            heartbeatStop();
        }
        if (channel) {
            channel.ws.onclose = null;
            channel.close();
        }
        handleDisconnected();
    };

    const deviceCore = makeDeviceCore(session, serverUrl, teardown);

    const wsBase = getWsApiBase();
    const handshake = session.handshake;
    const url = `${wsBase}/ws/control${
        handshake ? `?handshake=${encodeURIComponent(handshake)}` : ""
    }`;
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    channel = createControlChannel(ws, relay, (msg, ch) => deviceCore.handle(msg, ch));

    try {
        if (reconnect) {
            await awaitDeviceAdmission(ws, channel);
        } else {
            const enroll = await awaitAdmission(ws, channel, session.sas);
            if (enroll) {
                await enrollDevice(ws, channel, serverUrl);
            }
        }
    } catch (err) {
        if (reconnect && serverUrl) {
            await deleteDeviceRecord(serverUrl);
        }
        channel.close();
        throw err;
    }

    let versionTimeout = null;
    let version;
    try {
        version = await awaitVersionAnnounce(ws, channel, (t) => {
            versionTimeout = t;
        });
    } catch (err) {
        if (versionTimeout !== null) {
            clearTimeout(versionTimeout);
        }
        channel.close();
        throw err;
    }
    if (versionTimeout !== null) {
        clearTimeout(versionTimeout);
    }

    ws.onerror = null;
    ws.onclose = (event) => {
        if (event.code === 4001) {
            handleDisconnected();
        } else {
            handleReconnection();
        }
    };

    heartbeatStop = startHeartbeat(channel, deviceCore, teardown);

    return {
        zellijVersion: version.zellij_version,
        appBundleSha384: version.app_bundle_sha384,
        controlChannel: channel,
        bufferedControl: channel.snapshotBuffered(),
    };
}

function awaitAdmission(ws, channel, sas) {
    return new Promise((resolve, reject) => {
        let settled = false;
        let admissionTimeout = null;
        const waitingModal =
            typeof showAdmissionWaitingModal === "function"
                ? showAdmissionWaitingModal(sas)
                : null;
        const finish = (fn, value) => {
            if (settled) {
                return;
            }
            settled = true;
            if (waitingModal) {
                waitingModal.close();
            }
            if (admissionTimeout !== null) {
                clearTimeout(admissionTimeout);
            }
            fn(value);
        };
        channel.onFrame((msg) => {
            if (settled) {
                return;
            }
            if (msg && msg.type === "Admitted") {
                channel.detachHandler();
                finish(resolve, msg.enroll === true);
            } else if (msg && msg.type === "Rejected") {
                channel.detachHandler();
                finish(reject, new Error(msg.reason || "the host did not admit this session"));
            } else {
                channel.bufferFrame(msg);
            }
        });
        ws.onerror = () => {
            finish(reject, new Error("control channel error before admission"));
        };
        ws.onclose = (event) => {
            finish(reject, new Error("control channel closed before admission"));
        };
        admissionTimeout = setTimeout(() => {
            finish(reject, new Error("timed out waiting to be admitted"));
        }, 100000);
    });
}

function awaitVersionAnnounce(ws, channel, setTimeoutRef) {
    return new Promise((resolve, reject) => {
        let settled = false;
        const finish = (fn, value) => {
            if (settled) {
                return;
            }
            settled = true;
            fn(value);
        };
        channel.onFrame((msg) => {
            if (settled) {
                return;
            }
            if (msg && msg.type === "VersionAnnounce") {
                channel.detachHandler();
                finish(resolve, msg);
            } else {
                channel.bufferFrame(msg);
            }
        });
        ws.onerror = () => {
            finish(reject, new Error("control channel error before VersionAnnounce"));
        };
        ws.onclose = (event) => {
            finish(reject, new Error("control channel closed before VersionAnnounce"));
        };
        channel.send({ type: "VersionRequest" });
        setTimeoutRef(
            setTimeout(() => {
                finish(reject, new Error("timed out waiting for VersionAnnounce"));
            }, 15000)
        );
    });
}
