const DB_NAME = "zellij-device-store";
const STORE = "devices";
const DB_VERSION = 1;

function openDb() {
    return new Promise((resolve, reject) => {
        let req;
        try {
            req = indexedDB.open(DB_NAME, DB_VERSION);
        } catch (err) {
            reject(err);
            return;
        }
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(STORE)) {
                db.createObjectStore(STORE, { keyPath: "serverUrl" });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function loadDeviceRecord(serverUrl) {
    let db;
    try {
        db = await openDb();
    } catch (_) {
        return null;
    }
    return new Promise((resolve) => {
        let tx;
        try {
            tx = db.transaction(STORE, "readonly");
        } catch (_) {
            resolve(null);
            return;
        }
        const req = tx.objectStore(STORE).get(serverUrl);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
    });
}

export async function saveDeviceRecord(record) {
    let db;
    try {
        db = await openDb();
    } catch (_) {
        return;
    }
    await new Promise((resolve) => {
        let tx;
        try {
            tx = db.transaction(STORE, "readwrite");
        } catch (_) {
            resolve();
            return;
        }
        tx.objectStore(STORE).put(record);
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
        tx.onabort = () => resolve();
    });
}

export async function deleteDeviceRecord(serverUrl) {
    let db;
    try {
        db = await openDb();
    } catch (_) {
        return;
    }
    await new Promise((resolve) => {
        let tx;
        try {
            tx = db.transaction(STORE, "readwrite");
        } catch (_) {
            resolve();
            return;
        }
        tx.objectStore(STORE).delete(serverUrl);
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
        tx.onabort = () => resolve();
    });
}
