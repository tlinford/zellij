use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use serde::{Deserialize, Serialize};

use zellij_relay_protocol::crypto::{self, DEVICE_PUBKEY_LEN};
use zellij_utils::data::{DeviceScope, DeviceStorageLevel};

use crate::types::{CredentialAccess, GuestCredential, LinkId, RelayTunnelState};

const DEVICE_ID_LEN: usize = 16;
const DEVICE_SECRET_LEN: usize = 16;
const STORAGE_DIR_NAME: &str = "relay-devices";
const ROSTER_FILE_NAME: &str = "roster.json";
const HOST_IDENTITY_FILE_NAME: &str = "host_identity";
const REVOCATIONS_FILE_NAME: &str = "revocations.json";
const HOST_ID_LEN: usize = 16;
const REVOCATION_PRUNE_SECS: u64 = 7 * 24 * 60 * 60;
const REVOCATION_POLL_SECS: u64 = 3;

pub const SCOPE_SESSION: &str = "session";
pub const SCOPE_HOST: &str = "host";
pub const STORAGE_LEVEL_FILE: &str = "file, perms-only";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRecord {
    device_id: String,
    device_secret: String,
    pubkey: String,
    pubkey_alg: String,
    label: String,
    read_only: bool,
    scope: String,
    session_name: Option<String>,
    host_id: Option<String>,
    last_used: Option<u64>,
    storage_level: String,
    #[serde(default)]
    enrolled_from: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Roster {
    devices: Vec<DeviceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Revocation {
    device_id: String,
    revoked_at: u64,
    #[serde(default)]
    enrolled_from: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Revocations {
    entries: Vec<Revocation>,
}

#[derive(Debug, Clone)]
pub struct EnrolledDevice {
    pub device_id: Vec<u8>,
    pub device_secret: String,
    pub scope: DeviceScope,
    pub host_id: Option<String>,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub device_id: Vec<u8>,
    pub label: String,
    pub read_only: bool,
    pub scope: DeviceScope,
    pub last_used: Option<u64>,
    pub storage_level: DeviceStorageLevel,
    pub connected: bool,
}

struct DeviceTunnel {
    credentials: crate::types::CredentialMap,
    states: Vec<Weak<RelayTunnelState>>,
    host_id: String,
    session_name: String,
}

fn live_states(states: &[Weak<RelayTunnelState>]) -> Vec<Arc<RelayTunnelState>> {
    states.iter().filter_map(|w| w.upgrade()).collect()
}

#[cfg(test)]
fn live_state_count(credentials: &crate::types::CredentialMap) -> usize {
    let guard = tunnels().lock().unwrap();
    guard
        .iter()
        .find(|t| Arc::ptr_eq(&t.credentials, credentials))
        .map(|t| live_states(&t.states).len())
        .unwrap_or(0)
}

fn disconnect_link_everywhere(link_id: &LinkId, source: &str) {
    let guard = tunnels().lock().unwrap();
    log::info!(
        "{}: disconnecting link_id={} across {} tunnel(s)",
        source,
        hex_encode(link_id),
        guard.len()
    );
    for (idx, tunnel) in guard.iter().enumerate() {
        tunnel.credentials.lock().unwrap().remove(link_id);
        for (sidx, state) in live_states(&tunnel.states).iter().enumerate() {
            let present = crate::multiplexer::client_link_ids(state)
                .iter()
                .map(|id| hex_encode(id))
                .collect::<Vec<_>>()
                .join(",");
            let kicked = crate::multiplexer::disconnect_clients_with_link(state, link_id);
            let rejected = crate::multiplexer::reject_pending_with_link(state, link_id);
            log::info!(
                "{}: tunnel[{}].state[{}] connected link_ids=[{}]; kicked {} rejected {}",
                source, idx, sidx, present, kicked, rejected
            );
        }
    }
}

fn revocation_targets(device_id: &str, enrolled_from: Option<&str>) -> Vec<LinkId> {
    let mut targets = Vec::new();
    if let Some(l) = decode_link_id(device_id) {
        targets.push(l);
    }
    if let Some(ef) = enrolled_from {
        if let Some(l) = decode_link_id(ef) {
            if !targets.contains(&l) {
                targets.push(l);
            }
        }
    }
    targets
}

static TUNNELS: OnceLock<Mutex<Vec<DeviceTunnel>>> = OnceLock::new();
static STORAGE_DIR_OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
static REVOCATION_WATCHER_STARTED: OnceLock<()> = OnceLock::new();

fn tunnels() -> &'static Mutex<Vec<DeviceTunnel>> {
    TUNNELS.get_or_init(|| Mutex::new(Vec::new()))
}

fn storage_override() -> &'static Mutex<Option<PathBuf>> {
    STORAGE_DIR_OVERRIDE.get_or_init(|| Mutex::new(None))
}

fn storage_dir() -> PathBuf {
    if let Some(dir) = storage_override().lock().unwrap().clone() {
        return dir;
    }
    zellij_utils::home::get_default_data_dir().join(STORAGE_DIR_NAME)
}

fn ensure_storage_dir() -> std::io::Result<PathBuf> {
    let dir = storage_dir();
    std::fs::create_dir_all(&dir)?;
    restrict_permissions(&dir, 0o700);
    Ok(dir)
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path, _mode: u32) {}

fn read_roster() -> Roster {
    let path = storage_dir().join(ROSTER_FILE_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Roster::default(),
    }
}

fn write_roster(roster: &Roster) {
    let dir = match ensure_storage_dir() {
        Ok(d) => d,
        Err(e) => {
            log::error!("could not create device roster dir: {}", e);
            return;
        },
    };
    let path = dir.join(ROSTER_FILE_NAME);
    match serde_json::to_vec_pretty(roster) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                log::error!("could not write device roster: {}", e);
                return;
            }
            restrict_permissions(&path, 0o600);
        },
        Err(e) => log::error!("could not serialize device roster: {}", e),
    }
}

fn read_revocations() -> Revocations {
    let path = storage_dir().join(REVOCATIONS_FILE_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Revocations::default(),
    }
}

fn write_revocations(revocations: &Revocations) {
    let dir = match ensure_storage_dir() {
        Ok(d) => d,
        Err(e) => {
            log::error!("could not create device roster dir: {}", e);
            return;
        },
    };
    let path = dir.join(REVOCATIONS_FILE_NAME);
    match serde_json::to_vec_pretty(revocations) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(&path, bytes) {
                log::error!("could not write device revocations: {}", e);
                return;
            }
            restrict_permissions(&path, 0o600);
        },
        Err(e) => log::error!("could not serialize device revocations: {}", e),
    }
}

fn append_revocation(device_id: &str, enrolled_from: Option<&str>) {
    let now = unix_now();
    let mut revocations = read_revocations();
    revocations
        .entries
        .retain(|r| now.saturating_sub(r.revoked_at) < REVOCATION_PRUNE_SECS);
    revocations.entries.push(Revocation {
        device_id: device_id.to_string(),
        revoked_at: now,
        enrolled_from: enrolled_from.map(|s| s.to_string()),
    });
    write_revocations(&revocations);
}

fn process_revocations(high_water: u64) -> u64 {
    let revocations = read_revocations();
    let fresh: Vec<&Revocation> = revocations
        .entries
        .iter()
        .filter(|e| e.revoked_at > high_water)
        .collect();
    if !fresh.is_empty() {
        log::info!(
            "revocation watcher: {} total tombstone(s), {} newer than high_water={}",
            revocations.entries.len(),
            fresh.len(),
            high_water
        );
    }
    let mut new_high = high_water;
    for entry in fresh {
        if entry.revoked_at > new_high {
            new_high = entry.revoked_at;
        }
        let targets = revocation_targets(&entry.device_id, entry.enrolled_from.as_deref());
        if targets.is_empty() {
            log::warn!(
                "revocation watcher: tombstone device={} yielded no link_ids — skipping",
                entry.device_id
            );
            continue;
        }
        log::info!(
            "revocation watcher: applying tombstone device={} enrolled_from={:?} ({} link target(s))",
            entry.device_id,
            entry.enrolled_from,
            targets.len()
        );
        for link_id in &targets {
            disconnect_link_everywhere(link_id, "revocation watcher");
        }
    }
    new_high
}

fn event_touches_revocations(paths: &[PathBuf]) -> bool {
    paths.iter().any(|p| {
        p.file_name()
            .map(|n| n == std::ffi::OsStr::new(REVOCATIONS_FILE_NAME))
            .unwrap_or(false)
    })
}

fn spawn_revocation_fs_watcher(
    event_tx: tokio::sync::mpsc::UnboundedSender<()>,
) -> notify::Result<notify::RecommendedWatcher> {
    use notify::{RecursiveMode, Watcher};
    let dir = ensure_storage_dir()
        .map_err(|e| notify::Error::new(notify::ErrorKind::Generic(format!("storage dir: {}", e))))?;
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if event_touches_revocations(&event.paths) {
                let _ = event_tx.send(());
            }
        }
    })?;
    watcher.watch(&dir, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

pub fn start_revocation_watcher() {
    if REVOCATION_WATCHER_STARTED.set(()).is_err() {
        return;
    }
    let revocations_path = storage_dir().join(REVOCATIONS_FILE_NAME);
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let watcher = spawn_revocation_fs_watcher(event_tx);
    match &watcher {
        Ok(_) => log::info!(
            "revocation watcher: watching {} (with {}s safety poll)",
            revocations_path.display(),
            REVOCATION_POLL_SECS
        ),
        Err(e) => log::warn!(
            "revocation watcher: filesystem watch unavailable ({}) — falling back to {}s poll of {}",
            e,
            REVOCATION_POLL_SECS,
            revocations_path.display()
        ),
    }
    tokio::spawn(async move {
        let _watcher = watcher;
        let mut high_water: u64 = 0;
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(REVOCATION_POLL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                Some(_) = event_rx.recv() => {},
                _ = tick.tick() => {},
            }
            high_water = process_revocations(high_water);
        }
    });
}

pub fn load_or_create_host_id() -> String {
    let dir = match ensure_storage_dir() {
        Ok(d) => d,
        Err(_) => return hex_encode(&crypto::random_bytes(HOST_ID_LEN)),
    };
    let path = dir.join(HOST_IDENTITY_FILE_NAME);
    if let Ok(bytes) = std::fs::read(&path) {
        let existing = String::from_utf8_lossy(&bytes).trim().to_string();
        if !existing.is_empty() {
            return existing;
        }
    }
    let host_id = hex_encode(&crypto::random_bytes(HOST_ID_LEN));
    if std::fs::write(&path, host_id.as_bytes()).is_ok() {
        restrict_permissions(&path, 0o600);
    }
    host_id
}

pub fn register_tunnel(
    credentials: crate::types::CredentialMap,
    host_id: String,
    session_name: String,
) {
    {
        let mut guard = tunnels().lock().unwrap();
        if let Some(existing) = guard
            .iter_mut()
            .find(|t| Arc::ptr_eq(&t.credentials, &credentials))
        {
            existing.host_id = host_id.clone();
            existing.session_name = session_name.clone();
        } else {
            guard.push(DeviceTunnel {
                credentials: credentials.clone(),
                states: Vec::new(),
                host_id: host_id.clone(),
                session_name: session_name.clone(),
            });
        }
    }
    inject_matching_credentials(&credentials, &host_id, &session_name);
}

pub fn register_state(state: &Arc<RelayTunnelState>) {
    let credentials = state.credentials.clone();
    let mut guard = tunnels().lock().unwrap();
    if let Some(existing) = guard
        .iter_mut()
        .find(|t| Arc::ptr_eq(&t.credentials, &credentials))
    {
        existing
            .states
            .retain(|w| w.upgrade().map(|s| !Arc::ptr_eq(&s, state)).unwrap_or(false));
        existing.states.push(Arc::downgrade(state));
        log::info!(
            "device_roster::register_state matched tunnel; now tracking {} live state(s)",
            existing.states.len()
        );
    }
}

fn inject_matching_credentials(
    credentials: &crate::types::CredentialMap,
    host_id: &str,
    session_name: &str,
) {
    let roster = read_roster();
    for record in roster.devices.iter() {
        if !record_applies(record, host_id, session_name) {
            continue;
        }
        let Some(link_id) = decode_link_id(&record.device_id) else {
            continue;
        };
        let access = if record.read_only {
            CredentialAccess::ReadOnly
        } else {
            CredentialAccess::ReadWrite
        };
        let credential = GuestCredential::device(
            link_id,
            record.device_secret.clone().into_bytes(),
            access,
            record.label.clone(),
        );
        credentials
            .lock()
            .unwrap()
            .entry(link_id)
            .or_insert(credential);
    }
}

fn record_applies(record: &DeviceRecord, host_id: &str, session_name: &str) -> bool {
    match DeviceScope::from_token(&record.scope) {
        DeviceScope::Host if record.scope == SCOPE_HOST => {
            record.host_id.as_deref() == Some(host_id)
        },
        DeviceScope::Session if record.scope == SCOPE_SESSION => {
            record.session_name.as_deref() == Some(session_name)
        },
        _ => false,
    }
}

pub fn enroll(
    credentials: &crate::types::CredentialMap,
    access: CredentialAccess,
    label: String,
    pubkey: &[u8],
    pubkey_alg: &str,
    enrolled_from: Option<LinkId>,
) -> Result<EnrolledDevice, String> {
    let (host_id, session_name) = {
        let guard = tunnels().lock().unwrap();
        let tunnel = guard
            .iter()
            .find(|t| Arc::ptr_eq(&t.credentials, credentials))
            .ok_or_else(|| "device tunnel not registered".to_string())?;
        (tunnel.host_id.clone(), tunnel.session_name.clone())
    };

    let read_only = access.is_read_only();
    let scope = if read_only { SCOPE_SESSION } else { SCOPE_HOST };
    let link_id = fresh_device_id();
    let device_secret = hex_encode(&crypto::random_bytes(DEVICE_SECRET_LEN));

    let record = DeviceRecord {
        device_id: hex_encode(&link_id),
        device_secret: device_secret.clone(),
        pubkey: hex_encode(pubkey),
        pubkey_alg: pubkey_alg.to_string(),
        label,
        read_only,
        scope: scope.to_string(),
        session_name: if read_only {
            Some(session_name)
        } else {
            None
        },
        host_id: if read_only { None } else { Some(host_id.clone()) },
        last_used: Some(unix_now()),
        storage_level: STORAGE_LEVEL_FILE.to_string(),
        enrolled_from: enrolled_from.map(|l| hex_encode(&l)),
    };

    let mut roster = read_roster();
    roster.devices.push(record.clone());
    write_roster(&roster);

    let credential = GuestCredential::device(
        link_id,
        device_secret.clone().into_bytes(),
        access,
        record.label.clone(),
    );
    credentials.lock().unwrap().insert(link_id, credential);

    Ok(EnrolledDevice {
        device_id: link_id.to_vec(),
        device_secret,
        scope: DeviceScope::from_token(scope),
        host_id: if read_only { None } else { Some(host_id) },
        read_only,
    })
}

pub fn pinned_pubkey(link_id: &LinkId) -> Option<[u8; DEVICE_PUBKEY_LEN]> {
    let target = hex_encode(link_id);
    let roster = read_roster();
    let record = roster.devices.iter().find(|d| d.device_id == target)?;
    let bytes = decode_hex(&record.pubkey)?;
    <[u8; DEVICE_PUBKEY_LEN]>::try_from(bytes.as_slice()).ok()
}

pub fn mark_used(link_id: &LinkId) {
    let target = hex_encode(link_id);
    let mut roster = read_roster();
    let mut changed = false;
    let now = unix_now();
    for record in roster.devices.iter_mut() {
        if record.device_id == target {
            record.last_used = Some(now);
            changed = true;
        }
    }
    if changed {
        write_roster(&roster);
    }
}

pub fn revoke(device_id: &[u8]) -> bool {
    let target = hex_encode(device_id);
    let mut roster = read_roster();
    let enrolled_from = roster
        .devices
        .iter()
        .find(|d| d.device_id == target)
        .and_then(|d| d.enrolled_from.clone());
    let before = roster.devices.len();
    roster.devices.retain(|d| d.device_id != target);
    if roster.devices.len() == before {
        return false;
    }
    write_roster(&roster);
    let targets = revocation_targets(&target, enrolled_from.as_deref());
    log::info!(
        "device_roster::revoke device={} enrolled_from={:?} ({} link target(s))",
        target,
        enrolled_from,
        targets.len()
    );
    for link_id in &targets {
        disconnect_link_everywhere(link_id, "device_roster::revoke");
    }
    append_revocation(&target, enrolled_from.as_deref());
    true
}

pub fn list() -> Vec<DeviceInfo> {
    let (scopes, connected_link_ids) = {
        let guard = tunnels().lock().unwrap();
        let scopes = guard
            .iter()
            .map(|t| (t.host_id.clone(), t.session_name.clone()))
            .collect::<Vec<_>>();
        let mut connected = std::collections::HashSet::new();
        for tunnel in guard.iter() {
            for state in live_states(&tunnel.states) {
                for client in state.clients.lock().unwrap().values() {
                    connected.insert(client.link_id);
                }
            }
        }
        (scopes, connected)
    };
    let roster = read_roster();
    let mut out = Vec::new();
    for record in roster.devices.iter() {
        let applies = scopes
            .iter()
            .any(|(host_id, session_name)| record_applies(record, host_id, session_name));
        if !applies && !scopes.is_empty() {
            continue;
        }
        let Some(link_id) = decode_link_id(&record.device_id) else {
            continue;
        };
        out.push(DeviceInfo {
            device_id: link_id.to_vec(),
            label: record.label.clone(),
            read_only: record.read_only,
            scope: DeviceScope::from_token(&record.scope),
            last_used: record.last_used,
            storage_level: DeviceStorageLevel::from_token(&record.storage_level),
            connected: connected_link_ids.contains(&link_id),
        });
    }
    out.sort_by(|a, b| a.label.cmp(&b.label).then(a.device_id.cmp(&b.device_id)));
    out
}

pub fn clear() {
    tunnels().lock().unwrap().clear();
}

fn fresh_device_id() -> LinkId {
    let roster = read_roster();
    loop {
        let bytes = crypto::random_bytes(DEVICE_ID_LEN);
        let mut id = [0u8; DEVICE_ID_LEN];
        id.copy_from_slice(&bytes);
        let hex = hex_encode(&id);
        if id != [0u8; DEVICE_ID_LEN] && !roster.devices.iter().any(|d| d.device_id == hex) {
            return id;
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_link_id(hex: &str) -> Option<LinkId> {
    let bytes = decode_hex(hex)?;
    <LinkId>::try_from(bytes.as_slice()).ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn use_temp_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        *storage_override().lock().unwrap() = Some(dir.path().to_path_buf());
        dir
    }

    fn fresh_registry() -> crate::types::CredentialMap {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn registered_state(host_id: &str, session: &str) -> Arc<RelayTunnelState> {
        let (state, _ctrl_tunnel_rx) = crate::multiplexer::test_support::make_state();
        register_tunnel(
            state.credentials.clone(),
            host_id.to_string(),
            session.to_string(),
        );
        register_state(&state);
        state
    }

    fn enroll_device(
        credentials: &crate::types::CredentialMap,
        access: CredentialAccess,
        enrolled_from: Option<LinkId>,
    ) -> (EnrolledDevice, LinkId) {
        let (_, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            credentials,
            access,
            "laptop".to_string(),
            &pubkey,
            "ed25519",
            enrolled_from,
        )
        .expect("enroll");
        let link_id = <LinkId>::try_from(enrolled.device_id.as_slice()).unwrap();
        (enrolled, link_id)
    }

    fn assert_rejected(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let frame = rx.try_recv().expect("a reject frame was sent to the viewer");
        let parsed: zellij_browser_bridge::protocol::ToBrowser =
            serde_json::from_slice(&frame).expect("valid ToBrowser frame");
        assert!(
            matches!(parsed, zellij_browser_bridge::protocol::ToBrowser::Rejected { .. }),
            "expected Rejected, got {:?}",
            parsed
        );
    }

    #[test]
    fn enroll_persists_and_reloads_as_credential() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let credentials = fresh_registry();
        register_tunnel(credentials.clone(), host_id.clone(), "sess".to_string());

        let (_, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            &credentials,
            CredentialAccess::ReadWrite,
            "laptop".to_string(),
            &pubkey,
            "ed25519",
            None,
        )
        .expect("enroll");
        assert_eq!(enrolled.scope, DeviceScope::Host);
        assert_eq!(enrolled.host_id.as_deref(), Some(host_id.as_str()));

        let link_id = <LinkId>::try_from(enrolled.device_id.as_slice()).unwrap();
        assert!(credentials.lock().unwrap().contains_key(&link_id));
        assert_eq!(pinned_pubkey(&link_id), Some(pubkey));

        let reloaded = fresh_registry();
        register_tunnel(reloaded.clone(), host_id, "sess".to_string());
        assert!(reloaded.lock().unwrap().contains_key(&link_id));

        clear();
    }

    #[test]
    fn revoke_removes_credential_and_pinned_key() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let credentials = fresh_registry();
        register_tunnel(credentials.clone(), host_id, "sess".to_string());

        let (_, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            &credentials,
            CredentialAccess::ReadWrite,
            "phone".to_string(),
            &pubkey,
            "ed25519",
            None,
        )
        .expect("enroll");
        let link_id = <LinkId>::try_from(enrolled.device_id.as_slice()).unwrap();

        assert_eq!(list().len(), 1);
        assert!(revoke(&enrolled.device_id));
        assert!(!credentials.lock().unwrap().contains_key(&link_id));
        assert!(pinned_pubkey(&link_id).is_none());
        assert!(list().is_empty());
        assert!(!revoke(&enrolled.device_id));

        clear();
    }

    #[test]
    fn enroll_then_sign_verifies_until_revoked() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let credentials = fresh_registry();
        register_tunnel(credentials.clone(), host_id, "sess".to_string());

        let (seed, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            &credentials,
            CredentialAccess::ReadWrite,
            "laptop".to_string(),
            &pubkey,
            "ed25519",
            None,
        )
        .expect("enroll");
        let link_id = <LinkId>::try_from(enrolled.device_id.as_slice()).unwrap();

        let challenge = crypto::random_bytes(crypto::DEVICE_CHALLENGE_LEN);
        let signature = crypto::sign_device_challenge(&seed, &challenge);
        let pinned = pinned_pubkey(&link_id).expect("pinned key present after enroll");
        assert!(crypto::verify_device_challenge(&pinned, &challenge, &signature));

        assert!(revoke(&enrolled.device_id));
        assert!(pinned_pubkey(&link_id).is_none());

        clear();
    }

    #[test]
    fn revocation_tombstone_processed_by_poller() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");

        let link_id = [9u8; DEVICE_ID_LEN];
        state.credentials.lock().unwrap().insert(
            link_id,
            GuestCredential::device(
                link_id,
                b"secret".to_vec(),
                CredentialAccess::ReadWrite,
                "laptop".to_string(),
            ),
        );
        let mut ctrl_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, link_id);
        append_revocation(&hex_encode(&link_id), None);

        let high = process_revocations(0);
        assert!(high > 0);
        assert!(!state.credentials.lock().unwrap().contains_key(&link_id));
        assert_rejected(&mut ctrl_rx);
        assert!(state.clients.lock().unwrap().is_empty());

        clear();
    }

    #[test]
    fn revocation_tombstone_prunes_old_entries() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let mut revocations = Revocations::default();
        revocations.entries.push(Revocation {
            device_id: "deadbeef".to_string(),
            revoked_at: unix_now().saturating_sub(REVOCATION_PRUNE_SECS + 10),
            enrolled_from: None,
        });
        write_revocations(&revocations);

        append_revocation("00112233", None);
        let reloaded = read_revocations();
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.entries[0].device_id, "00112233");

        clear();
    }

    #[test]
    fn high_water_mark_skips_seen_tombstone() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let credentials = fresh_registry();
        register_tunnel(credentials.clone(), host_id, "sess".to_string());

        let (_, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            &credentials,
            CredentialAccess::ReadWrite,
            "laptop".to_string(),
            &pubkey,
            "ed25519",
            None,
        )
        .expect("enroll");
        let link_id = <LinkId>::try_from(enrolled.device_id.as_slice()).unwrap();
        assert!(revoke(&enrolled.device_id));

        let high = process_revocations(0);
        assert!(high > 0);

        credentials.lock().unwrap().insert(
            link_id,
            GuestCredential::device(
                link_id,
                b"resurrected".to_vec(),
                CredentialAccess::ReadWrite,
                "laptop".to_string(),
            ),
        );
        let high2 = process_revocations(high);
        assert_eq!(high2, high);
        assert!(credentials.lock().unwrap().contains_key(&link_id));

        clear();
    }

    #[test]
    fn read_only_device_is_session_scoped() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let credentials = fresh_registry();
        register_tunnel(credentials.clone(), host_id.clone(), "sess-a".to_string());

        let (_, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            &credentials,
            CredentialAccess::ReadOnly,
            "tablet".to_string(),
            &pubkey,
            "ed25519",
            None,
        )
        .expect("enroll");
        assert_eq!(enrolled.scope, DeviceScope::Session);

        let other_session = fresh_registry();
        register_tunnel(other_session.clone(), host_id, "sess-b".to_string());
        let link_id = <LinkId>::try_from(enrolled.device_id.as_slice()).unwrap();
        assert!(!other_session.lock().unwrap().contains_key(&link_id));

        clear();
    }

    #[test]
    fn revocation_targets_cover_device_and_origin_link() {
        let device = "0102030405060708090a0b0c0d0e0f10";
        let origin = "1112131415161718191a1b1c1d1e1f20";
        assert_eq!(revocation_targets(device, Some(origin)).len(), 2);
        assert_eq!(revocation_targets(device, None).len(), 1);
        assert_eq!(revocation_targets(device, Some(device)).len(), 1);
    }

    #[test]
    fn revoke_tombstone_carries_enrolled_from_origin_link() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let credentials = fresh_registry();
        register_tunnel(credentials.clone(), host_id, "sess".to_string());

        let origin_link: LinkId = [9u8; 16];
        let (_, pubkey) = crypto::generate_device_keypair();
        let enrolled = enroll(
            &credentials,
            CredentialAccess::ReadWrite,
            "laptop".to_string(),
            &pubkey,
            "ed25519",
            Some(origin_link),
        )
        .expect("enroll");

        let stored = read_roster();
        assert_eq!(
            stored.devices[0].enrolled_from.as_deref(),
            Some(hex_encode(&origin_link).as_str())
        );

        assert!(revoke(&enrolled.device_id));
        let revocations = read_revocations();
        let entry = revocations.entries.last().expect("tombstone written");
        assert_eq!(entry.enrolled_from.as_deref(), Some(hex_encode(&origin_link).as_str()));
        assert_eq!(
            revocation_targets(&entry.device_id, entry.enrolled_from.as_deref()).len(),
            2
        );

        clear();
    }

    #[test]
    fn revoke_kicks_device_auth_reconnect_on_own_link() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");
        let (enrolled, device_link) =
            enroll_device(&state.credentials, CredentialAccess::ReadWrite, None);

        let mut ctrl_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, device_link);
        assert!(revoke(&enrolled.device_id));
        assert_rejected(&mut ctrl_rx);
        assert!(state.clients.lock().unwrap().is_empty());

        clear();
    }

    #[test]
    fn revoke_kicks_enrollment_session_on_origin_link() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");
        let guest_link: LinkId = [4u8; 16];
        let (enrolled, _device_link) =
            enroll_device(&state.credentials, CredentialAccess::ReadWrite, Some(guest_link));

        let mut ctrl_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, guest_link);
        assert!(revoke(&enrolled.device_id));
        assert_rejected(&mut ctrl_rx);
        assert!(state.clients.lock().unwrap().is_empty());

        clear();
    }

    #[test]
    fn revoke_leaves_unrelated_viewer_connected() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");
        let (enrolled, _device_link) =
            enroll_device(&state.credentials, CredentialAccess::ReadWrite, None);

        let other_link: LinkId = [5u8; 16];
        let mut ctrl_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, other_link);
        assert!(revoke(&enrolled.device_id));
        assert!(ctrl_rx.try_recv().is_err());
        assert!(state.clients.lock().unwrap().contains_key(&1));

        clear();
    }

    #[test]
    fn revoke_kicks_all_device_sessions() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");
        let (enrolled, device_link) =
            enroll_device(&state.credentials, CredentialAccess::ReadWrite, None);

        let mut rx1 =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, device_link);
        let mut rx2 =
            crate::multiplexer::test_support::insert_connected_client(&state, 2, device_link);
        let mut rx3 =
            crate::multiplexer::test_support::insert_connected_client(&state, 3, device_link);
        assert!(revoke(&enrolled.device_id));
        assert_rejected(&mut rx1);
        assert_rejected(&mut rx2);
        assert_rejected(&mut rx3);
        assert!(state.clients.lock().unwrap().is_empty());

        clear();
    }

    #[test]
    fn old_binary_enrollment_session_survives_revoke() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");
        let (enrolled, device_link) =
            enroll_device(&state.credentials, CredentialAccess::ReadWrite, None);

        let guest_link: LinkId = [6u8; 16];
        let mut device_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, device_link);
        let mut guest_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 2, guest_link);
        assert!(revoke(&enrolled.device_id));
        assert_rejected(&mut device_rx);
        assert!(guest_rx.try_recv().is_err());
        assert!(!state.clients.lock().unwrap().contains_key(&1));
        assert!(state.clients.lock().unwrap().contains_key(&2));

        clear();
    }

    #[test]
    fn revoke_kicks_across_all_live_states() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let (state_a, _) = crate::multiplexer::test_support::make_state();
        let credentials = state_a.credentials.clone();
        register_tunnel(credentials.clone(), host_id, "sess".to_string());
        register_state(&state_a);
        let (state_b, _) =
            crate::multiplexer::test_support::make_state_with_credentials(credentials.clone());
        register_state(&state_b);
        assert_eq!(live_state_count(&credentials), 2);

        let (enrolled, device_link) =
            enroll_device(&credentials, CredentialAccess::ReadWrite, None);
        let mut rx_a =
            crate::multiplexer::test_support::insert_connected_client(&state_a, 1, device_link);
        assert!(revoke(&enrolled.device_id));
        assert_rejected(&mut rx_a);
        assert!(state_a.clients.lock().unwrap().is_empty());

        clear();
    }

    #[test]
    fn register_state_dedupes_and_prunes_dead_weaks() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let (state, _) = crate::multiplexer::test_support::make_state();
        let credentials = state.credentials.clone();
        register_tunnel(credentials.clone(), host_id, "sess".to_string());
        register_state(&state);
        register_state(&state);
        assert_eq!(live_state_count(&credentials), 1);

        {
            let (transient, _) =
                crate::multiplexer::test_support::make_state_with_credentials(credentials.clone());
            register_state(&transient);
            assert_eq!(live_state_count(&credentials), 2);
        }
        assert_eq!(live_state_count(&credentials), 1);

        register_state(&state);
        assert_eq!(live_state_count(&credentials), 1);

        let (enrolled, device_link) =
            enroll_device(&credentials, CredentialAccess::ReadWrite, None);
        let mut rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, device_link);
        assert!(revoke(&enrolled.device_id));
        assert_rejected(&mut rx);

        clear();
    }

    #[test]
    fn tombstone_with_enrolled_from_disconnects_both_links() {
        let _guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let _tmp = use_temp_dir();
        let host_id = load_or_create_host_id();
        let state = registered_state(&host_id, "sess");

        let device_link: LinkId = [9u8; 16];
        let guest_link: LinkId = [10u8; 16];
        for link in [device_link, guest_link] {
            state.credentials.lock().unwrap().insert(
                link,
                GuestCredential::device(
                    link,
                    b"secret".to_vec(),
                    CredentialAccess::ReadWrite,
                    "laptop".to_string(),
                ),
            );
        }
        let mut device_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 1, device_link);
        let mut guest_rx =
            crate::multiplexer::test_support::insert_connected_client(&state, 2, guest_link);
        append_revocation(&hex_encode(&device_link), Some(&hex_encode(&guest_link)));

        let high = process_revocations(0);
        assert!(high > 0);
        assert_rejected(&mut device_rx);
        assert_rejected(&mut guest_rx);
        assert!(state.clients.lock().unwrap().is_empty());

        clear();
    }

    #[test]
    fn event_touches_revocations_matches_only_revocations_file() {
        assert!(event_touches_revocations(&[PathBuf::from(
            "/some/dir/revocations.json"
        )]));
        assert!(!event_touches_revocations(&[PathBuf::from("/some/dir/roster.json")]));
        assert!(!event_touches_revocations(&[]));
        assert!(event_touches_revocations(&[
            PathBuf::from("/a/roster.json"),
            PathBuf::from("/a/revocations.json"),
        ]));
    }

    #[test]
    fn device_record_deserializes_without_enrolled_from() {
        let json = r#"{
            "device_id":"aa","device_secret":"bb","pubkey":"cc","pubkey_alg":"ed25519",
            "label":"laptop","read_only":false,"scope":"host","session_name":null,
            "host_id":"h","last_used":null,"storage_level":"file, perms-only"
        }"#;
        let rec: DeviceRecord = serde_json::from_str(json).unwrap();
        assert!(rec.enrolled_from.is_none());
        assert_eq!(rec.device_id, "aa");
    }

    #[test]
    fn revocation_deserializes_without_enrolled_from() {
        let json = r#"{"device_id":"aa","revoked_at":5}"#;
        let rev: Revocation = serde_json::from_str(json).unwrap();
        assert!(rev.enrolled_from.is_none());
        assert_eq!(rev.revoked_at, 5);
    }
}
