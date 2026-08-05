use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use zellij_relay_protocol::crypto::ViewerKeys;
use zellij_utils::data::{RelayFailureReason, RelayShareStatus};
use zellij_utils::input::{config::Config, options::Options};

use zellij_browser_bridge::factory::SessionLinkFactory;
use zellij_browser_bridge::{BrowserBridge, ViewerId};

/// Phase 6 structured status of a single relay tunnel. Combined across the
/// session's tunnels into a `RelayShareStatus` for the share plugin (see
/// `RelayTunnelRegistry::share_status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayTunnelStatus {
    /// Tunnel is live; the carried URL matches what the relay handed back.
    Connected(String),
    /// Last known URL was `url`, reconnect is in progress; `attempt`
    /// counts consecutive reconnect cycles (1-based).
    Reconnecting {
        last_known_url: Option<String>,
        attempt: u32,
    },
    /// Reconnect budget exhausted or non-retryable error. `reason` is the typed
    /// cause; `message` is a human-readable diagnostic.
    Failed {
        reason: RelayFailureReason,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPluginEvent {
    AdmissionPending,
    DevicesChanged,
    GuestConnectionsChanged,
}

/// Handle to a running relay tunnel. Holds the shutdown signal whose firing
/// causes the multiplexer tasks to exit and the sockets to close.
pub struct RelayTunnelHandle {
    #[allow(dead_code)]
    pub public_url: String,
    #[allow(dead_code)]
    pub slug: String,
    #[allow(dead_code)]
    pub tunnel_id: String,
    /// Fires the initial multiplexer shutdown. Only consumed once by
    /// `run_supervisor`; reconnect iterations rely on `stop_requested`
    /// + a per-iteration oneshot instead.
    pub shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Cooperative stop flag checked by the supervisor around every
    /// reconnect boundary. `stop_relay_tunnel` flips it to `true`.
    pub stop_requested: Arc<AtomicBool>,
    /// Per-iteration shutdown signaller: the supervisor stores the
    /// current `oneshot::Sender<()>` here each time it kicks off a new
    /// `run_multiplexer`. `stop_relay_tunnel` drains it to forcibly
    /// break a live reconnected run.
    pub current_iteration_shutdown: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    /// Phase 6: latest known status for this tunnel, shared with the
    /// supervisor task. The server-side poll reads this and translates
    /// transitions into `RelayShareStatusChange` screen instructions.
    pub status: Arc<Mutex<RelayTunnelStatus>>,
    /// Phase 6 Session C: shared handle to the control-tunnel writer of
    /// the current (first or reconnected) iteration. Refreshed by the
    /// supervisor on every reconnect. Consumers send encoded
    /// `ControlMessage` bytes into this to reach the relay. `None` between
    /// reconnect boundaries. Currently unread (the token-hash revoke
    /// broadcast became a no-op under the E2E model); retained for the
    /// per-slug revoke/stop rewiring.
    #[allow(dead_code)]
    pub control_tx: Arc<Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>>,
}

/// Session-level registry. One `zellij-server` process hosts exactly one
/// session, so the share is session-scoped by construction: the `Vec` holds
/// the session's live tunnels (a read-write slug plus an optional read-only
/// slug), kept in insertion order. It is *not* keyed by `ClientId` — a second
/// local client or a reattaching sharer (new id) must see the same share.
#[derive(Default)]
pub struct RelayTunnelRegistry {
    inner: AsyncMutex<Vec<RelayTunnelHandle>>,
}

impl RelayTunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(RelayTunnelRegistry::default())
    }

    /// Append a tunnel to the session's share (does not replace existing
    /// tunnels).
    pub async fn insert(&self, handle: RelayTunnelHandle) {
        self.inner.lock().await.push(handle);
    }

    /// Remove and return *all* tunnels of the session's share.
    pub async fn remove(&self) -> Vec<RelayTunnelHandle> {
        std::mem::take(&mut *self.inner.lock().await)
    }

    /// Whether the session has a share that is still serving (any tunnel
    /// not in a terminal `Failed` state). A second `share` request consults
    /// this to avoid opening a duplicate tunnel.
    pub async fn is_live(&self) -> bool {
        self.inner
            .lock()
            .await
            .iter()
            .any(|h| !matches!(*h.status.lock().unwrap(), RelayTunnelStatus::Failed { .. }))
    }

    /// Map the session's tunnel status into the `RelayShareStatus` surfaced to
    /// the share plugin.
    pub async fn share_status(&self) -> Option<RelayShareStatus> {
        let guard = self.inner.lock().await;
        let primary = guard.first()?;
        let status = primary.status.lock().unwrap().clone();
        match status {
            RelayTunnelStatus::Reconnecting { attempt, .. } => {
                Some(RelayShareStatus::Reconnecting { attempt })
            },
            RelayTunnelStatus::Failed { reason, message } => {
                Some(RelayShareStatus::Failed { reason, message })
            },
            RelayTunnelStatus::Connected(url) => {
                Some(RelayShareStatus::Connected { url: Some(url) })
            },
        }
    }
}

pub type SharedRegistry = Arc<RelayTunnelRegistry>;

/// A PAKE handshake in progress between a viewer's `PakeChallenge` and its
/// `PakeConfirm`, keyed by `request_id`. The sharer runs `pake_finish` at
/// challenge time, so it holds the resulting key and the transcript needed to
/// verify the viewer's confirmation tag — not the (consumed) SPAKE2 state.
pub struct PendingPake {
    pub client_id: u32,
    pub pake_key: Vec<u8>,
    pub viewer_msg: Vec<u8>,
    pub sharer_msg: Vec<u8>,
    pub link_id: LinkId,
}

pub type LinkId = [u8; 16];

pub type CredentialMap = Arc<Mutex<HashMap<LinkId, Arc<GuestCredential>>>>;

pub const ADMISSION_TIMEOUT_SECS: u64 = 90;

pub const DEVICE_AUTH_TIMEOUT_SECS: u64 = 30;

pub const ENROLL_TIMEOUT_SECS: u64 = 120;

pub struct PendingEnroll {
    pub client_id: u32,
    pub link_id: LinkId,
    pub access: CredentialAccess,
    pub label: String,
    pub control_s2v: [u8; 32],
    pub control_v2s: [u8; 32],
    pub out_seq: u64,
    pub last_in_seq: Option<u64>,
    pub created_at: std::time::Instant,
    /// Device id assigned once the device's pubkey is enrolled. The live client
    /// is spawned under this id (not the single-use enrollment `link_id`) so it
    /// is attributed to the enrolled device rather than the consumed link.
    pub enrolled_device_id: Option<LinkId>,
}

pub struct PendingDeviceAuth {
    pub client_id: u32,
    pub link_id: LinkId,
    pub access: CredentialAccess,
    pub challenge: Vec<u8>,
    pub control_s2v: [u8; 32],
    pub control_v2s: [u8; 32],
    pub out_seq: u64,
    pub last_in_seq: Option<u64>,
    pub challenge_sent: bool,
    pub created_at: std::time::Instant,
}

pub struct PendingAdmission {
    pub client_id: u32,
    pub link_id: LinkId,
    pub sas: String,
    pub access: CredentialAccess,
    pub label: String,
    pub claimed_name: Option<String>,
    pub created_at: std::time::Instant,
}

impl PendingAdmission {
    pub fn seconds_remaining(&self) -> u64 {
        ADMISSION_TIMEOUT_SECS.saturating_sub(self.created_at.elapsed().as_secs())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Link,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialAccess {
    ReadOnly,
    ReadWrite,
}

impl CredentialAccess {
    pub fn is_read_only(self) -> bool {
        matches!(self, CredentialAccess::ReadOnly)
    }
}

pub struct GuestCredential {
    pub link_id: LinkId,
    pub secret: Vec<u8>,
    pub kind: CredentialKind,
    pub access: CredentialAccess,
    pub label: String,
    pub enroll: bool,
    pub spent: AtomicBool,
}

impl GuestCredential {
    pub fn device(
        link_id: LinkId,
        secret: Vec<u8>,
        access: CredentialAccess,
        label: String,
    ) -> Arc<Self> {
        Arc::new(GuestCredential {
            link_id,
            secret,
            kind: CredentialKind::Device,
            access,
            label,
            enroll: false,
            spent: AtomicBool::new(false),
        })
    }

    pub fn spend(&self) -> bool {
        !self.spent.swap(true, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn is_spent(&self) -> bool {
        self.spent.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Per-tunnel state owned by the multiplexer task. Each remote viewer that
/// completes the SPAKE2 handshake becomes a `RelayVirtualClient` entry here.
pub struct RelayTunnelState {
    /// Relay-side client_id allocator. Zellij is authoritative for these ids;
    /// the counter is per-tunnel and starts at 1.
    pub next_client_id: AtomicU32,
    /// Live virtual clients, keyed by the allocated client_id.
    pub clients: Mutex<HashMap<u32, RelayVirtualClient>>,
    /// Writer queue for encoded `ControlMessage` bytes.
    pub control_tunnel_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Writer queue for encoded `TerminalMessage` bytes.
    pub terminal_tunnel_tx: mpsc::UnboundedSender<Vec<u8>>,

    /// Tunnel id returned by the relay in `TunnelEstablished`. Folded (with
    /// the per-viewer `client_id`) into the HKDF `info` when deriving the
    /// per-viewer AES key from the confirmed SPAKE2 key.
    pub tunnel_id: String,
    /// Slug returned by the relay; binds the SPAKE2 identity so a handshake
    /// captured on one share cannot be replayed against another.
    pub slug: Mutex<String>,

    pub credentials: CredentialMap,

    /// Handshakes between `PakeChallenge` and `PakeConfirm`, keyed by
    /// `request_id`.
    pub pending_pake: Mutex<HashMap<Vec<u8>, PendingPake>>,
    /// Confirmed per-viewer AES keys, drained by `spawn_virtual_client`.
    /// Keyed by the Zellij-allocated `client_id`.
    pub pending_e2e_keys: Mutex<HashMap<u32, ViewerKeys>>,

    pub pending_admissions: Mutex<HashMap<u32, PendingAdmission>>,

    pub relay_event_notify: mpsc::UnboundedSender<RelayPluginEvent>,

    pub pending_device_auth: Mutex<HashMap<u32, PendingDeviceAuth>>,

    pub pending_enroll: Mutex<HashMap<u32, PendingEnroll>>,

    pub session_name: String,
    pub zellij_version: String,
    pub bridge: Arc<BrowserBridge>,
    pub os_api_factory: Arc<dyn SessionLinkFactory>,
    pub config: Arc<Mutex<Config>>,
    pub config_options: Options,
    pub config_file_path: PathBuf,
}

impl RelayTunnelState {
    pub fn select_credential(&self, link_id: &[u8]) -> Option<Arc<GuestCredential>> {
        let credentials = self.credentials.lock().unwrap();
        if link_id.is_empty() {
            return if credentials.len() == 1 {
                credentials.values().next().cloned()
            } else {
                None
            };
        }
        let key: LinkId = link_id.try_into().ok()?;
        credentials.get(&key).cloned()
    }
}

pub struct RelayVirtualClient {
    pub web_client_id: ViewerId,
    #[allow(dead_code)]
    pub is_read_only: bool,
    pub link_id: LinkId,
    pub terminal_input_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub control_input_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub control_out_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub shutdown: Option<oneshot::Sender<()>>,
}

