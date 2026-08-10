#![cfg(unix)]

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serial_test::serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use zellij_relay_server::{
    registry::Registry,
    relay_tunnel_auth_tokens::{store_new_relay_tunnel_auth_token, ENV_DATA_DIR},
    router::{build_router, AppState},
};

use zellij_browser_bridge::factory::{SessionLinkFactory, SessionSource};
use zellij_browser_bridge::virtual_client::SessionLink;
use zellij_browser_bridge::BrowserBridge;

use zellij_relay_client::{
    admissions, guest_links, start_relay_tunnel, stop_relay_tunnel, RelayPluginEvent,
    RelayTunnelStatus,
};

use zellij_client::os_input_output::{AsyncSignals, AsyncStdin, ClientOsApi, SignalEvent};
use zellij_client::remote_attach::{attach_to_remote_session, join_secret_from_url};
use zellij_client::{run_admission_handshake, run_remote_client_terminal_loop};

use zellij_utils::data::Palette;
use zellij_utils::errors::ErrorContext;
use zellij_utils::input::config::Config;
use zellij_utils::input::options::Options;
use zellij_utils::ipc::{ClientToServerMsg, ExitReason, ServerToClientMsg};
use zellij_utils::pane_size::Size;
use zellij_utils::shared::default_palette;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_graceful_host_quit_disconnects_the_guest() {
    let world = RelayWorld::start().await;
    let guest = world.a_guest_connects().await;

    world.the_host_quits_the_session().await;

    guest.expect_disconnected().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn revoking_the_guest_link_disconnects_the_guest() {
    let world = RelayWorld::start().await;
    let guest = world.a_guest_connects().await;

    world.the_host_revokes(&guest);

    guest.expect_disconnected().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn killing_the_relay_disconnects_the_guest() {
    let world = RelayWorld::start().await;
    let guest = world.a_guest_connects().await;

    world.the_relay_drops_the_tunnel().await;

    guest.expect_disconnected().await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_silent_connection_trips_the_guest_heartbeat() {
    let world = RelayWorld::start_behind_a_pausable_network().await;
    let guest = world.a_guest_connects().await;

    world.the_network_goes_silent();

    guest.expect_disconnected().await;
}

struct RelayWorld {
    address_the_guest_dials: SocketAddr,
    relay_registry: Registry,
    host: Host,
    pausable_network: Option<PausableNetwork>,
}

struct ConnectedGuest {
    events: std_mpsc::Receiver<GuestEvent>,
    guest_link_id: Vec<u8>,
    _thread: std::thread::JoinHandle<()>,
}

impl RelayWorld {
    async fn start() -> Self {
        Self::start_inner(false).await
    }

    async fn start_behind_a_pausable_network() -> Self {
        Self::start_inner(true).await
    }

    async fn start_inner(route_the_guest_through_a_pausable_proxy: bool) -> Self {
        isolate_process_state();
        clear_process_global_registries().await;
        forget_heartbeat_overrides();

        let (relay_address, relay_registry) = spawn_relay().await;
        let token = shared_relay_auth_token().to_string();
        let host = spawn_host(&format!("ws://{}", relay_address), &token).await;

        let (address_the_guest_dials, pausable_network) =
            if route_the_guest_through_a_pausable_proxy {
                shorten_heartbeat_to_two_seconds();
                let proxy = PausableNetwork::in_front_of(relay_address).await;
                (proxy.address, Some(proxy))
            } else {
                (relay_address, None)
            };

        RelayWorld {
            address_the_guest_dials,
            relay_registry,
            host,
            pausable_network,
        }
    }

    async fn a_guest_connects(&self) -> ConnectedGuest {
        let link = guest_links::mint(false, "guest".into(), false).expect("host minted a guest link");
        let secret = join_secret_from_url(&link.url).expect("the guest link carries its secret");
        let dial_url = guest_dial_url(
            self.address_the_guest_dials,
            &self.host.slug,
            &secret,
            &hex_encode(&link.link_id),
        );

        let guest = spawn_guest(dial_url);
        self.host_admits_the_waiting_guest().await;
        match next_guest_event(&guest.events, step_timeout()).await {
            GuestEvent::Connected => {},
            other => panic!("the guest never finished connecting: {:?}", other),
        }
        ConnectedGuest {
            events: guest.events,
            guest_link_id: link.link_id,
            _thread: guest.thread,
        }
    }

    async fn host_admits_the_waiting_guest(&self) {
        let client_id = wait_for(
            "a guest to reach the admission gate",
            || admissions::list().first().map(|pending| pending.client_id),
            step_timeout(),
        )
        .await;
        admissions::resolve(client_id, true, true).expect("host admitted the guest");
    }

    async fn the_host_quits_the_session(&self) {
        let session = wait_for(
            "the host to attach the guest's session",
            || self.host.session_channels.lock().unwrap().first().cloned(),
            step_timeout(),
        )
        .await;
        session
            .send(ServerToClientMsg::Exit {
                exit_reason: ExitReason::Normal,
            })
            .expect("the host's session-quit reached the bridge");
    }

    fn the_host_revokes(&self, guest: &ConnectedGuest) {
        assert!(
            guest_links::revoke(&guest.guest_link_id),
            "the host's revoke matched the live guest link"
        );
    }

    async fn the_relay_drops_the_tunnel(&self) {
        wait_for(
            "the relay to register the connected guest",
            || {
                self.relay_registry
                    .get(&self.host.slug)
                    .filter(|tunnel| !tunnel.viewers.lock().unwrap().is_empty())
                    .map(|_| ())
            },
            step_timeout(),
        )
        .await;

        let tunnel = self
            .relay_registry
            .remove(&self.host.slug)
            .expect("the relay was holding the tunnel");
        for guest in tunnel.viewers.lock().unwrap().values_mut() {
            if let Some(close_terminal) = guest.disconnect_terminal.take() {
                let _ = close_terminal.send(());
            }
            if let Some(close_control) = guest.disconnect_control.take() {
                let _ = close_control.send(());
            }
        }
    }

    fn the_network_goes_silent(&self) {
        self.pausable_network
            .as_ref()
            .expect("this world routes the guest through a pausable network")
            .stop_forwarding();
    }
}

impl Drop for RelayWorld {
    fn drop(&mut self) {
        forget_heartbeat_overrides();
    }
}

impl ConnectedGuest {
    async fn expect_disconnected(&self) {
        match next_guest_event(&self.events, disconnect_timeout()).await {
            GuestEvent::Exited(_) => {},
            other => panic!("the guest stayed connected instead of disconnecting: {:?}", other),
        }
    }
}

const RELAY_PUBLIC_URL_TEMPLATE: &str = "http://localhost:8765/r/{slug}";
const HEARTBEAT_INTERVAL_ENV: &str = "ZELLIJ_ATTACH_HEARTBEAT_INTERVAL_SECS";
const HEARTBEAT_TIMEOUT_ENV: &str = "ZELLIJ_ATTACH_HEARTBEAT_TIMEOUT_SECS";

fn step_timeout() -> Duration {
    std::env::var("ZELLIJ_TEST_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(20))
}

fn disconnect_timeout() -> Duration {
    step_timeout().max(Duration::from_secs(30))
}

fn shorten_heartbeat_to_two_seconds() {
    std::env::set_var(HEARTBEAT_INTERVAL_ENV, "2");
    std::env::set_var(HEARTBEAT_TIMEOUT_ENV, "2");
}

fn forget_heartbeat_overrides() {
    std::env::remove_var(HEARTBEAT_INTERVAL_ENV);
    std::env::remove_var(HEARTBEAT_TIMEOUT_ENV);
}

fn isolate_process_state() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let base = std::env::temp_dir().join(format!("zellij-relay-e2e-{}", uuid::Uuid::new_v4()));
        for leaf in ["home", "data", "cache", "config", "run", "tmp"] {
            std::fs::create_dir_all(base.join(leaf)).ok();
        }
        std::env::set_var("HOME", base.join("home"));
        std::env::set_var("XDG_DATA_HOME", base.join("data"));
        std::env::set_var("XDG_CACHE_HOME", base.join("cache"));
        std::env::set_var("XDG_CONFIG_HOME", base.join("config"));
        std::env::set_var("XDG_RUNTIME_DIR", base.join("run"));
        std::env::set_var("TMPDIR", base.join("tmp"));
    });
}

async fn clear_process_global_registries() {
    stop_relay_tunnel().await;
    admissions::clear();
}

fn shared_relay_auth_token() -> &'static str {
    static TOKEN: OnceLock<String> = OnceLock::new();
    TOKEN.get_or_init(|| {
        let scratch = std::env::temp_dir().join(format!("zellij-relay-it-{}", uuid::Uuid::new_v4()));
        std::env::set_var(ENV_DATA_DIR, &scratch);
        store_new_relay_tunnel_auth_token(Some("integration-test".into()))
            .expect("minted the relay's tunnel-auth token")
    })
}

async fn spawn_relay() -> (SocketAddr, Registry) {
    let _ = shared_relay_auth_token();
    let state = AppState::new(RELAY_PUBLIC_URL_TEMPLATE.to_string(), vec![]);
    let registry = state.registry.clone();
    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (address, registry)
}

struct Host {
    slug: String,
    session_channels: Arc<Mutex<Vec<std_mpsc::Sender<ServerToClientMsg>>>>,
    _status: mpsc::UnboundedReceiver<RelayTunnelStatus>,
}

async fn spawn_host(relay_ws: &str, token: &str) -> Host {
    let session_channels = Arc::new(Mutex::new(Vec::new()));
    let factory: Arc<dyn SessionLinkFactory> = Arc::new(HostSessionFactory {
        session_channels: session_channels.clone(),
    });
    let source: Arc<dyn SessionSource> = Arc::new(NoResumableSessions);
    let bridge = BrowserBridge::new(source);
    let (status_tx, status_rx) = mpsc::unbounded_channel::<RelayTunnelStatus>();
    let (relay_event_tx, _relay_event_rx) = mpsc::unbounded_channel::<RelayPluginEvent>();

    let share_url = start_relay_tunnel(
        relay_ws.to_string(),
        "relay-e2e".to_string(),
        "0.0.0-test".to_string(),
        token.to_string(),
        status_tx,
        relay_event_tx,
        bridge,
        factory,
        Arc::new(Mutex::new(Config::default())),
        Options::default(),
        PathBuf::new(),
    )
    .await
    .expect("host opened a relay tunnel");

    Host {
        slug: slug_of(&share_url),
        session_channels,
        _status: status_rx,
    }
}

fn slug_of(share_url: &str) -> String {
    share_url
        .split("/r/")
        .nth(1)
        .expect("a share url carries /r/<slug>")
        .split(|c| c == '/' || c == '#' || c == '?')
        .next()
        .unwrap()
        .to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn guest_dial_url(relay: SocketAddr, slug: &str, secret: &str, link_hex: &str) -> String {
    format!("http://{relay}/r/{slug}#k={secret}&l={link_hex}")
}

#[derive(Debug)]
#[allow(dead_code)]
enum GuestEvent {
    Connected,
    Failed(String),
    Exited(Result<(), String>),
}

struct SpawnedGuest {
    events: std_mpsc::Receiver<GuestEvent>,
    thread: std::thread::JoinHandle<()>,
}

fn spawn_guest(dial_url: String) -> SpawnedGuest {
    let (report, events) = std_mpsc::channel();
    let thread = std::thread::Builder::new()
        .name("relay-e2e-guest".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let terminal = HeadlessTerminal::new();
            let attach = attach_to_remote_session(
                runtime.handle().clone(),
                &dial_url,
                None,
                false,
                false,
                false,
                None,
                true,
                &[],
            );
            let mut session = match attach {
                Ok(session) => session,
                Err(e) => {
                    let _ = report.send(GuestEvent::Failed(format!("attach: {}", e)));
                    return;
                },
            };
            if let Err(e) = runtime.block_on(run_admission_handshake(&mut session)) {
                let _ = report.send(GuestEvent::Failed(format!("handshake: {}", e)));
                return;
            }
            let _ = report.send(GuestEvent::Connected);
            let outcome =
                runtime.block_on(run_remote_client_terminal_loop(Box::new(terminal), session, None));
            let _ = report.send(GuestEvent::Exited(outcome.map(|_| ()).map_err(|e| e.to_string())));
        })
        .unwrap();
    SpawnedGuest { events, thread }
}

async fn wait_for<T>(what: &str, produce: impl Fn() -> Option<T>, timeout: Duration) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = produce() {
            return value;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for {}", what);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn next_guest_event(events: &std_mpsc::Receiver<GuestEvent>, timeout: Duration) -> GuestEvent {
    let deadline = Instant::now() + timeout;
    loop {
        match events.try_recv() {
            Ok(event) => return event,
            Err(std_mpsc::TryRecvError::Empty) => {
                if Instant::now() >= deadline {
                    panic!("timed out waiting for the guest to report an event");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
            Err(std_mpsc::TryRecvError::Disconnected) => {
                panic!("the guest thread ended without reporting an event");
            },
        }
    }
}

struct PausableNetwork {
    address: SocketAddr,
    forwarding: Arc<AtomicBool>,
}

impl PausableNetwork {
    async fn in_front_of(upstream: SocketAddr) -> Self {
        let forwarding = Arc::new(AtomicBool::new(true));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let forwarding_for_acceptor = forwarding.clone();
        tokio::spawn(async move {
            loop {
                let (guest_side, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let relay_side = match tokio::net::TcpStream::connect(upstream).await {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                let forwarding_for_conn = forwarding_for_acceptor.clone();
                tokio::spawn(async move {
                    let (from_guest, to_guest) = guest_side.into_split();
                    let (from_relay, to_relay) = relay_side.into_split();
                    let upstream_leg = tokio::spawn(forward_while_open(
                        from_guest,
                        to_relay,
                        forwarding_for_conn.clone(),
                    ));
                    let downstream_leg =
                        tokio::spawn(forward_while_open(from_relay, to_guest, forwarding_for_conn));
                    let _ = upstream_leg.await;
                    let _ = downstream_leg.await;
                });
            }
        });
        PausableNetwork { address, forwarding }
    }

    fn stop_forwarding(&self) {
        self.forwarding.store(false, Ordering::Relaxed);
    }
}

async fn forward_while_open(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    forwarding: Arc<AtomicBool>,
) {
    let mut buffer = vec![0u8; 8192];
    loop {
        if !forwarding.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        tokio::select! {
            read = reader.read(&mut buffer) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        if writer.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    },
                    Err(_) => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
}

#[derive(Clone)]
struct HostSessionLink {
    from_host: Arc<Mutex<std_mpsc::Receiver<ServerToClientMsg>>>,
    terminal_size: Size,
    session_name: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for HostSessionLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSessionLink").finish()
    }
}

impl SessionLink for HostSessionLink {
    fn send_to_server(&self, _msg: ClientToServerMsg) {}

    fn recv_from_server(&self) -> Option<(ServerToClientMsg, ErrorContext)> {
        match self.from_host.lock().unwrap().recv() {
            Ok(msg) => Some((msg, ErrorContext::default())),
            Err(_) => None,
        }
    }

    fn connect_to_server(&self, _path: &Path) {}

    fn get_terminal_size(&self) -> Size {
        self.terminal_size
    }

    fn load_palette(&self) -> Palette {
        default_palette()
    }

    fn update_session_name(&mut self, new_session_name: String) {
        *self.session_name.lock().unwrap() = Some(new_session_name);
    }

    fn spawn_server(&self, _socket_path: &Path, _debug: bool) -> Result<(), io::Error> {
        Ok(())
    }

    fn box_clone(&self) -> Box<dyn SessionLink> {
        Box::new(self.clone())
    }
}

#[derive(Debug)]
struct NoResumableSessions;

impl SessionSource for NoResumableSessions {
    fn session_exists(&self, _session_name: &str) -> Result<bool, Box<dyn std::error::Error>> {
        Ok(false)
    }

    fn get_resurrection_layout(
        &self,
        _session_name: &str,
    ) -> Option<zellij_utils::input::layout::Layout> {
        None
    }

    fn spawn_session_if_needed(
        &self,
        _session_name: &str,
        _os_input: Box<dyn SessionLink>,
        _session_exists: bool,
        _zellij_ipc_pipe: &PathBuf,
        _first_message: ClientToServerMsg,
    ) {
    }
}

#[derive(Debug)]
struct HostSessionFactory {
    session_channels: Arc<Mutex<Vec<std_mpsc::Sender<ServerToClientMsg>>>>,
}

impl SessionLinkFactory for HostSessionFactory {
    fn create(&self) -> Result<Box<dyn SessionLink>, Box<dyn std::error::Error>> {
        let (to_link, from_host) = std_mpsc::channel();
        self.session_channels.lock().unwrap().push(to_link);
        Ok(Box::new(HostSessionLink {
            from_host: Arc::new(Mutex::new(from_host)),
            terminal_size: Size { rows: 24, cols: 80 },
            session_name: Arc::new(Mutex::new(None)),
        }))
    }
}

#[derive(Clone)]
struct HeadlessTerminal {
    stdout: Arc<Mutex<Vec<u8>>>,
    stdin: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    signals: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<SignalEvent>>>,
    _keep_stdin_open: mpsc::UnboundedSender<Vec<u8>>,
    _keep_signals_open: mpsc::UnboundedSender<SignalEvent>,
    terminal_size: Size,
}

impl HeadlessTerminal {
    fn new() -> Self {
        let (keep_stdin_open, stdin) = mpsc::unbounded_channel();
        let (keep_signals_open, signals) = mpsc::unbounded_channel();
        HeadlessTerminal {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stdin: Arc::new(tokio::sync::Mutex::new(stdin)),
            signals: Arc::new(tokio::sync::Mutex::new(signals)),
            _keep_stdin_open: keep_stdin_open,
            _keep_signals_open: keep_signals_open,
            terminal_size: Size { rows: 24, cols: 80 },
        }
    }
}

impl std::fmt::Debug for HeadlessTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadlessTerminal").finish()
    }
}

struct IdleStdin {
    stdin: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

#[async_trait]
impl AsyncStdin for IdleStdin {
    async fn read(&mut self) -> io::Result<Vec<u8>> {
        match self.stdin.lock().await.recv().await {
            Some(data) => Ok(data),
            None => Ok(Vec::new()),
        }
    }
}

struct IdleSignals {
    signals: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<SignalEvent>>>,
}

#[async_trait]
impl AsyncSignals for IdleSignals {
    async fn recv(&mut self) -> Option<SignalEvent> {
        self.signals.lock().await.recv().await
    }
}

struct DiscardingStdout {
    stdout: Arc<Mutex<Vec<u8>>>,
}

impl Write for DiscardingStdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdout.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ClientOsApi for HeadlessTerminal {
    fn get_terminal_size(&self) -> Size {
        self.terminal_size
    }
    fn set_raw_mode(&mut self) {}
    fn unset_raw_mode(&self) -> Result<(), io::Error> {
        Ok(())
    }
    fn get_stdout_writer(&self) -> Box<dyn Write> {
        Box::new(DiscardingStdout {
            stdout: self.stdout.clone(),
        })
    }
    fn get_stdin_reader(&self) -> Box<dyn io::BufRead> {
        Box::new(io::Cursor::new(Vec::new()))
    }
    fn update_session_name(&mut self, _new_session_name: String) {}
    fn read_from_stdin(&mut self) -> Result<Vec<u8>, &'static str> {
        Ok(Vec::new())
    }
    fn box_clone(&self) -> Box<dyn ClientOsApi> {
        Box::new(self.clone())
    }
    fn send_to_server(&self, _msg: ClientToServerMsg) {}
    fn recv_from_server(&self) -> Option<(ServerToClientMsg, ErrorContext)> {
        None
    }
    fn handle_signals(
        &self,
        _sigwinch_cb: Box<dyn Fn()>,
        _quit_cb: Box<dyn Fn()>,
        _resize_receiver: Option<std::sync::mpsc::Receiver<()>>,
    ) {
    }
    fn connect_to_server(&self, _path: &Path) {}
    fn should_install_panic_hook(&self) -> bool {
        false
    }
    fn load_palette(&self) -> Palette {
        default_palette()
    }
    fn enable_mouse(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn disable_mouse(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn get_async_stdin_reader(&self) -> Box<dyn AsyncStdin> {
        Box::new(IdleStdin {
            stdin: self.stdin.clone(),
        })
    }
    fn get_async_signal_listener(&self) -> io::Result<Box<dyn AsyncSignals>> {
        Ok(Box::new(IdleSignals {
            signals: self.signals.clone(),
        }))
    }
}
