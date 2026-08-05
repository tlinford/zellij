//! Axum router and shared application state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    http::{header::CONTENT_TYPE, HeaderName, HeaderValue, Method},
    routing::{any, get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::registry::Registry;
use crate::viewer::HANDSHAKE_HEADER;

/// Honest-relay defense-in-depth: cap login (PAKE-start) attempts per client
/// IP within a sliding window. Not a security guarantee (a malicious relay
/// won't enforce it, and proxied IPs can be spoofed) — the real protection is
/// the sharer-side lockout. Keyed on the forwarded client-IP header.
const LOGIN_WINDOW_SECS: u64 = 60;
const MAX_LOGINS_PER_WINDOW: u32 = 20;

#[derive(Clone)]
pub struct AppState {
    pub registry: Registry,
    pub public_url_template: String,
    pub allowed_origins: Arc<Vec<String>>,
    login_attempts: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}

impl AppState {
    pub fn new(public_url_template: String, allowed_origins: Vec<String>) -> Self {
        Self {
            registry: Registry::new(),
            public_url_template,
            allowed_origins: Arc::new(allowed_origins),
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn origin_allowed(&self, origin: &str) -> bool {
        let origin = origin.trim_end_matches('/');
        self.allowed_origins.iter().any(|o| o == origin)
    }

    pub fn render_public_url(&self, slug: &str) -> String {
        crate::config::format_public_url(&self.public_url_template, slug)
    }

    /// Record a login attempt from `client_ip`; return whether it is within
    /// the per-IP rate limit. The window resets once it elapses.
    pub fn login_attempt_allowed(&self, client_ip: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(LOGIN_WINDOW_SECS);
        let mut map = self.login_attempts.lock().unwrap();
        let entry = map.entry(client_ip.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) > window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= MAX_LOGINS_PER_WINDOW
    }
}

pub fn build_router(state: AppState) -> Router {
    let cors = cors_layer(&state.allowed_origins);
    Router::new()
        .route("/health", get(health))
        .route("/tunnel/control", any(crate::tunnel_control::handler))
        .route("/tunnel/terminal", any(crate::tunnel_terminal::handler))
        .route("/r/{slug}/session", post(crate::viewer::post_session))
        .route(
            "/r/{slug}/command/login",
            post(crate::viewer::post_login),
        )
        .route(
            "/r/{slug}/ws/terminal",
            any(crate::viewer::ws_terminal),
        )
        .route(
            "/r/{slug}/ws/terminal/{session}",
            any(crate::viewer::ws_terminal_with_session),
        )
        .route(
            "/r/{slug}/ws/control",
            any(crate::viewer::ws_control),
        )
        .layer(cors)
        .with_state(state)
}

fn cors_layer(allowed_origins: &Arc<Vec<String>>) -> CorsLayer {
    let allowed = allowed_origins.clone();
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin: &HeaderValue, _| {
            origin
                .to_str()
                .map(|o| {
                    let o = o.trim_end_matches('/');
                    allowed.iter().any(|a| a == o)
                })
                .unwrap_or(false)
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static(HANDSHAKE_HEADER)])
}

async fn health() -> &'static str {
    "ok"
}
