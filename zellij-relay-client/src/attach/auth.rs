use super::config::{LOGIN_ENDPOINT, SESSION_ENDPOINT};
use super::http_client::HttpClientWithCookies;
use super::RemoteClientError;
use isahc::{AsyncReadResponseExt, Request};
use serde::{Deserialize, Serialize};
use zellij_relay_protocol::crypto::{
    self, ViewerKeys, CONFIRM_LABEL_SHARER, CONFIRM_LABEL_VIEWER,
};

#[derive(Serialize)]
struct LoginRequest {
    auth_token: String,
    remember_me: bool,
}

#[derive(Deserialize)]
pub struct SessionResponse {
    pub web_client_id: String,
    /// Sharer-allocated client id; folded into the per-viewer key
    /// derivation on the relay PAKE path. Absent on the local web server.
    #[serde(default)]
    pub client_id: u32,
    /// Whether the server will encrypt TerminalFrameData payloads on this
    /// connection. Absent for pre-Phase-3 servers; treated as `false`.
    #[serde(default)]
    pub e2e_encrypted: bool,
    /// HKDF `info` parameter for per-client key derivation. Absent for
    /// pre-Phase-3 servers.
    #[serde(default)]
    pub tunnel_id: Option<String>,
    /// Whether this viewer attached with a read-only token. Absent for
    /// pre-Phase-5 servers; treated as `false`.
    #[serde(default)]
    pub is_read_only: bool,
    /// Sharer's session viewport rows. Relay stamps `0` when the r/o
    /// fan-out group has not yet received a `SessionSize` frame; callers
    /// should fall back to `24`.
    #[serde(default)]
    pub session_rows: u32,
    /// Sharer's session viewport cols. `0` sentinel — see `session_rows`.
    #[serde(default)]
    pub session_cols: u32,
}

/// Bundle returned to the attach caller: enough to establish WS
/// connections plus the E2E state needed to encrypt/decrypt frames.
pub struct AuthResult {
    pub web_client_id: String,
    pub http_client: HttpClientWithCookies,
    /// Set when `--remember` was passed and the server set a cookie.
    /// Carries both the cookie name (may be `session_token` or
    /// `relay_session`) and value so the attach client can restore it.
    pub remembered: Option<RememberedCookie>,
    pub e2e_encrypted: bool,
    pub tunnel_id: Option<String>,
    pub is_read_only: bool,
    pub session_rows: u32,
    pub session_cols: u32,
    pub relay_keys: Option<ViewerKeys>,
    pub handshake: Option<String>,
    pub sas: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RememberedCookie {
    pub name: String,
    pub value: String,
}

/// Extract the relay slug from a server base URL containing `/r/<slug>`.
/// Relay shares are addressed this way; the local web server is not, so a
/// `None` result selects the legacy token-auth path.
fn relay_slug_from_url(url: &str) -> Option<String> {
    let after = url.split("/r/").nth(1)?;
    let slug = after.split('/').next().unwrap_or("");
    if slug.is_empty() {
        None
    } else {
        Some(slug.to_string())
    }
}

#[derive(Serialize)]
struct PakeLoginRequest {
    viewer_msg: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    link_id: Vec<u8>,
}

#[derive(Deserialize, Default)]
struct PakeLoginResponse {
    #[serde(default)]
    sharer_msg: Vec<u8>,
    #[serde(default)]
    sharer_confirm: Vec<u8>,
    #[serde(default)]
    handshake: String,
}

#[derive(Serialize)]
struct PakeSessionRequest {
    viewer_confirm: Vec<u8>,
}

/// Relay authentication: a SPAKE2 handshake driven by the PIN, run over the
/// two auth POSTs. Mirrors the browser flow in `auth.js`. The PIN never
/// leaves this process; the relay only forwards opaque SPAKE2 blobs.
async fn authenticate_relay_pake(
    server_base_url: &str,
    auth_token: &str,
    slug: &str,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    link_id: Vec<u8>,
) -> Result<AuthResult, RemoteClientError> {
    let http_client = HttpClientWithCookies::new(ca_cert, insecure)
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    let (pake_state, viewer_msg) = crypto::pake_start(auth_token.as_bytes(), slug);

    // Round-trip 1: send the viewer's SPAKE2 message.
    let login_url = format!("{}{}", server_base_url, LOGIN_ENDPOINT);
    let login_body = serde_json::to_vec(&PakeLoginRequest {
        viewer_msg: viewer_msg.clone(),
        link_id,
    })
    .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
    let mut login_response = http_client
        .send_with_cookies(
            Request::post(login_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body(login_body)
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;
    match login_response.status().as_u16() {
        401 => return Err(RemoteClientError::InvalidAuthToken),
        status if !login_response.status().is_success() => {
            return Err(RemoteClientError::ConnectionFailed(format!(
                "Server returned status {}",
                status
            )));
        },
        _ => {},
    }
    let login_text = login_response
        .text()
        .await
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
    let login: PakeLoginResponse =
        serde_json::from_str(&login_text).map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    let pake_key = crypto::pake_finish(pake_state, &login.sharer_msg)
        .map_err(|_| RemoteClientError::InvalidAuthToken)?;
    // Verify the sharer's confirmation tag: a mismatch is a wrong PIN or a
    // tampering relay (MITM). Refuse before transmitting anything further.
    if !crypto::verify_confirmation(
        &login.sharer_confirm,
        &pake_key,
        CONFIRM_LABEL_SHARER,
        &viewer_msg,
        &login.sharer_msg,
    ) {
        return Err(RemoteClientError::InvalidAuthToken);
    }
    let viewer_confirm =
        crypto::confirmation_tag(&pake_key, CONFIRM_LABEL_VIEWER, &viewer_msg, &login.sharer_msg);

    // Round-trip 2: prove our key.
    let session_url = format!("{}{}", server_base_url, SESSION_ENDPOINT);
    let session_body = serde_json::to_vec(&PakeSessionRequest {
        viewer_confirm: viewer_confirm.to_vec(),
    })
    .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
    let mut session_response = http_client
        .send_with_cookies(
            Request::post(session_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .header("X-Zellij-Handshake", &login.handshake)
                .body(session_body)
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;
    match session_response.status().as_u16() {
        401 => return Err(RemoteClientError::Unauthorized),
        status if !session_response.status().is_success() => {
            return Err(RemoteClientError::ConnectionFailed(format!(
                "Server returned status {}",
                status
            )));
        },
        _ => {},
    }
    let session_text = session_response
        .text()
        .await
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
    let session_data: SessionResponse =
        serde_json::from_str(&session_text).map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    let relay_keys = session_data
        .tunnel_id
        .as_ref()
        .map(|tid| crypto::derive_viewer_keys(&pake_key, tid, session_data.client_id));

    let sas = relay_keys
        .as_ref()
        .map(|_| crypto::derive_sas(&pake_key, &viewer_msg, &login.sharer_msg));

    Ok(AuthResult {
        web_client_id: session_data.web_client_id,
        http_client,
        // Relay PAKE has no resumable credential: a saved cookie cannot
        // recover the per-viewer key, so do not offer one.
        remembered: None,
        e2e_encrypted: relay_keys.is_some(),
        tunnel_id: session_data.tunnel_id,
        is_read_only: session_data.is_read_only,
        session_rows: 0,
        session_cols: 0,
        relay_keys,
        handshake: Some(login.handshake),
        sas,
    })
}

pub async fn authenticate(
    server_base_url: &str,
    auth_token: &str,
    remember_me: bool,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    link_id: Vec<u8>,
) -> Result<AuthResult, RemoteClientError> {
    // Relay shares (`…/r/<slug>`) use the SPAKE2 handshake; the local web
    // server keeps the legacy token-auth path below.
    if let Some(slug) = relay_slug_from_url(server_base_url) {
        return authenticate_relay_pake(
            server_base_url,
            auth_token,
            &slug,
            ca_cert,
            insecure,
            link_id,
        )
        .await;
    }

    let http_client = HttpClientWithCookies::new(ca_cert, insecure)
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    // Step 1: Login with auth token
    let login_url = format!("{}{}", server_base_url, LOGIN_ENDPOINT);

    let login_request = LoginRequest {
        auth_token: auth_token.to_string(),
        remember_me,
    };

    let response = http_client
        .send_with_cookies(
            Request::post(login_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body(
                    serde_json::to_vec(&login_request)
                        .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
                )
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

    // Handle HTTP status codes
    match response.status().as_u16() {
        401 => return Err(RemoteClientError::InvalidAuthToken),
        status if !response.status().is_success() => {
            return Err(RemoteClientError::ConnectionFailed(format!(
                "Server returned status {}",
                status
            )));
        },
        _ => {},
    }

    // Step 2: Get session/client ID
    let session_url = format!("{}{}", server_base_url, SESSION_ENDPOINT);

    let mut session_response = http_client
        .send_with_cookies(
            Request::post(session_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body("{}".as_bytes().to_vec())
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

    // Handle session response
    match session_response.status().as_u16() {
        401 => return Err(RemoteClientError::Unauthorized),
        status if !session_response.status().is_success() => {
            return Err(RemoteClientError::ConnectionFailed(format!(
                "Server returned status {}",
                status
            )));
        },
        _ => {},
    }

    let response_body = session_response
        .text()
        .await
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
    let session_data: SessionResponse =
        serde_json::from_str(&response_body).map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    // Prefer the well-known cookie names the local web server and the
    // relay set. We only surface one; any extra cookies stay in the jar
    // for the duration of this run but aren't persisted.
    let remembered = if remember_me {
        first_session_cookie(&http_client)
    } else {
        None
    };

    Ok(AuthResult {
        web_client_id: session_data.web_client_id,
        http_client,
        remembered,
        e2e_encrypted: session_data.e2e_encrypted,
        tunnel_id: session_data.tunnel_id,
        is_read_only: session_data.is_read_only,
        session_rows: session_data.session_rows,
        session_cols: session_data.session_cols,
        relay_keys: None,
        handshake: None,
        sas: None,
    })
}

/// Return the first session-scoped cookie the server set. `session_token`
/// is the local web server's cookie; `relay_session` is the relay's.
fn first_session_cookie(http_client: &HttpClientWithCookies) -> Option<RememberedCookie> {
    for name in &["session_token", "relay_session"] {
        if let Some(value) = http_client.get_cookie(name) {
            return Some(RememberedCookie {
                name: (*name).to_string(),
                value,
            });
        }
    }
    None
}

pub async fn validate_session_token(
    server_base_url: &str,
    cookie_name: &str,
    cookie_value: &str,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
) -> Result<(SessionResponse, HttpClientWithCookies), RemoteClientError> {
    let http_client = HttpClientWithCookies::new(ca_cert, insecure)
        .map_err(|e| RemoteClientError::Other(Box::new(e)))?;

    // Pre-populate the session cookie (name differs between local web
    // server — `session_token` — and the relay — `relay_session`).
    http_client.set_cookie(cookie_name.to_string(), cookie_value.to_string());

    // Skip /login, go directly to /session endpoint
    let session_url = format!("{}{}", server_base_url, SESSION_ENDPOINT);

    let mut session_response = http_client
        .send_with_cookies(
            Request::post(session_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "http-terminal-client/1.0")
                .header("Accept", "application/json")
                .body("{}".as_bytes().to_vec())
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?,
        )
        .await
        .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

    match session_response.status().as_u16() {
        401 => Err(RemoteClientError::SessionTokenExpired),
        status if !session_response.status().is_success() => Err(
            RemoteClientError::ConnectionFailed(format!("Server returned status {}", status)),
        ),
        _ => {
            let response_body = session_response
                .text()
                .await
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
            let session_data: SessionResponse = serde_json::from_str(&response_body)
                .map_err(|e| RemoteClientError::Other(Box::new(e)))?;
            Ok((session_data, http_client))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::SessionResponse;

    #[test]
    fn session_response_deserializes_phase_5_fields() {
        let body = r#"{
            "web_client_id": "relay-client-0",
            "e2e_encrypted": true,
            "tunnel_id": "abcd",
            "is_read_only": true,
            "session_rows": 40,
            "session_cols": 120
        }"#;
        let s: SessionResponse = serde_json::from_str(body).unwrap();
        assert_eq!(s.web_client_id, "relay-client-0");
        assert!(s.e2e_encrypted);
        assert_eq!(s.tunnel_id.as_deref(), Some("abcd"));
        assert!(s.is_read_only);
        assert_eq!(s.session_rows, 40);
        assert_eq!(s.session_cols, 120);
    }

    #[test]
    fn session_response_defaults_phase_5_fields_when_absent() {
        // Pre-Phase-5 body: no is_read_only / session_rows / session_cols.
        let body = r#"{
            "web_client_id": "relay-client-0",
            "e2e_encrypted": true,
            "tunnel_id": "abcd"
        }"#;
        let s: SessionResponse = serde_json::from_str(body).unwrap();
        assert!(!s.is_read_only);
        assert_eq!(s.session_rows, 0);
        assert_eq!(s.session_cols, 0);
    }
}
