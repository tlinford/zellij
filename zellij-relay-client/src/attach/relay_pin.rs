use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};

const STORAGE_DIR_NAME: &str = "relay-client-pins";
const STORE_FILE_NAME: &str = "pins.json";

#[derive(Debug)]
pub enum PinError {
    Tls(String),
    Parse(String),
    Changed { host: String, old: String, new: String },
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::Tls(msg) => write!(f, "TLS probe failed: {}", msg),
            PinError::Parse(msg) => write!(f, "certificate parse failed: {}", msg),
            PinError::Changed { host, old, new } => write!(
                f,
                "pinned TLS key for {} changed (old {}, new {})",
                host, old, new
            ),
        }
    }
}

impl std::error::Error for PinError {}

pub enum PinOutcome {
    Matched,
    Learned([u8; 32]),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayPin {
    host: String,
    spki_b64: String,
    first_seen: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    pins: Vec<RelayPin>,
}

static STORAGE_DIR_OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

fn storage_override() -> &'static Mutex<Option<PathBuf>> {
    STORAGE_DIR_OVERRIDE.get_or_init(|| Mutex::new(None))
}

fn storage_dir() -> PathBuf {
    if let Some(dir) = storage_override().lock().unwrap().clone() {
        return dir;
    }
    zellij_utils::home::get_default_data_dir().join(STORAGE_DIR_NAME)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _mode: u32) {}

fn read_store() -> Store {
    let path = storage_dir().join(STORE_FILE_NAME);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Store::default(),
    }
}

fn write_store(store: &Store) {
    let dir = storage_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    restrict_permissions(&dir, 0o700);
    let path = dir.join(STORE_FILE_NAME);
    if let Ok(bytes) = serde_json::to_vec_pretty(store) {
        if std::fs::write(&path, bytes).is_ok() {
            restrict_permissions(&path, 0o600);
        }
    }
}

pub fn has_pin(host: &str) -> bool {
    read_store().pins.iter().any(|p| p.host == host)
}

pub fn load(host: &str) -> Option<[u8; 32]> {
    let store = read_store();
    let record = store.pins.iter().find(|p| p.host == host)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(record.spki_b64.as_bytes())
        .ok()?;
    <[u8; 32]>::try_from(raw.as_slice()).ok()
}

pub fn save(host: &str, spki: &[u8; 32]) {
    let mut store = read_store();
    store.pins.retain(|p| p.host != host);
    store.pins.push(RelayPin {
        host: host.to_string(),
        spki_b64: base64::engine::general_purpose::STANDARD.encode(spki),
        first_seen: now_unix(),
    });
    write_store(&store);
}

pub fn forget(host: &str) {
    let mut store = read_store();
    let before = store.pins.len();
    store.pins.retain(|p| p.host != host);
    if store.pins.len() != before {
        write_store(&store);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn format_pin(spki: &[u8; 32]) -> String {
    format!(
        "sha256//{}",
        base64::engine::general_purpose::STANDARD.encode(spki)
    )
}

pub fn spki_sha256(leaf_der: &[u8]) -> Result<[u8; 32], PinError> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf_der)
        .map_err(|e| PinError::Parse(e.to_string()))?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert.tbs_certificate.subject_pki.raw);
    Ok(hasher.finalize().into())
}

pub fn build_root_store(ca_cert: Option<&Path>) -> Result<rustls::RootCertStore, PinError> {
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(ca_path) = ca_cert {
        let ca_pem = std::fs::read(ca_path).map_err(|e| PinError::Tls(e.to_string()))?;
        let mut cursor = std::io::Cursor::new(ca_pem);
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cursor)
                .filter_map(|r| r.ok())
                .collect();
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| PinError::Tls(e.to_string()))?;
        }
    } else {
        let native_certs = rustls_native_certs::load_native_certs();
        for err in &native_certs.errors {
            log::warn!("Error loading native certificate: {}", err);
        }
        root_store.add_parsable_certificates(native_certs.certs);
    }
    Ok(root_store)
}

#[derive(Debug)]
pub struct TofuPinVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected: Option<[u8; 32]>,
    observed: Arc<Mutex<Option<[u8; 32]>>>,
}

impl TofuPinVerifier {
    pub fn new(
        root_store: rustls::RootCertStore,
        provider: Arc<rustls::crypto::CryptoProvider>,
        expected: Option<[u8; 32]>,
        observed: Arc<Mutex<Option<[u8; 32]>>>,
    ) -> Result<Self, PinError> {
        let inner =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider)
                .build()
                .map_err(|e| PinError::Tls(e.to_string()))?;
        Ok(Self {
            inner,
            expected,
            observed,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for TofuPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let spki = spki_sha256(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        if let Ok(mut cell) = self.observed.lock() {
            *cell = Some(spki);
        }
        if let Some(expected) = self.expected {
            if expected != spki {
                return Err(rustls::Error::General(
                    "relay TLS public key does not match the pinned key".to_string(),
                ));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn probe_config(
    ca_cert: Option<&Path>,
    expected: Option<[u8; 32]>,
    observed: Arc<Mutex<Option<[u8; 32]>>>,
) -> Result<rustls::ClientConfig, PinError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let root_store = build_root_store(ca_cert)?;
    let verifier = TofuPinVerifier::new(root_store, provider.clone(), expected, observed)?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| PinError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(config)
}

fn drive_handshake(host: &str, port: u16, config: rustls::ClientConfig) -> Result<(), PinError> {
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| PinError::Tls(e.to_string()))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| PinError::Tls(e.to_string()))?;
    let mut sock = TcpStream::connect((host, port)).map_err(|e| PinError::Tls(e.to_string()))?;
    let timeout = super::config::connection_timeout();
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    while conn.is_handshaking() {
        let (_read, _written) = complete_io(&mut conn, &mut sock)?;
    }
    Ok(())
}

fn complete_io<T: Read + Write>(
    conn: &mut rustls::ClientConnection,
    io: &mut T,
) -> Result<(usize, usize), PinError> {
    conn.complete_io(io).map_err(|e| PinError::Tls(e.to_string()))
}

pub fn verify_or_learn(
    host: &str,
    port: u16,
    ca_cert: Option<&Path>,
) -> Result<PinOutcome, PinError> {
    let stored = load(host);
    let observed = Arc::new(Mutex::new(None));
    let config = probe_config(ca_cert, stored, observed.clone())?;
    let handshake = drive_handshake(host, port, config);
    let observed_pin = *observed.lock().unwrap();
    match handshake {
        Ok(()) => match (stored, observed_pin) {
            (None, Some(spki)) => Ok(PinOutcome::Learned(spki)),
            (Some(_), Some(_)) => Ok(PinOutcome::Matched),
            (_, None) => Err(PinError::Tls(
                "handshake completed without a server certificate".to_string(),
            )),
        },
        Err(e) => {
            if let (Some(old), Some(new)) = (stored, observed_pin) {
                if old != new {
                    return Err(PinError::Changed {
                        host: host.to_string(),
                        old: format_pin(&old),
                        new: format_pin(&new),
                    });
                }
            }
            Err(e)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct DirGuard;

    fn use_temp_dir() -> (tempfile::TempDir, DirGuard) {
        let dir = tempfile::tempdir().unwrap();
        *storage_override().lock().unwrap() = Some(dir.path().to_path_buf());
        (dir, DirGuard)
    }

    impl Drop for DirGuard {
        fn drop(&mut self) {
            *storage_override().lock().unwrap() = None;
        }
    }

    fn make_cert() -> (Vec<u8>, [u8; 32]) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let der = cert.cert.der().to_vec();
        let spki = spki_sha256(&der).unwrap();
        (der, spki)
    }

    struct CaFixture {
        ca_pem: String,
        cert_a_der: Vec<u8>,
        key_a_der: Vec<u8>,
        cert_b_der: Vec<u8>,
        key_b_der: Vec<u8>,
    }

    fn make_ca_fixture() -> CaFixture {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf = |key: &rcgen::KeyPair| {
            let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            params.signed_by(key, &ca, &ca_key).unwrap()
        };

        let key_a = rcgen::KeyPair::generate().unwrap();
        let cert_a = leaf(&key_a);
        let key_b = rcgen::KeyPair::generate().unwrap();
        let cert_b = leaf(&key_b);

        CaFixture {
            ca_pem: ca.pem(),
            cert_a_der: cert_a.der().as_ref().to_vec(),
            key_a_der: key_a.serialize_der(),
            cert_b_der: cert_b.der().as_ref().to_vec(),
            key_b_der: key_b.serialize_der(),
        }
    }

    fn chain_and_key(
        cert_der: &[u8],
        key_der: &[u8],
    ) -> (
        Vec<rustls_pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ) {
        let chain = vec![rustls_pki_types::CertificateDer::from(cert_der.to_vec())];
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(key_der.to_vec()),
        );
        (chain, key)
    }

    async fn spawn_tls_server(
        chain: Vec<rustls_pki_types::CertificateDer<'static>>,
        key: rustls_pki_types::PrivateKeyDer<'static>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        (port, handle)
    }

    async fn probe(host: String, port: u16, ca_path: PathBuf) -> Result<PinOutcome, PinError> {
        tokio::task::spawn_blocking(move || verify_or_learn(&host, port, Some(&ca_path)))
            .await
            .unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn tofu_learns_refuses_then_matches_over_real_tls() {
        let _dir_override = use_temp_dir();
        let fixture = make_ca_fixture();
        let ca_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), &fixture.ca_pem).unwrap();
        let ca_path = ca_file.path().to_path_buf();

        let (chain_a, key_a) = chain_and_key(&fixture.cert_a_der, &fixture.key_a_der);
        let (port_a, server_a) = spawn_tls_server(chain_a, key_a).await;
        let expected_a = spki_sha256(&fixture.cert_a_der).unwrap();
        match probe("localhost".to_string(), port_a, ca_path.clone())
            .await
            .unwrap()
        {
            PinOutcome::Learned(spki) => assert_eq!(spki, expected_a),
            PinOutcome::Matched => panic!("first connect should learn, not match"),
        }
        save("localhost", &expected_a);
        server_a.abort();

        let (chain_b, key_b) = chain_and_key(&fixture.cert_b_der, &fixture.key_b_der);
        let (port_b, server_b) = spawn_tls_server(chain_b, key_b).await;
        match probe("localhost".to_string(), port_b, ca_path.clone()).await {
            Err(PinError::Changed { host, .. }) => assert_eq!(host, "localhost"),
            other => panic!("changed key must be refused, got {:?}", other.map(|_| ())),
        }
        server_b.abort();

        let (chain_a2, key_a2) = chain_and_key(&fixture.cert_a_der, &fixture.key_a_der);
        let (port_c, server_c) = spawn_tls_server(chain_a2, key_a2).await;
        match probe("localhost".to_string(), port_c, ca_path).await.unwrap() {
            PinOutcome::Matched => {},
            PinOutcome::Learned(_) => panic!("re-connect with same key should match"),
        }
        server_c.abort();
    }

    #[test]
    fn spki_is_stable_across_reparse() {
        let (der, spki) = make_cert();
        assert_eq!(spki_sha256(&der).unwrap(), spki);
    }

    #[test]
    fn distinct_keys_have_distinct_spki() {
        let (_, a) = make_cert();
        let (_, b) = make_cert();
        assert_ne!(a, b);
    }

    #[test]
    #[serial]
    fn store_round_trips_under_override() {
        let _guard = use_temp_dir();
        let (_, spki) = make_cert();
        assert!(!has_pin("relay.example"));
        assert!(load("relay.example").is_none());
        save("relay.example", &spki);
        assert!(has_pin("relay.example"));
        assert_eq!(load("relay.example").unwrap(), spki);
        forget("relay.example");
        assert!(!has_pin("relay.example"));
        assert!(load("relay.example").is_none());
    }

    #[test]
    #[serial]
    fn save_replaces_existing_pin() {
        let _guard = use_temp_dir();
        let (_, a) = make_cert();
        let (_, b) = make_cert();
        save("relay.example", &a);
        save("relay.example", &b);
        assert_eq!(load("relay.example").unwrap(), b);
        assert_eq!(read_store().pins.len(), 1);
    }

    #[test]
    fn format_pin_uses_hpkp_convention() {
        let spki = [0u8; 32];
        assert_eq!(
            format_pin(&spki),
            "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }
}
