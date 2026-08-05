use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use zellij_relay_protocol::crypto::{self, DEVICE_SEED_LEN, KEY_LEN};
use zellij_utils::data::DeviceScope;

const STORAGE_DIR_NAME: &str = "relay-client-devices";
const STORE_FILE_NAME: &str = "devices.json";
const KDF_SALT_LEN: usize = 16;
const ARGON2_M_COST: u32 = 19456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;
const MAX_UNLOCK_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDevice {
    server_url: String,
    device_id: String,
    read_only: bool,
    scope: String,
    kdf_salt: String,
    sealed: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    devices: Vec<StoredDevice>,
}

#[derive(Serialize, Deserialize)]
struct SecretBundle {
    seed: String,
    device_secret: String,
}

#[derive(Debug, Clone)]
pub struct ClientDevice {
    pub seed: [u8; DEVICE_SEED_LEN],
    pub device_id: Vec<u8>,
    pub device_secret: String,
    pub read_only: bool,
    pub scope: DeviceScope,
}

fn storage_dir() -> PathBuf {
    zellij_utils::home::get_default_data_dir().join(STORAGE_DIR_NAME)
}

fn store_file_path() -> PathBuf {
    storage_dir().join(STORE_FILE_NAME)
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

fn derive_key(passphrase: &str, salt: &[u8]) -> Option<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .ok()?;
    Some(key)
}

fn seal(
    passphrase: &str,
    seed: &[u8; DEVICE_SEED_LEN],
    device_secret: &str,
) -> Option<(String, String)> {
    let salt = crypto::random_bytes(KDF_SALT_LEN);
    let key = derive_key(passphrase, &salt)?;
    let bundle = SecretBundle {
        seed: hex_encode(seed),
        device_secret: device_secret.to_string(),
    };
    let plaintext = serde_json::to_vec(&bundle).ok()?;
    let sealed = crypto::encrypt(&key, &plaintext).ok()?;
    Some((hex_encode(&salt), hex_encode(&sealed)))
}

fn open(
    passphrase: &str,
    salt_hex: &str,
    sealed_hex: &str,
) -> Option<([u8; DEVICE_SEED_LEN], String)> {
    let salt = decode_hex(salt_hex)?;
    let sealed = decode_hex(sealed_hex)?;
    let key = derive_key(passphrase, &salt)?;
    let plaintext = crypto::decrypt(&key, &sealed).ok()?;
    let bundle: SecretBundle = serde_json::from_slice(&plaintext).ok()?;
    let seed_bytes = decode_hex(&bundle.seed)?;
    let seed = <[u8; DEVICE_SEED_LEN]>::try_from(seed_bytes.as_slice()).ok()?;
    Some((seed, bundle.device_secret))
}

pub fn has_device(server_url: &str) -> bool {
    read_store()
        .devices
        .iter()
        .any(|d| d.server_url == server_url)
}

pub fn load(server_url: &str, passphrase: &str) -> Option<ClientDevice> {
    let store = read_store();
    let record = store.devices.iter().find(|d| d.server_url == server_url)?;
    let (seed, device_secret) = open(passphrase, &record.kdf_salt, &record.sealed)?;
    let device_id = decode_hex(&record.device_id)?;
    Some(ClientDevice {
        seed,
        device_id,
        device_secret,
        read_only: record.read_only,
        scope: DeviceScope::from_token(&record.scope),
    })
}

pub fn save(
    server_url: &str,
    seed: &[u8; DEVICE_SEED_LEN],
    device_id: &[u8],
    device_secret: &str,
    read_only: bool,
    scope: DeviceScope,
    passphrase: &str,
) -> bool {
    let Some((kdf_salt, sealed)) = seal(passphrase, seed, device_secret) else {
        return false;
    };
    let mut store = read_store();
    store.devices.retain(|d| d.server_url != server_url);
    store.devices.push(StoredDevice {
        server_url: server_url.to_string(),
        device_id: hex_encode(device_id),
        read_only,
        scope: scope.as_token().to_string(),
        kdf_salt,
        sealed,
    });
    write_store(&store);
    true
}

pub fn delete(server_url: &str) {
    let mut store = read_store();
    let before = store.devices.len();
    store.devices.retain(|d| d.server_url != server_url);
    if store.devices.len() != before {
        write_store(&store);
    }
}

pub fn prompt_unlock_passphrase() -> Option<String> {
    use dialoguer::Password;
    Password::new()
        .with_prompt("Enter the passphrase for this device")
        .interact()
        .ok()
}

pub fn save_enrolled(
    server_url: &str,
    seed: &[u8; DEVICE_SEED_LEN],
    device_id: &[u8],
    device_secret: &str,
    read_only: bool,
    scope: DeviceScope,
) -> bool {
    let passphrase = match super::passphrase::resolve_supplied_passphrase() {
        Some(supplied) => {
            if super::passphrase::is_weak(&supplied) {
                eprintln!(
                    "Supplied device passphrase is too weak — set a longer, less predictable one."
                );
                return false;
            }
            supplied
        },
        None => {
            let Some(chosen) = super::passphrase::prompt_new_passphrase(&store_file_path()) else {
                return false;
            };
            chosen
        },
    };
    save(
        server_url,
        seed,
        device_id,
        device_secret,
        read_only,
        scope,
        &passphrase,
    )
}

pub fn load_interactive(server_url: &str) -> Option<ClientDevice> {
    if !has_device(server_url) {
        return None;
    }
    if let Some(supplied) = super::passphrase::resolve_supplied_passphrase() {
        if let Some(device) = load(server_url, &supplied) {
            return Some(device);
        }
    }
    for _ in 0..MAX_UNLOCK_ATTEMPTS {
        let passphrase = prompt_unlock_passphrase()?;
        if let Some(device) = load(server_url, &passphrase) {
            return Some(device);
        }
        eprintln!("Incorrect passphrase — try again.");
    }
    None
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

    #[test]
    fn seal_open_round_trips() {
        let seed = [7u8; DEVICE_SEED_LEN];
        let (salt, sealed) = seal("correct horse battery staple", &seed, "device-secret").unwrap();
        let (out_seed, out_secret) = open("correct horse battery staple", &salt, &sealed).unwrap();
        assert_eq!(out_seed, seed);
        assert_eq!(out_secret, "device-secret");
    }

    #[test]
    fn open_rejects_wrong_passphrase() {
        let seed = [9u8; DEVICE_SEED_LEN];
        let (salt, sealed) = seal("right", &seed, "secret").unwrap();
        assert!(open("wrong", &salt, &sealed).is_none());
    }

    #[test]
    fn distinct_salts_per_seal() {
        let seed = [1u8; DEVICE_SEED_LEN];
        let (salt_a, _) = seal("pass", &seed, "s").unwrap();
        let (salt_b, _) = seal("pass", &seed, "s").unwrap();
        assert_ne!(salt_a, salt_b);
    }
}
