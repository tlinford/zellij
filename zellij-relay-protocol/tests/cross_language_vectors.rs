use zellij_relay_protocol::crypto::{
    derive_frame_key, derive_sas, device_public_key, encrypt_seq, sign_device_challenge,
    verify_device_challenge, DEVICE_SEED_LEN,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn cross_language_vector_matches_fixture() {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/e2e_test_vectors.json"
    ));
    let v: serde_json::Value = serde_json::from_str(raw).expect("valid fixture json");

    let pake_key = v["pake_key_utf8"].as_str().unwrap();
    let tunnel_id = v["tunnel_id"].as_str().unwrap();
    let client_id = v["client_id"].as_u64().unwrap() as u32;
    let frame_type = v["frame_type"].as_str().unwrap().as_bytes()[0];
    let direction = v["direction"].as_str().unwrap().as_bytes()[0];
    let seq = v["seq"].as_u64().unwrap();
    let plaintext = v["plaintext_utf8"].as_str().unwrap();

    let key = derive_frame_key(pake_key.as_bytes(), tunnel_id, client_id, frame_type, direction);
    assert_eq!(hex(&key), v["derive_frame_key_hex"].as_str().unwrap());

    let ct = encrypt_seq(&key, seq, frame_type, direction, plaintext.as_bytes()).unwrap();
    assert_eq!(hex(&ct), v["encrypt_seq_hex"].as_str().unwrap());

    let sas_viewer = v["sas_viewer_msg_utf8"].as_str().unwrap();
    let sas_sharer = v["sas_sharer_msg_utf8"].as_str().unwrap();
    let sas = derive_sas(pake_key.as_bytes(), sas_viewer.as_bytes(), sas_sharer.as_bytes());
    assert_eq!(sas, v["sas_digits"].as_str().unwrap());

    let seed_bytes = unhex(v["device_seed_hex"].as_str().unwrap());
    let mut seed = [0u8; DEVICE_SEED_LEN];
    seed.copy_from_slice(&seed_bytes);
    let challenge = unhex(v["device_challenge_hex"].as_str().unwrap());
    let pubkey = device_public_key(&seed);
    assert_eq!(hex(&pubkey), v["device_pubkey_hex"].as_str().unwrap());
    let signature = sign_device_challenge(&seed, &challenge);
    assert_eq!(hex(&signature), v["device_signature_hex"].as_str().unwrap());
    assert!(verify_device_challenge(&pubkey, &challenge, &signature));
}
