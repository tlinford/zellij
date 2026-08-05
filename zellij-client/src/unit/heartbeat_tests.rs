use crate::heartbeat_expired;

const TIMEOUT_MS: u64 = 60_000;

#[test]
fn fresh_pong_is_not_expired() {
    assert!(!heartbeat_expired(10_000, 10_000, TIMEOUT_MS));
}

#[test]
fn within_timeout_is_not_expired() {
    assert!(!heartbeat_expired(0, TIMEOUT_MS, TIMEOUT_MS));
}

#[test]
fn beyond_timeout_is_expired() {
    assert!(heartbeat_expired(0, TIMEOUT_MS + 1, TIMEOUT_MS));
}

#[test]
fn clock_skew_backwards_is_not_expired() {
    assert!(!heartbeat_expired(10_000, 5_000, TIMEOUT_MS));
}
