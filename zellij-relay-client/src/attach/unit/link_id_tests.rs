use crate::attach::{join_link_id_from_url, join_secret_from_url};

#[test]
fn parses_hex_link_id_from_fragment() {
    let url = "https://host/r/abc#k=secret&l=000102030405060708090a0b0c0d0e0f";
    assert_eq!(
        join_link_id_from_url(url),
        Some(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    );
    assert_eq!(join_secret_from_url(url), Some("secret".to_string()));
}

#[test]
fn absent_link_id_is_none() {
    let url = "https://host/r/abc#k=secret";
    assert_eq!(join_link_id_from_url(url), None);
}

#[test]
fn malformed_link_id_is_none() {
    assert_eq!(join_link_id_from_url("https://host/r/abc#l=zzz"), None);
    assert_eq!(join_link_id_from_url("https://host/r/abc#l=abc"), None);
    assert_eq!(join_link_id_from_url("https://host/r/abc#l="), None);
}
