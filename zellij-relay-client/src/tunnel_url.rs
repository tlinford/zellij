use anyhow::{bail, Result};

pub fn reject_insecure_relay_url(url: &str) -> Result<()> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("relay URL {} has no scheme; expected wss://", url))?;
    match scheme.to_ascii_lowercase().as_str() {
        "wss" => Ok(()),
        "ws" if authority_is_loopback(rest) => Ok(()),
        _ => bail!(
            "refusing to open relay tunnel over insecure URL {}: only wss:// is permitted (ws:// allowed for loopback hosts only)",
            url
        ),
    }
}

fn authority_is_loopback(rest: &str) -> bool {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(after_bracket) = host_port.strip_prefix('[') {
        after_bracket.split(']').next().unwrap_or(after_bracket)
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host.starts_with("127.")
}

#[cfg(test)]
mod tests {
    use super::reject_insecure_relay_url;

    #[test]
    fn wss_is_accepted() {
        assert!(reject_insecure_relay_url("wss://relay.example/tunnel/control").is_ok());
    }

    #[test]
    fn ws_to_remote_host_is_rejected() {
        let err = reject_insecure_relay_url("ws://relay.example/tunnel/control")
            .expect_err("ws:// to a remote host must be rejected");
        assert!(err.to_string().contains("ws://relay.example/tunnel/control"));
    }

    #[test]
    fn ws_to_loopback_is_accepted() {
        assert!(reject_insecure_relay_url("ws://localhost:8080/tunnel/control").is_ok());
        assert!(reject_insecure_relay_url("ws://127.0.0.1:8080/tunnel/terminal?slug=abc").is_ok());
        assert!(reject_insecure_relay_url("ws://[::1]:8080/tunnel/control").is_ok());
    }

    #[test]
    fn other_schemes_are_rejected() {
        assert!(reject_insecure_relay_url("http://relay.example/tunnel/control").is_err());
        assert!(reject_insecure_relay_url("relay.example/tunnel/control").is_err());
    }
}
