use std::net::{IpAddr, Ipv4Addr};

use clap::{CommandFactory, Parser};
use zellij_utils::cli::{CliArgs, Command};
use zellij_utils::pane_size::Size;

const CLI_PARSE_TEST_STACK_SIZE: usize = 16 * 1024 * 1024;

fn on_large_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(CLI_PARSE_TEST_STACK_SIZE)
        .spawn(f)
        .expect("failed to spawn cli parse test thread")
        .join()
        .expect("cli parse test thread panicked")
}

fn try_parse(args: &[&str]) -> Result<CliArgs, clap::Error> {
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    on_large_stack(move || CliArgs::try_parse_from(args))
}

#[test]
fn verify_cli() {
    on_large_stack(|| CliArgs::command().debug_assert());
}

#[test]
fn web_cli_status_alone_works() {
    let args = try_parse(&["zellij", "web", "--status"]);
    assert!(args.is_ok());
    if let Ok(CliArgs {
        command: Some(Command::Web(web)),
        ..
    }) = args
    {
        assert!(web.status);
        assert!(web.timeout.is_none());
    } else {
        panic!("Expected Web command");
    }
}

#[test]
fn web_cli_status_with_timeout_works() {
    let args = try_parse(&["zellij", "web", "--status", "--timeout", "5"]);
    assert!(args.is_ok());
    if let Ok(CliArgs {
        command: Some(Command::Web(web)),
        ..
    }) = args
    {
        assert!(web.status);
        assert_eq!(web.timeout, Some(5));
    } else {
        panic!("Expected Web command");
    }
}

#[test]
fn web_cli_timeout_with_status_works() {
    // Test with --timeout before --status (order shouldn't matter)
    let args = try_parse(&["zellij", "web", "--timeout", "10", "--status"]);
    assert!(args.is_ok());
    if let Ok(CliArgs {
        command: Some(Command::Web(web)),
        ..
    }) = args
    {
        assert!(web.status);
        assert_eq!(web.timeout, Some(10));
    } else {
        panic!("Expected Web command");
    }
}

#[test]
fn web_cli_timeout_without_status_fails() {
    let args = try_parse(&["zellij", "web", "--timeout", "5"]);
    assert!(args.is_err());
}

#[test]
fn web_cli_status_with_start_fails() {
    let args = try_parse(&["zellij", "web", "--status", "--start"]);
    assert!(args.is_err());
}

#[test]
fn web_cli_status_with_stop_fails() {
    let args = try_parse(&["zellij", "web", "--status", "--stop"]);
    assert!(args.is_err());
}

#[test]
fn web_cli_status_with_ip_works() {
    let args = try_parse(&["zellij", "web", "--status", "--ip", "127.0.0.1"]);
    assert!(args.is_ok());
    if let Ok(CliArgs {
        command: Some(Command::Web(web)),
        ..
    }) = args
    {
        assert!(web.status);
        assert_eq!(web.ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    } else {
        panic!("Expected Web command");
    }
}

#[test]
fn web_cli_status_with_port_works() {
    let args = try_parse(&["zellij", "web", "--status", "--port", "9000"]);
    assert!(args.is_ok());
    if let Ok(CliArgs {
        command: Some(Command::Web(web)),
        ..
    }) = args
    {
        assert!(web.status);
        assert_eq!(web.port, Some(9000));
    } else {
        panic!("Expected Web command");
    }
}

#[test]
fn web_cli_status_with_ip_and_port_works() {
    let args = try_parse(&[
        "zellij", "web", "--status", "--ip", "0.0.0.0", "--port", "9000",
    ]);
    assert!(args.is_ok());
    if let Ok(CliArgs {
        command: Some(Command::Web(web)),
        ..
    }) = args
    {
        assert!(web.status);
        assert_eq!(web.ip, Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert_eq!(web.port, Some(9000));
    } else {
        panic!("Expected Web command");
    }
}

#[test]
fn attach_headless_defaults_to_40_rows_by_120_cols() {
    let args = try_parse(&["zellij", "attach", "s", "--headless"]).unwrap();
    assert_eq!(
        args.headless_size(),
        Some(Size {
            rows: 40,
            cols: 120
        })
    );
}

#[test]
fn attach_headless_takes_rows_and_cols() {
    let args = try_parse(&[
        "zellij",
        "attach",
        "s",
        "--headless",
        "--rows",
        "30",
        "--cols",
        "100",
    ])
    .unwrap();
    assert_eq!(
        args.headless_size(),
        Some(Size {
            rows: 30,
            cols: 100
        })
    );
}

#[test]
fn attach_without_headless_has_no_headless_size() {
    let args = try_parse(&["zellij", "attach", "s"]).unwrap();
    assert_eq!(args.headless_size(), None);
}

#[test]
fn attach_rows_and_cols_require_headless() {
    assert!(try_parse(&["zellij", "attach", "s", "--rows", "30"]).is_err());
    assert!(try_parse(&["zellij", "attach", "s", "--cols", "100"]).is_err());
}

#[test]
fn attach_headless_conflicts_with_create_background() {
    assert!(try_parse(&["zellij", "attach", "s", "--headless", "--create-background"]).is_err());
}

#[test]
fn attach_headless_rejects_a_zero_size() {
    assert!(try_parse(&["zellij", "attach", "s", "--headless", "--rows", "0"]).is_err());
    assert!(try_parse(&["zellij", "attach", "s", "--headless", "--cols", "0"]).is_err());
}
