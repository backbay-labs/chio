#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "chio-hosted-mcp-support-config-{}-{nonce}",
        std::process::id()
    ));
    support::create_private_test_directory(&path);
    path
}

fn listen_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
}

fn normal_dependency_names(manifest: &str) -> Vec<String> {
    let mut in_dependencies = false;
    let mut names = Vec::new();

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_dependencies = true;
            continue;
        }
        if in_dependencies && trimmed.starts_with('[') {
            break;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, _)) = trimmed.split_once('=') else {
            continue;
        };
        names.push(name.trim().trim_matches('"').to_string());
    }

    names
}

#[test]
fn hosted_mcp_normal_dependencies_are_reexport_boundary_only() {
    assert_eq!(
        normal_dependency_names(include_str!("../Cargo.toml")),
        vec!["chio-control-plane", "chio-mcp-remote"]
    );
}

#[test]
fn base_remote_config_carries_wrapped_server_defaults() {
    let dir = test_dir();
    let listen = listen_addr();

    let config = support::base_remote_config(&dir, listen);

    assert_eq!(config.listen, listen);
    assert_eq!(config.auth_token, None);
    assert_eq!(config.auth_jwt_public_key, None);
    assert_eq!(config.admin_token, None);
    assert_eq!(config.auth_scopes, Vec::<String>::new());
    assert_eq!(
        config.receipt_db_path,
        Some(dir.join("remote-receipts.sqlite3"))
    );
    assert_eq!(config.revocation_db_path, None);
    assert_eq!(
        config.authority_seed_path,
        Some(dir.join("remote-authority.seed"))
    );
    assert_eq!(
        config.session_db_path,
        Some(dir.join("remote-session-tombstones.sqlite3"))
    );
    assert_eq!(config.policy_path, dir.join("http-policy.yaml"));
    assert_eq!(config.server_id, "wrapped-http-mock");
    assert_eq!(config.server_name, "Wrapped HTTP Mock");
    assert_eq!(config.server_version, "0.1.0");
    assert_eq!(config.page_size, 50);
    assert_eq!(config.wrapped_command, "python3");
    assert_eq!(
        config.wrapped_args,
        vec![dir
            .join("mock_http_mcp_server.py")
            .to_string_lossy()
            .into_owned()]
    );
    assert!(config.policy_path.exists());
    assert!(std::path::Path::new(&config.wrapped_args[0]).exists());
}
