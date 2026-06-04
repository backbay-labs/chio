#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;

fn unique_revocation_db_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_trust_service(
    listen: std::net::SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

/// Drain stderr from a trust service child that has already been killed (or
/// observed exited). Reading from a still-running child's stderr pipe will
/// block forever because the pipe stays open while the process is alive, so
/// callers must ensure the child has been terminated before invoking this.
fn drain_stderr_after_exit(service: &mut ServerGuard) -> String {
    let _ = service.child.wait();
    let mut stderr = String::new();
    if let Some(child_stderr) = service.child.stderr.as_mut() {
        let _ = child_stderr.read_to_string(&mut stderr);
    }
    stderr
}

fn wait_for_trust_service(client: &Client, base_url: &str, service: &mut ServerGuard) {
    // 30s readiness budget matches mcp_auth_server.rs and provider_admin.rs.
    // A tighter budget risks flake on slow CI runners.
    for _ in 0..300 {
        if let Some(status) = service.child.try_wait().expect("poll trust service child") {
            let stderr = drain_stderr_after_exit(service);
            panic!(
                "trust service exited before becoming ready (status {status})\nstderr:\n{stderr}",
            );
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    // Readiness budget exhausted but the trust service may still be running.
    // Kill the child *first* and only then drain stderr: read_to_string on a
    // live child's piped stderr blocks until the writer closes, which never
    // happens while the process is alive, so reading first would hang the
    // test forever instead of surfacing the diagnostic.
    let _ = service.child.kill();
    let stderr = drain_stderr_after_exit(service);
    panic!("trust service did not become ready\nstderr:\n{stderr}");
}

#[test]
fn trust_revoke_and_status_use_persisted_revocation_db() {
    let db_path = unique_revocation_db_path("chio-cli-trust-revocations");
    let capability_id = "cap-test-123";

    let revoke = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--revocation-db",
            db_path.to_str().expect("utf-8 path"),
            "trust",
            "revoke",
            "--capability-id",
            capability_id,
        ])
        .output()
        .expect("run chio trust revoke");

    assert!(
        revoke.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--revocation-db",
            db_path.to_str().expect("utf-8 path"),
            "trust",
            "status",
            "--capability-id",
            capability_id,
        ])
        .output()
        .expect("run chio trust status");

    assert!(
        status.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    let output: serde_json::Value = serde_json::from_slice(&status.stdout).expect("valid json");
    assert_eq!(output["capability_id"], capability_id);
    assert_eq!(output["revoked"], true);

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn trust_revoke_and_status_can_target_control_service() {
    if skip_when_loopback_bind_denied("trust_revoke_and_status_can_target_control_service") {
        return;
    }

    let dir = unique_dir("chio-cli-trust-service");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let listen = reserve_listen_addr();
    let service_token = "control-secret";
    let mut service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url, &mut service);

    let capability_id = "cap-test-remote-123";

    let revoke = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "revoke",
            "--capability-id",
            capability_id,
        ])
        .output()
        .expect("run chio trust revoke against control service");

    assert!(
        revoke.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&revoke.stdout),
        String::from_utf8_lossy(&revoke.stderr)
    );

    let status = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "status",
            "--capability-id",
            capability_id,
        ])
        .output()
        .expect("run chio trust status against control service");

    assert!(
        status.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    let output: serde_json::Value = serde_json::from_slice(&status.stdout).expect("valid json");
    assert_eq!(output["capability_id"], capability_id);
    assert_eq!(output["revoked"], true);
    assert_eq!(output["revocation_backend"], base_url);

    let listed = client
        .get(format!("{base_url}/v1/revocations"))
        .query(&[("capabilityId", capability_id), ("limit", "1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("query trust service revocations");
    assert_eq!(listed.status(), reqwest::StatusCode::OK);
    let listed: serde_json::Value = listed.json().expect("revocations json");
    assert_eq!(listed["revoked"], true);
    assert_eq!(listed["count"], 1);
}
