#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use rusqlite::Connection;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

fn receipt_db_policy() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/receipt-db-policy.yaml")
}

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{prefix}-{nonce}"));
    std::fs::create_dir_all(&path).expect("create private store directory");
    secure_private_directory(&path);
    path
}

fn secure_private_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("secure private store directory");
    }
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
    authority_db_path: &Path,
    joint_authority_db_path: &Path,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--session-db",
            joint_authority_db_path
                .to_str()
                .expect("joint authority db path"),
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

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..100 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

#[test]
fn check_command_persists_receipt_to_sqlite() {
    let dir = tempfile::tempdir().expect("private store directory");
    secure_private_directory(dir.path());
    let db_path = dir.path().join("receipts.sqlite3");
    let session_db_path = dir.path().join("sessions.sqlite3");
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            db_path.to_str().expect("utf-8 path"),
            "--session-db",
            session_db_path.to_str().expect("utf-8 session path"),
            "check",
            "--policy",
            receipt_db_policy().to_str().expect("policy path"),
            "--tool",
            "bash",
            "--server",
            "*",
            "--params",
            r#"{"command":"echo durable receipt"}"#,
        ])
        .output()
        .expect("run chio check");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let connection = Connection::open(&db_path).expect("open receipt db");
    let (count, distinct_count, decision_kind): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(decision_kind) FROM chio_tool_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("query tool receipts");
    let child_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })
        .expect("query child receipts");

    assert_eq!(count, 1);
    assert_eq!(distinct_count, 1);
    assert_eq!(decision_kind, "allow");
    assert_eq!(child_count, 0);

    drop(connection);
    let _ = std::fs::remove_file(db_path);
}

#[test]
fn check_command_persists_receipt_via_control_service() {
    if skip_when_loopback_bind_denied("check_command_persists_receipt_via_control_service") {
        return;
    }

    let dir = unique_dir("chio-cli-check-control");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    secure_private_directory(&dir);
    let receipt_db_path = dir.join("receipts.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let joint_authority_db_path = dir.join("joint-authority.sqlite3");
    let session_db_path = dir.join("sessions.sqlite3");
    let listen = reserve_listen_addr();
    let service_token = "control-secret";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &authority_db_path,
        &joint_authority_db_path,
    );
    let client = Client::builder().build().expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "--session-db",
            session_db_path.to_str().expect("session db path"),
            "check",
            "--policy",
            receipt_db_policy().to_str().expect("policy path"),
            "--tool",
            "bash",
            "--server",
            "*",
            "--params",
            r#"{"command":"echo control receipt"}"#,
        ])
        .output()
        .expect("run chio check via control service");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let connection = Connection::open(&receipt_db_path).expect("open receipt db");
    let (count, distinct_count, decision_kind): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(decision_kind) FROM chio_tool_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("query tool receipts");
    let child_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })
        .expect("query child receipts");

    assert_eq!(count, 1);
    assert_eq!(distinct_count, 1);
    assert_eq!(decision_kind, "allow");
    assert_eq!(child_count, 0);
}
