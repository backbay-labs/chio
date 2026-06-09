#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

use chio_core::Keypair;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn fixed_public_key() -> String {
    Keypair::from_seed(&[7u8; 32]).public_key().to_hex()
}

fn fixed_did() -> String {
    format!("did:chio:{}", fixed_public_key())
}

#[test]
fn did_resolve_from_public_key_emits_self_certifying_document() {
    let public_key = fixed_public_key();
    let did = fixed_did();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args(["did", "resolve", "--public-key", &public_key])
        .output()
        .expect("run chio did resolve");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse DID document");
    assert_eq!(document["id"], did);
    assert_eq!(
        document["verificationMethod"][0]["id"],
        format!("{did}#key-1")
    );
    assert_eq!(
        document["verificationMethod"][0]["type"],
        "Ed25519VerificationKey2020"
    );
    assert_eq!(document["service"], serde_json::Value::Null);
}

#[test]
fn did_resolve_with_receipt_log_urls_emits_service_entries() {
    let did = fixed_did();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "did",
            "resolve",
            "--did",
            &did,
            "--receipt-log-url",
            "https://trust.example.com/v1/receipts",
            "--receipt-log-url",
            "https://mirror.example.com/v1/receipts",
        ])
        .output()
        .expect("run chio did resolve");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse DID document");
    let services = document["service"].as_array().expect("service array");
    assert_eq!(services.len(), 2);
    assert_eq!(services[0]["id"], format!("{did}#receipt-log"));
    assert_eq!(services[1]["id"], format!("{did}#receipt-log-2"));
    assert_eq!(services[0]["type"], "ChioReceiptLogService");
}

#[test]
fn did_resolve_with_passport_status_urls_emits_service_entries() {
    let did = fixed_did();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "did",
            "resolve",
            "--did",
            &did,
            "--passport-status-url",
            "https://trust.example.com/v1/passport/statuses/resolve",
            "--passport-status-url",
            "https://mirror.example.com/v1/passport/statuses/resolve",
        ])
        .output()
        .expect("run chio did resolve");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse DID document");
    let services = document["service"].as_array().expect("service array");
    assert_eq!(services.len(), 2);
    assert_eq!(services[0]["id"], format!("{did}#passport-status"));
    assert_eq!(services[1]["id"], format!("{did}#passport-status-2"));
    assert_eq!(services[0]["type"], "ChioPassportStatusService");
}

#[test]
fn did_resolve_rejects_invalid_identifier() {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args(["did", "resolve", "--did", "did:chio:not-hex"])
        .output()
        .expect("run chio did resolve");

    assert!(
        !output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("did:chio"));
}
