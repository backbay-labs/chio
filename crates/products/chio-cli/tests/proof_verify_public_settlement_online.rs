#![allow(dead_code)]

#[path = "proof_verify/support.rs"]
mod support;

use chio_test_support::prelude::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};
use support::*;

#[test]
fn proof_verify_accepts_public_settlement_online_head_readback() {
    let rpc_url = start_public_settlement_rpc(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON")
        .env("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL", rpc_url)
        .env("CHIO_TEST_PUBLIC_SETTLEMENT_ALLOW_LOOPBACK_RPC", "true")
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("\"verdict\":\"verified\""));
    assert!(stdout.contains(
        "\"block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""
    ));
}

#[test]
fn proof_verify_rejects_public_settlement_online_head_readback_mismatch() {
    let rpc_url = start_public_settlement_rpc(
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON")
        .env("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL", rpc_url)
        .env("CHIO_TEST_PUBLIC_SETTLEMENT_ALLOW_LOOPBACK_RPC", "true")
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(
        stderr.contains("public settlement independent head block hash mismatch"),
        "{stderr}"
    );
}

#[test]
fn proof_verify_rejects_public_settlement_loopback_online_head_readback() {
    let rpc_url = start_public_settlement_rpc(
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    let output = chio_with_transaction_fixture_roots()
        .env_remove("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON")
        .env("CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL", rpc_url)
        .arg("proof")
        .arg("verify")
        .arg(public_settlement_fixture_path("valid-offline-finality"))
        .output()
        .test_expect("chio command runs");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains("loopback egress target denied"), "{stderr}");
}

fn start_public_settlement_rpc(observed_block_hash: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").test_expect("bind public settlement RPC");
    let address = listener
        .local_addr()
        .test_expect("read public settlement RPC address");
    thread::spawn(move || {
        for _ in 0..64 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let request = read_http_request(&mut stream);
            let response = if request.contains("eth_blockNumber") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": "0xbc6165"})
            } else if request.contains("eth_getBlockByNumber") {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"number": "0xbc614e", "hash": observed_block_hash}
                })
            } else {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32601, "message": "method not found"}
                })
            };
            let body = response.to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    format!("http://{address}")
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while let Ok(read) = stream.read(&mut buffer) {
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
