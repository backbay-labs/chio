use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    receipt::decision::{Decision, ToolCallAction},
    receipt::kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    receipt::metadata::ActorRef,
    Keypair,
};
use chio_test_support::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

#[path = "support/archive.rs"]
mod archive;
pub(crate) use archive::{
    tgz_member_names, write_tar_zst_with_symlink_member, write_tgz_with_symlink_member,
};

pub(crate) const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str =
    "application/vnd.chio.proof-room.bundle.v1+json";
pub(crate) const TEST_SIGNATURE_SEED: [u8; 32] = [7; 32];
pub(crate) const COLLECT_SIGNATURE_SEED: [u8; 32] = [11; 32];
pub(crate) const PUBLIC_EXPORT_SIGNATURE_SEED: [u8; 32] = [13; 32];
const PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_SEED: [u8; 32] = [9; 32];
const PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_ALGORITHM: &str = "ed25519-rfc8785-v1";
const COLLECT_SIGNATURE_SEED_HEX: &str =
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const PUBLIC_EXPORT_SIGNATURE_SEED_HEX: &str =
    "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";
pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &str =
    "chio-agent-web-standard-webhooks-fixture-secret-v1";
const STANDARD_WEBHOOKS_VERIFIER_NOW: &str = "1770508860";
const STANDARD_WEBHOOKS_MAX_AGE_SECONDS: &str = "300";
pub(crate) const AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS: &str = concat!(
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de,",
    "4508a07aa941707f3eb2db94c8897a80b2c1197476b6de213ac273df7d86c4ff,",
    "bed7d2ab668da3efad613998f06f7abf7875f3a6b7677a9f3ce947d77d7760a6,",
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737,",
    "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565"
);
pub(crate) const AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS: &str =
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const SWARM_FIXTURE_TRUSTED_WITNESS_KEYS: &str =
    "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de";
pub(crate) const PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS: &str = concat!(
    "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc,",
    "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa,",
    "a6d2455ea3a5771aba9fcb037924114c92f9f325049f6b4269e739d9048bb869"
);
pub(crate) const PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
);
const TRANSACTION_FIXTURE_TRUSTED_ROOT_KEYS: &str = concat!(
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c,",
    "68f4b6017d0f876a55c80a82b8388a54aad264d367269e2de8be079c935b5f96"
);
const RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS: &str =
    "5b8649c0cfcdbe78a5ff962edfa48914dfd45af22afe358de1f4dd7e4567d5ca";
const ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS: &str =
    "f95c6a5dff031fac7b1a6a54b6610caeb83b39f7e8a66be16ff5faa4a511ed2d";
const ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS: &str =
    "3f0dda81e6abbcc5f17c359df8517177769d2dfff3d4ce942e7ce9a82dfb0db2";
const TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS: &str =
    "cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7";
const COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS: &str =
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";
const COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BUNDLE_SIGNER_KEYS: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS: &str =
    "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS: &str =
    "91a28a0b74381593a4d9469579208926afc8ad82c8839b7644359b9eba9a4b3a";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS: &str =
    "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CONTRACT_PACKAGE_ID: &str = "chio.official-web3-contracts";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_REVIEWED_MANIFEST_HASH: &str =
    "0x454a9a92b54a835a2776750196b171501bff6e5c02df1a192616194fc0a095cc";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH: &str =
    "0xfc5d76d87b02096c6ae32ce644a2b98ca0bdf3c56700ad16731fad2062e6bd7f";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH: &str =
    "0xd4f87cc63c00d0640c8f232c8fac5e5cb99bc6cf185ef912225e07fa438614cc";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ESCROW_RUNTIME_CODEHASH: &str =
    "0x03d8f545c330922a33db6473430c50eafd527e04474f31abee2dc1f8c6ab2d36";
const PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH: &str =
    "0x17f7936469584b38404765ac44bd7e2384337983e4bc6448a3500d0637711f09";
const PUBLIC_SETTLEMENT_FIXTURE_INDEPENDENT_CHAIN_HEAD_JSON: &str =
    "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"latest_block_number\":12345701}";
const PUBLIC_SETTLEMENT_FIXTURE_ENV: &[(&str, &str)] = &[
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CAPITAL_SIGNER_KEYS,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BUNDLE_SIGNER_KEYS,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ANCHOR_KERNEL_KEYS,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BENEFICIARY_IDENTITY_KEYS,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ORACLE_KEYS,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_CONTRACT_PACKAGE_ID,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_REVIEWED_MANIFEST_HASH,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_ESCROW_RUNTIME_CODEHASH,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH",
        PUBLIC_SETTLEMENT_FIXTURE_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS",
        "eip155:8453,eip155:42161",
    ),
    ("CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS", "1"),
    (
        "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON",
        PUBLIC_SETTLEMENT_FIXTURE_INDEPENDENT_CHAIN_HEAD_JSON,
    ),
    (
        "CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS",
        "1743293560",
    ),
];
const DISCLOSURE_LINEAGE_SIGNATURE_SEED: [u8; 32] = [29; 32];
const DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS: &str =
    "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa";
pub(crate) const PROOF_SERVE_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(90);
const PROOF_SERVE_HTTP_READ_POLL: Duration = Duration::from_millis(200);
const PROOF_SERVE_HTTP_WAIT_TIMEOUT: Duration = Duration::from_secs(180);

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/products/chio-cli")
        .to_path_buf()
}

pub(crate) fn chio(args: &[&str]) -> std::process::Output {
    chio_command()
        .args(args)
        .output()
        .test_expect("chio command runs")
}

pub(crate) fn chio_command() -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_chio"));
    set_envs(
        &mut command,
        &[
            (
                "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
                STANDARD_WEBHOOKS_VERIFIER_SECRET,
            ),
            (
                "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS",
                STANDARD_WEBHOOKS_VERIFIER_NOW,
            ),
            (
                "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS",
                STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
            ),
            (
                "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
                AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS,
            ),
            (
                "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
                AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS,
            ),
            (
                "CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS",
                PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS,
            ),
        ],
    );
    command.env(
        "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS",
        proof_room_fixture_trusted_bundle_signer_keys(),
    );
    command.env(
        "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
        transaction_fixture_trusted_root_keys(),
    );
    set_envs(
        &mut command,
        &[
            (
                "CHIO_RUNTIME_TRUSTED_ROOT_KEYS",
                RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS,
            ),
            (
                "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS",
                ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS,
            ),
            (
                "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS",
                ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS,
            ),
            (
                "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS",
                PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS,
            ),
            (
                "CHIO_SWARM_TRUSTED_WITNESS_KEYS",
                SWARM_FIXTURE_TRUSTED_WITNESS_KEYS,
            ),
            (
                "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS",
                TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS,
            ),
            (
                "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS",
                COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS,
            ),
            (
                "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS",
                COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS,
            ),
            (
                "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS",
                COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS,
            ),
            (
                "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS",
                DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS,
            ),
            (
                "CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS",
                DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS,
            ),
            (
                "CHIO_PROOF_COLLECT_BUNDLE_SIGNER_SEED_HEX",
                COLLECT_SIGNATURE_SEED_HEX,
            ),
            (
                "CHIO_PROOF_EXPORT_BUNDLE_SIGNER_SEED_HEX",
                PUBLIC_EXPORT_SIGNATURE_SEED_HEX,
            ),
        ],
    );
    set_envs(&mut command, PUBLIC_SETTLEMENT_FIXTURE_ENV);
    command
}

fn set_envs(command: &mut std::process::Command, values: &[(&str, &str)]) {
    for (name, value) in values {
        command.env(name, value);
    }
}

struct ScopedEnv {
    previous: Vec<(&'static str, Option<OsString>)>,
}

impl ScopedEnv {
    fn set(values: Vec<(&'static str, String)>) -> Self {
        let mut previous = Vec::with_capacity(values.len());
        for (name, value) in values {
            previous.push((name, std::env::var_os(name)));
            std::env::set_var(name, value);
        }
        Self { previous }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (name, previous) in self.previous.drain(..).rev() {
            match previous {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

pub(crate) fn proof_room_fixture_trusted_bundle_signer_keys() -> String {
    let test_bundle_signer = Keypair::from_seed(&TEST_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    let collect_bundle_signer = Keypair::from_seed(&COLLECT_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    let public_export_bundle_signer = Keypair::from_seed(&PUBLIC_EXPORT_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    format!(
        "{PROOF_ROOM_SHIPPED_BUNDLE_SIGNER_KEYS},{test_bundle_signer},{collect_bundle_signer},{public_export_bundle_signer}"
    )
}

fn transaction_fixture_trusted_root_keys() -> String {
    let collect_bundle_signer = Keypair::from_seed(&COLLECT_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    let public_export_bundle_signer = Keypair::from_seed(&PUBLIC_EXPORT_SIGNATURE_SEED)
        .public_key()
        .to_hex();
    format!(
        "{TRANSACTION_FIXTURE_TRUSTED_ROOT_KEYS},{collect_bundle_signer},{public_export_bundle_signer}"
    )
}

pub(crate) fn stdout(output: std::process::Output) -> String {
    String::from_utf8(output.stdout).test_expect("stdout is utf8")
}

pub(crate) fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn assert_failure(output: &std::process::Output, expected: &str) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(expected),
        "expected failure to contain {expected:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn assert_failure_exit_code(
    output: &std::process::Output,
    expected: &str,
    exit_code: i32,
) {
    assert_failure(output, expected);
    assert_eq!(
        output.status.code(),
        Some(exit_code),
        "unexpected exit code\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) struct ChildGuard {
    pub(crate) child: Child,
}

pub(crate) struct RunningProofServe {
    _guard: ChildGuard,
    _serve_lock: MutexGuard<'static, ()>,
    pub(crate) address: SocketAddr,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn utf8_path(path: &Path) -> String {
    path.to_str().test_expect("path is utf8").to_string()
}

pub(crate) fn assert_json_schema_accepts(relative_schema_path: &str, instance: &serde_json::Value) {
    let schema_path = workspace_root().join(relative_schema_path);
    let schema_bytes = std::fs::read(&schema_path).test_expect("schema file reads");
    let schema: serde_json::Value =
        serde_json::from_slice(&schema_bytes).test_expect("schema parses");
    let validator = jsonschema::validator_for(&schema).test_expect("schema compiles");
    if validator.is_valid(instance) {
        return;
    }

    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join(" | ");
    panic!(
        "schema {relative_schema_path} rejected instance:\n{}\nerrors={errors}",
        serde_json::to_string_pretty(instance).test_expect("instance pretty prints")
    );
}

pub(crate) fn http_get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, PROOF_SERVE_HTTP_REQUEST_TIMEOUT)?;
    stream.set_read_timeout(Some(PROOF_SERVE_HTTP_READ_POLL))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let deadline = Instant::now() + PROOF_SERVE_HTTP_REQUEST_TIMEOUT;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&buffer[..count]);
                if http_response_has_declared_body(&response) {
                    break;
                }
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                    && Instant::now() < deadline =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "timed out reading HTTP response",
            ));
        }
    }
    String::from_utf8(response).map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
}

fn http_response_has_declared_body(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let Some(content_length) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("content-length") {
            return None;
        }
        value.trim().parse::<usize>().ok()
    }) else {
        return false;
    };
    response.len() >= header_end + 4 + content_length
}

pub(crate) fn wait_for_http_body(address: SocketAddr, path: &str) -> String {
    let deadline = Instant::now() + PROOF_SERVE_HTTP_WAIT_TIMEOUT;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match http_get(address, path) {
            Ok(response) if response.starts_with("HTTP/1.1 200") => {
                return response
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body.to_string())
                    .test_expect("http response has body");
            }
            Ok(response) => {
                last_error = response
                    .lines()
                    .next()
                    .unwrap_or("empty response")
                    .to_string();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {path}: {last_error}");
}

pub(crate) fn wait_for_http_response(address: SocketAddr, path: &str) -> String {
    let deadline = Instant::now() + PROOF_SERVE_HTTP_WAIT_TIMEOUT;
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match http_get(address, path) {
            Ok(response) => return response,
            Err(error) => {
                last_error = error.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {path}: {last_error}");
}

fn proof_serve_lock() -> MutexGuard<'static, ()> {
    static PROOF_SERVE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match PROOF_SERVE_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn spawn_proof_serve(bundle: &Path, ui_dir: Option<&Path>) -> RunningProofServe {
    let serve_lock = proof_serve_lock();
    let mut command = chio_command();
    if let Some(ui_dir) = ui_dir {
        command.env("CHIO_PROOF_ROOM_UI_DIR", ui_dir);
    }
    let mut child = command
        .arg("proof")
        .arg("serve")
        .arg(bundle)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .test_expect("spawn proof serve");
    let stdout = child.stdout.take().test_expect("proof serve stdout");
    let mut reader = BufReader::new(stdout);
    let mut report_line = String::new();
    reader
        .read_line(&mut report_line)
        .test_expect("read proof serve report");
    let report: serde_json::Value =
        serde_json::from_str(&report_line).test_expect("parse proof serve report");
    let listen = report
        .get("listen")
        .and_then(serde_json::Value::as_str)
        .test_expect("serve report listen address");
    let address: SocketAddr = listen.parse().test_expect("listen address parses");
    assert_ne!(address.port(), 0);
    RunningProofServe {
        _guard: ChildGuard { child },
        _serve_lock: serve_lock,
        address,
    }
}

pub(crate) fn copy_dir_all(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &destination_path)?;
        } else {
            std::fs::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

pub(crate) fn proof_room_bundle_fixture() -> PathBuf {
    workspace_root().join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle")
}

pub(crate) fn mutate_proof_room_bundle(
    negative_case: &str,
) -> (tempfile::TempDir, PathBuf, String) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");

    let negative_path = source
        .join("negatives")
        .join(format!("{negative_case}.json"));
    let negative: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&negative_path).test_expect("read negative case"))
            .test_expect("negative case parses");
    let expected = negative["expected_failure_code"]
        .as_str()
        .test_expect("negative case has expected failure code")
        .to_string();

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");

    match negative_case {
        "report-hash-mismatch" => {
            manifest["verifier_report_ref"]["sha256"] = negative["mutation"]["value"].clone();
        }
        "missing-denial-receipt" => {
            let claim_id = negative["mutation"]["claim_id"]
                .as_str()
                .test_expect("negative case has claim id");
            let claim = manifest["claims"]
                .as_array_mut()
                .test_expect("manifest claims array")
                .iter_mut()
                .find(|claim| {
                    claim.get("claim_id").and_then(serde_json::Value::as_str) == Some(claim_id)
                })
                .test_expect("manifest claim exists");
            claim["required_artifacts"] = negative["mutation"]["required_artifacts"].clone();
        }
        "receipt-coverage-status-mismatch" => {
            let category = negative["mutation"]["category"]
                .as_str()
                .test_expect("negative case has category");
            let terminal_status = negative["mutation"]["terminal_status"]
                .as_str()
                .test_expect("negative case has terminal status");
            let coverage = manifest["receipt_coverage"]
                .as_array_mut()
                .test_expect("manifest receipt coverage array")
                .iter_mut()
                .find(|entry| {
                    entry.get("category").and_then(serde_json::Value::as_str) == Some(category)
                })
                .test_expect("coverage category exists");
            coverage["terminal_status"] = serde_json::Value::String(terminal_status.to_string());
        }
        "missing-authority-evidence" => {
            let claim_id = negative["mutation"]["claim_id"]
                .as_str()
                .test_expect("negative case has claim id");
            if let Some(claims) = manifest["claims"].as_array_mut() {
                claims.retain(|claim| {
                    claim.get("claim_id").and_then(serde_json::Value::as_str) != Some(claim_id)
                });
            }
            let artifact_paths = negative["mutation"]["artifact_paths"]
                .as_array()
                .test_expect("negative case has artifact paths")
                .iter()
                .map(|path| {
                    path.as_str()
                        .test_expect("artifact path is string")
                        .to_string()
                })
                .collect::<BTreeSet<_>>();
            if let Some(artifacts) = manifest["artifacts"].as_array_mut() {
                artifacts.retain(|artifact| {
                    artifact
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|path| !artifact_paths.contains(path))
                });
            }
            for artifact_path in artifact_paths {
                let _ = std::fs::remove_file(bundle.join(artifact_path));
            }
        }
        "missing-authority-graph-node" => {
            let artifact_path = negative["mutation"]["artifact_path"]
                .as_str()
                .test_expect("negative case has artifact path");
            remove_evidence_graph_node_and_rehash(&bundle, &mut manifest, artifact_path);
        }
        other => panic!("unsupported negative case: {other}"),
    }

    let manifest_bytes = serde_json::to_vec_pretty(&manifest).test_expect("serialize manifest");
    std::fs::write(&manifest_path, [&manifest_bytes[..], b"\n"].concat())
        .test_expect("write manifest");
    refresh_bundle_signature(&bundle);

    (tempdir, bundle, expected)
}

pub(crate) fn remove_evidence_graph_node_and_rehash(
    bundle: &Path,
    manifest: &mut serde_json::Value,
    artifact_path: &str,
) {
    let evidence_graph_path = bundle.join("roots/evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .retain(|node| node.get("path").and_then(serde_json::Value::as_str) != Some(artifact_path));
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("roots/transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
    write_json(&passport_path, &passport);
    let passport_sha256 = sha256_file(&passport_path);

    let verifier_report_path = bundle.join("verifier/report.json");
    let mut verifier_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&verifier_report_path).test_expect("read report"))
            .test_expect("report parses");
    verifier_report["evidence_graph_sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    write_json(&verifier_report_path, &verifier_report);
    let verifier_report_sha256 = sha256_file(&verifier_report_path);

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
            .test_expect("UI report parses");
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    write_json(&ui_report_path, &ui_report);
    let ui_report_sha256 = sha256_file(&ui_report_path);

    manifest["transaction_passport_ref"]["sha256"] =
        serde_json::Value::String(passport_sha256.clone());
    manifest["evidence_graph_ref"]["sha256"] =
        serde_json::Value::String(evidence_graph_sha256.clone());
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("roots/transaction-passport.json") => {
                artifact["sha256"] = serde_json::Value::String(passport_sha256.clone());
            }
            Some("roots/evidence-graph.json") => {
                artifact["sha256"] = serde_json::Value::String(evidence_graph_sha256.clone());
            }
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
}

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) {
    let value = sign_transaction_passport_if_needed(path, value.clone());
    let bytes = serde_json::to_vec_pretty(&value).test_expect("serialize JSON");
    std::fs::write(path, [&bytes[..], b"\n"].concat()).test_expect("write JSON");
}

fn sign_transaction_passport_if_needed(
    _path: &Path,
    mut value: serde_json::Value,
) -> serde_json::Value {
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some("chio.transaction-passport.v1")
    {
        return value;
    }
    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    value["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    value["signature"] = serde_json::Value::String(String::new());
    let passport: chio_control_plane::transaction_passport::TransactionPassport =
        serde_json::from_value(value.clone())
            .test_expect("transaction passport parses for signing");
    value["signature"] = serde_json::Value::String(
        chio_control_plane::transaction_passport::sign_transaction_passport(&passport, &keypair)
            .test_expect("transaction passport signs"),
    );
    value
}

pub(crate) fn signed_terminal_receipt(
    receipt_id: &str,
    terminal_status: &str,
    policy_digest: &str,
) -> serde_json::Value {
    sign_terminal_receipt(serde_json::json!({
        "schema": "chio.receipt.v1",
        "receipt_id": receipt_id,
        "terminal_status": terminal_status,
        "policy_digest": policy_digest
    }))
}

pub(crate) fn sign_terminal_receipt(mut receipt: serde_json::Value) -> serde_json::Value {
    let keypair = Keypair::from_seed(&[23; 32]);
    let receipt_object = receipt
        .as_object_mut()
        .test_expect("terminal receipt is object");
    receipt_object.remove("signature");
    receipt_object.insert(
        "kernel_key".to_string(),
        serde_json::Value::String(keypair.public_key().to_hex()),
    );
    let (signature, _) = keypair
        .sign_canonical(&receipt)
        .test_expect("terminal receipt signs");
    receipt["signature"] = serde_json::Value::String(signature.to_hex());
    receipt
}

fn sign_runtime_lease_with_fixture_authority(value: &mut serde_json::Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] =
        serde_json::Value::String(sign_runtime_execution_lease(value, &signing_key));
}

fn sign_runtime_execution_lease(value: &serde_json::Value, keypair: &Keypair) -> String {
    let mut body = serde_json::json!({
        "schema": "chio.runtime.execution-lease-signature.v1",
        "leaseId": value["lease_id"],
        "subjectAgent": value["subject_agent"],
        "toolServerId": value["tool_server_id"],
        "toolInstanceId": value["tool_instance_id"],
        "toolManifestDigest": value["tool_manifest_digest"],
        "sandboxAttestationRef": value["sandbox_attestation_ref"],
        "capabilityDigest": value["capability_digest"],
        "requestDigest": value["request_digest"],
        "responsePolicyDigest": value["response_policy_digest"],
        "taskGraphDigest": value["task_graph_digest"],
        "childTaskId": value["child_task_id"],
        "parentReceiptRef": value["parent_receipt_ref"],
        "joinReceiptRef": value["join_receipt_ref"],
        "budgetPoolRef": value["budget_pool_ref"],
        "budgetAllocationRef": value["budget_allocation_ref"],
        "subjectCapabilityDigest": value["subject_capability_digest"],
        "ancestorCapabilityDigest": value["ancestor_capability_digest"],
        "revocationFreshnessRef": value["revocation_freshness_ref"],
        "policyDigest": value["policy_digest"],
        "nonce": value["nonce"],
        "sideEffectClass": value["side_effect_class"],
        "issuedAt": value["issued_at"],
        "expiresAt": value["expires_at"],
        "issuer": value["issuer"],
    });
    if value.get("revocation_epoch_ref").is_some() {
        body["revocationEpochRef"] = value["revocation_epoch_ref"].clone();
    }
    if value.get("route_plan_receipt_ref").is_some() {
        body["routePlanReceiptRef"] = value["route_plan_receipt_ref"].clone();
    }
    if value.get("max_invocations").is_some() {
        body["maxInvocations"] = value["max_invocations"].clone();
    }
    keypair
        .sign_canonical(&body)
        .test_expect("runtime execution lease signs")
        .0
        .to_hex()
}

fn sign_runtime_route_plan_with_fixture_authority(value: &mut serde_json::Value) {
    let signing_key = Keypair::from_seed(&[46u8; 32]);
    value["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", signing_key.public_key().to_hex()));
    value["signature"] = serde_json::Value::String(sign_runtime_route_plan(value, &signing_key));
}

fn sign_runtime_route_plan(value: &serde_json::Value, keypair: &Keypair) -> String {
    let body = serde_json::json!({
        "schema": "chio.swarm.route-plan-receipt-signature.v1",
        "routePlanId": value["routePlanId"],
        "graphId": value["graphId"],
        "taskId": value["taskId"],
        "selectedRoute": value["selectedRoute"],
        "candidateSetDigest": value["candidateSetDigest"],
        "registrySnapshotHash": value["registrySnapshotHash"],
        "bridgeId": value["bridgeId"],
        "protocolTarget": value["protocolTarget"],
        "egressContractId": value["egressContractId"],
        "egressConstraints": value["egressConstraints"],
        "attenuationDecision": value["attenuationDecision"],
        "policyDigest": value["policyDigest"],
        "expiresAtUnixMs": value["expiresAtUnixMs"],
        "issuer": value["issuer"],
    });
    keypair
        .sign_canonical(&body)
        .test_expect("runtime route plan signs")
        .0
        .to_hex()
}

fn sign_public_settlement_bundle_value(settlement_bundle: &mut serde_json::Value) {
    settlement_bundle
        .as_object_mut()
        .test_expect("settlement proof bundle object")
        .remove("bundle_signature");
    let typed_bundle: chio_web3::settlement_proof::PublicSettlementProofBundle =
        serde_json::from_value(settlement_bundle.clone())
            .test_expect("typed public settlement proof bundle");
    let keypair = Keypair::from_seed(&PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_SEED);
    let (signature, _) = keypair
        .sign_canonical(&typed_bundle)
        .test_expect("public settlement proof bundle signs");
    settlement_bundle["bundle_signature"] = serde_json::json!({
        "algorithm": PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_ALGORITHM,
        "signer_key": keypair.public_key().to_hex(),
        "signature": signature.to_hex()
    });
}

fn resign_public_settlement_bundle(bundle: &Path) {
    let settlement_path = bundle.join("settlement-proof-bundle.json");
    let mut settlement_bundle: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&settlement_path).test_expect("read settlement proof bundle"),
    )
    .test_expect("settlement proof bundle parses");
    sign_public_settlement_bundle_value(&mut settlement_bundle);
    write_json(&settlement_path, &settlement_bundle);
}

fn sign_runtime_terminal_receipt_with_fixture_kernel(value: &mut serde_json::Value) {
    let signing_key = Keypair::from_seed(&[23u8; 32]);
    value["kernel_key"] = serde_json::Value::String(signing_key.public_key().to_hex());
    value["signature"] =
        serde_json::Value::String(sign_runtime_terminal_receipt(value, &signing_key));
}

fn sign_runtime_terminal_receipt(value: &serde_json::Value, keypair: &Keypair) -> String {
    let mut body = serde_json::json!({
        "schema": "chio.runtime.terminal-receipt-signature.v1",
        "receiptId": value["receipt_id"],
        "terminalStatus": value["terminal_status"],
        "policyDigest": value["policy_digest"],
        "kernelKey": value["kernel_key"],
    });
    if value.get("execution_lease_ref").is_some() {
        body["executionLeaseRef"] = value["execution_lease_ref"].clone();
    }
    if value.get("incident_ref").is_some() {
        body["incidentRef"] = value["incident_ref"].clone();
    }
    keypair
        .sign_canonical(&body)
        .test_expect("runtime terminal receipt signs")
        .0
        .to_hex()
}

pub(crate) fn sign_transaction_receipt_artifact(bundle: &Path, artifact_path: &str) {
    let receipt_path = bundle.join(artifact_path);
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).test_expect("read receipt"))
            .test_expect("receipt parses");
    let signed_receipt = sign_terminal_receipt(receipt);
    let kernel_key = signed_receipt["kernel_key"]
        .as_str()
        .test_expect("signed receipt kernel key")
        .to_string();
    write_json(&receipt_path, &signed_receipt);
    authorize_transaction_trust_root_subject(bundle, &kernel_key);
    refresh_transaction_artifact_digest(bundle, "trust-root.json");
    refresh_transaction_artifact_digest(bundle, artifact_path);
}

fn authorize_transaction_trust_root_subject(bundle: &Path, subject: &str) {
    for trust_root_path in [
        bundle.join("trust-root.json"),
        bundle.join("roots/trust-root.json"),
    ] {
        if !trust_root_path.is_file() {
            continue;
        }
        let mut trust_root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&trust_root_path).test_expect("read trust root"))
                .test_expect("trust root parses");
        let roots = trust_root["roots"]
            .as_array_mut()
            .test_expect("trust root roots array");
        if !roots
            .iter()
            .any(|root| root.get("subject").and_then(serde_json::Value::as_str) == Some(subject))
        {
            roots.push(serde_json::json!({ "subject": subject }));
        }
        let object = trust_root
            .as_object_mut()
            .test_expect("trust root is object");
        object.remove("signature");
        let keypair = Keypair::from_seed(&[54u8; 32]);
        let (signature, _) = keypair
            .sign_canonical(&trust_root)
            .test_expect("trust root signs");
        trust_root["signature"] = serde_json::Value::String(signature.to_hex());
        write_json(&trust_root_path, &trust_root);
    }
}

pub(crate) fn refresh_transaction_artifact_digest(bundle: &Path, artifact_path: &str) {
    if bundle.join("roots/evidence-graph.json").is_file() {
        let top_level_artifact = bundle.join(artifact_path);
        let root_artifact = bundle.join("roots").join(artifact_path);
        if top_level_artifact.is_file() && root_artifact.is_file() {
            std::fs::copy(&top_level_artifact, &root_artifact)
                .test_expect("sync root transaction artifact");
            refresh_manifest_artifact_ref_if_present(bundle, &format!("roots/{artifact_path}"));
        }
        refresh_transaction_artifact_digest_at(
            bundle,
            &bundle.join("roots/evidence-graph.json"),
            &bundle.join("roots/transaction-passport.json"),
            artifact_path,
        );
        refresh_manifest_artifact_ref_if_present(bundle, "roots/evidence-graph.json");
        refresh_manifest_artifact_ref_if_present(bundle, "roots/transaction-passport.json");
    }
    refresh_transaction_artifact_digest_at(
        bundle,
        &bundle.join("evidence-graph.json"),
        &bundle.join("transaction-passport.json"),
        artifact_path,
    );
    refresh_manifest_artifact_ref_if_present(bundle, "evidence-graph.json");
    refresh_manifest_artifact_ref_if_present(bundle, "transaction-passport.json");
}

pub(crate) fn sync_proof_room_transaction_roots(bundle: &Path) {
    if !bundle.join("roots").is_dir() {
        return;
    }
    refresh_top_level_transaction_artifact_digests(bundle);
    for artifact_path in [
        "transaction-passport.json",
        "evidence-graph.json",
        "claim-set.json",
        "verifier-policy.json",
    ] {
        let source = bundle.join(artifact_path);
        let destination = bundle.join("roots").join(artifact_path);
        if source.is_file() && destination.is_file() {
            std::fs::copy(&source, &destination).test_expect("sync proof-room root artifact");
        }
    }
    refresh_existing_manifest_artifacts(bundle);
    refresh_proof_room_source_verifier_report(bundle);
}

pub(crate) fn retain_proof_room_manifest_claims(bundle: &Path, claim_ids: &[&str]) {
    let manifest_path = bundle.join("manifest.json");
    if !manifest_path.is_file() {
        return;
    }
    let allowed = claim_ids.iter().copied().collect::<BTreeSet<_>>();
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    if ui_report_path.is_file() {
        let mut ui_report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
                .test_expect("UI report parses");
        if let Some(rendered_claims) = ui_report
            .get_mut("rendered_claims")
            .and_then(serde_json::Value::as_array_mut)
        {
            rendered_claims.retain(|claim| {
                claim
                    .get("claim_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|claim_id| allowed.contains(claim_id))
            });
        }
        write_json(&ui_report_path, &ui_report);
        refresh_manifest_artifact_ref_if_present(bundle, "ui/proof-room-static/load-report.json");
    }
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["claims"]
        .as_array_mut()
        .test_expect("manifest claims array")
        .retain(|claim| {
            claim
                .get("claim_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|claim_id| allowed.contains(claim_id))
        });
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(bundle);
}

fn refresh_top_level_transaction_artifact_digests(bundle: &Path) {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let passport_path = bundle.join("transaction-passport.json");
    if !evidence_graph_path.is_file() || !passport_path.is_file() {
        return;
    }
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    refresh_evidence_graph_content_ids(bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] =
        serde_json::Value::String(sha256_file(&evidence_graph_path));
    for (field, path) in [
        ("claim_set_sha256", "claim-set.json"),
        ("verifier_policy_sha256", "verifier-policy.json"),
    ] {
        let artifact_path = bundle.join(path);
        if artifact_path.is_file() {
            passport[field] = serde_json::Value::String(sha256_file(&artifact_path));
        }
    }
    write_json(&passport_path, &passport);
}

fn refresh_proof_room_source_verifier_report(bundle: &Path) {
    let passport_path = bundle.join("roots/transaction-passport.json");
    let report_path = bundle.join("verifier/report.json");
    if !passport_path.is_file() || !report_path.is_file() {
        return;
    }
    static SOURCE_REPORT_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = SOURCE_REPORT_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .test_expect("source verifier env lock");
    let _env = ScopedEnv::set(source_verifier_fixture_env());
    let report = chio_proof_room::build_proof_room_source_verifier_report(bundle, &passport_path)
        .test_expect("source verifier report refreshes");
    write_json(&report_path, &report);
    refresh_verifier_report_refs_with_seed(bundle, bundle_signature_seed(bundle));
}

fn source_verifier_fixture_env() -> Vec<(&'static str, String)> {
    let mut env = vec![
        (
            "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET",
            STANDARD_WEBHOOKS_VERIFIER_SECRET.to_string(),
        ),
        (
            "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS",
            STANDARD_WEBHOOKS_VERIFIER_NOW.to_string(),
        ),
        (
            "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS",
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS.to_string(),
        ),
        (
            "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS",
            AGENT_WEB_FIXTURE_TRUSTED_KERNEL_KEYS.to_string(),
        ),
        (
            "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS",
            AGENT_WEB_FIXTURE_TRUSTED_SIDECAR_KEYS.to_string(),
        ),
        (
            "CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS",
            PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS.to_string(),
        ),
        (
            "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS",
            transaction_fixture_trusted_root_keys(),
        ),
        (
            "CHIO_RUNTIME_TRUSTED_ROOT_KEYS",
            RUNTIME_FIXTURE_TRUSTED_ROOT_KEYS.to_string(),
        ),
        (
            "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS",
            ENTERPRISE_FIXTURE_TRUSTED_APPROVAL_KEYS.to_string(),
        ),
        (
            "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS",
            ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS.to_string(),
        ),
        (
            "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS",
            PROOF_ROOM_FIXTURE_TRUSTED_RECEIPT_KERNEL_KEYS.to_string(),
        ),
        (
            "CHIO_SWARM_TRUSTED_WITNESS_KEYS",
            SWARM_FIXTURE_TRUSTED_WITNESS_KEYS.to_string(),
        ),
        (
            "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS",
            TRUST_MARKET_FIXTURE_TRUSTED_AUTHORITY_KEYS.to_string(),
        ),
        (
            "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS",
            COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS.to_string(),
        ),
        (
            "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS",
            COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS.to_string(),
        ),
        (
            "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS",
            COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS.to_string(),
        ),
        (
            "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS",
            DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS.to_string(),
        ),
        (
            "CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS",
            DISCLOSURE_FIXTURE_TRUSTED_SIGNER_KEYS.to_string(),
        ),
    ];
    env.extend(
        PUBLIC_SETTLEMENT_FIXTURE_ENV
            .iter()
            .map(|(name, value)| (*name, (*value).to_string())),
    );
    env
}

fn refresh_existing_manifest_artifacts(bundle: &Path) {
    let manifest_path = bundle.join("manifest.json");
    if !manifest_path.is_file() {
        return;
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    let mut artifact_paths = BTreeSet::new();
    for ref_field in [
        "transaction_passport_ref",
        "evidence_graph_ref",
        "verifier_report_ref",
        "proof_room_verifier_report_ref",
    ] {
        if let Some(path) = manifest
            .get(ref_field)
            .and_then(|reference| reference.get("path"))
            .and_then(serde_json::Value::as_str)
        {
            artifact_paths.insert(path.to_string());
        }
    }
    for artifact in manifest
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(path) = artifact.get("path").and_then(serde_json::Value::as_str) {
            artifact_paths.insert(path.to_string());
        }
    }
    for artifact_path in artifact_paths {
        if bundle.join(&artifact_path).is_file() {
            refresh_manifest_artifact_ref(bundle, &artifact_path);
        }
    }
}

pub(crate) fn refresh_transaction_artifact_digest_at(
    bundle: &Path,
    evidence_graph_path: &Path,
    passport_path: &Path,
    artifact_path: &str,
) {
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    let mut refreshed = false;
    for node in evidence_graph["nodes"]
        .as_array()
        .test_expect("graph nodes array")
    {
        if node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path) {
            refreshed = true;
        }
    }
    assert!(
        refreshed,
        "transaction evidence graph did not contain {artifact_path}"
    );
    refresh_evidence_graph_content_ids(bundle, &mut evidence_graph);
    write_json(evidence_graph_path, &evidence_graph);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(sha256_file(evidence_graph_path));
    if let Some(artifact_hash) = evidence_graph_path
        .parent()
        .map(|parent| parent.join(artifact_path))
        .filter(|path| path.is_file())
        .map(|path| sha256_file(&path))
    {
        match artifact_path {
            "claim-set.json" => {
                passport["claim_set_sha256"] = serde_json::Value::String(artifact_hash);
            }
            "verifier-policy.json" => {
                passport["verifier_policy_sha256"] = serde_json::Value::String(artifact_hash);
            }
            _ => {}
        }
    }
    write_json(passport_path, &passport);
}

pub(crate) fn refresh_evidence_graph_content_ids(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
) {
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    let mut id_remaps = BTreeMap::new();
    let mut refreshed_nodes = Vec::with_capacity(nodes.len());
    let mut retained_ids = BTreeSet::new();

    for mut node in std::mem::take(nodes) {
        let path = node
            .get("path")
            .and_then(serde_json::Value::as_str)
            .map(std::string::ToString::to_string);
        let old_id = node
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(std::string::ToString::to_string);
        let old_sha256 = node
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .map(std::string::ToString::to_string);
        let Some(path) = path else {
            refreshed_nodes.push(node);
            continue;
        };
        if path.ends_with("evidence-graph.json") {
            refreshed_nodes.push(node);
            continue;
        }
        let artifact_path = bundle.join(&path);
        if !artifact_path.is_file() {
            refreshed_nodes.push(node);
            continue;
        }

        let artifact_sha256 = sha256_file(&artifact_path);
        if let Some(old_id) = old_id {
            id_remaps.insert(old_id, artifact_sha256.clone());
        }
        if let Some(old_sha256) = old_sha256 {
            id_remaps.insert(old_sha256, artifact_sha256.clone());
        }
        node["id"] = serde_json::Value::String(artifact_sha256.clone());
        node["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        if retained_ids.insert(artifact_sha256) {
            refreshed_nodes.push(node);
        }
    }
    *nodes = refreshed_nodes;
    let node_ids = nodes
        .iter()
        .filter_map(|node| node.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();

    if let Some(edges) = evidence_graph["edges"].as_array_mut() {
        for edge in &mut *edges {
            for field in ["from", "to"] {
                let Some(current) = edge
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .map(std::string::ToString::to_string)
                else {
                    continue;
                };
                if let Some(next) = id_remaps.get(&current) {
                    edge[field] = serde_json::Value::String(next.clone());
                }
            }
        }
        edges.retain(|edge| {
            let Some(from) = edge.get("from").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let Some(to) = edge.get("to").and_then(serde_json::Value::as_str) else {
                return false;
            };
            node_ids.contains(from) && node_ids.contains(to)
        });
    }
}

pub(crate) fn artifact_ref(bundle: &Path, path: &str, schema: &str) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "sha256": sha256_file(&bundle.join(path)),
        "schema": schema
    })
}

pub(crate) fn artifact(
    bundle: &Path,
    path: &str,
    schema: &str,
    artifact_class: &str,
    renderer_hint: &str,
) -> serde_json::Value {
    let mut value = artifact_ref(bundle, path, schema);
    value["media_type"] = serde_json::Value::String("application/json".to_string());
    value["artifact_class"] = serde_json::Value::String(artifact_class.to_string());
    value["sensitivity_class"] = serde_json::Value::String("public-fixture".to_string());
    value["producer"] =
        serde_json::Value::String("fixtures/proof-room/minimal-passport/valid".to_string());
    value["participates_in_primary_verdict"] = serde_json::Value::Bool(true);
    value["renderer_hint"] = serde_json::Value::String(renderer_hint.to_string());
    value
}

pub(crate) fn sha256_file(path: &Path) -> String {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("read file for sha256 {}: {error}", path.display()),
    };
    hex::encode(Sha256::digest(&bytes))
}

pub(crate) fn graph_node_by_schema<'a>(
    evidence_graph: &'a serde_json::Value,
    schema: &str,
) -> &'a serde_json::Value {
    evidence_graph["nodes"]
        .as_array()
        .test_expect("evidence graph nodes array")
        .iter()
        .find(|node| node.get("schema").and_then(serde_json::Value::as_str) == Some(schema))
        .unwrap_or_else(|| panic!("evidence graph missing schema {schema}"))
}

pub(crate) fn assert_graph_node_hashes_bundle_artifact(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
    schema: &str,
) -> serde_json::Value {
    let node = graph_node_by_schema(evidence_graph, schema);
    let path = node["path"]
        .as_str()
        .test_expect("evidence graph node path is string");
    assert_eq!(
        node["sha256"].as_str(),
        Some(sha256_file(&bundle.join(path)).as_str()),
        "evidence graph digest mismatch for {schema}"
    );
    serde_json::from_slice(&std::fs::read(bundle.join(path)).test_expect("read graph artifact"))
        .test_expect("graph artifact parses")
}

pub(crate) fn resign_agent_web_receipts_for_policy(bundle: &Path, policy_sha256: &str) {
    let receipts_dir = bundle.join("receipts");
    if !receipts_dir.is_dir() {
        return;
    }
    let keypair = Keypair::from_seed(&[17u8; 32]);
    for entry in std::fs::read_dir(&receipts_dir).test_expect("read Agent Web receipts dir") {
        let entry = entry.test_expect("read Agent Web receipt entry");
        let receipt_path = entry.path();
        if receipt_path.extension().and_then(std::ffi::OsStr::to_str) != Some("json") {
            continue;
        }
        let receipt: ChioReceipt =
            serde_json::from_slice(&std::fs::read(&receipt_path).test_expect("read receipt"))
                .test_expect("Agent Web receipt parses");
        let Some(receipt_ref) = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let content_hash = agent_web_receipt_subject_path(receipt_ref)
            .map(|subject_path| bundle.join(subject_path))
            .filter(|subject_path| subject_path.is_file())
            .map(|subject_path| sha256_file(&subject_path))
            .unwrap_or_else(|| receipt.content_hash.clone());
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "agent_web_receipt_ref": receipt_ref,
            "content_hash": content_hash
        }))
        .test_expect("Agent Web receipt action hashes");
        let body = ChioReceiptBody {
            id: receipt_ref.to_string(),
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id,
            tool_server: receipt.tool_server,
            tool_name: receipt.tool_name,
            action,
            decision: receipt.decision,
            receipt_kind: receipt.receipt_kind,
            boundary_class: receipt.boundary_class,
            observation_outcome: receipt.observation_outcome,
            tool_origin: receipt.tool_origin,
            redaction_mode: receipt.redaction_mode,
            actor_chain: receipt.actor_chain,
            content_hash,
            policy_hash: policy_sha256.to_string(),
            evidence: receipt.evidence,
            metadata: receipt.metadata,
            trust_level: receipt.trust_level,
            tenant_id: receipt.tenant_id,
            kernel_key: keypair.public_key(),
            bbs_projection_version: receipt.bbs_projection_version,
        };
        let signed_receipt =
            ChioReceipt::sign(body, &keypair).test_expect("Agent Web receipt signs");
        let bytes =
            serde_json::to_vec_pretty(&signed_receipt).test_expect("Agent Web receipt serializes");
        std::fs::write(&receipt_path, [&bytes[..], b"\n"].concat())
            .test_expect("write Agent Web receipt");
    }
}

pub(crate) fn refresh_agent_web_envelopes_for_subjects(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
) {
    let keypair = Keypair::from_seed(&[17u8; 32]);
    let public_key = keypair.public_key().to_hex();
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        if node.get("role").and_then(serde_json::Value::as_str) != Some("agent-web-proof-envelope")
        {
            continue;
        }
        let path = node["path"]
            .as_str()
            .test_expect("Agent Web envelope node has path");
        let envelope_path = bundle.join(path);
        let mut envelope: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&envelope_path).test_expect("read Agent Web envelope"),
        )
        .test_expect("Agent Web envelope parses");
        let subject_path = envelope["external_subject_path"]
            .as_str()
            .test_expect("Agent Web envelope has external subject path");
        envelope["external_subject_digest"] =
            serde_json::Value::String(sha256_file(&bundle.join(subject_path)));
        sign_agent_web_envelope_value(&mut envelope, &keypair, &public_key);
        write_json(&envelope_path, &envelope);
        node["sha256"] = serde_json::Value::String(sha256_file(&envelope_path));
    }
}

fn sign_agent_web_envelope_value(
    envelope: &mut serde_json::Value,
    keypair: &Keypair,
    public_key: &str,
) {
    envelope["envelope_id"] = serde_json::Value::String(agent_web_envelope_id(envelope));
    let payload = agent_web_envelope_signature_payload(envelope);
    let canonical =
        chio_core_types::canonical_json_bytes(&payload).test_expect("Agent Web envelope signs");
    let signature = keypair.sign(&canonical).to_hex();
    envelope["signature"] =
        serde_json::Value::String(format!("sig-ed25519:{public_key}:{signature}"));
}

fn agent_web_envelope_id(envelope: &serde_json::Value) -> String {
    let payload = agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "transaction_passport_ref",
            "source_protocol",
            "source_protocol_version",
            "external_subject",
            "external_subject_path",
            "external_subject_digest",
            "external_subject_signature_ref",
            "projection_manifest_ref",
            "projection_manifest_sha256",
            "chio_claim_refs",
            "receipt_refs",
            "disclosure_capsule_refs",
            "settlement_refs",
            "risk_refs",
            "limitations",
        ],
    );
    let canonical =
        chio_core_types::canonical_json_bytes(&payload).test_expect("Agent Web envelope id hashes");
    chio_core_types::sha256_hex(&canonical)
}

fn agent_web_envelope_signature_payload(envelope: &serde_json::Value) -> serde_json::Value {
    agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "envelope_id",
            "transaction_passport_ref",
            "source_protocol",
            "source_protocol_version",
            "external_subject",
            "external_subject_path",
            "external_subject_digest",
            "external_subject_signature_ref",
            "projection_manifest_ref",
            "projection_manifest_sha256",
            "chio_claim_refs",
            "receipt_refs",
            "disclosure_capsule_refs",
            "settlement_refs",
            "risk_refs",
            "limitations",
        ],
    )
}

fn agent_web_envelope_payload(envelope: &serde_json::Value, fields: &[&str]) -> serde_json::Value {
    let object = envelope
        .as_object()
        .test_expect("Agent Web envelope is an object");
    let mut payload = serde_json::Map::new();
    for field in fields {
        payload.insert(
            (*field).to_string(),
            object
                .get(*field)
                .unwrap_or_else(|| panic!("Agent Web envelope missing field: {field}"))
                .clone(),
        );
    }
    serde_json::Value::Object(payload)
}

fn agent_web_receipt_subject_path(receipt_id: &str) -> Option<&'static str> {
    Some(match receipt_id {
        "receipt-agent-web-webhook-allow" => "external/webhook-delivery.json",
        "receipt-agent-web-cloudevents-allow" => "external/cloudevent.json",
        "receipt-agent-web-graphql-mutation-allow" => "external/graphql-operation.json",
        "receipt-agent-web-mcp-tool-call-allow" => "external/mcp-tool-call.json",
        "receipt-agent-web-a2a-task-allow" => "external/a2a-task.json",
        "receipt-agent-web-openapi-operation-allow" => "external/openapi-operation.json",
        "receipt-agent-web-acp-client-permission-allow" => "external/acp-client-permission.json",
        "receipt-agent-web-acp-commerce-checkout-allow" => "external/acp-commerce-checkout.json",
        "receipt-agent-web-ag-ui-event-allow" => "external/ag-ui-event.json",
        "receipt-agent-web-browser-command-allow" => "external/browser-command.json",
        "receipt-agent-web-rpa-transcript-allow" => "external/rpa-transcript.json",
        "receipt-agent-web-email-message-allow" => "external/email-message.json",
        "receipt-agent-web-calendar-event-allow" => "external/calendar-event.json",
        "receipt-agent-web-slack-message-allow" => "external/slack-message.json",
        "receipt-agent-web-oauth2-authorization-allow" => "external/oauth2-authorization.json",
        "receipt-agent-web-openid-connect-identity-allow" => {
            "external/openid-connect-identity.json"
        }
        "receipt-agent-web-scim-lifecycle-allow" => "external/scim-lifecycle.json",
        "receipt-agent-web-spiffe-workload-allow" => "external/spiffe-workload-identity.json",
        "receipt-agent-web-kubernetes-admission-allow" => {
            "external/kubernetes-admission-review.json"
        }
        "receipt-agent-web-oci-ref-allow" => "external/oci-ref.json",
        "receipt-agent-web-vc-allow" => "external/verifiable-credential.json",
        "receipt-agent-web-sd-jwt-vc-presentation-allow" => "external/sd-jwt-vc-presentation.json",
        "receipt-agent-web-bbs-disclosure-allow" => "external/bbs-receipt-disclosure.json",
        "receipt-agent-web-sigstore-bundle-allow" => "external/sigstore-bundle.json",
        "receipt-agent-web-in-toto-statement-allow" => "external/in-toto-statement.json",
        "receipt-agent-web-dsse-envelope-allow" => "external/dsse-envelope.json",
        "receipt-agent-web-slsa-provenance-allow" => "external/slsa-provenance.json",
        "receipt-agent-web-asyncapi-message-allow" => "external/asyncapi-message.json",
        "receipt-agent-web-ap2-mandate-allow" => "external/ap2-mandate-chain.json",
        "receipt-agent-web-x402-payment-allow" => "external/x402-payment.json",
        _ => return None,
    })
}

pub(crate) fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

pub(crate) fn sign_bundle_signature(bundle: &Path, signature: &mut serde_json::Value) {
    sign_bundle_signature_with_seed(bundle, signature, TEST_SIGNATURE_SEED);
}

pub(crate) fn sign_bundle_signature_with_seed(
    bundle: &Path,
    signature: &mut serde_json::Value,
    seed: [u8; 32],
) {
    let manifest_bytes = std::fs::read(bundle.join("manifest.json")).test_expect("read manifest");
    let signed_payload = dsse_pre_auth_encoding(PROOF_ROOM_DSSE_PAYLOAD_TYPE, &manifest_bytes);
    let keypair = chio_core::Keypair::from_seed(&seed);
    signature["payloadRef"]["sha256"] =
        serde_json::Value::String(hex::encode(Sha256::digest(&manifest_bytes)));
    signature["signatures"][0]["keyid"] = serde_json::Value::String(keypair.public_key().to_hex());
    signature["signatures"][0]["sig"] =
        serde_json::Value::String(keypair.sign(&signed_payload).to_hex());
}

pub(crate) fn proof_room_trust_roots_for_seed(seed: [u8; 32]) -> serde_json::Value {
    let keypair = chio_core::Keypair::from_seed(&seed);
    let key_id = keypair.public_key().to_hex();
    let key_digest = hex::encode(Sha256::digest(key_id.as_bytes()));
    let mut trust_roots = serde_json::json!({
        "schema": "chio.proof.first-run.trust-roots.v1",
        "id": "trust-roots-test-bundle",
        "trust_domain": "did:chio:proof-room-test",
        "roots": [
            {
                "subject": "did:chio:test-authority",
                "key_id": key_id,
                "key_digest": key_digest
            }
        ]
    });
    let (signature, _) = keypair
        .sign_canonical(&trust_roots)
        .test_expect("trust roots sign");
    trust_roots["signature"] = serde_json::Value::String(signature.to_hex());
    trust_roots
}

pub(crate) fn build_runtime_commerce_passport_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let runtime_source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let commerce_source =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle = tempdir.path().join("runtime-commerce-passport");
    copy_dir_all(&runtime_source, &bundle).test_expect("copy runtime bundle");

    for path in [
        "order-context.json",
        "event-log.json",
        "payment-lifecycle.json",
        "mandate-allowance-ledger.json",
        "settlement-packet.json",
        "provider-passport.json",
        "reputation-snapshot.json",
        "federation-trust-bundle.json",
        "order-passport.json",
    ] {
        std::fs::copy(commerce_source.join(path), bundle.join(path))
            .test_expect("copy commerce artifact");
    }
    copy_dir_all(
        &commerce_source.join("protocol-payloads"),
        &bundle.join("protocol-payloads"),
    )
    .test_expect("copy commerce protocol payloads");

    let policy_path = bundle.join("verifier-policy.json");
    let commerce_policy_path = commerce_source.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    let commerce_policy: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&commerce_policy_path).test_expect("read commerce verifier policy"),
    )
    .test_expect("commerce verifier policy parses");
    let required_claims = policy["required_claims"]
        .as_array_mut()
        .test_expect("policy required_claims array");
    for claim in commerce_policy["required_claims"]
        .as_array()
        .test_expect("commerce policy required_claims array")
    {
        required_claims.push(claim.clone());
    }
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);
    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport["id"].as_str().test_expect("passport has id"),
        passport["issued_at"]
            .as_str()
            .test_expect("passport has issued_at"),
        &policy,
    );

    for path in [
        "execution-lease.json",
        "route-plan-receipt.json",
        "allow-receipt.json",
    ] {
        let artifact_path = bundle.join(path);
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        match path {
            "execution-lease.json" => {
                artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_lease_with_fixture_authority(&mut artifact);
            }
            "route-plan-receipt.json" => {
                artifact["policyDigest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_route_plan_with_fixture_authority(&mut artifact);
            }
            "allow-receipt.json" => {
                artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_terminal_receipt_with_fixture_kernel(&mut artifact);
            }
            _ => {}
        }
        write_json(&artifact_path, &artifact);
    }

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    let commerce_graph_path = commerce_source.join("evidence-graph.json");
    let commerce_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&commerce_graph_path).test_expect("read commerce graph"),
    )
    .test_expect("commerce graph parses");
    for node in commerce_graph["nodes"]
        .as_array()
        .test_expect("commerce graph nodes array")
    {
        let path = node["path"].as_str().test_expect("commerce node path");
        let id = node["id"].as_str().test_expect("commerce node id");
        let role = node["role"].as_str().test_expect("commerce node role");
        let schema = node["schema"].as_str().test_expect("commerce node schema");
        if matches!(
            path,
            "transaction-passport.json"
                | "evidence-graph.json"
                | "claim-set.json"
                | "verifier-policy.json"
        ) || matches!(id, "claim-set" | "verifier-policy")
            || matches!(role, "claim-set" | "verifier-policy")
            || (schema == "chio.receipt.v1" && path.starts_with("authority-receipts/"))
        {
            continue;
        }
        let mut node = node.clone();
        let artifact_sha256 = sha256_file(&bundle.join(path));
        node["id"] = serde_json::Value::String(artifact_sha256.clone());
        node["sha256"] = serde_json::Value::String(artifact_sha256);
        evidence_graph["nodes"]
            .as_array_mut()
            .test_expect("graph nodes array")
            .push(node);
    }
    refresh_commerce_event_authority_receipts(&bundle, &mut evidence_graph, &policy_sha256);
    refresh_commerce_order_passport(&bundle, &mut evidence_graph);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);
    sync_proof_room_transaction_roots(&bundle);

    (tempdir, bundle)
}

pub(crate) fn build_commerce_transfer_group_mismatch_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let bundle = tempdir.path().join("commerce-transfer-group-mismatch");
    copy_dir_all(&source, &bundle).test_expect("copy commerce bundle");

    let payment_path = bundle.join("payment-lifecycle.json");
    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&payment_path).test_expect("read payment lifecycle"))
            .test_expect("payment lifecycle parses");
    payment_lifecycle["transfer_group"] = serde_json::json!("order-commerce-other");
    sign_commerce_payment_lifecycle(&mut payment_lifecycle);
    write_json(&payment_path, &payment_lifecycle);

    let order_context_path = bundle.join("order-context.json");
    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("order context parses");
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(sha256_file(&payment_path));
    write_json(&order_context_path, &order_context);

    refresh_transaction_artifact_digest(&bundle, "order-context.json");
    refresh_transaction_artifact_digest(&bundle, "payment-lifecycle.json");

    (tempdir, bundle)
}

pub(crate) fn build_commerce_settlement_passport_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let commerce_source =
        workspace_root().join("fixtures/proof-room/commerce-payments/offline-psp-valid");
    let settlement_source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let bundle = tempdir.path().join("commerce-settlement-passport");
    copy_dir_all(&commerce_source, &bundle).test_expect("copy commerce bundle");

    let settlement_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(settlement_source.join("transaction-passport.json"))
            .test_expect("read public settlement passport"),
    )
    .test_expect("public settlement passport parses");
    let passport_id = settlement_passport["id"]
        .as_str()
        .test_expect("public settlement passport has id");
    let settlement_proof: serde_json::Value = serde_json::from_slice(
        &std::fs::read(settlement_source.join("settlement-proof-bundle.json"))
            .test_expect("read settlement proof bundle"),
    )
    .test_expect("settlement proof bundle parses");
    let commerce_order_id = settlement_proof["commerce_order_id"]
        .as_str()
        .test_expect("settlement proof bundle has commerce_order_id");
    retarget_commerce_order_id(&bundle, commerce_order_id);

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    append_required_claims_from_policy(
        &mut policy,
        &settlement_source.join("verifier-policy.json"),
    );
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport_id,
        passport["issued_at"]
            .as_str()
            .test_expect("passport has issued_at"),
        &policy,
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    append_graph_artifacts_from_fixture(
        &bundle,
        &settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", passport_id)],
    );
    resign_public_settlement_bundle(&bundle);
    refresh_commerce_event_authority_receipts(&bundle, &mut evidence_graph, &policy_sha256);
    refresh_commerce_order_passport(&bundle, &mut evidence_graph);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    passport["id"] = serde_json::Value::String(passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);
    sync_proof_room_transaction_roots(&bundle);

    (tempdir, bundle)
}

pub(crate) fn build_integrated_runtime_commerce_settlement_agent_web_bundle(
) -> (tempfile::TempDir, PathBuf) {
    build_integrated_runtime_commerce_settlement_agent_web_bundle_for_commerce_order(
        "order-public-settlement-valid",
    )
}

pub(crate) fn build_integrated_runtime_commerce_settlement_agent_web_bundle_with_mismatched_orders(
) -> (tempfile::TempDir, PathBuf) {
    build_integrated_runtime_commerce_settlement_agent_web_bundle_for_commerce_order(
        "order-commerce-001",
    )
}

fn build_integrated_runtime_commerce_settlement_agent_web_bundle_for_commerce_order(
    commerce_order_id: &str,
) -> (tempfile::TempDir, PathBuf) {
    let (tempdir, bundle) = build_runtime_commerce_passport_bundle();
    let settlement_source =
        workspace_root().join("fixtures/proof-room/public-settlement/valid-offline-finality");
    let agent_web_source =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    retarget_commerce_order_id(&bundle, commerce_order_id);

    let passport_path = bundle.join("transaction-passport.json");
    let agent_web_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(agent_web_source.join("transaction-passport.json"))
            .test_expect("read Agent Web passport"),
    )
    .test_expect("Agent Web passport parses");
    let passport_id = agent_web_passport["id"]
        .as_str()
        .test_expect("Agent Web passport has id");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    let current_passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    append_required_claims_from_policy(
        &mut policy,
        &settlement_source.join("verifier-policy.json"),
    );
    remove_required_claim(
        &mut policy,
        "claim.public_settlement.trust_market_refs_bound",
    );
    append_required_claims_from_policy(&mut policy, &agent_web_source.join("verifier-policy.json"));
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport_id,
        current_passport["issued_at"]
            .as_str()
            .test_expect("passport issued_at"),
        &policy,
    );

    for path in [
        "execution-lease.json",
        "route-plan-receipt.json",
        "allow-receipt.json",
    ] {
        let artifact_path = bundle.join(path);
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        match path {
            "execution-lease.json" => {
                artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_lease_with_fixture_authority(&mut artifact);
            }
            "route-plan-receipt.json" => {
                artifact["policyDigest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_route_plan_with_fixture_authority(&mut artifact);
            }
            "allow-receipt.json" => {
                artifact["policy_digest"] = serde_json::Value::String(policy_sha256.clone());
                sign_runtime_terminal_receipt_with_fixture_kernel(&mut artifact);
            }
            _ => {}
        }
        write_json(&artifact_path, &artifact);
    }

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    append_graph_artifacts_from_fixture(
        &bundle,
        &settlement_source,
        &mut evidence_graph,
        &[("passport-public-settlement-valid", passport_id)],
    );
    resign_public_settlement_bundle(&bundle);
    append_graph_artifacts_from_fixture(&bundle, &agent_web_source, &mut evidence_graph, &[]);
    remove_graph_nodes_by_path(&mut evidence_graph, "external/settlement-packet.json");
    refresh_agent_web_envelopes_for_subjects(&bundle, &mut evidence_graph);
    resign_agent_web_receipts_for_policy(&bundle, &policy_sha256);
    refresh_commerce_event_authority_receipts(&bundle, &mut evidence_graph, &policy_sha256);
    refresh_commerce_order_passport(&bundle, &mut evidence_graph);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["id"] = serde_json::Value::String(passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);
    sync_proof_room_transaction_roots(&bundle);

    (tempdir, bundle)
}

fn retarget_commerce_order_id(bundle: &Path, order_id: &str) {
    let event_log_path = bundle.join("event-log.json");
    let payment_path = bundle.join("payment-lifecycle.json");
    let mandate_path = bundle.join("mandate-allowance-ledger.json");
    let settlement_packet_path = bundle.join("settlement-packet.json");
    let order_context_path = bundle.join("order-context.json");

    let mut order_context: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&order_context_path).test_expect("read order context"),
    )
    .test_expect("order context parses");
    order_context["order_id"] = serde_json::json!(order_id);
    let quote_sha256 = commerce_quote_sha256(&order_context);
    order_context["quote_sha256"] = serde_json::json!(quote_sha256.clone());

    let mut event_log: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_log_path).test_expect("read event log"))
            .test_expect("event log parses");
    event_log["order_id"] = serde_json::json!(order_id);
    for event in event_log["events"]
        .as_array_mut()
        .test_expect("event log events array")
    {
        event["order_id"] = serde_json::json!(order_id);
    }
    seal_commerce_event_log(&mut event_log);
    write_json(&event_log_path, &event_log);

    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&payment_path).test_expect("read payment lifecycle"))
            .test_expect("payment lifecycle parses");
    payment_lifecycle["order_id"] = serde_json::json!(order_id);
    payment_lifecycle["transfer_group"] = serde_json::json!(order_id);
    payment_lifecycle["quote_sha256"] = serde_json::json!(quote_sha256.clone());
    sign_commerce_payment_lifecycle(&mut payment_lifecycle);
    write_json(&payment_path, &payment_lifecycle);

    let mut mandate_ledger: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&mandate_path).test_expect("read mandate ledger"))
            .test_expect("mandate ledger parses");
    mandate_ledger["order_id"] = serde_json::json!(order_id);
    mandate_ledger["quote_sha256"] = serde_json::json!(quote_sha256.clone());
    retarget_commerce_mandate_projection_order_ids(&mut mandate_ledger, order_id);
    retarget_commerce_mandate_protocol_payloads(bundle, &mut mandate_ledger, order_id);
    write_json(&mandate_path, &mandate_ledger);

    let mut settlement_packet: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&settlement_packet_path).test_expect("read settlement packet"),
    )
    .test_expect("settlement packet parses");
    settlement_packet["order_id"] = serde_json::json!(order_id);
    settlement_packet["quote_sha256"] = serde_json::json!(quote_sha256);
    write_json(&settlement_packet_path, &settlement_packet);

    order_context["event_log_sha256"] = serde_json::Value::String(sha256_file(&event_log_path));
    order_context["payment_lifecycle_sha256"] =
        serde_json::Value::String(sha256_file(&payment_path));
    order_context["mandate_ledger_sha256"] = serde_json::Value::String(sha256_file(&mandate_path));
    order_context["settlement_packet_sha256"] =
        serde_json::Value::String(sha256_file(&settlement_packet_path));
    write_json(&order_context_path, &order_context);
}

fn commerce_quote_sha256(order_context: &serde_json::Value) -> String {
    let quote_amount_minor = order_context["quote_amount_minor"]
        .as_u64()
        .test_expect("quote amount is u64");
    let binding = serde_json::json!({
        "amount_minor": quote_amount_minor,
        "currency": order_context["quote_currency"],
        "merchant_subject": order_context["merchant_subject"],
        "order_id": order_context["order_id"],
        "quote_id": order_context["quote_id"],
    });
    let canonical =
        chio_core_types::canonical_json_bytes(&binding).test_expect("quote binding canonicalizes");
    hex::encode(Sha256::digest(&canonical))
}

fn seal_commerce_event_log(event_log: &mut serde_json::Value) {
    for event in event_log["events"]
        .as_array_mut()
        .test_expect("event log events array")
    {
        event
            .as_object_mut()
            .test_expect("event object")
            .remove("event_sha256");
        let canonical =
            chio_core_types::canonical_json_bytes(event).test_expect("event canonicalizes");
        event["event_sha256"] = serde_json::Value::String(hex::encode(Sha256::digest(&canonical)));
    }
}

fn refresh_commerce_event_authority_receipts(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
    policy_sha256: &str,
) {
    let event_log_path = bundle.join("event-log.json");
    let event_log: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&event_log_path).test_expect("read event log"))
            .test_expect("event log parses");
    let receipt_dir = bundle.join("authority-receipts");
    std::fs::create_dir_all(&receipt_dir).test_expect("create authority receipts dir");
    for event in event_log["events"]
        .as_array()
        .test_expect("event log events array")
    {
        let receipt_ref = event["authority_receipt_ref"]
            .as_str()
            .test_expect("event has authority receipt ref");
        let receipt_path = format!("authority-receipts/{receipt_ref}.json");
        let destination = bundle.join(&receipt_path);
        write_commerce_event_authority_receipt(&destination, event, policy_sha256);
        upsert_graph_node(
            evidence_graph,
            receipt_ref,
            &receipt_path,
            "chio.receipt.v1",
            "receipt",
            &sha256_file(&destination),
        );
    }
}

fn refresh_commerce_order_passport(bundle: &Path, evidence_graph: &mut serde_json::Value) {
    let order_context_path = bundle.join("order-context.json");
    let order_context_bytes = std::fs::read(&order_context_path).test_expect("read order context");
    let order_context: chio_commerce_order::CommerceOrderContext =
        serde_json::from_slice(&order_context_bytes).test_expect("order context parses");
    let event_log_bytes =
        std::fs::read(bundle.join(&order_context.event_log_path)).test_expect("read event log");
    let event_log: serde_json::Value =
        serde_json::from_slice(&event_log_bytes).test_expect("event log parses");
    let event_authority_receipts = event_log["events"]
        .as_array()
        .test_expect("event log events array")
        .iter()
        .map(|event| {
            let receipt_ref = event["authority_receipt_ref"]
                .as_str()
                .test_expect("event has authority receipt ref");
            let receipt_path = bundle.join(format!("authority-receipts/{receipt_ref}.json"));
            chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
                receipt_ref: receipt_ref.to_string(),
                receipt_bytes: std::fs::read(receipt_path).test_expect("read authority receipt"),
            }
        })
        .collect();
    let payment_lifecycle_bytes = std::fs::read(bundle.join(&order_context.payment_lifecycle_path))
        .test_expect("read payment lifecycle");
    let mandate_ledger_bytes = std::fs::read(bundle.join(&order_context.mandate_ledger_path))
        .test_expect("read mandate ledger");
    let provider_passport_bytes = std::fs::read(bundle.join(&order_context.provider_passport_path))
        .test_expect("read provider passport");
    let reputation_snapshot_bytes =
        std::fs::read(bundle.join(&order_context.reputation_snapshot_path))
            .test_expect("read reputation snapshot");
    let federation_trust_bundle_bytes =
        std::fs::read(bundle.join(&order_context.federation_trust_bundle_path))
            .test_expect("read federation trust bundle");
    let settlement_packet_bytes = std::fs::read(bundle.join(&order_context.settlement_packet_path))
        .test_expect("read settlement packet");
    let mandate_protocol_payloads =
        commerce_mandate_protocol_payloads(bundle, &mandate_ledger_bytes);
    let risk_comptroller_report_bytes = order_context
        .coverage_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
        .map(|requirement| {
            std::fs::read(bundle.join(&requirement.risk_comptroller_report_path))
                .test_expect("read risk comptroller report")
        });
    let verification_bundle = chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes,
        event_authority_receipts,
        payment_lifecycle_bytes,
        mandate_ledger_bytes,
        provider_passport_bytes,
        reputation_snapshot_bytes,
        federation_trust_bundle_bytes,
        settlement_packet_bytes,
        mandate_protocol_payloads,
        risk_comptroller_report_bytes,
        verified_trust_market_context: None,
        trusted_event_authority_receipt_kernel_keys: trusted_public_keys(
            COMMERCE_FIXTURE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS,
        ),
        trusted_payment_signer_keys: trusted_public_keys(
            COMMERCE_FIXTURE_TRUSTED_PAYMENT_SIGNER_KEYS,
        ),
        trusted_provider_trust_signer_keys: trusted_public_keys(
            COMMERCE_FIXTURE_TRUSTED_PROVIDER_KEYS,
        ),
        trusted_risk_comptroller_signer_keys: trusted_public_keys(
            ENTERPRISE_FIXTURE_TRUSTED_RISK_COMPTROLLER_KEYS,
        ),
    };
    let report = chio_commerce_order::verify_commerce_order(&verification_bundle)
        .test_expect("commerce order verifies for order passport");
    let order_passport_path = bundle.join("order-passport.json");
    let report_json =
        serde_json::to_value(report).test_expect("commerce order passport serializes");
    write_json(&order_passport_path, &report_json);
    let order_passport_sha256 = sha256_file(&order_passport_path);
    upsert_graph_node(
        evidence_graph,
        &order_passport_sha256,
        "order-passport.json",
        chio_commerce_order::COMMERCE_ORDER_PASSPORT_SCHEMA_ID,
        "commerce-order-passport",
        &order_passport_sha256,
    );
}

#[derive(serde::Deserialize)]
struct TestCommerceMandateProtocolPayloadRefs {
    protocol_projections: Vec<TestCommerceMandateProtocolPayloadRef>,
}

#[derive(serde::Deserialize)]
struct TestCommerceMandateProtocolPayloadRef {
    protocol: String,
    purpose: String,
    payload_path: String,
}

fn commerce_mandate_protocol_payloads(
    bundle: &Path,
    mandate_ledger_bytes: &[u8],
) -> Vec<chio_commerce_order::CommerceMandateProtocolPayload> {
    let refs: TestCommerceMandateProtocolPayloadRefs =
        serde_json::from_slice(mandate_ledger_bytes).test_expect("mandate payload refs parse");
    refs.protocol_projections
        .into_iter()
        .map(
            |projection| chio_commerce_order::CommerceMandateProtocolPayload {
                protocol: projection.protocol,
                purpose: projection.purpose,
                payload_bytes: std::fs::read(bundle.join(projection.payload_path))
                    .test_expect("read mandate protocol payload"),
            },
        )
        .collect()
}

fn trusted_public_keys(keys: &str) -> Vec<chio_core_types::PublicKey> {
    keys.split(',')
        .map(|key| {
            chio_core_types::PublicKey::from_hex(key.trim())
                .test_expect("fixture public key parses")
        })
        .collect()
}

fn write_commerce_event_authority_receipt(
    destination: &Path,
    event: &serde_json::Value,
    policy_sha256: &str,
) {
    let receipt_ref = event["authority_receipt_ref"]
        .as_str()
        .test_expect("event has authority receipt ref");
    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: receipt_ref.to_string(),
            timestamp: 1_781_072_000,
            capability_id: format!("cap-{receipt_ref}"),
            tool_server: "chio-commerce-order-authority".to_string(),
            tool_name: event["transition"]
                .as_str()
                .test_expect("event has transition")
                .to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "authority_receipt_ref": receipt_ref,
                "event_id": event["event_id"],
                "order_id": event["order_id"],
                "transition": event["transition"],
            }))
            .test_expect("commerce authority receipt action hashes"),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: event["actor"]
                    .as_str()
                    .test_expect("event has actor")
                    .to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: event["event_sha256"]
                .as_str()
                .test_expect("event has event_sha256")
                .to_string(),
            policy_hash: policy_sha256.to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_expect("commerce authority receipt signs");
    let mut value = serde_json::to_value(receipt).test_expect("commerce receipt serializes");
    value["schema"] = serde_json::Value::String("chio.receipt.v1".to_string());
    write_json(destination, &value);
}

fn retarget_commerce_mandate_projection_order_ids(
    mandate_ledger: &mut serde_json::Value,
    order_id: &str,
) {
    if let Some(projections) = mandate_ledger
        .get_mut("protocol_projections")
        .and_then(serde_json::Value::as_array_mut)
    {
        for projection in projections {
            projection["order_id"] = serde_json::json!(order_id);
        }
    }
}

fn retarget_commerce_mandate_protocol_payloads(
    bundle: &Path,
    mandate_ledger: &mut serde_json::Value,
    order_id: &str,
) {
    let projection_refs = mandate_ledger["protocol_projections"]
        .as_array()
        .test_expect("mandate projections array")
        .iter()
        .enumerate()
        .map(|(index, projection)| {
            (
                index,
                projection["protocol"]
                    .as_str()
                    .test_expect("projection protocol")
                    .to_string(),
                projection["purpose"]
                    .as_str()
                    .test_expect("projection purpose")
                    .to_string(),
                projection["payload_path"]
                    .as_str()
                    .test_expect("projection payload path")
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();

    for (index, protocol, purpose, payload_path) in projection_refs {
        let payload_path = bundle.join(payload_path);
        let mut payload: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&payload_path).test_expect("read payload"))
                .test_expect("payload parses");
        payload["order_id"] = serde_json::json!(order_id);
        write_json(&payload_path, &payload);
        let payload_sha256 = sha256_file(&payload_path);
        mandate_ledger["protocol_projections"]
            .as_array_mut()
            .test_expect("mandate projections array")[index]["digest"] =
            serde_json::Value::String(payload_sha256.clone());
        if let Some(field) = commerce_mandate_protocol_hash_field(&protocol, &purpose) {
            mandate_ledger[field] = serde_json::Value::String(payload_sha256);
        }
    }
}

fn commerce_mandate_protocol_hash_field(protocol: &str, purpose: &str) -> Option<&'static str> {
    match (protocol, purpose) {
        ("ap2", "checkout_mandate") => Some("ap2_checkout_mandate_hash"),
        ("ap2", "payment_mandate") => Some("ap2_payment_mandate_hash"),
        ("acp-commerce", "delegated_payment_token") => Some("acp_delegated_payment_token_hash"),
        ("x402", "payment_requirements") => Some("x402_payment_requirements_hash"),
        _ => None,
    }
}

fn sign_commerce_payment_lifecycle(payment_lifecycle: &mut serde_json::Value) {
    let keypair = Keypair::from_seed(&TEST_SIGNATURE_SEED);
    payment_lifecycle["issuer"] =
        serde_json::Value::String(format!("did:chio:{}", keypair.public_key().to_hex()));
    payment_lifecycle
        .as_object_mut()
        .test_expect("payment lifecycle object")
        .remove("signature");
    let (signature, _) = keypair
        .sign_canonical(payment_lifecycle)
        .test_expect("payment lifecycle signs");
    payment_lifecycle["signature"] = serde_json::Value::String(signature.to_hex());
}

pub(crate) fn build_disclosure_agent_web_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let disclosure_source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let agent_web_source =
        workspace_root().join("fixtures/proof-room/agent-web/valid-webhook-cloudevents");
    let bundle = tempdir.path().join("disclosure-agent-web-envelope");
    copy_dir_all(&disclosure_source, &bundle).test_expect("copy disclosure bundle");

    let passport_path = bundle.join("transaction-passport.json");
    let disclosure_passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("disclosure passport parses");
    let disclosure_passport_id = disclosure_passport["id"]
        .as_str()
        .test_expect("disclosure passport has id");
    let agent_web_passport: serde_json::Value = serde_json::from_slice(
        &std::fs::read(agent_web_source.join("transaction-passport.json"))
            .test_expect("read Agent Web passport"),
    )
    .test_expect("Agent Web passport parses");
    let agent_web_passport_id = agent_web_passport["id"]
        .as_str()
        .test_expect("Agent Web passport has id");

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    append_required_claims_from_policy(&mut policy, &agent_web_source.join("verifier-policy.json"));
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        agent_web_passport_id,
        disclosure_passport["issued_at"]
            .as_str()
            .test_expect("disclosure passport issued_at"),
        &policy,
    );

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    replace_json_strings_in_graph_artifacts(
        &bundle,
        &evidence_graph,
        &[(disclosure_passport_id, agent_web_passport_id)],
    );
    refresh_signed_lineage_subgraph_digest(&bundle);
    append_graph_artifacts_from_fixture(&bundle, &agent_web_source, &mut evidence_graph, &[]);
    resign_agent_web_receipts_for_policy(&bundle, &policy_sha256);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let mut passport = disclosure_passport;
    passport["id"] = serde_json::Value::String(agent_web_passport_id.to_string());
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn refresh_claim_set_for_policy(
    bundle: &Path,
    passport_id: &str,
    issued_at: &str,
    policy: &serde_json::Value,
) -> String {
    let claims = policy["required_claims"]
        .as_array()
        .test_expect("policy required_claims array")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let claim_set = serde_json::json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": format!("claim-set-{passport_id}"),
        "issued_at": issued_at,
        "claims": claims.into_iter().map(|claim_id| {
            serde_json::json!({
                "claim_id": claim_id,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio proof verify"
            })
        }).collect::<Vec<_>>()
    });
    let path = bundle.join("claim-set.json");
    write_json(&path, &claim_set);
    sha256_file(&path)
}

fn upsert_claim_set_graph_binding(evidence_graph: &mut serde_json::Value, claim_set_sha256: &str) {
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    let verifier_policy_node_id = nodes
        .iter()
        .find(|node| {
            node.get("role")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|role| role == "verifier-policy")
        })
        .and_then(|node| node.get("id"))
        .and_then(serde_json::Value::as_str)
        .test_expect("graph has verifier-policy node")
        .to_string();
    let removed_claim_set_ids = nodes
        .iter()
        .filter(|node| {
            node.get("path").and_then(serde_json::Value::as_str) == Some("claim-set.json")
        })
        .filter_map(|node| node.get("id").and_then(serde_json::Value::as_str))
        .map(std::string::ToString::to_string)
        .collect::<BTreeSet<_>>();
    nodes.retain(|node| {
        !removed_claim_set_ids.contains(
            node.get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
        ) && node.get("path").and_then(serde_json::Value::as_str) != Some("claim-set.json")
    });
    nodes.push(serde_json::json!({
        "id": claim_set_sha256,
        "path": "claim-set.json",
        "role": "claim-set",
        "schema": "chio.transaction.claim-set.v1",
        "sha256": claim_set_sha256
    }));

    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("graph edges array");
    edges.retain(|edge| {
        let from = edge.get("from").and_then(serde_json::Value::as_str);
        let to = edge.get("to").and_then(serde_json::Value::as_str);
        let predicate = edge.get("predicate").and_then(serde_json::Value::as_str);
        !(predicate == Some("binds")
            && to == Some(verifier_policy_node_id.as_str())
            && from.is_some_and(|from| {
                from == claim_set_sha256 || removed_claim_set_ids.contains(from)
            }))
    });
    edges.push(serde_json::json!({
        "evidence_class": "digest-bound-reference",
        "from": claim_set_sha256,
        "predicate": "binds",
        "to": verifier_policy_node_id
    }));
}

fn upsert_graph_node(
    evidence_graph: &mut serde_json::Value,
    node_id: &str,
    path: &str,
    schema: &str,
    role: &str,
    sha256: &str,
) {
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    nodes.retain(|node| {
        node.get("id").and_then(serde_json::Value::as_str) != Some(node_id)
            && node.get("path").and_then(serde_json::Value::as_str) != Some(path)
    });
    nodes.push(serde_json::json!({
        "id": sha256,
        "schema": schema,
        "path": path,
        "sha256": sha256,
        "role": role
    }));
}

fn remove_graph_nodes_by_path(evidence_graph: &mut serde_json::Value, path: &str) {
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array");
    let mut removed_ids = BTreeSet::new();
    nodes.retain(|node| {
        let should_remove = node.get("path").and_then(serde_json::Value::as_str) == Some(path);
        if should_remove {
            if let Some(id) = node.get("id").and_then(serde_json::Value::as_str) {
                removed_ids.insert(id.to_string());
            }
        }
        !should_remove
    });
    if removed_ids.is_empty() {
        return;
    }

    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("graph edges array");
    edges.retain(|edge| {
        let from_removed = edge
            .get("from")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|from| removed_ids.contains(from));
        let to_removed = edge
            .get("to")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|to| removed_ids.contains(to));
        !from_removed && !to_removed
    });
}

pub(crate) fn build_risk_only_policy_bundle(
    fixture_path: &str,
    bundle_name: &str,
) -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join(fixture_path);
    let bundle = tempdir.path().join(bundle_name);
    copy_dir_all(&source, &bundle).test_expect("copy proof bundle");

    if bundle.join("manifest.json").is_file() {
        std::fs::create_dir_all(bundle.join("artifacts/authority"))
            .test_expect("create proof room authority directory");
        write_json(
            &bundle.join("artifacts/authority/trust-roots.json"),
            &proof_room_trust_roots_for_seed(TEST_SIGNATURE_SEED),
        );
        refresh_manifest_artifact_ref(&bundle, "artifacts/authority/trust-roots.json");
        retain_standalone_risk_manifest_claim(&bundle);
    }

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    policy["required_claims"] = serde_json::json!(["claim.risk.comptroller_report_bound"]);
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);
    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport["id"].as_str().test_expect("passport has id"),
        passport["issued_at"]
            .as_str()
            .test_expect("passport has issued_at"),
        &policy,
    );
    refresh_standalone_risk_root_artifacts(&bundle);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);
    refresh_standalone_risk_root_artifacts(&bundle);

    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);
    refresh_standalone_risk_root_artifacts(&bundle);
    refresh_risk_only_policy_bundle_report_refs(&bundle);

    (tempdir, bundle)
}

pub(crate) fn build_standalone_risk_only_policy_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let bundle = tempdir.path().join("standalone-risk-only");
    copy_dir_all(&source, &bundle).test_expect("copy proof bundle");

    if bundle.join("manifest.json").is_file() {
        std::fs::create_dir_all(bundle.join("artifacts/authority"))
            .test_expect("create proof room authority directory");
        write_json(
            &bundle.join("artifacts/authority/trust-roots.json"),
            &proof_room_trust_roots_for_seed(TEST_SIGNATURE_SEED),
        );
        refresh_manifest_artifact_ref(&bundle, "artifacts/authority/trust-roots.json");
    }

    let policy_path = bundle.join("verifier-policy.json");
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy_path).test_expect("read verifier policy"))
            .test_expect("verifier policy parses");
    policy["required_claims"] = serde_json::json!(["claim.risk.comptroller_report_bound"]);
    write_json(&policy_path, &policy);
    let policy_sha256 = sha256_file(&policy_path);
    refresh_manifest_artifact_ref_if_present(&bundle, "verifier-policy.json");
    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let claim_set_sha256 = refresh_claim_set_for_policy(
        &bundle,
        passport["id"].as_str().test_expect("passport has id"),
        passport["issued_at"]
            .as_str()
            .test_expect("passport has issued_at"),
        &policy,
    );
    refresh_standalone_risk_root_artifacts(&bundle);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .retain(|node| {
            matches!(
                node.get("role").and_then(serde_json::Value::as_str),
                Some(
                    "risk-comptroller-report"
                        | "data-governance-report"
                        | "approval-case"
                        | "evidence-export-bundle"
                )
            )
        });
    for node in evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
    {
        if node.get("role").and_then(serde_json::Value::as_str) != Some("risk-comptroller-report") {
            node["role"] = serde_json::Value::String("risk-supporting-evidence".to_string());
        }
    }
    evidence_graph["edges"] = serde_json::Value::Array(Vec::new());
    upsert_graph_node(
        &mut evidence_graph,
        &policy_sha256,
        "verifier-policy.json",
        "chio.transaction.verifier-policy.v1",
        "verifier-policy",
        &policy_sha256,
    );
    upsert_claim_set_graph_binding(&mut evidence_graph, &claim_set_sha256);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);
    refresh_standalone_risk_root_artifacts(&bundle);

    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    passport["claim_set_sha256"] = serde_json::Value::String(claim_set_sha256);
    passport["claim_set_path"] = serde_json::Value::String("claim-set.json".to_string());
    passport["verifier_policy_sha256"] = serde_json::Value::String(policy_sha256);
    write_json(&passport_path, &passport);
    refresh_standalone_risk_root_artifacts(&bundle);
    refresh_standalone_risk_verifier_report(&bundle);

    (tempdir, bundle)
}

pub(crate) fn build_enterprise_bundle_with_unrelated_runtime_evidence(
) -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let enterprise_source =
        workspace_root().join("fixtures/proof-room/enterprise-export/valid-autonomous-commerce");
    let runtime_source =
        workspace_root().join("fixtures/proof-room/runtime-security/valid-side-effecting-call");
    let bundle = tempdir.path().join("enterprise-with-runtime-evidence");
    copy_dir_all(&enterprise_source, &bundle).test_expect("copy enterprise proof bundle");

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    append_graph_artifacts_from_fixture(&bundle, &runtime_source, &mut evidence_graph, &[]);
    refresh_evidence_graph_content_ids(&bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);

    (tempdir, bundle)
}

pub(crate) fn remove_standalone_risk_graph_node(bundle: &Path, removed_node_id: &str) {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    let mut removed_aliases = BTreeSet::new();
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes array")
        .retain(|node| {
            let matches_removed = graph_node_matches_ref(node, removed_node_id);
            if matches_removed {
                collect_graph_node_aliases(node, &mut removed_aliases);
            }
            !matches_removed
        });
    if let Some(edges) = evidence_graph
        .get_mut("edges")
        .and_then(serde_json::Value::as_array_mut)
    {
        edges.retain(|edge| {
            let from = edge.get("from").and_then(serde_json::Value::as_str);
            let to = edge.get("to").and_then(serde_json::Value::as_str);
            !from.is_some_and(|from| removed_aliases.contains(from))
                && !to.is_some_and(|to| removed_aliases.contains(to))
        });
    }
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);
    refresh_standalone_risk_root_artifacts(bundle);
}

fn graph_node_matches_ref(node: &serde_json::Value, reference: &str) -> bool {
    node.get("id").and_then(serde_json::Value::as_str) == Some(reference)
        || node.get("sha256").and_then(serde_json::Value::as_str) == Some(reference)
        || node.get("path").and_then(serde_json::Value::as_str) == Some(reference)
        || node
            .get("path")
            .and_then(serde_json::Value::as_str)
            .and_then(|path| Path::new(path).file_stem())
            .and_then(|stem| stem.to_str())
            == Some(reference)
}

fn collect_graph_node_aliases(node: &serde_json::Value, aliases: &mut BTreeSet<String>) {
    for value in [
        node.get("id").and_then(serde_json::Value::as_str),
        node.get("sha256").and_then(serde_json::Value::as_str),
        node.get("path").and_then(serde_json::Value::as_str),
    ]
    .into_iter()
    .flatten()
    {
        aliases.insert(value.to_string());
    }
    if let Some(path_stem) = node
        .get("path")
        .and_then(serde_json::Value::as_str)
        .and_then(|path| Path::new(path).file_stem())
        .and_then(|stem| stem.to_str())
    {
        aliases.insert(path_stem.to_string());
    }
}

pub(crate) fn add_standalone_risk_unbound_reserve_ledger(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-risk-ledger-bound"]);
    risk_report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["payout_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["settlement_units"] = serde_json::json!(100);
    risk_report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-unbound-receipt",
            "receipt_ref": "risk-receipt-not-in-graph",
            "lane": "claim_payout",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-ledger-bound",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "settlement-not-in-graph",
            "payer_subject": "did:chio:buyer-enterprise",
            "payee_subject": "did:chio:buyer-enterprise"
        }
    ]);
    set_standalone_risk_claim_payout_capital_instruction(&mut risk_report);
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn point_standalone_risk_lifecycle_authority_at_supporting_evidence(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["facility_lifecycle"][0]["authority_receipt_ref"] =
        serde_json::json!("data-governance-report");
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn deny_standalone_risk_approval_case(bundle: &Path) {
    let approval_path = bundle.join("approval-case.json");
    let mut approval: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&approval_path).test_expect("read approval case"))
            .test_expect("approval case parses");
    approval["decision"] = serde_json::json!("denied");
    write_json(&approval_path, &approval);
    rehash_standalone_risk_graph_artifact(bundle, "approval-case", &approval_path);
}

pub(crate) fn set_standalone_risk_approval_quorum(
    bundle: &Path,
    approvers: &[&str],
    required_quorum: u64,
) {
    let approval_path = bundle.join("approval-case.json");
    let mut approval: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&approval_path).test_expect("read approval case"))
            .test_expect("approval case parses");
    approval["approvers"] = serde_json::Value::Array(
        approvers
            .iter()
            .map(|approver| serde_json::Value::String((*approver).to_string()))
            .collect(),
    );
    approval["required_quorum"] = serde_json::json!(required_quorum);
    write_json(&approval_path, &approval);
    rehash_standalone_risk_graph_artifact(bundle, "approval-case", &approval_path);
}

pub(crate) fn set_standalone_risk_approval_window(
    bundle: &Path,
    issued_at: &str,
    expires_at: &str,
) {
    let approval_path = bundle.join("approval-case.json");
    let mut approval: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&approval_path).test_expect("read approval case"))
            .test_expect("approval case parses");
    approval["issued_at"] = serde_json::json!(issued_at);
    approval["expires_at"] = serde_json::json!(expires_at);
    write_json(&approval_path, &approval);
    rehash_standalone_risk_graph_artifact(bundle, "approval-case", &approval_path);
}

pub(crate) fn tamper_standalone_risk_supporting_evidence_without_rehash(bundle: &Path) {
    let report_path = bundle.join("data-governance-report.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).test_expect("read risk evidence"))
            .test_expect("risk evidence parses");
    report["observed_region"] = serde_json::json!("EU");
    write_json(&report_path, &report);
}

pub(crate) fn rehash_standalone_risk_graph_artifact(
    bundle: &Path,
    node_id: &str,
    artifact_path: &Path,
) {
    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    refresh_evidence_graph_content_ids(bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);
    let relative_artifact_path = artifact_path
        .strip_prefix(bundle)
        .test_expect("risk artifact path is inside bundle")
        .to_str()
        .test_expect("risk artifact path is utf8");
    refresh_manifest_artifact_ref_if_present(bundle, relative_artifact_path);
    refresh_standalone_risk_root_artifacts(bundle);
    if node_id == "approval-case" {
        refresh_standalone_risk_verifier_report(bundle);
    }
}

pub(crate) fn add_standalone_risk_uncovered_reserve_ledger_claim(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["coverage"]
        .as_object_mut()
        .test_expect("risk coverage object")
        .remove("covered_claim_ids");
    risk_report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["payout_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["settlement_units"] = serde_json::json!(100);
    risk_report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-uncovered-claim",
            "receipt_ref": "approval-case",
            "lane": "claim_payout",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-ledger-without-coverage",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "payer_subject": "did:chio:buyer-enterprise",
            "payee_subject": "did:chio:buyer-enterprise"
        }
    ]);
    set_standalone_risk_claim_payout_capital_instruction(&mut risk_report);
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

fn set_standalone_risk_claim_payout_capital_instruction(risk_report: &mut serde_json::Value) {
    let entry = risk_report["reserve_ledger"][0].clone();
    risk_report["capital_instructions"] = serde_json::json!([
        {
            "instruction_id": "capital-instruction-standalone-risk-claim-payout",
            "reserve_entry_id": entry["entry_id"],
            "order_id": risk_report["order_id"],
            "claim_id": entry["claim_id"],
            "reserve_ref": entry["reserve_ref"],
            "currency": entry["currency"],
            "units": entry["units"],
            "settlement_ref": entry["settlement_ref"],
            "intended_action": "transfer_funds",
            "source_kind": "facility_commitment",
            "intended_state": "pending_execution",
            "reconciled_state": "not_observed"
        }
    ]);
}

pub(crate) fn add_standalone_risk_sanction_backed_market_slash(bundle: &Path) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let mut risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    risk_report["coverage"]["covered_claim_ids"] = serde_json::json!(["claim-risk-market-slash"]);
    risk_report["reconciliation"]["consumed_reserve_units"] = serde_json::json!(100);
    risk_report["reconciliation"]["payout_units"] = serde_json::json!(0);
    risk_report["reconciliation"]["settlement_units"] = serde_json::json!(0);
    risk_report["reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "risk-ledger-market-slash",
            "receipt_ref": "approval-case",
            "lane": "market_slash",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "sanction_bridge": {
                "bridge_id": "sanction-bridge-risk-market-slash",
                "authority_receipt_ref": "approval-case",
                "evidence_ref": "data-governance-report",
                "jurisdiction_ref": "approval-case",
                "sanction_subject": "did:chio:buyer-enterprise",
                "maximum_slash_units": 100
            }
        }
    ]);
    risk_report["sanction_reserve_ledger"] = serde_json::json!([
        {
            "entry_id": "sanction-ledger-market-slash",
            "bridge_id": "sanction-bridge-risk-market-slash",
            "lane": "market_slash",
            "receipt_ref": "approval-case",
            "reserve_ref": "reserve-enterprise-valid",
            "claim_id": "claim-risk-market-slash",
            "currency": "USD",
            "units": 100,
            "settlement_ref": "evidence-export-bundle",
            "authority_receipt_ref": "approval-case",
            "evidence_ref": "data-governance-report",
            "jurisdiction_ref": "approval-case"
        }
    ]);
    write_standalone_risk_report_and_rehash(bundle, risk_report);
}

pub(crate) fn write_standalone_risk_report_and_rehash(
    bundle: &Path,
    mut risk_report: serde_json::Value,
) {
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    sign_standalone_risk_report(&mut risk_report);
    write_json(&risk_report_path, &risk_report);

    let evidence_graph_path = bundle.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_graph_path).test_expect("read graph"))
            .test_expect("graph parses");
    refresh_evidence_graph_content_ids(bundle, &mut evidence_graph);
    write_json(&evidence_graph_path, &evidence_graph);
    let evidence_graph_sha256 = sha256_file(&evidence_graph_path);

    let passport_path = bundle.join("transaction-passport.json");
    let mut passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    passport["evidence_graph_sha256"] = serde_json::Value::String(evidence_graph_sha256);
    write_json(&passport_path, &passport);
    refresh_manifest_artifact_ref_if_present(bundle, "risk-comptroller-report.json");
    refresh_standalone_risk_root_artifacts(bundle);
    refresh_standalone_risk_verifier_report(bundle);
}

fn sign_standalone_risk_report(risk_report: &mut serde_json::Value) {
    let Some(report) = risk_report.as_object_mut() else {
        return;
    };
    report.remove("signature");
    let keypair = Keypair::from_seed(&[63u8; 32]);
    let (signature, _) = keypair
        .sign_canonical(risk_report)
        .test_expect("risk comptroller report signs");
    risk_report["signature"] = serde_json::Value::String(format!(
        "sig-ed25519:{}:{}",
        keypair.public_key().to_hex(),
        signature.to_hex()
    ));
}

fn refresh_standalone_risk_root_artifacts(bundle: &Path) {
    for artifact_path in [
        "verifier-policy.json",
        "evidence-graph.json",
        "transaction-passport.json",
        "claim-set.json",
    ] {
        let root_artifact_path = format!("roots/{artifact_path}");
        let source = bundle.join(artifact_path);
        let destination = bundle.join(&root_artifact_path);
        if source.is_file() && destination.is_file() {
            std::fs::copy(&source, &destination).test_expect("sync standalone risk root artifact");
            refresh_manifest_artifact_ref_if_present(bundle, &root_artifact_path);
        }
        refresh_manifest_artifact_ref_if_present(bundle, artifact_path);
    }
}

fn refresh_standalone_risk_verifier_report(bundle: &Path) {
    let passport_path = bundle.join("transaction-passport.json");
    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let risk_report_path = bundle.join("risk-comptroller-report.json");
    let risk_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&risk_report_path).test_expect("read risk report"))
            .test_expect("risk report parses");
    let verifier_report = serde_json::json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": format!(
            "verifier-report-{}",
            passport["id"].as_str().test_expect("passport id")
        ),
        "issued_at": passport["issued_at"],
        "verdict": "verified",
        "passport_id": passport["id"],
        "passport_path": "transaction-passport.json",
        "evidence_graph_sha256": passport["evidence_graph_sha256"],
        "evidence_graph_path": passport["evidence_graph_path"],
        "verifier_policy_sha256": passport["verifier_policy_sha256"],
        "verifier_policy_path": passport["verifier_policy_path"],
        "risk_comptroller_report_ref": risk_report["id"],
        "order_id": risk_report["order_id"],
        "subject": risk_report["subject"],
        "verified_claims": ["claim.risk.comptroller_report_bound"]
    });
    write_json(&bundle.join("verifier/report.json"), &verifier_report);
    retain_standalone_risk_manifest_claim(bundle);
    retain_standalone_risk_ui_claim(bundle);
    refresh_verifier_report_refs_with_seed(bundle, TEST_SIGNATURE_SEED);
    retain_standalone_risk_manifest_claim(bundle);
}

fn refresh_risk_only_policy_bundle_report_refs(bundle: &Path) {
    let passport_path = bundle.join("transaction-passport.json");
    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).test_expect("read passport"))
            .test_expect("passport parses");
    let report_path = bundle.join("verifier/report.json");
    let mut report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).test_expect("read verifier report"))
            .test_expect("verifier report parses");
    report["evidence_graph_sha256"] = passport["evidence_graph_sha256"].clone();
    report["evidence_graph_path"] = passport["evidence_graph_path"].clone();
    report["verifier_policy_sha256"] = passport["verifier_policy_sha256"].clone();
    report["verifier_policy_path"] = passport["verifier_policy_path"].clone();
    if let Some(claim_set_sha256) = passport.get("claim_set_sha256") {
        report["claim_set_sha256"] = claim_set_sha256.clone();
    }
    if let Some(claim_set_path) = passport.get("claim_set_path") {
        report["claim_set_path"] = claim_set_path.clone();
    }
    write_json(&report_path, &report);
    retain_standalone_risk_manifest_claim(bundle);
    retain_standalone_risk_ui_claim(bundle);
    refresh_verifier_report_refs_with_seed(bundle, TEST_SIGNATURE_SEED);
    retain_standalone_risk_manifest_claim(bundle);
}

fn retain_standalone_risk_manifest_claim(bundle: &Path) {
    let manifest_path = bundle.join("manifest.json");
    if !manifest_path.is_file() {
        return;
    }
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    let claims = manifest["claims"]
        .as_array_mut()
        .test_expect("manifest claims array");
    claims.retain(|claim| {
        matches!(
            claim.get("claim_id").and_then(serde_json::Value::as_str),
            Some("claim.proof_room.verifier_report_bound")
                | Some("claim.risk.comptroller_report_bound")
        )
    });
    if let Some(negative_cases) = manifest
        .get_mut("negative_cases")
        .and_then(serde_json::Value::as_array_mut)
    {
        negative_cases.retain(|negative_case| {
            let expected_failure = negative_case
                .get("expected_failure_code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            expected_failure.starts_with("risk ")
                || expected_failure == "proof-room.report.hash-mismatch"
        });
    }
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(bundle);
}

fn retain_standalone_risk_ui_claim(bundle: &Path) {
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    if !ui_report_path.is_file() {
        return;
    }
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
            .test_expect("UI report parses");
    ui_report["rendered_claims"] = serde_json::json!([
        {
            "checker": "chio proof serve --dry-run",
            "claim_id": "claim.proof_room.verifier_report_bound",
            "source": "ui/proof-room-static/load-report.json",
            "verdict": "verified"
        },
        {
            "checker": "chio proof verify --require risk",
            "claim_id": "claim.risk.comptroller_report_bound",
            "source": "verifier/report.json",
            "verdict": "verified"
        }
    ]);
    write_json(&ui_report_path, &ui_report);
}

pub(crate) fn append_required_claims_from_policy(
    policy: &mut serde_json::Value,
    source_policy_path: &Path,
) {
    let source_policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(source_policy_path).test_expect("read policy"))
            .test_expect("policy parses");
    let required_claims = policy["required_claims"]
        .as_array_mut()
        .test_expect("policy required_claims array");
    for claim in source_policy["required_claims"]
        .as_array()
        .test_expect("source policy required_claims array")
    {
        if !required_claims.contains(claim) {
            required_claims.push(claim.clone());
        }
    }
}

fn remove_required_claim(policy: &mut serde_json::Value, claim_id: &str) {
    let required_claims = policy["required_claims"]
        .as_array_mut()
        .test_expect("policy required_claims array");
    required_claims.retain(|claim| claim.as_str() != Some(claim_id));
}

pub(crate) fn append_graph_artifacts_from_fixture(
    bundle: &Path,
    source: &Path,
    evidence_graph: &mut serde_json::Value,
    replacements: &[(&str, &str)],
) {
    let source_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(source.join("evidence-graph.json")).test_expect("read graph"),
    )
    .test_expect("graph parses");
    let mut id_remaps = BTreeMap::new();
    let mut retained_ids = BTreeSet::new();
    for node in source_graph["nodes"]
        .as_array()
        .test_expect("source graph nodes array")
    {
        let path = node["path"].as_str().test_expect("source node path");
        let id = node["id"].as_str().test_expect("source node id");
        let role = node["role"].as_str().test_expect("source node role");
        if matches!(
            path,
            "transaction-passport.json"
                | "evidence-graph.json"
                | "claim-set.json"
                | "verifier-policy.json"
        ) || matches!(id, "claim-set" | "verifier-policy")
            || matches!(role, "claim-set" | "verifier-policy")
        {
            continue;
        }
        let destination_path = bundle.join(path);
        if let Some(parent) = destination_path.parent() {
            std::fs::create_dir_all(parent).test_expect("create artifact parent");
        }
        if replacements.is_empty() {
            std::fs::copy(source.join(path), &destination_path).test_expect("copy artifact");
        } else {
            let mut artifact: serde_json::Value = serde_json::from_slice(
                &std::fs::read(source.join(path)).test_expect("read artifact"),
            )
            .test_expect("artifact parses");
            for (from, to) in replacements {
                replace_json_string(&mut artifact, from, to);
            }
            write_json(&destination_path, &artifact);
        }

        let mut node = node.clone();
        let artifact_sha256 = sha256_file(&destination_path);
        id_remaps.insert(id.to_string(), artifact_sha256.clone());
        node["id"] = serde_json::Value::String(artifact_sha256.clone());
        node["sha256"] = serde_json::Value::String(artifact_sha256);
        retained_ids.insert(node["id"].as_str().test_expect("node id").to_string());
        evidence_graph["nodes"]
            .as_array_mut()
            .test_expect("graph nodes array")
            .push(node);
    }

    for edge in source_graph["edges"]
        .as_array()
        .test_expect("source graph edges array")
    {
        let from = edge["from"].as_str().test_expect("edge from");
        let to = edge["to"].as_str().test_expect("edge to");
        let from = id_remaps.get(from).map(String::as_str).unwrap_or(from);
        let to = id_remaps.get(to).map(String::as_str).unwrap_or(to);
        if retained_ids.contains(from) && retained_ids.contains(to) {
            let mut edge = edge.clone();
            edge["from"] = serde_json::Value::String(from.to_string());
            edge["to"] = serde_json::Value::String(to.to_string());
            evidence_graph["edges"]
                .as_array_mut()
                .test_expect("graph edges array")
                .push(edge);
        }
    }
}

pub(crate) fn replace_json_strings_in_graph_artifacts(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
    replacements: &[(&str, &str)],
) {
    for node in evidence_graph["nodes"]
        .as_array()
        .test_expect("graph nodes array")
    {
        let path = node["path"].as_str().test_expect("node path");
        if matches!(
            path,
            "transaction-passport.json" | "evidence-graph.json" | "verifier-policy.json"
        ) {
            continue;
        }
        let artifact_path = bundle.join(path);
        if !artifact_path.is_file() {
            continue;
        }
        let mut artifact: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&artifact_path).test_expect("read artifact"))
                .test_expect("artifact parses");
        for (from, to) in replacements {
            replace_json_string(&mut artifact, from, to);
        }
        write_json(&artifact_path, &artifact);
    }
}

pub(crate) fn replace_json_string(value: &mut serde_json::Value, from: &str, to: &str) {
    match value {
        serde_json::Value::String(text) if text == from => {
            *text = to.to_string();
        }
        serde_json::Value::Array(items) => {
            for item in items {
                replace_json_string(item, from, to);
            }
        }
        serde_json::Value::Object(entries) => {
            for item in entries.values_mut() {
                replace_json_string(item, from, to);
            }
        }
        _ => {}
    }
}

pub(crate) fn refresh_signed_lineage_subgraph_digest(bundle: &Path) {
    let path = bundle.join("signed-lineage-subgraph.json");
    let mut lineage: chio_selective_disclosure::SignedLineageSubgraph =
        serde_json::from_slice(&std::fs::read(&path).test_expect("read signed lineage subgraph"))
            .test_expect("signed lineage subgraph parses");
    lineage.subgraph_sha256 =
        chio_selective_disclosure::compute_signed_lineage_subgraph_digest(&lineage)
            .test_expect("signed lineage subgraph digest computes");
    lineage.signature = chio_selective_disclosure::sign_lineage_subgraph(
        &lineage,
        &Keypair::from_seed(&DISCLOSURE_LINEAGE_SIGNATURE_SEED),
    )
    .test_expect("signed lineage subgraph signs");
    let lineage = serde_json::to_value(lineage).test_expect("signed lineage subgraph serializes");
    write_json(&path, &lineage);
}

pub(crate) fn refresh_bundle_signature(bundle: &Path) {
    refresh_bundle_signature_with_seed(bundle, bundle_signature_seed(bundle));
}

pub(crate) fn refresh_bundle_signature_with_seed(bundle: &Path, seed: [u8; 32]) {
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let mut signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    sign_bundle_signature_with_seed(bundle, &mut signature, seed);
    write_json(&signature_path, &signature);
}

fn bundle_signature_seed(bundle: &Path) -> [u8; 32] {
    let signature_path = bundle.join("bundle-signature.dsse.json");
    let signature: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&signature_path).test_expect("read signature"))
            .test_expect("signature parses");
    let Some(keyid) = signature
        .get("signatures")
        .and_then(serde_json::Value::as_array)
        .and_then(|signatures| signatures.first())
        .and_then(|signature| signature.get("keyid"))
        .and_then(serde_json::Value::as_str)
    else {
        return TEST_SIGNATURE_SEED;
    };

    for seed in [
        TEST_SIGNATURE_SEED,
        COLLECT_SIGNATURE_SEED,
        PUBLIC_EXPORT_SIGNATURE_SEED,
        PUBLIC_SETTLEMENT_BUNDLE_SIGNATURE_SEED,
    ] {
        if Keypair::from_seed(&seed).public_key().to_hex() == keyid {
            return seed;
        }
    }

    TEST_SIGNATURE_SEED
}

pub(crate) fn refresh_verifier_report_refs_with_seed(bundle: &Path, seed: [u8; 32]) {
    let verifier_report_sha256 = sha256_file(&bundle.join("verifier/report.json"));

    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    let mut ui_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ui_report_path).test_expect("read UI report"))
            .test_expect("UI report parses");
    ui_report["source_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    write_json(&ui_report_path, &ui_report);
    let ui_report_sha256 = sha256_file(&ui_report_path);

    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    manifest["verifier_report_ref"]["sha256"] =
        serde_json::Value::String(verifier_report_sha256.clone());
    manifest["proof_room_verifier_report_ref"]["sha256"] =
        serde_json::Value::String(ui_report_sha256.clone());
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        match artifact.get("path").and_then(serde_json::Value::as_str) {
            Some("verifier/report.json") => {
                artifact["sha256"] = serde_json::Value::String(verifier_report_sha256.clone());
            }
            Some("ui/proof-room-static/load-report.json") => {
                artifact["sha256"] = serde_json::Value::String(ui_report_sha256.clone());
            }
            _ => {}
        }
    }
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature_with_seed(bundle, seed);
}

pub(crate) fn refresh_manifest_artifact_ref(bundle: &Path, artifact_path: &str) {
    let artifact_sha256 = sha256_file(&bundle.join(artifact_path));
    let manifest_path = bundle.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("manifest parses");
    for ref_field in [
        "transaction_passport_ref",
        "evidence_graph_ref",
        "verifier_report_ref",
        "proof_room_verifier_report_ref",
    ] {
        if manifest
            .get(ref_field)
            .and_then(|reference| reference.get("path"))
            .and_then(serde_json::Value::as_str)
            == Some(artifact_path)
        {
            manifest[ref_field]["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        }
    }
    for artifact in manifest["artifacts"]
        .as_array_mut()
        .test_expect("manifest artifacts array")
    {
        if artifact.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path) {
            artifact["sha256"] = serde_json::Value::String(artifact_sha256.clone());
        }
    }
    write_json(&manifest_path, &manifest);
    refresh_bundle_signature(bundle);
}

pub(crate) fn refresh_manifest_artifact_ref_if_present(bundle: &Path, artifact_path: &str) {
    if bundle.join("manifest.json").is_file() {
        refresh_manifest_artifact_ref(bundle, artifact_path);
    }
}

pub(crate) fn copy_proof_room_bundle_to_temp() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    (tempdir, bundle)
}

pub(crate) fn build_minimal_passport_proof_room_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = tempdir.path().join("minimal-passport-proof-room-bundle");
    std::fs::create_dir_all(bundle.join("roots")).test_expect("create roots dir");
    std::fs::create_dir_all(bundle.join("verifier")).test_expect("create verifier dir");
    std::fs::create_dir_all(bundle.join("artifacts/authority")).test_expect("create authority dir");
    std::fs::create_dir_all(bundle.join("ui/proof-room-static")).test_expect("create ui dir");

    for file in [
        "transaction-passport.json",
        "evidence-graph.json",
        "claim-set.json",
        "verifier-policy.json",
    ] {
        std::fs::copy(source.join(file), bundle.join("roots").join(file))
            .test_expect("copy root artifact");
    }
    for file in [
        "capability-proof.json",
        "guard-decision.json",
        "kernel-receipt.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(file), bundle.join(file)).test_expect("copy evidence artifact");
    }

    let passport_path = source.join("transaction-passport.json");
    let verify_output = chio(&["proof", "verify", utf8_path(&passport_path).as_str()]);
    assert_success(&verify_output);
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&verify_output.stdout).test_expect("verifier report parses");
    let verifier_report_path = bundle.join("verifier/report.json");
    write_json(&verifier_report_path, &verifier_report);

    let verifier_report_ref = artifact_ref(
        &bundle,
        "verifier/report.json",
        "chio.transaction.verifier-report.v1",
    );
    let ui_report = serde_json::json!({
        "schema": "chio.proof-room.verifier-report.v1",
        "id": "proof-room-verifier-report-minimal-passport-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "verdict": "verified",
        "bundle_id": "proof-room-minimal-passport-valid",
        "fixture_id": "minimal-passport-valid",
        "source_verifier_report_ref": verifier_report_ref,
        "ui_verdict_source": "verifier_report_ref",
        "rendered_claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "source": "verifier/report.json",
                "verdict": "verified"
            },
            {
                "claim_id": "claim.proof_room.verifier_report_bound",
                "source": "verifier/report.json",
                "verdict": "verified"
            }
        ]
    });
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    write_json(&ui_report_path, &ui_report);
    write_json(
        &bundle.join("artifacts/authority/trust-roots.json"),
        &proof_room_trust_roots_for_seed(TEST_SIGNATURE_SEED),
    );

    let manifest = serde_json::json!({
        "schema": "chio.proof-room.bundle.v1",
        "bundle_id": "proof-room-minimal-passport-valid",
        "fixture_id": "minimal-passport-valid",
        "stage": "stage-0",
        "created_at": "2026-06-10T00:00:00Z",
        "source_commit": "fixture-static",
        "source_branch": "main",
        "source_command": "chio proof verify roots/transaction-passport.json",
        "chio_version": "0.1.0",
        "schema_versions": {
            "proof_room_bundle": "chio.proof-room.bundle.v1",
            "proof_room_verifier_report": "chio.proof-room.verifier-report.v1",
            "transaction_passport": "chio.transaction-passport.v1",
            "transaction_evidence_graph": "chio.transaction.evidence-graph.v1",
            "transaction_claim_set": "chio.transaction.claim-set.v1",
            "transaction_verifier_policy": "chio.transaction.verifier-policy.v1",
            "transaction_verifier_report": "chio.transaction.verifier-report.v1"
        },
        "hash_algorithm": "sha256",
        "transaction_passport_ref": artifact_ref(&bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1"),
        "evidence_graph_ref": artifact_ref(&bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1"),
        "verifier_report_ref": artifact_ref(&bundle, "verifier/report.json", "chio.transaction.verifier-report.v1"),
        "proof_room_verifier_report_ref": artifact_ref(&bundle, "ui/proof-room-static/load-report.json", "chio.proof-room.verifier-report.v1"),
        "artifacts": [
            artifact(&bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1", "transaction-root", "transaction-passport"),
            artifact(&bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1", "transaction-root", "evidence-graph"),
            artifact(&bundle, "roots/claim-set.json", "chio.transaction.claim-set.v1", "transaction-root", "claim-set"),
            artifact(&bundle, "roots/verifier-policy.json", "chio.transaction.verifier-policy.v1", "transaction-policy", "verifier-policy"),
            artifact(&bundle, "verifier/report.json", "chio.transaction.verifier-report.v1", "verifier-output", "verifier-report"),
            artifact(&bundle, "ui/proof-room-static/load-report.json", "chio.proof-room.verifier-report.v1", "proof-room-display", "proof-room-report"),
            artifact(&bundle, "capability-proof.json", "chio.capability.proof.v1", "transaction-root", "capability-proof"),
            artifact(&bundle, "guard-decision.json", "chio.guard.decision.v1", "transaction-root", "guard-decision"),
            artifact(&bundle, "kernel-receipt.json", "chio.receipt.v1", "receipt", "receipt"),
            artifact(&bundle, "policy.json", "chio.policy.bundle.v1", "transaction-policy", "policy"),
            artifact(&bundle, "request-digest.json", "chio.request.digest.v1", "transaction-root", "request-digest"),
            artifact(&bundle, "response-digest.json", "chio.response.digest.v1", "transaction-root", "response-digest"),
            artifact(&bundle, "trust-root.json", "chio.trust.root.v1", "transaction-root", "trust-root"),
            artifact(&bundle, "artifacts/authority/trust-roots.json", "chio.proof.first-run.trust-roots.v1", "proof-room-authority", "trust-roots")
        ],
        "claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "required_artifacts": [
                    "roots/transaction-passport.json",
                    "roots/evidence-graph.json",
                    "roots/claim-set.json",
                    "roots/verifier-policy.json",
                    "verifier/report.json"
                ],
                "checker": "chio proof verify roots/transaction-passport.json",
                "result": "verified",
                "proof_level": "deterministic-verifier-report",
                "caveat": "",
                "source_refs": ["verifier/report.json"]
            },
            {
                "claim_id": "claim.proof_room.verifier_report_bound",
                "required_artifacts": [
                    "verifier/report.json",
                    "ui/proof-room-static/load-report.json"
                ],
                "checker": "chio proof serve --dry-run",
                "result": "verified",
                "proof_level": "hash-bound-display-report",
                "caveat": "The UI report is a consumer of verifier output, not a proof source.",
                "source_refs": ["ui/proof-room-static/load-report.json"]
            }
        ],
        "receipt_coverage": [
            {
                "category": "runtime_terminal_allow",
                "status": "covered",
                "artifact_path": "kernel-receipt.json",
                "terminal_status": "allowed_executed"
            }
        ],
        "negative_cases": [],
        "advisory_artifacts": [],
        "excluded_artifacts": [],
        "signature": {
            "kind": "detached-dsse",
            "signature_ref": "bundle-signature.dsse.json"
        }
    });
    write_json(&bundle.join("manifest.json"), &manifest);

    let mut signature = serde_json::json!({
        "payloadType": "application/vnd.chio.proof-room.bundle.v1+json",
        "payloadRef": artifact_ref(&bundle, "manifest.json", "chio.proof-room.bundle.v1"),
        "signatures": [
            {
                "keyid": "",
                "sig": ""
            }
        ]
    });
    sign_bundle_signature(&bundle, &mut signature);
    write_json(&bundle.join("bundle-signature.dsse.json"), &signature);

    (tempdir, bundle)
}
