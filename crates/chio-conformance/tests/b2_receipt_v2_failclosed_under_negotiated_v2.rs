//! Trj5 B2 negative conformance: kernel MUST fail closed when a request
//! names a federation peer expected to be v2-capable but no matching
//! peer is pinned fresh.
//!
//! Spec MUST: spec/PROTOCOL.md section 6 ("Receipt v2 body_hash addressing
//!   (W2.1)") "Negotiation downgrade" bullet, post-TRJ5-B2 normative MUST.
//!   Pre-B2, the cited prose contained NEITHER `MUST` nor `SHOULD` (it
//!   read "the kernel falls back to minting only the v1 UUIDv7 receipt").
//!   B2 introduces a NEW normative MUST (a TIGHTENING, not a SHOULD->MUST
//!   promotion).
//!
//! Enforced call site:
//!   crates/chio-kernel/src/kernel/mod.rs (function
//!   `kernel_receipt_version_for_remote`, ~mod.rs:1574-1591 pre-B2;
//!   post-B2 the function returns
//!   `Result<KernelReceiptVersion, KernelError>` and emits
//!   `KernelError::ReceiptNegotiationDowngrade` when a federation peer
//!   is named but not pinned fresh).
//!
//! Production call path (the chain this fixture exercises):
//!   `ChioKernel::kernel_receipt_version_for_remote`
//!     (the production resolver), as called from
//!   `record_chio_receipt_with_federation`
//!     (`crates/chio-kernel/src/kernel/responses.rs:1405-1427`),
//!     which is the v2 mint hook every governed dispatch funnels
//!     through (`evaluate_tool_call_blocking` -> ... ->
//!     `record_chio_receipt_with_federation`).
//!   The resolver is invoked directly here so the test exercises the
//!   exact production code at the enforcement site without requiring a
//!   federation cosigner; this matches the pattern already used by
//!   `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:384`
//!   for the `KernelReceiptVersion::V1Legacy` advisory branch. The
//!   resolver is `pub fn` on `ChioKernel`, so no test-only accessor is
//!   used (per `EVIDENCE-GATE.md` §8.3 anti-pattern).
//!   The `Allow`-dispatch path in `no_peer_named_kernel_default_v1_mints_v1_only`
//!   still drives `evaluate_tool_call_blocking` end-to-end so the v1
//!   mint side effect is observed against the real `SqliteReceiptStore`.
//!
//! Reverts-to-fail proof (Evidence Gate Artifact D, close bar):
//!   If the function body of `kernel_receipt_version_for_remote` is
//!   reverted to the pre-B2 warn-and-continue form (i.e. the legacy
//!   `tracing::warn!` event followed by `return KernelReceiptVersion::V1Legacy`
//!   for the named-peer-not-pinned-fresh branch), the
//!   `v2_negotiation_with_stale_pin_fails_closed` and
//!   `v2_negotiation_with_never_pinned_peer_fails_closed` sub-tests
//!   MUST fail because the resolver returns `Ok(V1Legacy)` instead of
//!   the typed error variant -- the `expect_err` will panic.
//!   Local repro:
//!     1. Edit `crates/chio-kernel/src/kernel/mod.rs` and replace the
//!        `Err(KernelError::ReceiptNegotiationDowngrade { .. })` block
//!        with the pre-B2 `tracing::warn!` + `return Ok(V1Legacy)`
//!        body.
//!     2. Adjust the function signature back to `-> KernelReceiptVersion`.
//!        (Adjust callers to match.)
//!     3. `cargo test -p chio-conformance --test b2_receipt_v2_failclosed_under_negotiated_v2`.
//!     4. The two negative sub-tests fail with a panic on the
//!        `expect_err`.
//!
//! Threat: an adversary or operator-misconfiguration causes a peer pin
//!   to expire (or never be installed) for a federation peer whose
//!   negotiated profile was v2-capable. The pre-B2 resolver silently
//!   selects `V1Legacy`. The downgraded receipt does not carry
//!   `body_hash` and the v2 replay store is not consulted; an attacker
//!   who replays a request observes the silent regression and exfiltrates
//!   v2-binding properties.
//!
//! Why this passes Artifact D (production call path exercise):
//!   The fixture imports `chio_kernel::ChioKernel` (the production
//!   kernel) directly and calls the public `kernel_receipt_version_for_remote`
//!   resolver -- the exact function at the enforcement site. The
//!   advisory positive case drives `evaluate_tool_call_blocking` end-
//!   to-end and inspects `chio_receipts` and `chio_receipts_v2` rows
//!   via `rusqlite::Connection` directly (per R3 reservation: no
//!   kernel-side `test_only_*` accessor). Mocks beyond the OS clock
//!   and the `EchoToolServer` (a real `ToolServerConnection` impl
//!   identical in shape to
//!   `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:58-77`):
//!   none.

#![allow(clippy::unwrap_used, clippy::expect_used, deprecated)]

use std::sync::atomic::{AtomicUsize, Ordering};

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_federation::FederationPeer;
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, KernelReceiptVersion, NegotiationDowngradeReason,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteReceiptStore;
use rusqlite::Connection;

const SRV: &str = "srv-b2";
const TOOL: &str = "echo";

/// Minimal in-process `ToolServerConnection`, matching the
/// `v2_receipt_kernel_round_trip.rs` shape. The tool body is irrelevant
/// to the receipt-version resolver under test; what matters is that
/// the dispatch reaches `record_chio_receipt_with_federation` for the
/// advisory positive sub-test.
struct EchoToolServer {
    server_id: String,
    invocations: AtomicUsize,
}

impl EchoToolServer {
    fn new() -> Self {
        Self {
            server_id: SRV.to_string(),
            invocations: AtomicUsize::new(0),
        }
    }
}

impl ToolServerConnection for EchoToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL.to_string()]
    }

    fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        assert_eq!(tool_name, TOOL);
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"echoed": arguments}))
    }
}

fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{nonce}-{counter}.sqlite3",
        std::process::id()
    ))
}

fn make_kernel(receipt_store_path: &std::path::Path) -> ChioKernel {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "trj5-b2-failclosed-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    let store = SqliteReceiptStore::open(receipt_store_path).unwrap();
    kernel.set_receipt_store(Box::new(store));
    kernel.register_tool_server(Box::new(EchoToolServer::new()));
    // The kernel-level v2 default is on; this matches the production
    // expectation that a federation-capable kernel is v2-aware.
    kernel.set_receipt_v2_default(true);
    kernel
}

fn make_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: SRV.to_string(),
            tool_name: TOOL.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn make_request(
    request_id: &str,
    cap: &chio_core::capability::CapabilityToken,
    federated_origin_kernel_id: Option<String>,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: TOOL.to_string(),
        server_id: SRV.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments: serde_json::json!({"input": "b2-failclosed"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id,
    }
}

/// Build a v2-capable `FederationPeer` whose pin freshness window
/// has already expired (`rotation_due` < `now` we will pass to the
/// resolver).
///
/// The federation peer is constructed directly rather than going
/// through the full `KernelTrustExchange` handshake because the test
/// is exercising the resolver's reaction to a stale pin, NOT the
/// handshake itself. The peer carries `t1_default()` capabilities so
/// `from_capabilities` would resolve to `V2BodyHash` if the pin were
/// fresh.
fn stale_v2_capable_peer(remote_kernel_id: &str) -> FederationPeer {
    let remote_kp = Keypair::generate();
    FederationPeer {
        kernel_id: remote_kernel_id.to_string(),
        public_key: remote_kp.public_key(),
        conformance_tier: chio_federation::ConformanceTier::Bronze,
        // Established in the distant past; rotation_due in the past too.
        established_at: 1_700_000_000,
        rotation_due: 1_700_000_001,
        capabilities: chio_core::capability::CapabilityNegotiation::t1_default(),
    }
}

/// Count rows in the v2 `chio_receipts_v2` table. Reads the real SQLite
/// store; no kernel-side `test_only_*` accessor (per R3 reservation).
fn count_v2_receipts(receipt_store_path: &std::path::Path) -> i64 {
    let connection = Connection::open(receipt_store_path).unwrap();
    connection
        .query_row("SELECT COUNT(*) FROM chio_receipts_v2", [], |row| {
            row.get(0)
        })
        .unwrap_or(0)
}

/// Count rows in the legacy v1 `chio_tool_receipts` table (the
/// production table the `SqliteReceiptStore` writes v1 receipts into;
/// see `crates/chio-store-sqlite/src/receipt_store.rs:515`). Reads the
/// real SQLite store; no kernel-side `test_only_*` accessor (per R3
/// reservation).
fn count_v1_receipts(receipt_store_path: &std::path::Path) -> i64 {
    let connection = Connection::open(receipt_store_path).unwrap();
    connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap_or(0)
}

#[test]
fn v2_negotiation_with_stale_pin_fails_closed() {
    // CRITICAL B2 NEGATIVE: when the resolver is asked for the receipt
    // version for a federation peer that is NOT pinned fresh, the
    // kernel MUST return the typed
    // `KernelError::ReceiptNegotiationDowngrade` error. The pre-B2
    // warn-and-continue path returned `Ok(V1Legacy)` and silently let
    // a v1 receipt be minted; that path is the threat this fixture
    // defends against.
    let path = unique_db_path("b2-failclosed-stale");
    let kernel = make_kernel(&path);

    // Install a stale v2-capable federation peer. `is_fresh(now)` is
    // false because `rotation_due` is BEFORE the `now` we pass below,
    // so the resolver's `federation_peer(remote, now)` lookup returns
    // `None`, which is the input that drives the named-peer-not-pinned
    // -fresh branch under test.
    let remote_kernel_id = "kernel.org-stale";
    let kernel = kernel.with_federation_peers(vec![stale_v2_capable_peer(remote_kernel_id)]);

    // Drive the production resolver directly. Same shape as the
    // existing test at
    // `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs:384`,
    // so the call hits the production code at the exact enforcement
    // site (`kernel_receipt_version_for_remote` is `pub fn` on
    // `ChioKernel`).
    let now = 1_800_000_000_u64; // far past the peer's rotation_due
    let err = kernel
        .kernel_receipt_version_for_remote(Some(remote_kernel_id), now)
        .expect_err("resolver must fail closed when named peer is not pinned fresh");

    // Match on the typed variant rather than the Display string (per
    // CONFORMANCE-FIXTURE-PATTERN.md §8.4: error strings rot).
    match err {
        KernelError::ReceiptNegotiationDowngrade {
            expected,
            actual,
            reason,
        } => {
            assert_eq!(
                expected,
                KernelReceiptVersion::V2BodyHash,
                "expected receipt version must be V2BodyHash"
            );
            assert_eq!(
                actual,
                KernelReceiptVersion::V1Legacy,
                "actual (downgraded) receipt version must be V1Legacy"
            );
            match reason {
                NegotiationDowngradeReason::PeerNotPinnedFresh {
                    remote_kernel_id: rkid,
                } => {
                    assert_eq!(
                        rkid, remote_kernel_id,
                        "the structured reason must carry the remote_kernel_id from the request"
                    );
                }
                // The reason enum is non-exhaustive; future variants
                // are accepted as evidence the resolver still fail-
                // closed even if the discriminating condition expands.
                other => {
                    panic!("expected NegotiationDowngradeReason::PeerNotPinnedFresh, got {other:?}")
                }
            }
        }
        other => panic!(
            "expected KernelError::ReceiptNegotiationDowngrade, got {other:?}; \
             this test guards spec/PROTOCOL.md section 6 (Negotiation downgrade), \
             post-B2 normative MUST. If this branch is hit, the kernel has \
             reverted to warn-and-downgrade or silently produced a different \
             error."
        ),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn v2_negotiation_with_never_pinned_peer_fails_closed() {
    // The MUST explicitly enumerates BOTH stale and never-pinned cases
    // (R3 finding #4: a future implementation could plausibly read
    // "not pinned fresh" as "stale only" and re-introduce a bypass for
    // the never-pinned path; the fixture pins both).
    let path = unique_db_path("b2-failclosed-never");
    let kernel = make_kernel(&path);
    // No peer installed at all -- "never-pinned".
    let remote_kernel_id = "kernel.org-never-pinned";

    let err = kernel
        .kernel_receipt_version_for_remote(Some(remote_kernel_id), 1_700_000_000)
        .expect_err("resolver must fail closed when named peer was never pinned");

    match err {
        KernelError::ReceiptNegotiationDowngrade {
            expected,
            actual,
            reason,
        } => {
            assert_eq!(expected, KernelReceiptVersion::V2BodyHash);
            assert_eq!(actual, KernelReceiptVersion::V1Legacy);
            match reason {
                NegotiationDowngradeReason::PeerNotPinnedFresh {
                    remote_kernel_id: rkid,
                } => {
                    assert_eq!(rkid, remote_kernel_id);
                }
                other => {
                    panic!("expected NegotiationDowngradeReason::PeerNotPinnedFresh, got {other:?}")
                }
            }
        }
        other => panic!(
            "expected KernelError::ReceiptNegotiationDowngrade for never-pinned \
             peer, got {other:?}"
        ),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn no_peer_named_kernel_default_v1_mints_v1_only() {
    // POSITIVE (advisory mode preserved): when the request does not
    // name a federation peer and the kernel-level default is v1, the
    // resolver returns Ok(V1Legacy) and v1 minting proceeds. This is
    // the spec-conformant v1-only profile and B2 must NOT regress it.
    //
    // This sub-test additionally exercises
    // `evaluate_tool_call_blocking` end-to-end through
    // `record_chio_receipt_with_federation` -> the resolver, so the
    // production call chain that integrates the resolver into mint is
    // observed via the persisted SQLite rows directly.
    let path = unique_db_path("b2-failclosed-advisory-v1");
    let kernel = make_kernel(&path);
    kernel.set_receipt_v2_default(false);

    // Sanity: the resolver returns Ok(V1Legacy) directly (the no-remote
    // + kernel-default-v1 branch).
    let resolved = kernel
        .kernel_receipt_version_for_remote(None, 1_700_000_000)
        .unwrap();
    assert_eq!(resolved, KernelReceiptVersion::V1Legacy);

    let agent_kp = Keypair::generate();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request("req-b2-advisory-v1", &cap, None);

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    drop(kernel);
    assert!(
        count_v1_receipts(&path) >= 1,
        "advisory v1 dispatch must mint at least one v1 receipt"
    );
    assert_eq!(
        count_v2_receipts(&path),
        0,
        "advisory v1 dispatch must NOT mint a v2 receipt"
    );

    let _ = std::fs::remove_file(&path);
}
