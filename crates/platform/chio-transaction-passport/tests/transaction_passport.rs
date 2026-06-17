use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chio_test_support::prelude::*;
use serde_json::{json, Value};
use sha2::Digest;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|platform_dir| platform_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/platform/chio-transaction-passport")
        .to_path_buf()
}

fn runtime_security_fixture_dir(case_name: &str) -> PathBuf {
    workspace_root().join(format!("fixtures/proof-room/runtime-security/{case_name}"))
}

fn read_fixture_file(dir: &Path, relative_path: &str) -> Vec<u8> {
    std::fs::read(dir.join(relative_path)).test_expect("runtime security fixture file reads")
}

fn load_runtime_security_fixture(
    case_name: &str,
) -> chio_transaction_passport::RuntimeSecurityBundle {
    let dir = runtime_security_fixture_dir(case_name);
    let passport = serde_json::from_slice(&read_fixture_file(&dir, "transaction-passport.json"))
        .test_expect("runtime security passport parses");
    let evidence_graph_bytes = read_fixture_file(&dir, "evidence-graph.json");
    let verifier_policy_bytes = read_fixture_file(&dir, "verifier-policy.json");
    let mut artifacts = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).test_expect("runtime security fixture dir reads") {
        let entry = entry.test_expect("runtime security fixture entry reads");
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let relative_path = path
            .file_name()
            .and_then(|name| name.to_str())
            .test_expect("runtime security fixture path is utf8");
        if matches!(
            relative_path,
            "transaction-passport.json" | "evidence-graph.json" | "verifier-policy.json"
        ) {
            continue;
        }
        artifacts.insert(
            relative_path.to_string(),
            read_fixture_file(&dir, relative_path),
        );
    }

    chio_transaction_passport::RuntimeSecurityBundle {
        passport,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
    }
}

fn rebind_runtime_graph(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
    graph: Value,
) {
    let graph_bytes = serde_json::to_vec(&graph).test_expect("runtime graph serializes");
    bundle.passport.evidence_graph_sha256 = sha256_hex(&graph_bytes);
    bundle.evidence_graph_bytes = graph_bytes;
}

fn add_unavailable_runtime_receipt_node(
    bundle: &mut chio_transaction_passport::RuntimeSecurityBundle,
) {
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    graph["nodes"]
        .as_array_mut()
        .test_expect("runtime graph has nodes")
        .push(json!({
            "id": "receipt-runtime-denial-missing",
            "schema": "chio.runtime.terminal-receipt.v1",
            "path": "missing-denial-receipt.json",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "role": "receipt"
        }));
    rebind_runtime_graph(bundle, graph);
}

fn valid_minimal_passport() -> chio_transaction_passport::TransactionPassport {
    chio_transaction_passport::TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-minimal-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        evidence_graph_sha256: "0".repeat(64),
        evidence_graph_path: "evidence-graph.json".to_string(),
        verifier_policy_sha256: "1".repeat(64),
        verifier_policy_path: "verifier-policy.json".to_string(),
    }
}

fn valid_evidence_graph_bytes() -> &'static [u8] {
    br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-minimal-valid","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"verifier-policy","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"}],"edges":[]}"#
}

fn valid_verifier_policy_bytes() -> &'static [u8] {
    br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-minimal-valid","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#
}

fn governed_action_artifacts() -> BTreeMap<String, Vec<u8>> {
    let policy_bytes = br#"{"schema":"chio.policy.bundle.v1","id":"policy","version":"2026-06-10","rules":[{"id":"allow-demo-echo","effect":"allow","scope":"tool:demo.echo"}]}"#.to_vec();
    let policy_digest = sha256_hex(&policy_bytes);
    let request_bytes = br#"{"schema":"chio.request.digest.v1","id":"request-digest","method":"demo.echo","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.to_vec();
    let request_digest = sha256_hex(&request_bytes);
    let response_bytes = br#"{"schema":"chio.response.digest.v1","id":"response-digest","method":"demo.echo","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#.to_vec();
    let response_digest = sha256_hex(&response_bytes);
    let guard_decision_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "chio.guard.decision.v1",
        "id": "guard-decision",
        "capability_id": "cap-tool-read-demo",
        "policy_sha256": policy_digest,
        "decision": "allow",
        "request_sha256": request_digest,
        "response_sha256": response_digest,
        "signature": "sig-guard-decision"
    }))
    .test_expect("serialize guard decision");
    let receipt_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "chio.receipt.v1",
        "receipt_id": "receipt-minimal-allow",
        "capability_id": "cap-tool-read-demo",
        "guard_decision_id": "guard-decision",
        "policy_digest": policy_digest,
        "request_digest": request_digest,
        "response_digest": response_digest,
        "terminal_status": "allowed_executed",
        "signature": "sig-receipt-minimal-allow"
    }))
    .test_expect("serialize receipt");
    BTreeMap::from([
        (
            "capability-proof.json".to_string(),
            br#"{"schema":"chio.capability.proof.v1","id":"capability-proof","capability_id":"cap-tool-read-demo","subject":"agent:first-run","scope":"tool:demo.echo","expires_at":"2026-06-10T00:05:00Z","issuer":"did:chio:authority:first-run","signature":"sig-capability-proof"}"#.to_vec(),
        ),
        (
            "guard-decision.json".to_string(),
            guard_decision_bytes,
        ),
        (
            "kernel-receipt.json".to_string(),
            receipt_bytes,
        ),
        ("policy.json".to_string(), policy_bytes),
        ("request-digest.json".to_string(), request_bytes),
        ("response-digest.json".to_string(), response_bytes),
        (
            "trust-root.json".to_string(),
            br#"{"schema":"chio.trust.root.v1","id":"trust-root","root_id":"trust-root-first-run","authority":"did:chio:authority:first-run","signature":"sig-trust-root"}"#.to_vec(),
        ),
        (
            "verifier-policy.json".to_string(),
            valid_verifier_policy_bytes().to_vec(),
        ),
    ])
}

fn governed_action_evidence_graph_bytes(artifacts: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    governed_action_evidence_graph_bytes_with_verifier_policy_path(
        artifacts,
        "verifier-policy.json",
    )
}

fn governed_action_evidence_graph_bytes_with_verifier_policy_path(
    artifacts: &BTreeMap<String, Vec<u8>>,
    verifier_policy_path: &str,
) -> Vec<u8> {
    let digest = |path: &str| {
        sha256_hex(
            artifacts
                .get(path)
                .test_expect("governed action artifact exists"),
        )
    };
    serde_json::to_vec(&serde_json::json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "evidence-graph-minimal-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "nodes": [
            {
                "id": "capability-proof",
                "schema": "chio.capability.proof.v1",
                "path": "capability-proof.json",
                "sha256": digest("capability-proof.json"),
                "role": "capability"
            },
            {
                "id": "guard-decision",
                "schema": "chio.guard.decision.v1",
                "path": "guard-decision.json",
                "sha256": digest("guard-decision.json"),
                "role": "guard-decision"
            },
            {
                "id": "kernel-receipt",
                "schema": "chio.receipt.v1",
                "path": "kernel-receipt.json",
                "sha256": digest("kernel-receipt.json"),
                "role": "receipt"
            },
            {
                "id": "policy",
                "schema": "chio.policy.bundle.v1",
                "path": "policy.json",
                "sha256": digest("policy.json"),
                "role": "policy"
            },
            {
                "id": "request-digest",
                "schema": "chio.request.digest.v1",
                "path": "request-digest.json",
                "sha256": digest("request-digest.json"),
                "role": "request"
            },
            {
                "id": "response-digest",
                "schema": "chio.response.digest.v1",
                "path": "response-digest.json",
                "sha256": digest("response-digest.json"),
                "role": "response"
            },
            {
                "id": "trust-root",
                "schema": "chio.trust.root.v1",
                "path": "trust-root.json",
                "sha256": digest("trust-root.json"),
                "role": "trust-root"
            },
            {
                "id": "verifier-policy",
                "schema": "chio.transaction.verifier-policy.v1",
                "path": verifier_policy_path,
                "sha256": digest(verifier_policy_path),
                "role": "verifier-policy"
            }
        ],
        "edges": [
            {
                "from": "capability-proof",
                "to": "kernel-receipt",
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": "guard-decision",
                "to": "kernel-receipt",
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": "policy",
                "to": "guard-decision",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": "request-digest",
                "to": "kernel-receipt",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": "response-digest",
                "to": "kernel-receipt",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": "trust-root",
                "to": "capability-proof",
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": "verifier-policy",
                "to": "kernel-receipt",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            }
        ]
    }))
    .test_expect("serialize governed action evidence graph")
}

fn passport_error_for_evidence_graph(
    evidence_graph_bytes: &[u8],
) -> chio_transaction_passport::TransactionPassportError {
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(evidence_graph_bytes, verifier_policy_bytes);

    chio_transaction_passport::verify_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        evidence_graph_bytes,
        verifier_policy_bytes,
    )
    .test_expect_err("evidence graph must fail closed")
}

fn passport_for_artifact_bytes(
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
) -> chio_transaction_passport::TransactionPassport {
    let mut passport = valid_minimal_passport();
    passport.evidence_graph_sha256 = sha256_hex(evidence_graph_bytes);
    passport.verifier_policy_sha256 = sha256_hex(verifier_policy_bytes);
    passport
}

#[test]
fn transaction_passport_accepts_minimal_schema_shape() {
    let passport = valid_minimal_passport();

    chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect("valid minimal passport shape should pass");
}

#[test]
fn transaction_passport_rejects_unknown_schema_id() {
    let mut passport = valid_minimal_passport();
    passport.schema = "chio.transaction-passport.v999".to_string();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("unknown schema id must fail closed");
    assert!(error
        .to_string()
        .contains("unsupported transaction passport schema"));
}

#[test]
fn transaction_passport_rejects_empty_identity_fields() {
    let mut passport = valid_minimal_passport();
    passport.id.clear();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("empty passport id must fail closed");
    assert!(error
        .to_string()
        .contains("invalid transaction passport field id"));

    let mut passport = valid_minimal_passport();
    passport.issued_at.clear();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("empty issued_at must fail closed");
    assert!(error
        .to_string()
        .contains("invalid transaction passport field issued_at"));
}

#[test]
fn transaction_passport_rejects_bad_digest_shape() {
    let mut passport = valid_minimal_passport();
    passport.evidence_graph_sha256 = "abc".to_string();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("short digest must fail");
    assert!(error.to_string().contains("invalid evidence graph digest"));

    let mut passport = valid_minimal_passport();
    passport.verifier_policy_sha256 =
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("non-hex digest must fail");
    assert!(error.to_string().contains("invalid verifier policy digest"));
}

#[test]
fn transaction_passport_rejects_unsafe_artifact_paths() {
    let mut passport = valid_minimal_passport();
    passport.evidence_graph_path = "../evidence-graph.json".to_string();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("parent path traversal must fail");
    assert!(error.to_string().contains("unsafe evidence graph path"));

    let mut passport = valid_minimal_passport();
    passport.verifier_policy_path = "/tmp/verifier-policy.json".to_string();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("absolute paths must fail");
    assert!(error.to_string().contains("unsafe verifier policy path"));

    let mut passport = valid_minimal_passport();
    passport.evidence_graph_path = "C:\\outside\\evidence-graph.json".to_string();

    let error = chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("windows-style paths must fail portably");
    assert!(error.to_string().contains("unsafe evidence graph path"));
}

#[test]
fn transaction_passport_rejects_invalid_evidence_graph_artifact() {
    let evidence_graph_bytes = b"not-json";
    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(error
        .to_string()
        .contains("invalid evidence graph artifact"));
}

#[test]
fn transaction_passport_rejects_duplicate_evidence_graph_node_ids() {
    let evidence_graph_bytes = br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-duplicate-node","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"verifier-policy","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"},{"id":"verifier-policy","schema":"chio.receipt.v1","path":"receipt.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","role":"receipt"}],"edges":[]}"#;

    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(error
        .to_string()
        .contains("duplicate evidence graph node id"));
}

#[test]
fn transaction_passport_rejects_unresolved_evidence_graph_edge_refs() {
    let evidence_graph_bytes = br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-dangling-edge","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"verifier-policy","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"}],"edges":[{"from":"missing-receipt","to":"verifier-policy","predicate":"binds","evidence_class":"digest-bound-reference"}]}"#;

    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(error
        .to_string()
        .contains("unknown evidence graph edge source"));
}

#[test]
fn transaction_passport_rejects_wrong_verifier_policy_schema() {
    let evidence_graph_bytes = valid_evidence_graph_bytes();
    let verifier_policy_bytes =
        br#"{"schema":"chio.transaction.verifier-policy.v999","id":"verifier-policy-minimal-valid","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#;
    let passport = passport_for_artifact_bytes(evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        evidence_graph_bytes,
        verifier_policy_bytes,
    )
    .test_expect_err("wrong verifier policy schema must fail closed");

    assert!(error
        .to_string()
        .contains("unsupported verifier policy schema"));
}

#[test]
fn standalone_minimal_passport_rejects_missing_governed_action_evidence() {
    let evidence_graph_bytes = valid_evidence_graph_bytes();
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        evidence_graph_bytes,
        verifier_policy_bytes,
        &BTreeMap::new(),
    )
    .test_expect_err("standalone minimal passport must prove a governed action");

    assert!(error
        .to_string()
        .contains("minimal governed action evidence missing: receipt"));
}

#[test]
fn standalone_minimal_passport_accepts_governed_action_evidence() {
    let artifacts = governed_action_artifacts();
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
    )
    .test_expect("standalone minimal passport should accept governed action evidence");
}

#[test]
fn standalone_minimal_passport_rejects_governed_action_mismatch() {
    let mut artifacts = governed_action_artifacts();
    artifacts.insert(
        "guard-decision.json".to_string(),
        br#"{"schema":"chio.guard.decision.v1","id":"guard-decision","capability_id":"cap-tool-other","policy_sha256":"0e95e7e10531e5a1ca75856b4a74de5ae38d9443d9d6121584aa1aed93e13a8e","decision":"allow","request_sha256":"19eb2f6abf3f92c940aefc5684f140dfc9d137bd01fb9a528aeed6a6cfd2a085","response_sha256":"0c3ad6d9cbf59789e18ba025f7c2bec3925e043bb4f3f598f6cf22bb5e57aa45","signature":"sig-guard-decision"}"#.to_vec(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
    )
    .test_expect_err("standalone minimal passport must reject mismatched governed action evidence");

    assert!(error
        .to_string()
        .contains("minimal governed action evidence invalid"));
}

#[test]
fn standalone_minimal_passport_rejects_stale_capability_proof() {
    let mut artifacts = governed_action_artifacts();
    let mut capability: serde_json::Value = serde_json::from_slice(
        artifacts
            .get("capability-proof.json")
            .test_expect("capability artifact exists"),
    )
    .test_expect("capability artifact parses");
    capability["expires_at"] = serde_json::Value::String("2026-06-09T23:59:59Z".to_string());
    artifacts.insert(
        "capability-proof.json".to_string(),
        serde_json::to_vec(&capability).test_expect("capability artifact serializes"),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
    )
    .test_expect_err("standalone minimal passport must reject stale capability evidence");

    assert!(error
        .to_string()
        .contains("capability proof expired before evidence graph issuance"));
}

#[test]
fn standalone_minimal_passport_accepts_packaged_verifier_policy_node_path() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    artifacts.remove("verifier-policy.json");
    artifacts.insert(
        "roots/verifier-policy.json".to_string(),
        verifier_policy_bytes.to_vec(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes_with_verifier_policy_path(
        &artifacts,
        "roots/verifier-policy.json",
    );
    let passport = passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
    )
    .test_expect("standalone minimal passport should accept packaged verifier policy path");
}

#[test]
fn runtime_receipt_totality_rejects_graph_receipt_without_artifact() {
    let mut bundle = load_runtime_security_fixture("terminal-denial");
    add_unavailable_runtime_receipt_node(&mut bundle);

    let error = chio_transaction_passport::verify_runtime_security_claims(&bundle)
        .test_expect_err("graph-listed terminal receipt must have artifact bytes");
    let error = error.to_string();

    assert!(
        error.contains("missing runtime artifact: missing-denial-receipt.json"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_missing_governed_action_artifacts() {
    let mut artifacts = governed_action_artifacts();
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    artifacts.remove("kernel-receipt.json");
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
    )
    .test_expect_err("standalone minimal passport must verify graph artifact bytes");

    assert!(error
        .to_string()
        .contains("missing evidence graph artifact: kernel-receipt.json"));
}

#[test]
fn standalone_minimal_passport_rejects_detached_verifier_policy_node() {
    let mut artifacts = governed_action_artifacts();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-detached","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#.to_vec(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport = passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
    )
    .test_expect_err("evidence graph verifier policy node must match passport policy digest");

    assert!(error
        .to_string()
        .contains("verifier policy evidence graph digest mismatch"));
}
