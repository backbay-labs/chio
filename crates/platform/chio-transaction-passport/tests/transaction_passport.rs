use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use chio_core_types::crypto::Keypair;
use chio_test_support::prelude::*;
use serde_json::{json, Value};
use sha2::Digest;

#[path = "transaction_passport/runtime_security_support.rs"]
mod runtime_security_support;
use runtime_security_support::*;

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

fn evidence_graph_schema_roles() -> BTreeSet<String> {
    let schema_path =
        workspace_root().join("spec/schemas/chio-transaction/v1/evidence-graph.schema.json");
    let schema: Value = serde_json::from_slice(
        &std::fs::read(schema_path).test_expect("evidence graph schema reads"),
    )
    .test_expect("evidence graph schema parses");
    schema
        .pointer("/$defs/node/properties/role/enum")
        .and_then(Value::as_array)
        .test_expect("evidence graph schema role enum")
        .iter()
        .map(|role| {
            role.as_str()
                .test_expect("evidence graph schema role enum string")
                .to_string()
        })
        .collect()
}

#[test]
fn evidence_graph_schema_allows_public_settlement_proof_bundle_role() {
    assert!(evidence_graph_schema_roles().contains("public-settlement-proof-bundle"));
}

#[test]
fn evidence_graph_schema_allows_swarm_authority_roles() {
    let roles = evidence_graph_schema_roles();
    for role in [
        "swarm-task-graph",
        "swarm-continuation-token",
        "swarm-delegation-witness-chain",
        "swarm-join-receipt",
        "swarm-route-plan-receipt",
        "swarm-terminal-graph-receipt",
        "swarm-budget-pool",
        "swarm-revocation-epoch",
    ] {
        assert!(roles.contains(role), "missing evidence graph role {role}");
    }
}

#[test]
fn transaction_verifier_report_schema_requires_machine_result_fields() {
    let schema_path =
        workspace_root().join("spec/schemas/chio-transaction/v1/verifier-report.schema.json");
    let schema: Value = serde_json::from_slice(
        &std::fs::read(schema_path).test_expect("verifier report schema reads"),
    )
    .test_expect("verifier report schema parses");
    let validator =
        jsonschema::validator_for(&schema).test_expect("verifier report schema compiles");
    let valid_verified_report = json!({
        "schema": "chio.transaction.verifier-report.v1",
        "id": "verifier-report-passport-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "verdict": "verified",
        "accepted": true,
        "state": "verified",
        "passport_id": "passport-valid",
        "passport_path": "transaction-passport.json",
        "evidence_graph_sha256": "a".repeat(64),
        "evidence_graph_path": "evidence-graph.json",
        "claim_set_sha256": "b".repeat(64),
        "claim_set_path": "claim-set.json",
        "verifier_policy_sha256": "c".repeat(64),
        "verifier_policy_path": "verifier-policy.json",
        "transparencyState": "not_present",
        "claimResults": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "status": "verified",
                "verifier_module": "chio.transaction-passport"
            }
        ]
    });
    assert!(
        validator.is_valid(&valid_verified_report),
        "valid verified report rejected"
    );

    for field in ["accepted", "state", "transparencyState", "claimResults"] {
        let mut missing_field = valid_verified_report.clone();
        missing_field
            .as_object_mut()
            .test_expect("verified report object")
            .remove(field);
        assert!(
            !validator.is_valid(&missing_field),
            "verifier report schema accepted report missing {field}"
        );
    }

    let mut failed_report = valid_verified_report.clone();
    failed_report["verdict"] = Value::String("failed".to_string());
    failed_report["accepted"] = Value::Bool(false);
    failed_report["state"] = Value::String("failed".to_string());
    failed_report["failureCode"] = Value::String("CHIO-TRANSACTION-EVIDENCE-DIGEST".to_string());
    failed_report["claimResults"][0]["status"] = Value::String("failed".to_string());
    failed_report["claimResults"][0]["failure_reason"] =
        Value::String("evidence graph digest mismatch".to_string());
    assert!(
        validator.is_valid(&failed_report),
        "valid failed report rejected"
    );

    let mut failed_without_code = failed_report.clone();
    failed_without_code
        .as_object_mut()
        .test_expect("failed report object")
        .remove("failureCode");
    assert!(
        !validator.is_valid(&failed_without_code),
        "verifier report schema accepted failed report without failureCode"
    );
}

fn signed_json_bytes(mut value: Value, keypair: &Keypair) -> Vec<u8> {
    value
        .as_object_mut()
        .test_expect("signed artifact is an object")
        .remove("signature");
    let (signature, _) = keypair
        .sign_canonical(&value)
        .test_expect("signed artifact signs");
    value["signature"] = Value::String(signature.to_hex());
    serde_json::to_vec(&value).test_expect("signed artifact serializes")
}

fn replace_signed_artifact_key(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    artifact_path: &str,
    key_field: &str,
    keypair: &Keypair,
) {
    let mut artifact: Value = serde_json::from_slice(
        artifacts
            .get(artifact_path)
            .test_expect("governed action artifact exists"),
    )
    .test_expect("governed action artifact parses");
    artifact[key_field] = Value::String(keypair.public_key().to_hex());
    artifacts.insert(
        artifact_path.to_string(),
        signed_json_bytes(artifact, keypair),
    );
}

fn valid_minimal_passport() -> chio_transaction_passport::TransactionPassport {
    chio_transaction_passport::TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-minimal-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        issuer: format!(
            "did:chio:{}",
            Keypair::from_seed(&[7u8; 32]).public_key().to_hex()
        ),
        evidence_graph_sha256: "0".repeat(64),
        evidence_graph_path: "evidence-graph.json".to_string(),
        not_before: None,
        expires_at: None,
        claim_set_sha256: sha256_hex(valid_claim_set_bytes()),
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: "1".repeat(64),
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: "00".repeat(64),
    }
}

fn signed_minimal_passport(
    keypair: &Keypair,
) -> Result<
    chio_transaction_passport::TransactionPassport,
    chio_transaction_passport::TransactionPassportError,
> {
    let mut passport = valid_minimal_passport();
    passport.issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    passport.signature = chio_transaction_passport::sign_transaction_passport(&passport, keypair)?;
    Ok(passport)
}

fn valid_evidence_graph_bytes() -> &'static [u8] {
    br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-minimal-valid","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"ba7948a6ea038b3846c2402ae41a5d122a39133124cb493ddd7a30166b7a6dae","schema":"chio.transaction.claim-set.v1","path":"claim-set.json","sha256":"ba7948a6ea038b3846c2402ae41a5d122a39133124cb493ddd7a30166b7a6dae","role":"claim-set"},{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"}],"edges":[{"from":"ba7948a6ea038b3846c2402ae41a5d122a39133124cb493ddd7a30166b7a6dae","to":"1111111111111111111111111111111111111111111111111111111111111111","predicate":"binds","evidence_class":"digest-bound-reference"}]}"#
}

fn valid_claim_set_bytes() -> &'static [u8] {
    br#"{"schema":"chio.transaction.claim-set.v1","id":"claim-set-minimal-valid","issued_at":"2026-06-10T00:00:00Z","claims":[{"claim_id":"claim.transaction.passport_root_verified","status":"verified","required_evidence":["transaction-passport.json","evidence-graph.json","verifier-policy.json"],"evidence_refs":["transaction-passport.json","evidence-graph.json","verifier-policy.json"],"verifier_module":"chio-transaction-passport::minimal"}]}"#
}

fn valid_verifier_policy_bytes() -> &'static [u8] {
    br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-minimal-valid","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":[]}"#
}

fn all_standalone_transaction_claims() -> [&'static str; 6] {
    [
        "claim.transaction.passport_root_verified",
        "claim.transaction.evidence_graph_digest_bound",
        "claim.transaction.evidence_graph_structure_verified",
        "claim.transaction.claim_set_digest_bound",
        "claim.transaction.policy_digest_bound",
        "claim.transaction.omission_policy_bound",
    ]
}

fn verifier_policy_with_all_standalone_transaction_claims_bytes() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "verifier-policy-all-standalone-claims",
        "issued_at": "2026-06-10T00:00:00Z",
        "required_claims": all_standalone_transaction_claims(),
        "omitted_claims": []
    }))
    .test_expect("verifier policy serializes")
}

fn claim_set_with_all_standalone_transaction_claims_bytes() -> Vec<u8> {
    let claims = all_standalone_transaction_claims()
        .into_iter()
        .map(|claim_id| {
            json!({
                "claim_id": claim_id,
                "status": "verified",
                "required_evidence": ["transaction-passport.json", "evidence-graph.json", "verifier-policy.json"],
                "evidence_refs": ["transaction-passport.json", "evidence-graph.json", "verifier-policy.json"],
                "verifier_module": "chio-transaction-passport::minimal"
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-all-standalone-claims",
        "issued_at": "2026-06-10T00:00:00Z",
        "claims": claims
    }))
    .test_expect("claim set serializes")
}

fn verifier_policy_with_risk_claim_bytes() -> Vec<u8> {
    br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-with-risk","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified","claim.risk.comptroller_report_bound"],"omitted_claims":[]}"#.to_vec()
}

fn claim_set_with_risk_claim_bytes() -> Vec<u8> {
    br#"{"schema":"chio.transaction.claim-set.v1","id":"claim-set-with-risk","issued_at":"2026-06-10T00:00:00Z","claims":[{"claim_id":"claim.transaction.passport_root_verified","status":"verified","required_evidence":["transaction-passport.json","evidence-graph.json","verifier-policy.json"],"evidence_refs":["transaction-passport.json","evidence-graph.json","verifier-policy.json"],"verifier_module":"chio-transaction-passport::minimal"},{"claim_id":"claim.risk.comptroller_report_bound","status":"verified","required_evidence":["risk-comptroller-report.json"],"evidence_refs":["risk-comptroller-report.json"],"verifier_module":"chio-risk-comptroller"}]}"#.to_vec()
}

fn verifier_policy_with_omission_bytes() -> Vec<u8> {
    br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-with-omission","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.passport_root_verified"],"omitted_claims":["claim.transaction.settlement_finality_verified"]}"#.to_vec()
}

fn verifier_policy_with_rich_gates(gates: Value) -> Vec<u8> {
    let mut policy = json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "verifier-policy-rich-gates",
        "issued_at": "2026-06-10T00:00:00Z",
        "required_claims": ["claim.transaction.passport_root_verified"],
        "omitted_claims": []
    });
    let policy_object = policy
        .as_object_mut()
        .test_expect("rich verifier policy is an object");
    for (key, value) in gates
        .as_object()
        .test_expect("rich verifier policy gates are an object")
    {
        policy_object.insert(key.clone(), value.clone());
    }
    serde_json::to_vec(&policy).test_expect("rich verifier policy serializes")
}

#[derive(Clone, Copy)]
enum GovernedActionDigestBinding {
    DeclaredDigest,
    ArtifactWrapperDigest,
}

fn governed_action_artifacts() -> BTreeMap<String, Vec<u8>> {
    governed_action_artifacts_with_digest_binding(GovernedActionDigestBinding::DeclaredDigest)
}

fn governed_action_artifacts_bound_to_wrapper_digest() -> BTreeMap<String, Vec<u8>> {
    governed_action_artifacts_with_digest_binding(
        GovernedActionDigestBinding::ArtifactWrapperDigest,
    )
}

fn governed_action_artifacts_with_digest_binding(
    digest_binding: GovernedActionDigestBinding,
) -> BTreeMap<String, Vec<u8>> {
    let capability_key = Keypair::from_seed(&[51u8; 32]);
    let guard_key = Keypair::from_seed(&[52u8; 32]);
    let receipt_key = Keypair::from_seed(&[53u8; 32]);
    let trust_root_key = Keypair::from_seed(&[54u8; 32]);
    let capability_issuer = format!("did:chio:{}", capability_key.public_key().to_hex());
    let trust_root_authority = format!("did:chio:{}", trust_root_key.public_key().to_hex());
    let policy_bytes = br#"{"schema":"chio.policy.bundle.v1","id":"policy","version":"2026-06-10","rules":[{"id":"allow-demo-echo","effect":"allow","scope":"tool:demo.echo"}]}"#.to_vec();
    let policy_digest = sha256_hex(&policy_bytes);
    let request_declared_digest = "a".repeat(64);
    let request_bytes = serde_json::to_vec(&json!({
        "schema": "chio.request.digest.v1",
        "id": "request-digest",
        "method": "demo.echo",
        "sha256": request_declared_digest
    }))
    .test_expect("request digest artifact serializes");
    let response_declared_digest = "b".repeat(64);
    let response_bytes = serde_json::to_vec(&json!({
        "schema": "chio.response.digest.v1",
        "id": "response-digest",
        "method": "demo.echo",
        "sha256": response_declared_digest
    }))
    .test_expect("response digest artifact serializes");
    let request_digest = match digest_binding {
        GovernedActionDigestBinding::DeclaredDigest => request_declared_digest,
        GovernedActionDigestBinding::ArtifactWrapperDigest => sha256_hex(&request_bytes),
    };
    let response_digest = match digest_binding {
        GovernedActionDigestBinding::DeclaredDigest => response_declared_digest,
        GovernedActionDigestBinding::ArtifactWrapperDigest => sha256_hex(&response_bytes),
    };
    let capability_bytes = signed_json_bytes(
        json!({
            "schema": "chio.capability.proof.v1",
            "id": "capability-proof",
            "capability_id": "cap-tool-read-demo",
            "subject": "agent:first-run",
            "scope": "tool:demo.echo",
            "expires_at": "2026-06-10T00:05:00Z",
            "issuer": capability_issuer
        }),
        &capability_key,
    );
    let guard_decision_bytes = signed_json_bytes(
        json!({
            "schema": "chio.guard.decision.v1",
            "id": "guard-decision",
            "capability_id": "cap-tool-read-demo",
            "policy_sha256": policy_digest,
            "decision": "allow",
            "request_sha256": request_digest,
            "response_sha256": response_digest,
            "guard_key": guard_key.public_key().to_hex()
        }),
        &guard_key,
    );
    let receipt_bytes = signed_json_bytes(
        json!({
            "schema": "chio.receipt.v1",
            "receipt_id": "receipt-minimal-allow",
            "capability_id": "cap-tool-read-demo",
            "guard_decision_id": "guard-decision",
            "policy_digest": policy_digest,
            "request_digest": request_digest,
            "response_digest": response_digest,
            "terminal_status": "allowed_executed",
            "kernel_key": receipt_key.public_key().to_hex()
        }),
        &receipt_key,
    );
    let trust_root_bytes = signed_json_bytes(
        json!({
            "schema": "chio.trust.root.v1",
            "id": "trust-root",
            "root_id": "trust-root-first-run",
            "authority": trust_root_authority,
            "roots": [
                {"subject": capability_issuer},
                {"subject": guard_key.public_key().to_hex()},
                {"subject": receipt_key.public_key().to_hex()}
            ]
        }),
        &trust_root_key,
    );
    BTreeMap::from([
        ("capability-proof.json".to_string(), capability_bytes),
        ("guard-decision.json".to_string(), guard_decision_bytes),
        ("kernel-receipt.json".to_string(), receipt_bytes),
        ("policy.json".to_string(), policy_bytes),
        ("request-digest.json".to_string(), request_bytes),
        ("response-digest.json".to_string(), response_bytes),
        ("trust-root.json".to_string(), trust_root_bytes),
        (
            "verifier-policy.json".to_string(),
            valid_verifier_policy_bytes().to_vec(),
        ),
        (
            "claim-set.json".to_string(),
            valid_claim_set_bytes().to_vec(),
        ),
    ])
}

fn governed_action_trusted_root_keys() -> Vec<chio_core_types::PublicKey> {
    vec![Keypair::from_seed(&[54u8; 32]).public_key()]
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
                "id": digest("capability-proof.json"),
                "schema": "chio.capability.proof.v1",
                "path": "capability-proof.json",
                "sha256": digest("capability-proof.json"),
                "role": "capability"
            },
            {
                "id": digest("guard-decision.json"),
                "schema": "chio.guard.decision.v1",
                "path": "guard-decision.json",
                "sha256": digest("guard-decision.json"),
                "role": "guard-decision"
            },
            {
                "id": digest("kernel-receipt.json"),
                "schema": "chio.receipt.v1",
                "path": "kernel-receipt.json",
                "sha256": digest("kernel-receipt.json"),
                "role": "receipt"
            },
            {
                "id": digest("policy.json"),
                "schema": "chio.policy.bundle.v1",
                "path": "policy.json",
                "sha256": digest("policy.json"),
                "role": "policy"
            },
            {
                "id": digest("request-digest.json"),
                "schema": "chio.request.digest.v1",
                "path": "request-digest.json",
                "sha256": digest("request-digest.json"),
                "role": "request"
            },
            {
                "id": digest("response-digest.json"),
                "schema": "chio.response.digest.v1",
                "path": "response-digest.json",
                "sha256": digest("response-digest.json"),
                "role": "response"
            },
            {
                "id": digest("trust-root.json"),
                "schema": "chio.trust.root.v1",
                "path": "trust-root.json",
                "sha256": digest("trust-root.json"),
                "role": "trust-root"
            },
            {
                "id": digest("claim-set.json"),
                "schema": "chio.transaction.claim-set.v1",
                "path": "claim-set.json",
                "sha256": digest("claim-set.json"),
                "role": "claim-set"
            },
            {
                "id": digest(verifier_policy_path),
                "schema": "chio.transaction.verifier-policy.v1",
                "path": verifier_policy_path,
                "sha256": digest(verifier_policy_path),
                "role": "verifier-policy"
            }
        ],
        "edges": [
            {
                "from": digest("capability-proof.json"),
                "to": digest("kernel-receipt.json"),
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest("guard-decision.json"),
                "to": digest("kernel-receipt.json"),
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest("policy.json"),
                "to": digest("guard-decision.json"),
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest("request-digest.json"),
                "to": digest("kernel-receipt.json"),
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest("response-digest.json"),
                "to": digest("kernel-receipt.json"),
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest("trust-root.json"),
                "to": digest("capability-proof.json"),
                "predicate": "authorizes",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest("claim-set.json"),
                "to": digest(verifier_policy_path),
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            },
            {
                "from": digest(verifier_policy_path),
                "to": digest("kernel-receipt.json"),
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

fn standalone_passport_for_artifact_bytes(
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
) -> chio_transaction_passport::TransactionPassport {
    let keypair = Keypair::from_seed(&[54u8; 32]);
    let mut passport = passport_for_artifact_bytes(evidence_graph_bytes, verifier_policy_bytes);
    passport.issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    passport.signature = chio_transaction_passport::sign_transaction_passport(&passport, &keypair)
        .test_expect("standalone transaction passport signs with pinned root");
    passport
}

#[test]
fn transaction_passport_accepts_minimal_schema_shape() {
    let passport = valid_minimal_passport();

    chio_transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect("valid minimal passport shape should pass");
}

#[test]
fn transaction_passport_rejects_expired_validity_window() {
    let passport: chio_transaction_passport::TransactionPassport = serde_json::from_value(json!({
        "schema": "chio.transaction-passport.v1",
        "id": "passport-minimal-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "not_before": "2026-06-10T00:00:00Z",
        "expires_at": "2026-06-11T00:00:00Z",
        "issuer": format!("did:chio:{}", Keypair::from_seed(&[7u8; 32]).public_key().to_hex()),
        "evidence_graph_sha256": "0".repeat(64),
        "evidence_graph_path": "evidence-graph.json",
        "claim_set_sha256": sha256_hex(valid_claim_set_bytes()),
        "claim_set_path": "claim-set.json",
        "verifier_policy_sha256": "1".repeat(64),
        "verifier_policy_path": "verifier-policy.json",
        "signature": "00".repeat(64)
    }))
    .test_expect("passport with optional validity window parses");

    let now = chrono::DateTime::parse_from_rfc3339("2026-06-12T00:00:00Z")
        .test_expect("now timestamp parses")
        .with_timezone(&chrono::Utc);
    let error = chio_transaction_passport::verify_minimal_passport_schema_at(&passport, now)
        .test_expect_err("expired passport must fail closed");

    assert!(error.to_string().contains("transaction passport expired"));
}

#[test]
fn transaction_passport_rejects_unsigned_root_json() {
    let unsigned_passport = json!({
        "schema": "chio.transaction-passport.v1",
        "id": "passport-minimal-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "evidence_graph_sha256": "0".repeat(64),
        "evidence_graph_path": "evidence-graph.json",
        "verifier_policy_sha256": "1".repeat(64),
        "verifier_policy_path": "verifier-policy.json"
    });

    let error = match serde_json::from_value::<chio_transaction_passport::TransactionPassport>(
        unsigned_passport,
    ) {
        Ok(passport) => panic!("unsigned transaction passport parsed unexpectedly: {passport:#?}"),
        Err(error) => error,
    };

    assert!(
        error.to_string().contains("missing field `issuer`")
            || error.to_string().contains("missing field `signature`")
    );
}

#[test]
fn transaction_passport_rejects_root_without_claim_set_binding() {
    let unbound_passport = json!({
        "schema": "chio.transaction-passport.v1",
        "id": "passport-minimal-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "issuer": format!("did:chio:{}", Keypair::from_seed(&[7u8; 32]).public_key().to_hex()),
        "evidence_graph_sha256": "0".repeat(64),
        "evidence_graph_path": "evidence-graph.json",
        "verifier_policy_sha256": "1".repeat(64),
        "verifier_policy_path": "verifier-policy.json",
        "signature": "00".repeat(64)
    });

    let error = match serde_json::from_value::<chio_transaction_passport::TransactionPassport>(
        unbound_passport,
    ) {
        Ok(passport) => {
            panic!("transaction passport without claim set parsed unexpectedly: {passport:#?}")
        }
        Err(error) => error,
    };

    assert!(error
        .to_string()
        .contains("missing field `claim_set_sha256`"));
}

#[test]
fn transaction_passport_accepts_signed_root() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[7u8; 32]);
    let passport = signed_minimal_passport(&keypair)?;

    chio_transaction_passport::verify_transaction_passport_signature(
        &passport,
        &[keypair.public_key()],
    )?;

    Ok(())
}

#[test]
fn transaction_passport_rejects_tampered_signed_root() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[7u8; 32]);
    let mut passport = signed_minimal_passport(&keypair)?;
    passport.evidence_graph_sha256 = "f".repeat(64);

    let error = chio_transaction_passport::verify_transaction_passport_signature(
        &passport,
        &[keypair.public_key()],
    )
    .test_expect_err("tampered passport root must fail");
    assert!(error
        .to_string()
        .contains("transaction passport signature invalid"));
    Ok(())
}

#[test]
fn transaction_passport_rejects_untrusted_signed_root() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[7u8; 32]);
    let untrusted_keypair = Keypair::from_seed(&[8u8; 32]);
    let passport = signed_minimal_passport(&keypair)?;

    let error = chio_transaction_passport::verify_transaction_passport_signature(
        &passport,
        &[untrusted_keypair.public_key()],
    )
    .test_expect_err("passport signed by untrusted key must fail");
    assert!(error
        .to_string()
        .contains("transaction passport signer is not trusted"));
    Ok(())
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
    let evidence_graph_bytes = br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-duplicate-node","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"},{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.receipt.v1","path":"receipt.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"receipt"}],"edges":[]}"#;

    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(error
        .to_string()
        .contains("duplicate evidence graph node id"));
}

#[test]
fn transaction_passport_rejects_unresolved_evidence_graph_edge_refs() {
    let evidence_graph_bytes = br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-dangling-edge","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"}],"edges":[{"from":"missing-receipt","to":"1111111111111111111111111111111111111111111111111111111111111111","predicate":"binds","evidence_class":"digest-bound-reference"}]}"#;

    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(error
        .to_string()
        .contains("unknown evidence graph edge source"));
}

#[test]
fn transaction_passport_rejects_cyclic_evidence_graph() {
    let evidence_graph_bytes = br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-cycle","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.transaction.verifier-policy.v1","path":"verifier-policy.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"verifier-policy"},{"id":"2222222222222222222222222222222222222222222222222222222222222222","schema":"chio.receipt.v1","path":"receipt.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","role":"receipt"}],"edges":[{"from":"1111111111111111111111111111111111111111111111111111111111111111","to":"2222222222222222222222222222222222222222222222222222222222222222","predicate":"binds","evidence_class":"digest-bound-reference"},{"from":"2222222222222222222222222222222222222222222222222222222222222222","to":"1111111111111111111111111111111111111111111111111111111111111111","predicate":"binds","evidence_class":"digest-bound-reference"}]}"#;

    let error = passport_error_for_evidence_graph(evidence_graph_bytes);

    assert!(error.to_string().contains("cyclic evidence graph"));
}

#[test]
fn transaction_evidence_graph_rejects_advisory_authority_predicates() {
    for predicate in ["authorizes", "executes", "leases", "attenuates", "settles"] {
        let evidence_graph_bytes = format!(
            r#"{{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-advisory-{predicate}","issued_at":"2026-06-10T00:00:00Z","nodes":[{{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.capability.proof.v1","path":"capability.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"capability"}},{{"id":"2222222222222222222222222222222222222222222222222222222222222222","schema":"chio.receipt.v1","path":"receipt.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","role":"receipt"}}],"edges":[{{"from":"1111111111111111111111111111111111111111111111111111111111111111","to":"2222222222222222222222222222222222222222222222222222222222222222","predicate":"{predicate}","evidence_class":"advisory-observation"}}]}}"#
        );

        let error = chio_transaction_passport::validate_transaction_evidence_graph(
            evidence_graph_bytes.as_bytes(),
        )
        .test_expect_err("public evidence graph validator must reject advisory authority edges");

        assert!(
            error
                .to_string()
                .contains("advisory evidence cannot satisfy authority edge"),
            "{predicate}: {error}"
        );
    }
}

#[test]
fn transaction_evidence_graph_rejects_advisory_authority_endpoint() {
    let evidence_graph_bytes = br#"{"schema":"chio.transaction.evidence-graph.v1","id":"evidence-graph-advisory-node","issued_at":"2026-06-10T00:00:00Z","nodes":[{"id":"1111111111111111111111111111111111111111111111111111111111111111","schema":"chio.external.observation.v1","path":"advisory.json","sha256":"1111111111111111111111111111111111111111111111111111111111111111","role":"advisory-observation"},{"id":"2222222222222222222222222222222222222222222222222222222222222222","schema":"chio.receipt.v1","path":"receipt.json","sha256":"2222222222222222222222222222222222222222222222222222222222222222","role":"receipt"}],"edges":[{"from":"1111111111111111111111111111111111111111111111111111111111111111","to":"2222222222222222222222222222222222222222222222222222222222222222","predicate":"authorizes","evidence_class":"digest-bound-reference"}]}"#;

    let error =
        chio_transaction_passport::validate_transaction_evidence_graph(evidence_graph_bytes)
            .test_expect_err(
                "public evidence graph validator must reject advisory authority nodes",
            );

    assert!(
        error
            .to_string()
            .contains("advisory evidence cannot satisfy authority edge"),
        "{error}"
    );
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
    let passport =
        standalone_passport_for_artifact_bytes(evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        evidence_graph_bytes,
        verifier_policy_bytes,
        &BTreeMap::new(),
        &governed_action_trusted_root_keys(),
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
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("standalone minimal passport should accept governed action evidence");

    assert!(report.accepted);
    assert_eq!(report.state, "verified");
    assert_eq!(report.failure_code, None);
    assert_eq!(
        report.verified_claims,
        vec!["claim.transaction.passport_root_verified".to_string()]
    );
    assert_eq!(report.claim_results.len(), 1);
    assert_eq!(
        report.claim_results[0].claim_id,
        "claim.transaction.passport_root_verified"
    );
    assert_eq!(report.claim_results[0].status, "verified");
}

#[test]
fn standalone_minimal_passport_preserves_nonbinary_claim_result_statuses() {
    let mut artifacts = governed_action_artifacts();
    let claim_set_bytes = serde_json::to_vec(&json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-status-inventory",
        "issued_at": "2026-06-10T00:00:00Z",
        "claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "status": "verified",
                "required_evidence": ["transaction-passport.json", "evidence-graph.json", "verifier-policy.json"],
                "evidence_refs": ["transaction-passport.json", "evidence-graph.json", "verifier-policy.json"],
                "verifier_module": "chio-transaction-passport::minimal"
            },
            {
                "claim_id": "claim.transaction.settlement_finality_verified",
                "status": "omitted",
                "required_evidence": ["settlement-proof-bundle.json"],
                "evidence_refs": [],
                "verifier_module": "chio-transaction-passport::minimal"
            },
            {
                "claim_id": "claim.external.vc_wallet_native_authority",
                "status": "unsupported",
                "required_evidence": ["external-projection-manifest.json"],
                "evidence_refs": [],
                "verifier_module": "chio-agent-web-interop"
            },
            {
                "claim_id": "claim.transaction.buyer_review_rejected",
                "status": "failed",
                "required_evidence": ["buyer-review.json"],
                "evidence_refs": ["buyer-review.json"],
                "failure_reason": "buyer review rejected by verifier policy",
                "verifier_module": "chio-transaction-passport::minimal"
            }
        ]
    }))
    .test_expect("claim set serializes");
    artifacts.insert("claim-set.json".to_string(), claim_set_bytes.clone());
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);
    passport.claim_set_sha256 = sha256_hex(&claim_set_bytes);
    passport.signature = chio_transaction_passport::sign_transaction_passport(
        &passport,
        &Keypair::from_seed(&[54u8; 32]),
    )
    .test_expect("standalone transaction passport resigns");

    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("standalone verifier should preserve claim result statuses");

    let statuses: BTreeMap<String, String> = report
        .claim_results
        .iter()
        .map(|result| (result.claim_id.clone(), result.status.clone()))
        .collect();
    assert_eq!(
        statuses.get("claim.transaction.passport_root_verified"),
        Some(&"verified".to_string())
    );
    assert_eq!(
        statuses.get("claim.transaction.settlement_finality_verified"),
        Some(&"omitted".to_string())
    );
    assert_eq!(
        statuses.get("claim.external.vc_wallet_native_authority"),
        Some(&"unsupported".to_string())
    );
    assert_eq!(
        statuses.get("claim.transaction.buyer_review_rejected"),
        Some(&"failed".to_string())
    );
    assert_eq!(
        report.verified_claims,
        vec!["claim.transaction.passport_root_verified".to_string()]
    );
}

#[test]
fn standalone_minimal_passport_accepts_verifier_policy_as_policy_digest_anchor() {
    let guard_key = Keypair::from_seed(&[52u8; 32]);
    let receipt_key = Keypair::from_seed(&[53u8; 32]);
    let mut artifacts = governed_action_artifacts();
    let old_policy_digest = sha256_hex(
        artifacts
            .get("policy.json")
            .test_expect("legacy policy artifact exists"),
    );
    let verifier_policy_digest = sha256_hex(valid_verifier_policy_bytes());
    artifacts.insert(
        "guard-decision.json".to_string(),
        signed_json_bytes(
            json!({
                "schema": "chio.guard.decision.v1",
                "id": "guard-decision",
                "capability_id": "cap-tool-read-demo",
                "policy_sha256": verifier_policy_digest,
                "decision": "allow",
                "request_sha256": "a".repeat(64),
                "response_sha256": "b".repeat(64),
                "guard_key": guard_key.public_key().to_hex()
            }),
            &guard_key,
        ),
    );
    artifacts.insert(
        "kernel-receipt.json".to_string(),
        signed_json_bytes(
            json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-minimal-allow",
                "capability_id": "cap-tool-read-demo",
                "guard_decision_id": "guard-decision",
                "policy_digest": verifier_policy_digest,
                "request_digest": "a".repeat(64),
                "response_digest": "b".repeat(64),
                "terminal_status": "allowed_executed",
                "kernel_key": receipt_key.public_key().to_hex()
            }),
            &receipt_key,
        ),
    );
    let mut evidence_graph: Value =
        serde_json::from_slice(&governed_action_evidence_graph_bytes(&artifacts))
            .test_expect("governed action evidence graph parses");
    evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("governed action evidence graph has nodes")
        .retain(|node| node["path"] != "policy.json");
    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("governed action evidence graph has edges");
    for edge in edges {
        if edge["from"] == old_policy_digest {
            edge["from"] = Value::String(verifier_policy_digest.clone());
        }
    }
    artifacts.remove("policy.json");
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("evidence graph serializes");
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("verifier policy can anchor governed policy digests");

    assert!(report.accepted);
}

#[test]
fn standalone_minimal_passport_emits_all_registered_transaction_claims() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_all_standalone_transaction_claims_bytes();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let claim_set_bytes = claim_set_with_all_standalone_transaction_claims_bytes();
    artifacts.insert("claim-set.json".to_string(), claim_set_bytes.clone());
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);
    passport.claim_set_sha256 = sha256_hex(&claim_set_bytes);
    passport.signature = chio_transaction_passport::sign_transaction_passport(
        &passport,
        &Keypair::from_seed(&[54u8; 32]),
    )
    .test_expect("standalone transaction passport resigns");

    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("standalone verifier should emit all registered transaction claims");

    for claim in all_standalone_transaction_claims() {
        assert!(
            report.verified_claims.contains(&claim.to_string()),
            "missing verified claim {claim}"
        );
    }
    assert_eq!(
        report.claim_results.len(),
        all_standalone_transaction_claims().len()
    );
}

#[test]
fn root_claim_set_rejects_required_risk_claim_without_external_verifier() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_risk_claim_bytes();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let claim_set_bytes = claim_set_with_risk_claim_bytes();
    let claim_set_sha256 = sha256_hex(&claim_set_bytes);
    artifacts.insert("claim-set.json".to_string(), claim_set_bytes);
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);
    passport.claim_set_sha256 = claim_set_sha256;
    passport.signature = chio_transaction_passport::sign_transaction_passport(
        &passport,
        &Keypair::from_seed(&[54u8; 32]),
    )
    .test_expect("standalone transaction passport re-signs with risk claim set");

    let error = chio_transaction_passport::verify_passport_root_and_claim_set_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("risk claims must not be satisfied by claim-set self-report alone");

    assert!(
        error
            .to_string()
            .contains("required risk claim not verified by comptroller"),
        "{error}"
    );
}

#[test]
fn root_claim_set_accepts_required_risk_claim_after_external_verifier() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_risk_claim_bytes();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let claim_set_bytes = claim_set_with_risk_claim_bytes();
    let claim_set_sha256 = sha256_hex(&claim_set_bytes);
    artifacts.insert("claim-set.json".to_string(), claim_set_bytes);
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);
    passport.claim_set_sha256 = claim_set_sha256;
    passport.signature = chio_transaction_passport::sign_transaction_passport(
        &passport,
        &Keypair::from_seed(&[54u8; 32]),
    )
    .test_expect("standalone transaction passport re-signs with risk claim set");
    let verified_claims = vec!["claim.risk.comptroller_report_bound".to_string()];

    let report =
        chio_transaction_passport::verify_passport_root_and_claim_set_artifacts_with_external_claims(
            &passport,
            "transaction-passport.json".to_string(),
            &evidence_graph_bytes,
            &verifier_policy_bytes,
            &artifacts,
            &governed_action_trusted_root_keys(),
            &verified_claims,
        )
        .test_expect("risk claim should pass after comptroller verification");

    assert!(report.accepted);
    assert!(report
        .verified_claims
        .contains(&"claim.risk.comptroller_report_bound".to_string()));
}

#[test]
fn standalone_minimal_passport_rejects_unsigned_omission_policy() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_omission_bytes();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("omitted policy claims must be signed into the passport");

    assert!(error
        .to_string()
        .contains("passport omission policy missing claim"));
}

#[test]
fn standalone_minimal_passport_accepts_signed_omission_policy() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_omission_bytes();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);
    passport.omission_policy = vec![chio_transaction_passport::TransactionOmissionPolicyEntry {
        claim_id: "claim.transaction.settlement_finality_verified".to_string(),
        status: "omitted_not_applicable".to_string(),
        reason: "offline minimal fixture has no settlement leg".to_string(),
    }];
    let keypair = Keypair::from_seed(&[54u8; 32]);
    passport.signature = chio_transaction_passport::sign_transaction_passport(&passport, &keypair)
        .test_expect("passport signs with omission policy");

    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("signed omission policy should satisfy omitted claims");

    assert!(report.accepted);
}

#[test]
fn standalone_minimal_passport_rejects_tampered_signed_omission_policy() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_omission_bytes();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);
    passport.omission_policy = vec![chio_transaction_passport::TransactionOmissionPolicyEntry {
        claim_id: "claim.transaction.settlement_finality_verified".to_string(),
        status: "omitted_not_applicable".to_string(),
        reason: "offline minimal fixture has no settlement leg".to_string(),
    }];
    let keypair = Keypair::from_seed(&[54u8; 32]);
    passport.signature = chio_transaction_passport::sign_transaction_passport(&passport, &keypair)
        .test_expect("passport signs with omission policy");
    passport.omission_policy[0].status = "omitted_no_join_path".to_string();

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("tampered omission policy must break the passport signature");

    assert!(error
        .to_string()
        .contains("transaction passport signature invalid"));
}

#[test]
fn standalone_minimal_passport_rejects_tampered_passport_signature() {
    let artifacts = governed_action_artifacts();
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let mut passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);
    passport.signature = "00".repeat(64);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("standalone minimal passport must verify the signed root");

    assert!(error
        .to_string()
        .contains("transaction passport signature invalid"));
}

#[test]
fn standalone_minimal_passport_rejects_request_response_wrapper_digest_binding() {
    let artifacts = governed_action_artifacts_bound_to_wrapper_digest();
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("request and response bindings must use declared payload digests");

    assert!(
        error
            .to_string()
            .contains("receipt request digest mismatch"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_unpinned_trust_root_signer() {
    let artifacts = governed_action_artifacts();
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &[],
    )
    .test_expect_err("standalone minimal passport must require pinned transaction roots");

    assert!(error
        .to_string()
        .contains("trusted transaction root keys missing"));
}

#[test]
fn standalone_minimal_passport_rejects_forged_governed_action_signatures() {
    for (artifact_path, expected_error) in [
        (
            "capability-proof.json",
            "capability proof signature invalid",
        ),
        ("trust-root.json", "trust root signature invalid"),
        ("guard-decision.json", "guard decision signature invalid"),
        ("kernel-receipt.json", "receipt signature invalid"),
    ] {
        let mut artifacts = governed_action_artifacts();
        let mut artifact: serde_json::Value = serde_json::from_slice(
            artifacts
                .get(artifact_path)
                .test_expect("governed action artifact exists"),
        )
        .test_expect("governed action artifact parses");
        artifact["signature"] = serde_json::Value::String("sig-forged".to_string());
        artifacts.insert(
            artifact_path.to_string(),
            serde_json::to_vec(&artifact).test_expect("governed action artifact serializes"),
        );
        let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
        let verifier_policy_bytes = valid_verifier_policy_bytes();
        let passport =
            standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

        let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
            &passport,
            "transaction-passport.json".to_string(),
            &evidence_graph_bytes,
            verifier_policy_bytes,
            &artifacts,
            &governed_action_trusted_root_keys(),
        )
        .test_expect_err("standalone minimal passport must reject forged signatures");

        assert!(
            error.to_string().contains(expected_error),
            "{artifact_path} should fail with {expected_error}, got {error}"
        );
    }
}

#[test]
fn standalone_minimal_passport_rejects_evidence_node_id_digest_mismatch() {
    let artifacts = governed_action_artifacts();
    let mut evidence_graph: Value =
        serde_json::from_slice(&governed_action_evidence_graph_bytes(&artifacts))
            .test_expect("governed action evidence graph parses");
    let nodes = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("governed action evidence graph has nodes");
    let capability_node = nodes
        .iter_mut()
        .find(|node| node["path"] == "capability-proof.json")
        .test_expect("capability node exists");
    let original_id = capability_node["id"]
        .as_str()
        .test_expect("capability node id")
        .to_string();
    capability_node["id"] = Value::String("capability-proof".to_string());
    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("governed action evidence graph has edges");
    for edge in edges {
        if edge["from"] == original_id {
            edge["from"] = Value::String("capability-proof".to_string());
        }
        if edge["to"] == original_id {
            edge["to"] = Value::String("capability-proof".to_string());
        }
    }

    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("evidence graph serializes");
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("standalone minimal passport must reject non-content evidence node id");

    assert!(
        error
            .to_string()
            .contains("evidence graph node id digest mismatch"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_self_declared_guard_and_kernel_keys() {
    for (artifact_path, key_field, key_seed, expected_error) in [
        (
            "guard-decision.json",
            "guard_key",
            91_u8,
            "guard decision signer is not authorized",
        ),
        (
            "kernel-receipt.json",
            "kernel_key",
            92_u8,
            "receipt signer is not authorized",
        ),
    ] {
        let mut artifacts = governed_action_artifacts();
        replace_signed_artifact_key(
            &mut artifacts,
            artifact_path,
            key_field,
            &Keypair::from_seed(&[key_seed; 32]),
        );
        let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
        let verifier_policy_bytes = valid_verifier_policy_bytes();
        let passport =
            standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

        let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
            &passport,
            "transaction-passport.json".to_string(),
            &evidence_graph_bytes,
            verifier_policy_bytes,
            &artifacts,
            &governed_action_trusted_root_keys(),
        )
        .test_expect_err("standalone minimal passport must reject self-declared signer keys");

        assert!(
            error.to_string().contains(expected_error),
            "{artifact_path} should fail with {expected_error}, got {error}"
        );
    }
}

#[test]
fn standalone_minimal_passport_rejects_advisory_authority_edge() {
    let artifacts = governed_action_artifacts();
    let mut evidence_graph: Value =
        serde_json::from_slice(&governed_action_evidence_graph_bytes(&artifacts))
            .test_expect("governed action evidence graph parses");
    let nodes = evidence_graph["nodes"]
        .as_array()
        .test_expect("governed action evidence graph has nodes");
    let capability_node_id = nodes
        .iter()
        .find(|node| node["path"] == "capability-proof.json")
        .and_then(|node| node["id"].as_str())
        .test_expect("capability node id")
        .to_string();
    let receipt_node_id = nodes
        .iter()
        .find(|node| node["path"] == "kernel-receipt.json")
        .and_then(|node| node["id"].as_str())
        .test_expect("receipt node id")
        .to_string();
    let edges = evidence_graph["edges"]
        .as_array_mut()
        .test_expect("governed action evidence graph has edges");
    let authorizing_edge = edges
        .iter_mut()
        .find(|edge| {
            edge["from"] == capability_node_id
                && edge["to"] == receipt_node_id
                && edge["predicate"] == "authorizes"
        })
        .test_expect("capability authorizes receipt edge exists");
    authorizing_edge["evidence_class"] = Value::String("advisory-observation".to_string());

    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("evidence graph serializes");
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("standalone minimal passport must reject advisory authority evidence");

    assert!(
        error
            .to_string()
            .contains("advisory evidence cannot satisfy authority edge"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_unregistered_transaction_claim() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = br#"{"schema":"chio.transaction.verifier-policy.v1","id":"verifier-policy-minimal-invalid-claim","issued_at":"2026-06-10T00:00:00Z","required_claims":["claim.transaction.not_real"],"omitted_claims":[]}"#.to_vec();
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("standalone minimal passport must reject unregistered transaction claim");

    assert!(error.to_string().contains(
        "standalone transaction verifier cannot satisfy required claim: claim.transaction.not_real"
    ));
}

#[test]
fn standalone_minimal_passport_rejects_policy_disallowed_issuer() {
    let mut artifacts = governed_action_artifacts();
    let allowed_key = Keypair::from_seed(&[72u8; 32]);
    let verifier_policy_bytes = verifier_policy_with_rich_gates(json!({
        "accepted_passport_issuers": [
            format!("did:chio:{}", allowed_key.public_key().to_hex())
        ]
    }));
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("verifier policy issuer allowlist must fail closed");

    assert!(
        error
            .to_string()
            .contains("passport issuer not accepted by verifier policy"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_missing_policy_required_role() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_rich_gates(json!({
        "required_evidence_roles": ["public-settlement-proof-bundle"]
    }));
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("verifier policy required evidence role must fail closed");

    assert!(
        error.to_string().contains(
            "missing verifier policy required evidence role: public-settlement-proof-bundle"
        ),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_policy_transparency_state_mismatch() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_rich_gates(json!({
        "accepted_transparency_states": ["trust_anchored"]
    }));
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("verifier policy transparency state must fail closed");

    assert!(
        error
            .to_string()
            .contains("transparency state not accepted by verifier policy: not_present"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_report_surfaces_transparency_state() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_rich_gates(json!({
        "accepted_transparency_states": ["not_present"]
    }));
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let report = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("verifier policy accepted transparency state passes");

    assert_eq!(report.transparency_state, "not_present");
    let report_json = serde_json::to_value(&report).test_expect("report serializes");
    assert_eq!(report_json["transparencyState"], "not_present");
}

#[test]
fn root_claim_set_rejects_policy_required_commerce_state_without_claim() {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_rich_gates(json!({
        "required_commerce_states": ["settled"]
    }));
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, &verifier_policy_bytes);

    let error = chio_transaction_passport::verify_passport_root_and_claim_set_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("commerce-state policy gate must require settlement claim");

    assert!(
        error.to_string().contains(
            "claim set missing required claim: claim.commerce.settlement_lifecycle_bound"
        ),
        "{error}"
    );
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
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
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
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("standalone minimal passport must reject stale capability evidence");

    assert!(error
        .to_string()
        .contains("capability proof expired before evidence graph issuance"));
}

#[test]
fn standalone_minimal_passport_rejects_future_capability_not_before() {
    let mut artifacts = governed_action_artifacts();
    let mut capability: serde_json::Value = serde_json::from_slice(
        artifacts
            .get("capability-proof.json")
            .test_expect("capability artifact exists"),
    )
    .test_expect("capability artifact parses");
    capability["not_before"] = serde_json::Value::String("2026-06-10T00:00:01Z".to_string());
    artifacts.insert(
        "capability-proof.json".to_string(),
        serde_json::to_vec(&capability).test_expect("capability artifact serializes"),
    );
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("standalone minimal passport must reject future capability activation");

    assert!(error
        .to_string()
        .contains("capability proof not valid at evidence graph issuance"));
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
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect("standalone minimal passport should accept packaged verifier policy path");
}

#[test]
fn runtime_receipt_totality_rejects_graph_receipt_without_artifact() {
    let mut bundle = load_runtime_security_fixture("terminal-denial");
    add_unavailable_runtime_receipt_node(&mut bundle);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("graph-listed terminal receipt must have artifact bytes");
    let error = error.to_string();

    assert!(
        error.contains("missing runtime artifact: missing-denial-receipt.json"),
        "{error}"
    );
}

#[test]
fn runtime_receipt_totality_rejects_unsigned_terminal_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_policy_required_claims(
        &mut bundle,
        vec!["claim.runtime.receipt_totality_complete"],
    );
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_runtime_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["policy_digest"] = Value::String(policy_digest);
        receipt["terminal_status"] = Value::String("denied_guard_request".to_string());
        receipt
            .as_object_mut()
            .test_expect("terminal receipt is object")
            .remove("execution_lease_ref");
        receipt
            .as_object_mut()
            .test_expect("terminal receipt is object")
            .remove("kernel_key");
        receipt
            .as_object_mut()
            .test_expect("terminal receipt is object")
            .remove("signature");
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("unsigned terminal receipt must fail closed");
    let error = error.to_string();

    assert!(
        error.contains("terminal receipt kernel_key must not be empty")
            || error.contains("missing field `kernel_key`"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_advisory_authorization_by_node_role() {
    let mut bundle = load_runtime_security_fixture("advisory-used-as-authorization");
    let advisory_bytes = serde_json::to_vec(&json!({
        "schema": "chio.runtime.observation.v1",
        "id": "external-advisory-observation"
    }))
    .test_expect("advisory observation serializes");
    let advisory_digest = sha256_hex(&advisory_bytes);
    bundle
        .artifacts
        .insert("advisory-observation.json".to_string(), advisory_bytes);
    update_runtime_graph_node_digest(&mut bundle, "advisory-observation.json", &advisory_digest);
    let advisory_node_id = runtime_graph_node_id(&bundle, "advisory-observation.json");
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    let edges = graph["edges"]
        .as_array_mut()
        .test_expect("runtime graph has edges");
    let advisory_edge = edges
        .iter_mut()
        .find(|edge| edge["from"] == advisory_node_id)
        .test_expect("advisory edge exists");
    advisory_edge["evidence_class"] = Value::String("digest-bound-reference".to_string());
    rebind_runtime_graph(&mut bundle, graph);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("advisory node role must not authorize runtime execution");
    let error = error.to_string();

    assert!(
        error.contains("advisory evidence cannot authorize runtime execution"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_evidence_node_id_digest_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    let mut graph: Value =
        serde_json::from_slice(&bundle.evidence_graph_bytes).test_expect("runtime graph parses");
    let nodes = graph["nodes"]
        .as_array_mut()
        .test_expect("runtime graph has nodes");
    let lease_node = nodes
        .iter_mut()
        .find(|node| node["path"] == "execution-lease.json")
        .test_expect("execution lease node exists");
    let original_id = lease_node["id"]
        .as_str()
        .test_expect("execution lease node id")
        .to_string();
    lease_node["id"] = Value::String("execution-lease".to_string());
    let edges = graph["edges"]
        .as_array_mut()
        .test_expect("runtime graph has edges");
    for edge in edges {
        if edge["from"] == original_id {
            edge["from"] = Value::String("execution-lease".to_string());
        }
        if edge["to"] == original_id {
            edge["to"] = Value::String("execution-lease".to_string());
        }
    }
    rebind_runtime_graph(&mut bundle, graph);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("runtime graph must reject non-content node id");
    let error = error.to_string();

    assert!(
        error.contains("evidence graph node id digest mismatch"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_advisory_runtime_authority_edge_predicates() {
    for predicate in ["leases", "attenuates", "settles"] {
        let mut bundle = load_runtime_security_fixture("advisory-used-as-authorization");
        update_runtime_policy_required_claims(
            &mut bundle,
            vec!["claim.runtime.advisory_not_used_as_authorization"],
        );
        let advisory_bytes = serde_json::to_vec(&json!({
            "schema": "chio.runtime.observation.v1",
            "id": "external-advisory-observation"
        }))
        .test_expect("advisory observation serializes");
        let advisory_digest = sha256_hex(&advisory_bytes);
        bundle
            .artifacts
            .insert("advisory-observation.json".to_string(), advisory_bytes);
        update_runtime_graph_node_digest(
            &mut bundle,
            "advisory-observation.json",
            &advisory_digest,
        );
        let advisory_node_id = runtime_graph_node_id(&bundle, "advisory-observation.json");
        let mut graph: Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
            .test_expect("runtime graph parses");
        let edges = graph["edges"]
            .as_array_mut()
            .test_expect("runtime graph has edges");
        let advisory_edge = edges
            .iter_mut()
            .find(|edge| edge["from"] == advisory_node_id)
            .test_expect("advisory edge exists");
        advisory_edge["predicate"] = Value::String(predicate.to_string());
        advisory_edge["evidence_class"] = Value::String("digest-bound-reference".to_string());
        rebind_runtime_graph(&mut bundle, graph);

        let error = verify_runtime_security_fixture(&bundle)
            .test_expect_err("advisory edge must not satisfy runtime authority");
        let error = error.to_string();

        assert!(
            error.contains("advisory evidence cannot authorize runtime execution"),
            "{predicate}: {error}"
        );
    }
}

#[test]
fn runtime_online_checks_run_for_tool_ack_requirement() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_policy_required_claims(&mut bundle, vec!["claim.runtime.tool_server_ack_bound"]);
    let policy_digest = bundle.passport.verifier_policy_sha256.clone();
    update_runtime_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["policy_digest"] = Value::String(policy_digest.clone());
        sign_runtime_lease_with_fixture_authority(lease);
    });
    update_runtime_artifact(&mut bundle, "route-plan-receipt.json", |route_plan| {
        route_plan["policyDigest"] = Value::String(policy_digest.clone());
        sign_runtime_route_plan_with_fixture_authority(route_plan);
    });
    update_runtime_artifact(&mut bundle, "allow-receipt.json", |receipt| {
        receipt["policy_digest"] = Value::String(policy_digest);
        sign_runtime_terminal_receipt_with_fixture_kernel(receipt);
    });

    let report = verify_runtime_security_fixture(&bundle)
        .test_expect("tool ack claim should run the online runtime verifier");

    assert!(report
        .verified_claims
        .contains(&"claim.runtime.tool_server_ack_bound".to_string()));
}

#[test]
fn runtime_security_rejects_execution_lease_without_route_plan_receipt() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease
            .as_object_mut()
            .test_expect("execution lease is object")
            .remove("route_plan_receipt_ref");
        sign_runtime_lease_with_fixture_authority(lease);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting execution lease must bind a route-plan receipt");
    let error = error.to_string();

    assert!(
        error.contains("execution lease route plan receipt missing"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_execution_lease_without_task_graph_binding() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    remove_runtime_graph_nodes_by_role(&mut bundle, "swarm-task-graph");
    bundle.artifacts.remove("task-graph.json");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting execution lease must bind a task graph");
    let error = error.to_string();

    assert!(
        error.contains("missing task graph for execution lease"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_execution_lease_without_budget_pool_binding() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    remove_runtime_graph_nodes_by_role(&mut bundle, "swarm-budget-pool");
    bundle.artifacts.remove("budget-pool.json");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting execution lease must bind a budget pool");
    let error = error.to_string();

    assert!(
        error.contains("missing budget pool for execution lease"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_overflowing_budget_allocation_total() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_artifact(&mut bundle, "budget-pool.json", |budget_pool| {
        let allocation = budget_pool["allocations"]
            .as_array_mut()
            .and_then(|allocations| allocations.first_mut())
            .test_expect("runtime fixture has a budget allocation");
        allocation["reservedUnits"] = Value::from(u64::MAX);
        allocation["activeUnits"] = Value::from(1_u64);
        allocation["maxUnits"] = Value::from(u64::MAX);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("overflowing budget allocation total must fail");
    let error = error.to_string();

    assert!(
        error.contains("execution lease budget allocation exceeds max units"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_execution_lease_without_join_receipt_binding() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    remove_runtime_graph_nodes_by_role(&mut bundle, "swarm-join-receipt");
    bundle.artifacts.remove("join-receipt.json");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting execution lease must bind a join receipt");
    let error = error.to_string();

    assert!(
        error.contains("missing join receipt for execution lease"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_tampered_join_receipt_signature() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_artifact(&mut bundle, "join-receipt.json", |join_receipt| {
        sign_runtime_join_receipt_with_fixture_authority(join_receipt);
        join_receipt["resultDigest"] = Value::String(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting execution lease must verify join receipt signature");
    let error = error.to_string();

    assert!(error.contains("join receipt signature invalid"), "{error}");
}

#[test]
fn runtime_security_rejects_untrusted_join_receipt_issuer() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    let attacker_key = Keypair::from_seed(&[91u8; 32]);
    let attacker_identity = format!("did:chio:{}", attacker_key.public_key().to_hex());
    update_runtime_artifact(&mut bundle, "join-receipt.json", |join_receipt| {
        join_receipt["issuer"] = Value::String(attacker_identity);
        join_receipt["signature"] =
            Value::String(sign_runtime_join_receipt(join_receipt, &attacker_key));
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("side-effecting execution lease must reject untrusted join issuer");
    let error = error.to_string();

    assert!(
        error.contains("join receipt issuer is not trusted"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_tool_ack_without_trusted_time_proof() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    remove_runtime_graph_nodes_by_role(&mut bundle, "trusted-time-proof");
    bundle.artifacts.remove("trusted-time-proof.json");

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("tool entry time must be bound by trusted time proof");
    let error = error.to_string();

    assert!(
        error.contains("missing trusted time proof for tool acknowledgement"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_trusted_time_after_lease_expiry() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_artifact(&mut bundle, "trusted-time-proof.json", |proof| {
        proof["observed_at"] = Value::String("2026-06-10T00:06:00Z".to_string());
        sign_runtime_trusted_time_with_fixture_authority(proof);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("trusted time proof must decide post-tool-entry expiry");
    let error = error.to_string();

    assert!(
        error.contains("trusted time proof outside execution lease"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_revocation_freshness_subject_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_artifact(&mut bundle, "revocation-freshness-proof.json", |proof| {
        proof["subject_capability_digest"] = Value::String("f".repeat(64));
        sign_runtime_revocation_freshness_with_fixture_oracle(proof);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("revocation freshness proof must bind the queried runtime subject");
    let error = error.to_string();

    assert!(
        error.contains("revocation freshness subject capability mismatch"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_revocation_freshness_ancestor_mismatch() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    update_runtime_artifact(&mut bundle, "revocation-freshness-proof.json", |proof| {
        proof["ancestor_capability_digest"] = Value::String("e".repeat(64));
        sign_runtime_revocation_freshness_with_fixture_oracle(proof);
    });

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("revocation freshness proof must bind the ancestor chain");
    let error = error.to_string();

    assert!(
        error.contains("revocation freshness ancestor capability mismatch"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_tampered_transaction_passport_signature() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    bundle.passport.signature = "00".repeat(64);

    let error = verify_runtime_security_fixture(&bundle)
        .test_expect_err("tampered transaction passport signature must fail");
    let error = error.to_string();

    assert!(
        error.contains("transaction passport signature invalid"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_missing_claim_set_artifact() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    bundle.artifacts.remove("claim-set.json");

    let error =
        verify_runtime_security_fixture(&bundle).test_expect_err("missing claim set must fail");
    let error = error.to_string();

    assert!(
        error.contains("missing evidence graph artifact: claim-set.json")
            || error.contains("missing runtime artifact: claim-set.json"),
        "{error}"
    );
}

#[test]
fn runtime_security_rejects_self_supplied_runtime_trust_root() {
    let mut bundle = load_runtime_security_fixture("valid-side-effecting-call");
    let attacker_key = Keypair::from_seed(&[91u8; 32]);
    let attacker_identity = format!("did:chio:{}", attacker_key.public_key().to_hex());

    update_runtime_artifact(&mut bundle, "execution-lease.json", |lease| {
        lease["issuer"] = Value::String(attacker_identity.clone());
        lease["signature"] = Value::String(sign_runtime_execution_lease(lease, &attacker_key));
    });
    update_runtime_artifact(&mut bundle, "trust-root.json", |trust_root| {
        trust_root["authority"] = Value::String(attacker_identity);
        trust_root["signature"] = Value::String(sign_runtime_trust_root(trust_root, &attacker_key));
    });

    let error = chio_transaction_passport::verify_runtime_security_claims_with_trust(
        &bundle,
        &chio_transaction_passport::RuntimeSecurityTrust {
            trusted_passport_signer_keys: transaction_trusted_root_keys(),
            trusted_root_signer_keys: runtime_trusted_root_keys(),
        },
    )
    .test_expect_err("self-supplied runtime trust root must fail");

    assert!(error
        .to_string()
        .contains("runtime trust root signer is not trusted"));
}

#[test]
fn standalone_minimal_passport_rejects_missing_governed_action_artifacts() {
    let mut artifacts = governed_action_artifacts();
    let evidence_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    artifacts.remove("kernel-receipt.json");
    let verifier_policy_bytes = valid_verifier_policy_bytes();
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
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
    let passport =
        standalone_passport_for_artifact_bytes(&evidence_graph_bytes, verifier_policy_bytes);

    let error = chio_transaction_passport::verify_standalone_minimal_passport_artifacts(
        &passport,
        "transaction-passport.json".to_string(),
        &evidence_graph_bytes,
        verifier_policy_bytes,
        &artifacts,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("evidence graph verifier policy node must match passport policy digest");

    assert!(error
        .to_string()
        .contains("verifier policy evidence graph digest mismatch"));
}

fn transparency_anchored_fixture(
    mutate_artifact: impl FnOnce(&mut Value),
) -> (BTreeMap<String, Vec<u8>>, Vec<u8>, Vec<u8>) {
    let mut artifacts = governed_action_artifacts();
    let verifier_policy_bytes = verifier_policy_with_rich_gates(json!({
        "accepted_transparency_states": ["trust_anchored"]
    }));
    artifacts.insert(
        "verifier-policy.json".to_string(),
        verifier_policy_bytes.clone(),
    );

    let subject_bytes = artifacts
        .get("kernel-receipt.json")
        .test_expect("receipt artifact exists")
        .clone();
    let subject_sha256 = sha256_hex(&subject_bytes);
    let leaf = chio_core_types::merkle::leaf_hash(&subject_bytes);
    let leaf_hex = format!("0x{}", leaf.to_hex());

    // The log kernel key is deliberately NOT the passport root key: an issuer
    // that signs the checkpoints anchoring its own evidence is self-attesting.
    let root_key = transparency_checkpoint_keypair();
    let checkpoint_chain_leaf = json!({
        "checkpoint_seq": 1,
        "batch_start_seq": 1,
        "batch_end_seq": 1,
        "merkle_root": leaf_hex
    });
    let chain_root = chio_core_types::merkle::leaf_hash(
        &chio_core_types::canonical_json_bytes(&checkpoint_chain_leaf)
            .test_expect("canonical checkpoint chain leaf"),
    );
    let statement_body = json!({
        "schema": "chio.checkpoint_statement.v2",
        "checkpoint_seq": 1,
        "batch_start_seq": 1,
        "batch_end_seq": 1,
        "tree_size": 1,
        "merkle_root": leaf_hex,
        "issued_at": 1_749_000_000u64,
        "kernel_key": root_key.public_key().to_hex(),
        "chain_root": format!("0x{}", chain_root.to_hex())
    });
    let statement_signature = root_key
        .sign(
            &chio_core_types::canonical_json_bytes(&statement_body)
                .test_expect("canonical statement body"),
        )
        .to_hex();

    let mut inclusion_artifact = json!({
        "schema": "chio.transparency.inclusion-proof.v2",
        "proof_id": "transparency-proof-governed-action",
        "log_id": "local-log-governed-action",
        "artifact_ref": subject_sha256,
        "root_hash": leaf_hex,
        "leaf_hash": leaf_hex,
        "tree_size": 1,
        "leaf_index": 0,
        "checkpoint": "local-log-governed-action:1",
        "inclusion_path": [],
        "verified_at": 1_749_000_000u64,
        "checkpoint_statement": {
            "body": statement_body,
            "signature": statement_signature
        }
    });
    mutate_artifact(&mut inclusion_artifact);
    let inclusion_schema = inclusion_artifact["schema"]
        .as_str()
        .test_expect("inclusion artifact schema")
        .to_string();
    artifacts.insert(
        "transparency-inclusion-proof.json".to_string(),
        serde_json::to_vec(&inclusion_artifact).test_expect("inclusion artifact serializes"),
    );

    let base_graph_bytes = governed_action_evidence_graph_bytes(&artifacts);
    let mut graph: Value =
        serde_json::from_slice(&base_graph_bytes).test_expect("governed action graph parses");
    let inclusion_digest = sha256_hex(
        artifacts
            .get("transparency-inclusion-proof.json")
            .test_expect("inclusion artifact exists"),
    );
    graph["nodes"]
        .as_array_mut()
        .test_expect("graph nodes are an array")
        .push(json!({
            "id": inclusion_digest,
            "schema": inclusion_schema,
            "path": "transparency-inclusion-proof.json",
            "sha256": inclusion_digest,
            "role": "transparency-inclusion-proof"
        }));
    let evidence_graph_bytes =
        serde_json::to_vec(&graph).test_expect("anchored evidence graph serializes");
    (artifacts, evidence_graph_bytes, verifier_policy_bytes)
}

fn transparency_checkpoint_keypair() -> Keypair {
    Keypair::from_seed(&[71u8; 32])
}

fn transparency_checkpoint_keys() -> Vec<chio_core_types::PublicKey> {
    vec![transparency_checkpoint_keypair().public_key()]
}

fn verify_standalone_anchored(
    artifacts: &BTreeMap<String, Vec<u8>>,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
) -> Result<
    chio_transaction_passport::TransactionVerifierReport,
    chio_transaction_passport::TransactionPassportError,
> {
    verify_standalone_anchored_with_checkpoint_keys(
        artifacts,
        evidence_graph_bytes,
        verifier_policy_bytes,
        &transparency_checkpoint_keys(),
    )
}

fn verify_standalone_anchored_with_checkpoint_keys(
    artifacts: &BTreeMap<String, Vec<u8>>,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    trusted_checkpoint_signer_keys: &[chio_core_types::PublicKey],
) -> Result<
    chio_transaction_passport::TransactionVerifierReport,
    chio_transaction_passport::TransactionPassportError,
> {
    let passport =
        standalone_passport_for_artifact_bytes(evidence_graph_bytes, verifier_policy_bytes);
    chio_transaction_passport::verify_standalone_minimal_passport_artifacts_with_transparency_anchors(
        &passport,
        "transaction-passport.json".to_string(),
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        chio_transaction_passport::TransactionTrustAnchors {
            passport_root_signers: &governed_action_trusted_root_keys(),
            checkpoint_signers: trusted_checkpoint_signer_keys,
        },
    )
}

#[test]
fn standalone_minimal_passport_promotes_verified_transparency_anchor() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});

    let report =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect("verified transparency anchor promotes");

    assert_eq!(report.transparency_state, "trust_anchored");
}

#[test]
fn standalone_minimal_passport_rejects_v2_anchor_without_checkpoint_statement() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let object = artifact
                .as_object_mut()
                .test_expect("inclusion artifact is an object");
            object.remove("checkpoint_statement");
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a v2 inclusion proof without its signed anchor must deny");

    assert!(
        error
            .to_string()
            .contains("v2 inclusion proof envelope is invalid"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_requires_the_complete_v2_inclusion_envelope() {
    for field in ["proof_id", "log_id", "checkpoint", "verified_at"] {
        let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
            transparency_anchored_fixture(|artifact| {
                artifact
                    .as_object_mut()
                    .test_expect("inclusion artifact is an object")
                    .remove(field);
            });

        let error =
            verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
                .test_expect_err("an incomplete v2 envelope must deny");
        assert!(
            error
                .to_string()
                .contains("v2 inclusion proof envelope is invalid"),
            "missing {field}: {error}"
        );
    }
}

#[test]
fn standalone_minimal_passport_rejects_unknown_v2_inclusion_envelope_fields() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["smuggled"] = json!("field");
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a field-smuggled v2 envelope must deny");
    assert!(
        error.to_string().contains("unknown field `smuggled`"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_keeps_registered_v1_proofs_at_preview() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["schema"] = json!("chio.transparency.inclusion-proof.v1");
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("registered v1 proof hashing must not qualify as an RFC 6962 anchor");

    assert!(
        error
            .to_string()
            .contains("transparency state not accepted by verifier policy: transparency_preview"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_transparency_anchor_from_untrusted_signer() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let rogue = Keypair::from_seed(&[99u8; 32]);
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body["kernel_key"] = json!(rogue.public_key().to_hex());
            let signature = rogue
                .sign(
                    &chio_core_types::canonical_json_bytes(&body)
                        .test_expect("canonical rogue statement body"),
                )
                .to_hex();
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a checkpoint signed outside the pinned key set must not promote");

    assert!(
        error
            .to_string()
            .contains("transparency state not accepted by verifier policy: transparency_preview"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_transparency_anchor_with_tampered_root() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["root_hash"] = json!(format!("0x{}", "0".repeat(64)));
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a root the checkpoint does not commit must not promote");

    assert!(
        error
            .to_string()
            .contains("inclusion proof does not target the committed checkpoint tree"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_transparency_anchor_with_unbound_subject() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["artifact_ref"] = json!("b".repeat(64));
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("an anchor not bound to a graph artifact must not promote");

    assert!(
        error
            .to_string()
            .contains("inclusion proof subject is not this transaction's receipt"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_checkpoint_keys_shared_with_passport_roots() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});

    let error = verify_standalone_anchored_with_checkpoint_keys(
        &artifacts,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("a passport root key must not double as a checkpoint signer");

    assert!(
        error.to_string().contains(
            "trusted checkpoint signer keys must be disjoint from passport root signer keys"
        ),
        "{error}"
    );
}

#[path = "transaction_passport/transparency_anchor_edge_tests.rs"]
mod transparency_anchor_edge_tests;
