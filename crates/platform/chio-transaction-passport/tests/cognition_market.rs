use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    build_status_non_inclusion_proof_input, compute_report_id, compute_status_epoch_id,
    FindingAuthorityKeyPolicy, FindingClaimedVerdict, FindingFacetKind, FindingFacetOutcome,
    FindingFacetResult, FindingPredicate, FindingRecipeEnvironment, FindingRecipePhase,
    FindingRecipePhaseKind, FindingReplayRecipeInput, FindingResourceCaps, FindingStatusEpoch,
    FindingStatusFreshnessPolicy, FindingStatusOperatorAuthorization, FindingStatusOperatorRole,
    FindingVerifierReport, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_STATUS_EPOCH_SCHEMA_V1,
    FINDING_STATUS_PROOF_INPUT_SCHEMA_V1, FINDING_STATUS_SIGNATURE_DOMAIN,
    FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
use chio_revocation_oracle::{
    finding_status_empty_leaf_hash, FindingStatusSparseMap, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};
use chio_transaction_passport::{
    sign_transaction_passport, verify_cognition_market_passport_artifacts,
    CognitionMarketProofTrust, TransactionPassport, COGNITION_MARKET_CLAIMS,
};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const FINDING_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RETRACTED_FINDING_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RETRACTION_INTENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GENERATED_AT: u64 = 1_750_000_000;
const CHECKED_AT: u64 = 1_750_000_030;
const GOLDEN_RELATIVE: &str = "fixtures/proof-room/finding/cognition-market-qualified-profile";

struct QualifiedBundle {
    passport: TransactionPassport,
    evidence_graph: Value,
    evidence_graph_bytes: Vec<u8>,
    verifier_policy_bytes: Vec<u8>,
    artifacts: BTreeMap<String, Vec<u8>>,
    trust: CognitionMarketProofTrust,
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(root) = manifest_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
    else {
        panic!("workspace root is parent of crates/platform/chio-transaction-passport");
    };
    root.to_path_buf()
}

fn root_keypair() -> Keypair {
    Keypair::from_seed(&[7_u8; 32])
}

fn verifier_keypair() -> Keypair {
    Keypair::from_seed(&[9_u8; 32])
}

fn status_keypair() -> Keypair {
    Keypair::from_seed(&[42_u8; 32])
}

fn status_authorization(keypair: &Keypair) -> FindingStatusOperatorAuthorization {
    FindingStatusOperatorAuthorization {
        role: FindingStatusOperatorRole::FindingStatusOperator,
        feed_id: "qualified-finding-status".to_string(),
        operator: FindingAuthorityKeyPolicy {
            authority_id: "qualified-status-operator".to_string(),
            key: keypair.public_key(),
            key_epoch: 1,
            valid_from: GENERATED_AT - 60,
            valid_until: GENERATED_AT + 600,
            rotation_policy_ref: "rotation/qualified-status-v1".to_string(),
            revocation_status_ref: "revocations/qualified-status-v1".to_string(),
        },
        revoked_from: None,
    }
}

fn status_proof_bytes() -> TestResult<Vec<u8>> {
    let keypair = status_keypair();
    let mut map = FindingStatusSparseMap::new();
    let root = map.insert(RETRACTED_FINDING_ID, RETRACTION_INTENT)?;
    let sparse = map.proof(FINDING_ID)?;
    let mut epoch = FindingStatusEpoch {
        schema: FINDING_STATUS_EPOCH_SCHEMA_V1.to_string(),
        status_epoch_id: String::new(),
        signature_domain: FINDING_STATUS_SIGNATURE_DOMAIN.to_string(),
        status_map_version: FINDING_STATUS_MAP_VERSION.to_string(),
        proof_semantics: FINDING_STATUS_PROOF_SEMANTICS.to_string(),
        feed_id: "qualified-finding-status".to_string(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch: root.map_epoch,
        operator_id: "qualified-status-operator".to_string(),
        operator_key: keypair.public_key(),
        operator_key_epoch: 1,
        root_hash: hex::encode(root.root_hash),
        tree_depth: FINDING_STATUS_SPARSE_DEPTH as u16,
        hash_algorithm: FINDING_STATUS_HASH_ALGORITHM.to_string(),
        key_hash_domain: FINDING_STATUS_KEY_HASH_DOMAIN.to_string(),
        empty_leaf_domain: FINDING_STATUS_EMPTY_LEAF_DOMAIN.to_string(),
        occupied_leaf_domain: FINDING_STATUS_OCCUPIED_LEAF_DOMAIN.to_string(),
        branch_domain: FINDING_STATUS_BRANCH_DOMAIN.to_string(),
        empty_leaf_hash: hex::encode(finding_status_empty_leaf_hash()),
        anchor_refs: vec!["anchor/qualified-finding-status/1".to_string()],
        generated_at: GENERATED_AT,
        valid_from: GENERATED_AT - 60,
        valid_until: GENERATED_AT + 600,
    };
    epoch.status_epoch_id = compute_status_epoch_id(&epoch)?;
    let signed = SignedExportEnvelope::sign(epoch, &keypair)?;
    let proof = build_status_non_inclusion_proof_input(&signed, FINDING_ID, &sparse, CHECKED_AT)?;
    Ok(canonical_json_bytes(&proof)?)
}

fn recipe_bytes(payload_suffix: &str) -> TestResult<Vec<u8>> {
    recipe_bytes_for_profile(payload_suffix, "23")
}

fn recipe_bytes_for_profile(
    payload_suffix: &str,
    verifier_profile_prefix: &str,
) -> TestResult<Vec<u8>> {
    let caps = FindingResourceCaps {
        max_recipe_bytes: 65_536,
        max_evidence_receipts: 8,
        max_runtime_secs: 600,
        max_memory_bytes: 1_073_741_824,
    };
    let environment = FindingRecipeEnvironment {
        runtime_image_sha256: "22".repeat(32),
        platform: "linux-amd64".to_string(),
        network_policy: "deny_all".to_string(),
        clock_policy: "fixed".to_string(),
        randomness_policy: "seeded".to_string(),
        locale: "C.UTF-8".to_string(),
        timezone: "UTC".to_string(),
    };
    let recipe = FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/baseline-fails-candidate-passes-v1".to_string(),
        verifier_profile_envelope_sha256: verifier_profile_prefix.repeat(32),
        context_sha256: "44".repeat(32),
        payload_sha256: format!("{payload_suffix}{}", "5".repeat(62)),
        runner_server: "qualified-replay-runner".to_string(),
        runner_tool: "replay_patch".to_string(),
        runner_manifest_sha256: "66".repeat(32),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: "77".repeat(32),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: "88".repeat(32),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: "99".repeat(32),
        environment,
        resource_bounds: caps,
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: "aa".repeat(32),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    };
    recipe.validate()?;
    Ok(canonical_json_bytes(&recipe)?)
}

fn report_bytes(recipe: &[u8], status: &[u8]) -> TestResult<Vec<u8>> {
    report_bytes_for_profile(recipe, status, "23")
}

fn report_bytes_for_profile(
    recipe: &[u8],
    status: &[u8],
    verifier_profile_prefix: &str,
) -> TestResult<Vec<u8>> {
    let verifier = verifier_keypair();
    let facets = FindingFacetKind::ALL
        .into_iter()
        .map(|facet| FindingFacetResult {
            facet,
            outcome: FindingFacetOutcome::Verified,
            reason: "independently verified for the bounded cognition-market profile".to_string(),
            evidence_refs: Vec::new(),
        })
        .collect();
    let mut report = FindingVerifierReport {
        schema: FINDING_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        report_id: String::new(),
        finding_id: FINDING_ID.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        verifier_profile_id: "12".repeat(32),
        verifier_profile_envelope_sha256: verifier_profile_prefix.repeat(32),
        verifier_implementation_id: "chio-finding-verifier/0.1-qualified".to_string(),
        resolved_evidence_bundle_sha256: "34".repeat(32),
        replay_recipe_input_sha256: Some(sha256_hex(recipe)),
        status_proof_input_sha256: Some(sha256_hex(status)),
        trust_root_snapshot_sha256: "45".repeat(32),
        resolver_policy_sha256: "56".repeat(32),
        trusted_time_input_sha256: "67".repeat(32),
        facets,
        backing_allocation_id: Some("78".repeat(32)),
        verifier_authority: verifier.public_key(),
        verifier_key_epoch: 1,
        evaluation_time: CHECKED_AT,
    };
    report.report_id = compute_report_id(&report)?;
    report.validate()?;
    let signed = SignedExportEnvelope::sign(report, &verifier)?;
    Ok(canonical_json_bytes(&signed)?)
}

fn claim_set_bytes(report_path: &str, recipe_path: &str, status_path: &str) -> TestResult<Vec<u8>> {
    let paths = [
        vec![report_path],
        vec![report_path, recipe_path],
        vec![report_path, status_path],
        vec![report_path],
    ];
    let claims = COGNITION_MARKET_CLAIMS
        .iter()
        .zip(paths)
        .map(|(claim_id, evidence)| {
            json!({
                "claim_id": claim_id,
                "status": "verified",
                "required_evidence": evidence,
                "evidence_refs": evidence,
                "verifier_module": "chio-finding-verifier"
            })
        })
        .collect::<Vec<_>>();
    Ok(canonical_json_bytes(&json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-cognition-market-qualified-profile",
        "issued_at": "2026-07-31T20:00:30Z",
        "claims": claims
    }))?)
}

fn verifier_policy_bytes() -> TestResult<Vec<u8>> {
    Ok(canonical_json_bytes(&json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "verifier-policy-cognition-market-qualified-profile",
        "issued_at": "2026-07-31T20:00:30Z",
        "required_claims": COGNITION_MARKET_CLAIMS,
        "omitted_claims": [],
        "required_evidence_roles": ["report", "advisory-observation"]
    }))?)
}

fn node(path: &str, role: &str, schema: &str, bytes: &[u8]) -> Value {
    let digest = sha256_hex(bytes);
    json!({
        "id": digest,
        "schema": schema,
        "path": path,
        "sha256": digest,
        "role": role
    })
}

fn build_bundle() -> TestResult<QualifiedBundle> {
    let recipe_path = "attachments/replay-recipe-input.json";
    let status_path = "attachments/status-proof-input.json";
    let report_path = "report.json";
    let recipe = recipe_bytes("55")?;
    let status = status_proof_bytes()?;
    let report = report_bytes(&recipe, &status)?;
    let claim_set = claim_set_bytes(report_path, recipe_path, status_path)?;
    let verifier_policy = verifier_policy_bytes()?;

    let report_id = sha256_hex(&report);
    let recipe_id = sha256_hex(&recipe);
    let status_id = sha256_hex(&status);
    let claim_set_id = sha256_hex(&claim_set);
    let policy_id = sha256_hex(&verifier_policy);
    let graph = json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "evidence-graph-cognition-market-qualified-profile",
        "issued_at": "2026-07-31T20:00:30Z",
        "nodes": [
            node("claim-set.json", "claim-set", "chio.transaction.claim-set.v1", &claim_set),
            node("verifier-policy.json", "verifier-policy", "chio.transaction.verifier-policy.v1", &verifier_policy),
            node(report_path, "report", FINDING_VERIFIER_REPORT_SCHEMA_V1, &report),
            node(recipe_path, "advisory-observation", FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, &recipe),
            node(status_path, "advisory-observation", FINDING_STATUS_PROOF_INPUT_SCHEMA_V1, &status)
        ],
        "edges": [
            {"from": claim_set_id, "to": policy_id, "predicate": "binds", "evidence_class": "digest-bound-reference"},
            {"from": claim_set_id, "to": report_id, "predicate": "binds", "evidence_class": "digest-bound-reference"},
            {"from": report_id, "to": recipe_id, "predicate": "binds", "evidence_class": "digest-bound-reference"},
            {"from": report_id, "to": status_id, "predicate": "binds", "evidence_class": "digest-bound-reference"}
        ]
    });
    let evidence_graph_bytes = canonical_json_bytes(&graph)?;
    let root = root_keypair();
    let mut passport = TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-cognition-market-qualified-profile".to_string(),
        issued_at: "2026-07-31T20:00:30Z".to_string(),
        not_before: None,
        expires_at: None,
        issuer: format!("did:chio:{}", root.public_key().to_hex()),
        evidence_graph_sha256: sha256_hex(&evidence_graph_bytes),
        evidence_graph_path: "evidence-graph.json".to_string(),
        claim_set_sha256: claim_set_id,
        claim_set_path: "claim-set.json".to_string(),
        verifier_policy_sha256: policy_id,
        verifier_policy_path: "verifier-policy.json".to_string(),
        omission_policy: Vec::new(),
        signature: String::new(),
    };
    passport.signature = sign_transaction_passport(&passport, &root)?;

    let artifacts = BTreeMap::from([
        ("claim-set.json".to_string(), claim_set),
        ("verifier-policy.json".to_string(), verifier_policy.clone()),
        (report_path.to_string(), report),
        (recipe_path.to_string(), recipe),
        (status_path.to_string(), status),
    ]);
    let status_keypair = status_keypair();
    let trust = CognitionMarketProofTrust {
        trusted_passport_signer_keys: vec![root.public_key()],
        finding_verifier_authority: verifier_keypair().public_key(),
        trusted_verifier_profile_envelope_sha256: "23".repeat(32),
        status_operator_authorization: status_authorization(&status_keypair),
        status_freshness: FindingStatusFreshnessPolicy {
            now: CHECKED_AT,
            max_epoch_age_secs: 60,
        },
    };
    Ok(QualifiedBundle {
        passport,
        evidence_graph: graph,
        evidence_graph_bytes,
        verifier_policy_bytes: verifier_policy,
        artifacts,
        trust,
    })
}

fn verify(bundle: &QualifiedBundle) -> TestResult {
    let report = verify_cognition_market_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trust,
    )?;
    assert!(report.accepted);
    for claim in COGNITION_MARKET_CLAIMS {
        assert!(report
            .verified_claims
            .iter()
            .any(|candidate| candidate == claim));
    }
    Ok(())
}

fn resign_graph(bundle: &mut QualifiedBundle) -> TestResult {
    bundle.evidence_graph_bytes = canonical_json_bytes(&bundle.evidence_graph)?;
    bundle.passport.evidence_graph_sha256 = sha256_hex(&bundle.evidence_graph_bytes);
    bundle.passport.signature = sign_transaction_passport(&bundle.passport, &root_keypair())?;
    Ok(())
}

fn replace_graph_artifact(
    bundle: &mut QualifiedBundle,
    path: &str,
    replacement: Vec<u8>,
) -> TestResult<String> {
    let old_id = sha256_hex(bundle.artifacts.get(path).ok_or("artifact missing")?);
    let replacement_id = sha256_hex(&replacement);
    bundle.artifacts.insert(path.to_string(), replacement);
    let node = bundle.evidence_graph["nodes"]
        .as_array_mut()
        .and_then(|nodes| {
            nodes
                .iter_mut()
                .find(|node| node.get("path").and_then(Value::as_str) == Some(path))
        })
        .ok_or("artifact node missing")?;
    node["id"] = Value::String(replacement_id.clone());
    node["sha256"] = Value::String(replacement_id.clone());
    for edge in bundle.evidence_graph["edges"]
        .as_array_mut()
        .ok_or("edges missing")?
    {
        if edge.get("from").and_then(Value::as_str) == Some(old_id.as_str()) {
            edge["from"] = Value::String(replacement_id.clone());
        }
        if edge.get("to").and_then(Value::as_str) == Some(old_id.as_str()) {
            edge["to"] = Value::String(replacement_id.clone());
        }
    }
    Ok(replacement_id)
}

#[test]
fn cognition_market_qualified_profile() -> TestResult {
    verify(&build_bundle()?)
}

#[test]
fn cognition_market_qualified_profile_preserves_verified_transaction_claims() -> TestResult {
    const TRANSACTION_CLAIM: &str = "claim.transaction.passport_root_verified";
    let mut bundle = build_bundle()?;
    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("claim set missing")?,
    )?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim rows missing")?
        .push(json!({
            "claim_id": TRANSACTION_CLAIM,
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
            "verifier_module": "chio-transaction-passport::minimal"
        }));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;

    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["required_claims"]
        .as_array_mut()
        .ok_or("policy required claims missing")?
        .push(Value::String(TRANSACTION_CLAIM.to_string()));
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(&mut bundle, "verifier-policy.json", policy_bytes)?;
    resign_graph(&mut bundle)?;

    let report = verify_cognition_market_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trust,
    )?;
    assert!(report.accepted);
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| claim == TRANSACTION_CLAIM));
    assert!(report
        .claim_results
        .iter()
        .any(|claim| claim.claim_id == TRANSACTION_CLAIM && claim.status == "verified"));
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_wrong_role_and_schema() -> TestResult {
    let mut wrong_role = build_bundle()?;
    let recipe_node = wrong_role.evidence_graph["nodes"]
        .as_array_mut()
        .and_then(|nodes| {
            nodes.iter_mut().find(|node| {
                node.get("schema").and_then(Value::as_str)
                    == Some(FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1)
            })
        })
        .ok_or("recipe node missing")?;
    recipe_node["role"] = Value::String("external-subject".to_string());
    resign_graph(&mut wrong_role)?;
    assert!(verify(&wrong_role).is_err());

    let mut wrong_schema = build_bundle()?;
    let status_node = wrong_schema.evidence_graph["nodes"]
        .as_array_mut()
        .and_then(|nodes| {
            nodes.iter_mut().find(|node| {
                node.get("schema").and_then(Value::as_str)
                    == Some(FINDING_STATUS_PROOF_INPUT_SCHEMA_V1)
            })
        })
        .ok_or("status node missing")?;
    status_node["schema"] = Value::String("chio.finding.status-proof-input.v9".to_string());
    resign_graph(&mut wrong_schema)?;
    assert!(verify(&wrong_schema).is_err());
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_wrong_digest() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .artifacts
        .get_mut("attachments/status-proof-input.json")
        .ok_or("status attachment missing")?
        .push(b' ');
    assert!(verify(&bundle).is_err());
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_substituted_attachment() -> TestResult {
    let mut bundle = build_bundle()?;
    let path = "attachments/replay-recipe-input.json";
    let old_id = sha256_hex(bundle.artifacts.get(path).ok_or("recipe missing")?);
    let replacement = recipe_bytes("ab")?;
    let replacement_id = sha256_hex(&replacement);
    bundle.artifacts.insert(path.to_string(), replacement);
    let recipe_node = bundle.evidence_graph["nodes"]
        .as_array_mut()
        .and_then(|nodes| {
            nodes
                .iter_mut()
                .find(|node| node.get("path").and_then(Value::as_str) == Some(path))
        })
        .ok_or("recipe node missing")?;
    recipe_node["id"] = Value::String(replacement_id.clone());
    recipe_node["sha256"] = Value::String(replacement_id.clone());
    for edge in bundle.evidence_graph["edges"]
        .as_array_mut()
        .ok_or("edges missing")?
    {
        if edge.get("to").and_then(Value::as_str) == Some(old_id.as_str()) {
            edge["to"] = Value::String(replacement_id.clone());
        }
    }
    resign_graph(&mut bundle)?;
    assert!(verify(&bundle).is_err());
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_recipe_for_another_profile() -> TestResult {
    let mut bundle = build_bundle()?;
    let status = bundle
        .artifacts
        .get("attachments/status-proof-input.json")
        .ok_or("status attachment missing")?
        .clone();
    let recipe = recipe_bytes_for_profile("55", "33")?;
    let report = report_bytes(&recipe, &status)?;
    replace_graph_artifact(&mut bundle, "attachments/replay-recipe-input.json", recipe)?;
    replace_graph_artifact(&mut bundle, "report.json", report)?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("mismatched verifier profiles were accepted")?
        .to_string();
    assert!(
        error.contains("different verifier profiles"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_unpinned_profile() -> TestResult {
    let mut bundle = build_bundle()?;
    let status = bundle
        .artifacts
        .get("attachments/status-proof-input.json")
        .ok_or("status attachment missing")?
        .clone();
    let recipe = recipe_bytes_for_profile("55", "33")?;
    let report = report_bytes_for_profile(&recipe, &status, "33")?;
    replace_graph_artifact(&mut bundle, "attachments/replay-recipe-input.json", recipe)?;
    replace_graph_artifact(&mut bundle, "report.json", report)?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("unpinned verifier profile was accepted")?
        .to_string();
    assert!(
        error.contains("deployment-pinned verifier profile"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_inconsistent_status_clock() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle.trust.status_freshness.now = CHECKED_AT - 1;

    let error = verify(&bundle)
        .err()
        .ok_or("inconsistent status clock was accepted")?
        .to_string();
    assert!(
        error.contains("status freshness clock"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_extra_finding_claim() -> TestResult {
    let mut bundle = build_bundle()?;
    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("claim set missing")?,
    )?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim rows missing")?
        .push(json!({
                "claim_id": "claim.finding.unqualified",
                "status": "verified",
                "required_evidence": ["report.json"],
                "evidence_refs": ["report.json"],
                "verifier_module": "chio-finding-verifier"
        }));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    let claim_set_id = replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;
    bundle.passport.claim_set_sha256 = claim_set_id;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("unqualified Finding claim was accepted")?
        .to_string();
    assert!(
        error.contains("unqualified Finding claim"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn persisted_cognition_market_golden_verifies() -> TestResult {
    let root = workspace_root().join(GOLDEN_RELATIVE);
    let mut bundle = build_bundle()?;
    bundle.passport =
        serde_json::from_slice(&std::fs::read(root.join("transaction-passport.json"))?)?;
    bundle.evidence_graph_bytes = std::fs::read(root.join("evidence-graph.json"))?;
    bundle.evidence_graph = serde_json::from_slice(&bundle.evidence_graph_bytes)?;
    bundle.verifier_policy_bytes = std::fs::read(root.join("verifier-policy.json"))?;
    bundle.artifacts = BTreeMap::from([
        (
            "claim-set.json".to_string(),
            std::fs::read(root.join("claim-set.json"))?,
        ),
        (
            "verifier-policy.json".to_string(),
            bundle.verifier_policy_bytes.clone(),
        ),
        (
            "report.json".to_string(),
            std::fs::read(root.join("report.json"))?,
        ),
        (
            "attachments/replay-recipe-input.json".to_string(),
            std::fs::read(root.join("attachments/replay-recipe-input.json"))?,
        ),
        (
            "attachments/status-proof-input.json".to_string(),
            std::fs::read(root.join("attachments/status-proof-input.json"))?,
        ),
    ]);
    verify(&bundle)
}

#[test]
#[ignore = "writes the checked-in cognition-market proof-room golden"]
fn regenerate_cognition_market_golden() -> TestResult {
    let bundle = build_bundle()?;
    let root = workspace_root().join(GOLDEN_RELATIVE);
    std::fs::create_dir_all(root.join("attachments"))?;
    std::fs::write(
        root.join("transaction-passport.json"),
        canonical_json_bytes(&bundle.passport)?,
    )?;
    std::fs::write(
        root.join("evidence-graph.json"),
        &bundle.evidence_graph_bytes,
    )?;
    for (path, bytes) in &bundle.artifacts {
        std::fs::write(root.join(path), bytes)?;
    }
    Ok(())
}
