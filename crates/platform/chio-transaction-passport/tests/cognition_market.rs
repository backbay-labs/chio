use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    build_status_non_inclusion_proof_input, compute_profile_id, compute_report_id,
    compute_status_epoch_id, signed_envelope_sha256, FindingAuthorityKeyPolicy,
    FindingBbsIssuerPolicy, FindingChallengeVerifierProfile, FindingCheckpointLogPolicy,
    FindingClaimedVerdict, FindingFacetKind, FindingFacetOutcome, FindingFacetResult,
    FindingPredicate, FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment,
    FindingRecipePhase, FindingRecipePhaseKind, FindingReplayRecipeInput, FindingResourceCaps,
    FindingStatusEpoch, FindingStatusFreshnessPolicy, FindingStatusOperatorAuthorization,
    FindingStatusOperatorRole, FindingVerifierReport, SignedFindingChallengeVerifierProfile,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    FINDING_STATUS_EPOCH_SCHEMA_V1, FINDING_STATUS_PROOF_INPUT_SCHEMA_V1,
    FINDING_STATUS_SIGNATURE_DOMAIN, FINDING_VERIFIER_REPORT_SCHEMA_V1,
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
    verify_cognition_market_passport_artifacts_with_external_claims, CognitionMarketProofTrust,
    CognitionMarketStatusObservation, CognitionMarketStatusTrust, CognitionMarketStatusTrustStore,
    TransactionPassport, COGNITION_MARKET_CLAIMS,
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

#[derive(Default)]
struct TestStatusState {
    floor: Option<(String, String, u64, String, String)>,
    retracted_findings: std::collections::BTreeSet<String>,
}

#[derive(Default)]
struct TestStatusStore {
    state: Mutex<TestStatusState>,
}

impl TestStatusStore {
    fn with_floor(map_epoch: u64) -> Self {
        Self {
            state: Mutex::new(TestStatusState {
                floor: Some((
                    "qualified-finding-status".to_owned(),
                    "qualified-status-operator".to_owned(),
                    map_epoch,
                    HEX64.to_owned(),
                    "34".repeat(32),
                )),
                retracted_findings: std::collections::BTreeSet::new(),
            }),
        }
    }

    fn with_retracted(finding_id: &str) -> Self {
        let mut retracted_findings = std::collections::BTreeSet::new();
        retracted_findings.insert(finding_id.to_owned());
        Self {
            state: Mutex::new(TestStatusState {
                floor: None,
                retracted_findings,
            }),
        }
    }
}

impl CognitionMarketStatusTrustStore for TestStatusStore {
    fn admit_verified_non_inclusion(
        &self,
        observation: &CognitionMarketStatusObservation<'_>,
    ) -> Result<(), String> {
        let epoch = &observation.signed_epoch.body;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "test status trust lock poisoned".to_owned())?;
        if state
            .retracted_findings
            .contains(&observation.proof.finding_id)
        {
            return Err("non-inclusion contradicts sticky retracted state".to_owned());
        }
        if let Some((feed_id, operator_id, map_epoch, epoch_id, root_hash)) = &state.floor {
            if feed_id != &epoch.feed_id || operator_id != &epoch.operator_id {
                return Err("status feed operator identity changed".to_owned());
            }
            if epoch.map_epoch < *map_epoch {
                return Err("status epoch rollback".to_owned());
            }
            if epoch.map_epoch == *map_epoch
                && (epoch.status_epoch_id != *epoch_id || epoch.root_hash != *root_hash)
            {
                return Err("status epoch equivocation".to_owned());
            }
        }
        state.floor = Some((
            epoch.feed_id.clone(),
            epoch.operator_id.clone(),
            epoch.map_epoch,
            epoch.status_epoch_id.clone(),
            epoch.root_hash.clone(),
        ));
        Ok(())
    }
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

fn verifier_signer_policy() -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: "qualified-finding-verifier".to_string(),
        key: verifier_keypair().public_key(),
        key_epoch: 1,
        valid_from: GENERATED_AT - 60,
        valid_until: GENERATED_AT + 600,
        rotation_policy_ref: "rotation/qualified-finding-verifier-v1".to_string(),
        revocation_status_ref: "revocations/qualified-finding-verifier-v1".to_string(),
    }
}

fn profile_key_policy(seed: u8, authority_id: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: authority_id.to_owned(),
        key: Keypair::from_seed(&[seed; 32]).public_key(),
        key_epoch: 1,
        valid_from: GENERATED_AT - 60,
        valid_until: GENERATED_AT + 600,
        rotation_policy_ref: format!("rotation/{authority_id}-v1"),
        revocation_status_ref: format!("revocations/{authority_id}-v1"),
    }
}

fn verifier_profile() -> TestResult<SignedFindingChallengeVerifierProfile> {
    let governance = Keypair::from_seed(&[8_u8; 32]);
    let mut profile = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_owned(),
        profile_id: String::new(),
        governance_authority: governance.public_key(),
        operator: "qualified-market-operator".to_owned(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: profile_key_policy(18, "production-receipts"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: profile_key_policy(19, "delivery-receipts"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: profile_key_policy(20, "replay-receipts"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: "qualified-finding-checkpoint-log".to_owned(),
            signer: profile_key_policy(21, "checkpoint-log"),
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "qualified-bbs-issuer".to_owned(),
            key_hex: HEX64.to_owned(),
            registry_ref: "registry/qualified-bbs-issuers".to_owned(),
            key_epoch: 1,
            valid_from: GENERATED_AT - 60,
            valid_until: GENERATED_AT + 600,
            revocation_status_ref: "revocations/qualified-bbs-issuer-v1".to_owned(),
        },
        allowed_runner_manifests: vec!["66".repeat(32)],
        required_receipt_semantics: "chio.mediated_spend.v1".to_owned(),
        resolver_policy_ref: "resolver/qualified-finding-v1".to_owned(),
        retention_policy_ref: "retention/qualified-finding-v1".to_owned(),
        resource_caps: FindingResourceCaps {
            max_recipe_bytes: 65_536,
            max_evidence_receipts: 8,
            max_runtime_secs: 600,
            max_memory_bytes: 1_073_741_824,
        },
        predicate_engine: "chio-replay-v1".to_owned(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![FindingFacetKind::KernelAndRevocationTrust],
        verifier_report_signer: verifier_signer_policy(),
        purchase_authority: profile_key_policy(22, "purchase-authority"),
        failed_delivery_authority: profile_key_policy(23, "failed-delivery-authority"),
        issued_at: GENERATED_AT - 60,
        expires_at: GENERATED_AT + 600,
    };
    profile.profile_id = compute_profile_id(&profile)?;
    Ok(SignedExportEnvelope::sign(profile, &governance)?)
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
    let profile = verifier_profile()?;
    recipe_bytes_for_profile(payload_suffix, &signed_envelope_sha256(&profile)?)
}

fn recipe_bytes_for_profile(
    payload_suffix: &str,
    verifier_profile_digest: &str,
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
        verifier_profile_envelope_sha256: verifier_profile_digest.to_owned(),
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
    let profile = verifier_profile()?;
    report_bytes_for_profile(recipe, status, &signed_envelope_sha256(&profile)?)
}

fn report_bytes_for_profile(
    recipe: &[u8],
    status: &[u8],
    verifier_profile_digest: &str,
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
        verifier_profile_envelope_sha256: verifier_profile_digest.to_owned(),
        verifier_implementation_id: "chio-finding-verifier/0.1-qualified".to_string(),
        resolved_evidence_bundle_sha256: "34".repeat(32),
        replay_recipe_input_sha256: Some(sha256_hex(recipe)),
        status_proof_input_sha256: Some(sha256_hex(status)),
        finding_delivery_receipt_id: Some("89".repeat(32)),
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
        "subject": {
            "kind": "finding",
            "id": FINDING_ID,
            "artifact_sha256": HEX64
        },
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
    let trusted_verifier_profile = verifier_profile()?;
    let trusted_verifier_profile_envelope_sha256 =
        signed_envelope_sha256(&trusted_verifier_profile)?;
    let trust = CognitionMarketProofTrust {
        trusted_passport_signer_keys: vec![root.public_key()],
        trusted_checkpoint_signer_keys: Vec::new(),
        profile_governance_authority: Keypair::from_seed(&[8_u8; 32]).public_key(),
        finding_verifier_authority: verifier_keypair().public_key(),
        trusted_verifier_profile_envelope_sha256,
        trusted_verifier_profile,
        trusted_trust_root_snapshot_sha256: "45".repeat(32),
        trusted_resolver_policy_sha256: "56".repeat(32),
        trusted_time_input_sha256: "67".repeat(32),
        status: Some(CognitionMarketStatusTrust {
            status_operator_authorization: status_authorization(&status_keypair),
            status_freshness: FindingStatusFreshnessPolicy {
                now: CHECKED_AT,
                max_epoch_age_secs: 60,
            },
            status_store: Arc::new(TestStatusStore::default()),
        }),
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

fn replace_trusted_profile(
    bundle: &mut QualifiedBundle,
    mutate: impl FnOnce(&mut FindingChallengeVerifierProfile),
) -> TestResult {
    let mut profile = bundle.trust.trusted_verifier_profile.body.clone();
    mutate(&mut profile);
    profile.profile_id = compute_profile_id(&profile)?;
    let signed = SignedExportEnvelope::sign(profile, &Keypair::from_seed(&[8_u8; 32]))?;
    bundle.trust.trusted_verifier_profile_envelope_sha256 = signed_envelope_sha256(&signed)?;
    bundle.trust.trusted_verifier_profile = signed;
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

fn add_transparency_anchor(bundle: &mut QualifiedBundle) -> TestResult {
    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["accepted_transparency_states"] = json!(["trust_anchored"]);
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(bundle, "verifier-policy.json", policy_bytes)?;

    let receipt_key = Keypair::from_seed(&[86_u8; 32]);
    let receipt_body = json!({
        "schema": "chio.receipt.v1",
        "receipt_id": "receipt-cognition-market-anchor",
        "capability_id": "cap-cognition-market-verify",
        "guard_decision_id": "guard-cognition-market-verify",
        "policy_digest": "87".repeat(32),
        "request_digest": "88".repeat(32),
        "response_digest": "89".repeat(32),
        "terminal_status": "allowed_executed",
        "kernel_key": receipt_key.public_key().to_hex()
    });
    let mut receipt: Value = receipt_body.clone();
    receipt["signature"] = Value::String(
        receipt_key
            .sign(&canonical_json_bytes(&receipt_body)?)
            .to_hex(),
    );
    let receipt_bytes = canonical_json_bytes(&receipt)?;
    let receipt_digest = sha256_hex(&receipt_bytes);
    bundle
        .artifacts
        .insert("anchor-receipt.json".to_string(), receipt_bytes.clone());
    bundle.evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("graph nodes missing")?
        .push(node(
            "anchor-receipt.json",
            "receipt",
            "chio.receipt.v1",
            &receipt_bytes,
        ));
    bundle.evidence_graph["edges"]
        .as_array_mut()
        .ok_or("graph edges missing")?
        .push(json!({
            "from": bundle.passport.claim_set_sha256,
            "to": receipt_digest,
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));

    let checkpoint_key = Keypair::from_seed(&[87_u8; 32]);
    let leaf = chio_core_types::merkle::leaf_hash(&receipt_bytes);
    let leaf_hex = format!("0x{}", leaf.to_hex());
    let checkpoint_chain_leaf = json!({
        "checkpoint_seq": 1,
        "batch_start_seq": 1,
        "batch_end_seq": 1,
        "merkle_root": leaf_hex
    });
    let chain_root =
        chio_core_types::merkle::leaf_hash(&canonical_json_bytes(&checkpoint_chain_leaf)?);
    let statement_body = json!({
        "schema": "chio.checkpoint_statement.v2",
        "checkpoint_seq": 1,
        "batch_start_seq": 1,
        "batch_end_seq": 1,
        "tree_size": 1,
        "merkle_root": leaf_hex,
        "issued_at": CHECKED_AT,
        "kernel_key": checkpoint_key.public_key().to_hex(),
        "chain_root": format!("0x{}", chain_root.to_hex())
    });
    let statement_signature = checkpoint_key
        .sign(&canonical_json_bytes(&statement_body)?)
        .to_hex();
    let log_id = format!(
        "local-log-{}",
        sha256_hex(checkpoint_key.public_key().as_bytes())
    );
    let inclusion = json!({
        "schema": "chio.transparency.inclusion-proof.v2",
        "proof_id": "transparency-proof-cognition-market",
        "log_id": log_id,
        "artifact_ref": receipt_digest,
        "root_hash": leaf_hex,
        "leaf_hash": leaf_hex,
        "tree_size": 1,
        "leaf_index": 0,
        "checkpoint": format!("{log_id}:1"),
        "inclusion_path": [],
        "verified_at": CHECKED_AT,
        "checkpoint_statement": {
            "body": statement_body,
            "signature": statement_signature
        }
    });
    let inclusion_bytes = canonical_json_bytes(&inclusion)?;
    bundle.artifacts.insert(
        "transparency-inclusion-proof.json".to_string(),
        inclusion_bytes.clone(),
    );
    bundle.evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("graph nodes missing")?
        .push(node(
            "transparency-inclusion-proof.json",
            "transparency-inclusion-proof",
            "chio.transparency.inclusion-proof.v2",
            &inclusion_bytes,
        ));
    bundle.trust.trusted_checkpoint_signer_keys = vec![checkpoint_key.public_key()];
    resign_graph(bundle)
}

#[test]
fn cognition_market_qualified_profile() -> TestResult {
    verify(&build_bundle()?)
}

#[test]
fn cognition_market_qualified_profile_rejects_an_unselected_failed_facet() -> TestResult {
    let mut bundle = build_bundle()?;
    let selected_claim = COGNITION_MARKET_CLAIMS[3];

    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("claim set missing")?,
    )?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim rows missing")?
        .retain(|claim| claim.get("claim_id").and_then(Value::as_str) == Some(selected_claim));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;

    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["required_claims"] = json!([selected_claim]);
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(&mut bundle, "verifier-policy.json", policy_bytes)?;

    let report_bytes = bundle
        .artifacts
        .get("report.json")
        .ok_or("report missing")?;
    let signed: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(report_bytes)?;
    let mut report = signed.body;
    let unrelated = report
        .facets
        .iter_mut()
        .find(|facet| facet.facet == FindingFacetKind::ArtifactIntegrity)
        .ok_or("artifact-integrity facet missing")?;
    unrelated.outcome = FindingFacetOutcome::Failed;
    unrelated.reason = "contradicted by malformed optional evidence".to_string();
    report.report_id = compute_report_id(&report)?;
    let replacement = SignedExportEnvelope::sign(report, &verifier_keypair())?;
    replace_graph_artifact(
        &mut bundle,
        "report.json",
        canonical_json_bytes(&replacement)?,
    )?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("a report with an unselected failed facet was accepted")?
        .to_string();
    assert!(
        error.contains("contains failed facet ArtifactIntegrity"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_accepts_anchored_only_policy() -> TestResult {
    let mut bundle = build_bundle()?;
    add_transparency_anchor(&mut bundle)?;

    let report = verify_cognition_market_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trust,
    )?;
    assert_eq!(report.transparency_state, "trust_anchored");
    Ok(())
}

#[test]
fn cognition_market_delivery_claim_verifies_without_unselected_attachments() -> TestResult {
    let mut bundle = build_bundle()?;
    let selected_claim = COGNITION_MARKET_CLAIMS[0];

    let mut claim_set: Value = serde_json::from_slice(
        bundle
            .artifacts
            .get("claim-set.json")
            .ok_or("claim set missing")?,
    )?;
    claim_set["claims"]
        .as_array_mut()
        .ok_or("claim rows missing")?
        .retain(|claim| claim.get("claim_id").and_then(Value::as_str) == Some(selected_claim));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;

    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["required_claims"] = json!([selected_claim]);
    policy["required_evidence_roles"] = json!(["report"]);
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(&mut bundle, "verifier-policy.json", policy_bytes)?;

    let removed_ids = bundle.evidence_graph["nodes"]
        .as_array()
        .ok_or("graph nodes missing")?
        .iter()
        .filter(|node| {
            matches!(
                node.get("schema").and_then(Value::as_str),
                Some(FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1)
                    | Some(FINDING_STATUS_PROOF_INPUT_SCHEMA_V1)
            )
        })
        .filter_map(|node| node.get("id").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();
    bundle.evidence_graph["nodes"]
        .as_array_mut()
        .ok_or("graph nodes missing")?
        .retain(|node| {
            !matches!(
                node.get("schema").and_then(Value::as_str),
                Some(FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1)
                    | Some(FINDING_STATUS_PROOF_INPUT_SCHEMA_V1)
            )
        });
    bundle.evidence_graph["edges"]
        .as_array_mut()
        .ok_or("graph edges missing")?
        .retain(|edge| {
            !["from", "to"].iter().any(|field| {
                edge.get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|id| removed_ids.iter().any(|removed| removed == id))
            })
        });
    bundle
        .artifacts
        .remove("attachments/replay-recipe-input.json");
    bundle
        .artifacts
        .remove("attachments/status-proof-input.json");
    bundle.trust.status = None;
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
    assert_eq!(report.verified_claims, vec![selected_claim.to_string()]);
    assert_eq!(report.claim_results.len(), 1);
    assert_eq!(report.claim_results[0].claim_id, selected_claim);
    Ok(())
}

#[test]
fn cognition_market_delivery_claim_rejects_a_pre_sale_report() -> TestResult {
    let mut bundle = build_bundle()?;
    let report_bytes = bundle
        .artifacts
        .get("report.json")
        .ok_or("report missing")?;
    let signed: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(report_bytes)?;
    let mut report = signed.body;
    report.finding_delivery_receipt_id = None;
    report.report_id = compute_report_id(&report)?;
    let replacement = SignedExportEnvelope::sign(report, &verifier_keypair())?;
    replace_graph_artifact(
        &mut bundle,
        "report.json",
        canonical_json_bytes(&replacement)?,
    )?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("pre-sale report granted a delivery-bound claim")?
        .to_string();
    assert!(
        error.contains("requires a verified Finding delivery receipt"),
        "unexpected error: {error}"
    );
    Ok(())
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
fn cognition_market_root_accepts_an_independently_verified_risk_claim() -> TestResult {
    const RISK_CLAIM: &str = "claim.risk.comptroller_report_bound";
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
            "claim_id": RISK_CLAIM,
            "status": "verified",
            "required_evidence": ["risk-comptroller-report.json"],
            "evidence_refs": ["risk-comptroller-report.json"],
            "verifier_module": "chio-risk-comptroller"
        }));
    let claim_set_bytes = canonical_json_bytes(&claim_set)?;
    bundle.passport.claim_set_sha256 =
        replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;

    let mut policy: Value = serde_json::from_slice(&bundle.verifier_policy_bytes)?;
    policy["required_claims"]
        .as_array_mut()
        .ok_or("policy required claims missing")?
        .push(Value::String(RISK_CLAIM.to_string()));
    bundle.verifier_policy_bytes = canonical_json_bytes(&policy)?;
    let policy_bytes = bundle.verifier_policy_bytes.clone();
    bundle.passport.verifier_policy_sha256 =
        replace_graph_artifact(&mut bundle, "verifier-policy.json", policy_bytes)?;
    resign_graph(&mut bundle)?;

    assert!(verify_cognition_market_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trust,
    )
    .is_err());
    let report = verify_cognition_market_passport_artifacts_with_external_claims(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
        &bundle.artifacts,
        &bundle.trust,
        &[RISK_CLAIM.to_string()],
    )?;
    assert!(report.accepted);
    assert!(!report
        .verified_claims
        .iter()
        .any(|claim| claim == RISK_CLAIM));
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
    let recipe = recipe_bytes_for_profile("55", &"33".repeat(32))?;
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
    let recipe = recipe_bytes_for_profile("55", &"33".repeat(32))?;
    let report = report_bytes_for_profile(&recipe, &status, &"33".repeat(32))?;
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
fn cognition_market_qualified_profile_rejects_self_pinned_governance() -> TestResult {
    let mut bundle = build_bundle()?;
    let unauthorized_governance = Keypair::from_seed(&[88_u8; 32]);
    let mut profile = bundle.trust.trusted_verifier_profile.body.clone();
    profile.governance_authority = unauthorized_governance.public_key();
    profile.required_facets.clear();
    profile.profile_id = compute_profile_id(&profile)?;
    let signed = SignedExportEnvelope::sign(profile, &unauthorized_governance)?;
    bundle.trust.trusted_verifier_profile_envelope_sha256 = signed_envelope_sha256(&signed)?;
    bundle.trust.trusted_verifier_profile = signed;

    let error = verify(&bundle)
        .err()
        .ok_or("a self-pinned profile governance authority was accepted")?
        .to_string();
    assert!(
        error.contains("envelope signer does not match the pinned authority: profile"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_enforces_required_facet_floor() -> TestResult {
    let mut bundle = build_bundle()?;
    let report_bytes = bundle
        .artifacts
        .get("report.json")
        .ok_or("report missing")?;
    let signed: SignedExportEnvelope<FindingVerifierReport> = serde_json::from_slice(report_bytes)?;
    let mut report = signed.body;
    let required = report
        .facets
        .iter_mut()
        .find(|facet| facet.facet == FindingFacetKind::KernelAndRevocationTrust)
        .ok_or("kernel-and-revocation-trust facet missing")?;
    required.outcome = FindingFacetOutcome::Unavailable;
    required.reason = "trusted profile floor was not evaluated".to_string();
    report.report_id = compute_report_id(&report)?;
    let replacement = SignedExportEnvelope::sign(report, &verifier_keypair())?;
    replace_graph_artifact(
        &mut bundle,
        "report.json",
        canonical_json_bytes(&replacement)?,
    )?;
    resign_graph(&mut bundle)?;

    let error = verify(&bundle)
        .err()
        .ok_or("report below the trusted profile facet floor was accepted")?
        .to_string();
    assert!(
        error.contains("profile requires verified facet KernelAndRevocationTrust"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_an_independent_facet_projection() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .trusted_verifier_profile
        .body
        .required_facets
        .clear();

    let error = verify(&bundle)
        .err()
        .ok_or("a facet projection detached from the pinned profile was accepted")?
        .to_string();
    assert!(
        error.contains("profile bytes do not match the deployment-pinned digest"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_unpinned_trust_root_snapshot() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle.trust.trusted_trust_root_snapshot_sha256 = "ab".repeat(32);

    let error = verify(&bundle)
        .err()
        .ok_or("report from an unpinned trust-root snapshot was accepted")?
        .to_string();
    assert!(
        error.contains("deployment-pinned trust-root snapshot"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_unpinned_resolution_inputs() -> TestResult {
    let mut wrong_resolver = build_bundle()?;
    wrong_resolver.trust.trusted_resolver_policy_sha256 = "ab".repeat(32);
    let resolver_error = verify(&wrong_resolver)
        .err()
        .ok_or("report from an unpinned resolver policy was accepted")?
        .to_string();
    assert!(
        resolver_error.contains("deployment-pinned resolver policy"),
        "unexpected error: {resolver_error}"
    );

    let mut wrong_time = build_bundle()?;
    wrong_time.trust.trusted_time_input_sha256 = "cd".repeat(32);
    let time_error = verify(&wrong_time)
        .err()
        .ok_or("report from an unpinned trusted-time input was accepted")?
        .to_string();
    assert!(
        time_error.contains("deployment-pinned trusted-time input"),
        "unexpected error: {time_error}"
    );
    Ok(())
}

#[test]
fn cognition_market_claim_set_subject_must_match_the_signed_report() -> TestResult {
    for (field, replacement, expected_error) in [
        (
            "id",
            "ab".repeat(32),
            "names a different Finding than the signed verifier report",
        ),
        (
            "artifact_sha256",
            "cd".repeat(32),
            "subject artifact digest does not match the signed verifier report",
        ),
    ] {
        let mut bundle = build_bundle()?;
        let mut claim_set: Value = serde_json::from_slice(
            bundle
                .artifacts
                .get("claim-set.json")
                .ok_or("claim set missing")?,
        )?;
        claim_set["subject"][field] = Value::String(replacement);
        let claim_set_bytes = canonical_json_bytes(&claim_set)?;
        bundle.passport.claim_set_sha256 =
            replace_graph_artifact(&mut bundle, "claim-set.json", claim_set_bytes)?;
        resign_graph(&mut bundle)?;

        let error = verify(&bundle)
            .err()
            .ok_or("ClaimSet with a mismatched Finding subject was accepted")?
            .to_string();
        assert!(
            error.contains(expected_error),
            "unexpected error for subject {field}: {error}"
        );
    }
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_enforces_verifier_signer_lifecycle() -> TestResult {
    let mut wrong_epoch = build_bundle()?;
    replace_trusted_profile(&mut wrong_epoch, |profile| {
        profile.verifier_report_signer.key_epoch = 2;
    })?;
    let epoch_error = verify(&wrong_epoch)
        .err()
        .ok_or("wrong verifier key epoch was accepted")?
        .to_string();
    assert!(
        epoch_error.contains("key epoch"),
        "unexpected error: {epoch_error}"
    );

    let mut expired = build_bundle()?;
    replace_trusted_profile(&mut expired, |profile| {
        profile.verifier_report_signer.valid_until = CHECKED_AT;
    })?;
    let lifecycle_error = verify(&expired)
        .err()
        .ok_or("expired verifier signer was accepted")?
        .to_string();
    assert!(
        lifecycle_error.contains("signer lifecycle"),
        "unexpected error: {lifecycle_error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_inconsistent_status_clock() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .status
        .as_mut()
        .ok_or("status trust missing")?
        .status_freshness
        .now = CHECKED_AT - 1;

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
fn cognition_market_qualified_profile_rejects_durable_status_rollback() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .status
        .as_mut()
        .ok_or("status trust missing")?
        .status_store = Arc::new(TestStatusStore::with_floor(2));

    let error = verify(&bundle)
        .err()
        .ok_or("durable status rollback was accepted")?
        .to_string();
    assert!(
        error.contains("status epoch rollback"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn cognition_market_qualified_profile_rejects_sticky_retraction() -> TestResult {
    let mut bundle = build_bundle()?;
    bundle
        .trust
        .status
        .as_mut()
        .ok_or("status trust missing")?
        .status_store = Arc::new(TestStatusStore::with_retracted(FINDING_ID));

    let error = verify(&bundle)
        .err()
        .ok_or("sticky retraction was accepted")?
        .to_string();
    assert!(
        error.contains("sticky retracted state"),
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
    let persisted_profile = std::fs::read(root.join("deployment/verifier-profile.json"))?;
    assert_eq!(
        persisted_profile,
        canonical_json_bytes(&bundle.trust.trusted_verifier_profile)?,
        "deployment profile fixture must match the profile pinned by the golden report"
    );
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
    std::fs::create_dir_all(root.join("deployment"))?;
    std::fs::write(
        root.join("deployment/verifier-profile.json"),
        canonical_json_bytes(&bundle.trust.trusted_verifier_profile)?,
    )?;
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
