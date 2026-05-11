use std::env;
use std::fs;
use std::path::PathBuf;

use chio_core_types::{canonical_json_bytes, sha256_hex, Keypair};
use chio_federation::{
    verify_pheromone_gossip_frame, PheromoneDepositGossip, PheromoneGossipBatch,
    PheromoneTransitChain, PheromoneTransitHop, PheromoneTransitPolicy,
    PHEROMONE_GOSSIP_BATCH_SCHEMA, PHEROMONE_GOSSIP_SCHEMA, PHEROMONE_TRANSIT_POLICY_SCHEMA,
};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, sign_deposit, CostCommitmentPolicy,
    PassportAdmission, PheromoneCostCommitment, PheromoneDepositBody, PheromoneValidationContext,
    PheromoneWorkflowContext, Severity, SubjectClassPolicy, PHEROMONE_COST_COMMITMENT_SCHEMA,
    PHEROMONE_DEPOSIT_SCHEMA, PHEROMONE_WORKFLOW_CONTEXT_SCHEMA,
};
use chio_pheromone_runtime::{
    PeerWeightEntry, PeerWeightsDocument, PheromoneAdmissionPolicyDocument, PheromoneReceiver,
    PheromoneReceiverConfig, PheromoneRuntimeStore, SqlitePheromoneRuntimeStore,
    StaticPeerWeightProvider, VerifiedChiodosWorkflowResolver, PHEROMONE_PEER_WEIGHTS_SCHEMA,
};
use chiodos_three_vendor_example::{
    authority_issuance_request, authority_profile_document, authority_profile_json,
    authority_signing_keys_document, disclosure_policy, fresh_proof_package, issuance_request_json,
    package_json, peer_pins_document_for_package, peer_pins_json, report_json,
    revocation_publication_request, revocation_publication_request_json, signing_keys_json,
    verification_context, verification_context_json, verifier_trust_bundle_document_for_package,
    verifier_trust_bundle_json, verify_package, write_signed_negative_case_inputs,
    ChiodosPackageError, ChiodosVerifierTrustBundle,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ChiodosPackageError> {
    let package = fresh_proof_package()?;
    let context = verification_context();
    let trust_bundle_document = verifier_trust_bundle_document_for_package(&package)?;
    let trust_bundle = ChiodosVerifierTrustBundle::from_document(trust_bundle_document.clone())?;
    let report = verify_package(&package, &trust_bundle, &context)?;
    let args = env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_] => {
            println!("{}", package_json(&package)?);
        }
        [_, flag] if flag == "--report" => {
            println!("{}", report_json(&report)?);
        }
        [_, flag, dir] if flag == "--out-dir" => {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("buyer-auditor-proof-package.json"),
                package_json(&package)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("selective-disclosure-proof.json"),
                serde_json::to_string_pretty(&package.selective_disclosure_proof)
                    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("verifier-trust-bundle.json"),
                verifier_trust_bundle_json(&trust_bundle_document)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("verification-context.json"),
                verification_context_json(&context)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(dir.join("verifier-report.json"), report_json(&report)?)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
        }
        [_, flag, dir] if flag == "--signed-negative-dir" => {
            write_signed_negative_case_inputs(&PathBuf::from(dir))?;
        }
        [_, flag, dir] if flag == "--authority-input-dir" => {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir)
                .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("authority-profile.json"),
                authority_profile_json(&authority_profile_document()?)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("issuance-request.json"),
                issuance_request_json(&authority_issuance_request()?)?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("local-signing-keys.json"),
                signing_keys_json(&authority_signing_keys_document())?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("peer-pins.json"),
                peer_pins_json(&peer_pins_document_for_package(&package))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("workflow-intersection.json"),
                serde_json::to_string_pretty(&package.workflow_intersection)
                    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("disclosure-policy.json"),
                serde_json::to_string_pretty(&disclosure_policy())
                    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
            fs::write(
                dir.join("revocation-publication-request.json"),
                revocation_publication_request_json(&revocation_publication_request(Vec::new()))?,
            )
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
        }
        [_, flag, dir] if flag == "--pheromone-out-dir" => {
            write_pheromone_fixtures(&package, &PathBuf::from(dir))?;
        }
        _ => {
            return Err(ChiodosPackageError::Json(
                "usage: generate-chiodos-proof-package [--report|--out-dir DIR|--signed-negative-dir DIR|--authority-input-dir DIR|--pheromone-out-dir DIR]"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn write_pheromone_fixtures(
    package: &chiodos_three_vendor_example::ChiodosProofPackage,
    dir: &PathBuf,
) -> Result<(), ChiodosPackageError> {
    fs::create_dir_all(dir).map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let passport_key = Keypair::from_seed(&[31; 32]);
    let buyer_kernel_key = Keypair::from_seed(&[11; 32]);
    let step = package
        .workflow_receipt
        .steps
        .first()
        .ok_or_else(|| ChiodosPackageError::Json("workflow has no steps".to_string()))?;
    let workflow_receipt_sha256 = canonical_sha256(&package.workflow_receipt)?;
    let workflow_intersection_sha256 = canonical_sha256(&package.workflow_intersection)?;
    let workflow_context = PheromoneWorkflowContext {
        schema: PHEROMONE_WORKFLOW_CONTEXT_SCHEMA.to_string(),
        workflow_id: package.workflow_id.clone(),
        workflow_receipt_id: package.workflow_receipt.id.clone(),
        workflow_receipt_sha256,
        workflow_intersection_id: package.workflow_intersection.intersection_id.clone(),
        workflow_intersection_sha256,
        step_index: step.step_index as u64,
        tool_receipt_id: step
            .tool_receipt_id
            .clone()
            .ok_or_else(|| ChiodosPackageError::Json("step has no tool receipt".to_string()))?,
        bilateral_dsse_sha256: step.bilateral_dsse_sha256.clone().ok_or_else(|| {
            ChiodosPackageError::Json("step has no bilateral DSSE hash".to_string())
        })?,
        consistency_anchor: step.consistency_anchor.clone().ok_or_else(|| {
            ChiodosPackageError::Json("step has no consistency anchor".to_string())
        })?,
    };
    let public_key = passport_key.public_key();
    let deposit = sign_deposit(
        PheromoneDepositBody {
            schema: PHEROMONE_DEPOSIT_SCHEMA.to_string(),
            kernel_id: "did:chio:llamaworks".to_string(),
            agent_passport_key_hash: agent_passport_key_hash(&public_key),
            agent_passport_jwk_thumbprint: agent_passport_jwk_thumbprint(&public_key),
            subject_class: "support.prompt_injection".to_string(),
            subject_class_namespace: "dev.chio.support".to_string(),
            indicator: serde_json::json!({
                "kind": "prompt_injection",
                "workflowId": package.workflow_id,
                "indicatorDigest": sha256_hex(b"llamaworks-prompt-injection-indicator")
            }),
            severity: Severity::High,
            confidence: 0.82,
            timestamp_unix_ms: package.generated_at_unix_ms,
            decay_half_life_secs: 3_600.0,
            evaporation_floor: Some(0.01),
            nonce: "pheromone-nonce-llamaworks-001".to_string(),
            treaty_scope: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            cost_commitment: Some(PheromoneCostCommitment {
                schema: PHEROMONE_COST_COMMITMENT_SCHEMA.to_string(),
                telemetry_chain_root: sha256_hex(b"llamaworks-telemetry-chain-root"),
                chain_position: 7,
                chain_position_proof: serde_json::json!({"fixture": "telemetry-chain-position"}),
                observed_at_unix_ms: package.generated_at_unix_ms,
            }),
            workflow_context: Some(workflow_context),
        },
        &passport_key,
    )
    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let policy = PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: vec!["did:chio:buyer-kernel".to_string()],
        allowed_ingress_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        allowed_egress_treaties: vec![
            "treaty:buyer-dataco:support-ops".to_string(),
            "treaty:buyer-payswift:support-ops".to_string(),
        ],
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        valid_from_unix_ms: package.generated_at_unix_ms.saturating_sub(60_000),
        valid_until_unix_ms: package.generated_at_unix_ms.saturating_add(60_000),
        max_hops: 2,
        required_action_class_id: "whisker.pheromone_deposit".to_string(),
    };
    let frame = PheromoneDepositGossip {
        schema: PHEROMONE_GOSSIP_SCHEMA.to_string(),
        deposit: deposit.clone(),
        origin_kernel_id: "did:chio:llamaworks".to_string(),
        gossiping_peer_kernel_id: "did:chio:buyer-kernel".to_string(),
        treaty_id: "treaty:buyer-dataco:support-ops".to_string(),
        ts_unix_ms: package.generated_at_unix_ms.saturating_add(500),
        transit_chain: Some(PheromoneTransitChain {
            hops: vec![
                transit_hop(
                    "did:chio:llamaworks",
                    "did:chio:buyer-kernel",
                    "treaty:buyer-llamaworks:support-ops",
                    "ladder:llamaworks:support:v1",
                    "intersection:buyer:llamaworks",
                    package.generated_at_unix_ms,
                ),
                transit_hop(
                    "did:chio:buyer-kernel",
                    "did:chio:dataco",
                    "treaty:buyer-dataco:support-ops",
                    "ladder:buyer:refund:v1",
                    "intersection:buyer:dataco",
                    package.generated_at_unix_ms,
                ),
            ],
        }),
    };
    verify_pheromone_gossip_frame(
        &frame,
        &policy,
        package.generated_at_unix_ms.saturating_add(500),
    )
    .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let batch = PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:dataco".to_string(),
        treaty_id: frame.treaty_id.clone(),
        frames: vec![frame],
        flushed_at_unix_ms: package.generated_at_unix_ms.saturating_add(500),
    };
    let validation_context = PheromoneValidationContext {
        now_unix_ms: package.generated_at_unix_ms.saturating_add(500),
        replay_window_ms: 86_400_000,
        active_peers_in_treaty: 9,
        known_reputation_epochs: vec![42],
        passports: vec![PassportAdmission {
            kernel_id: "did:chio:llamaworks".to_string(),
            public_key,
            valid_from_unix_ms: package.generated_at_unix_ms.saturating_sub(60_000),
            valid_until_unix_ms: package.generated_at_unix_ms.saturating_add(60_000),
            first_seen_epoch: 37,
            revoked: false,
        }],
        kernel_public_keys: vec![buyer_kernel_key.public_key()],
        subject_classes: vec![SubjectClassPolicy {
            subject_class: "support.prompt_injection".to_string(),
            subject_class_namespace: "dev.chio.support".to_string(),
            allowed_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
            cost_commitment: CostCommitmentPolicy::Required,
            destructive: true,
        }],
        max_deposits_per_pair: 8,
    };
    let policy_document = transit_policy_document(&policy, &validation_context)?;
    let trust_bundle_document = verifier_trust_bundle_document_for_package(package)?;
    let trust_bundle = ChiodosVerifierTrustBundle::from_document(trust_bundle_document)?;
    let context = verification_context();
    let resolver =
        VerifiedChiodosWorkflowResolver::from_verified_package(package, &trust_bundle, &context)
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let store = SqlitePheromoneRuntimeStore::open_in_memory()
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let receiver = PheromoneReceiver::new(
        store,
        resolver,
        PheromoneReceiverConfig {
            recipient_kernel_id: "did:chio:dataco".to_string(),
            authenticated_sender_kernel_id: "did:chio:buyer-kernel".to_string(),
            validation_context: validation_context.clone(),
        },
    );
    let receive_report = receiver
        .receive_batch(&batch, &policy)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let peer_weights = PeerWeightsDocument {
        schema: PHEROMONE_PEER_WEIGHTS_SCHEMA.to_string(),
        reputation_epoch: 42,
        weights: vec![PeerWeightEntry {
            kernel_id: "did:chio:llamaworks".to_string(),
            weight: 0.75,
        }],
    };
    let query_report = receiver
        .query_concentration(
            "support.prompt_injection",
            "dev.chio.support",
            42,
            &StaticPeerWeightProvider::new(
                peer_weights.reputation_epoch,
                peer_weights
                    .weights
                    .iter()
                    .map(|entry| (entry.kernel_id.clone(), entry.weight)),
            ),
        )
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let negative_cases = serde_json::json!({
        "schema": "chio.pheromone.negative-fixture-corpus.v1",
        "cases": [
            {
                "id": "workflow-receipt-hash-mismatch",
                "target": "deposit",
                "mutation": {"op": "set", "path": ["workflow_context", "workflow_receipt_sha256"], "value": "0".repeat(64)},
                "expected_failure_code": "signature_invalid"
            },
            {
                "id": "dsse-hash-mismatch",
                "target": "deposit",
                "mutation": {"op": "set", "path": ["workflow_context", "bilateral_dsse_sha256"], "value": "1".repeat(64)},
                "expected_failure_code": "signature_invalid"
            },
            {
                "id": "missing-cost-commitment",
                "target": "deposit",
                "mutation": {"op": "remove", "path": ["cost_commitment"]},
                "expected_failure_code": "observation_cost_commitment_required"
            },
            {
                "id": "stale-transit-policy",
                "target": "policy",
                "mutation": {"op": "set", "path": ["valid_until_unix_ms"], "value": package.generated_at_unix_ms},
                "expected_failure_code": "transit_policy_violation"
            }
        ]
    });

    write_json(dir.join("deposit.json"), &deposit)?;
    write_json(dir.join("gossip-batch.json"), &batch)?;
    write_json(dir.join("transit-policy.json"), &policy_document)?;
    write_json(dir.join("receive-report.json"), &receive_report)?;
    write_json(dir.join("peer-weights.json"), &peer_weights)?;
    write_json(dir.join("query-report.json"), &query_report)?;
    write_json(dir.join("concentration.json"), &query_report.concentration)?;
    write_json(dir.join("negative-cases.json"), &negative_cases)?;
    let queried = receiver
        .store()
        .query_deposits(
            Some("support.prompt_injection"),
            Some("treaty:buyer-llamaworks:support-ops"),
        )
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    if queried.len() != 1 {
        return Err(ChiodosPackageError::Json(
            "pheromone fixture query did not return one deposit".to_string(),
        ));
    }
    Ok(())
}

fn transit_policy_document(
    policy: &PheromoneTransitPolicy,
    context: &PheromoneValidationContext,
) -> Result<serde_json::Value, ChiodosPackageError> {
    let mut value = serde_json::to_value(policy)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    let admission = PheromoneAdmissionPolicyDocument {
        recipient_kernel_id: "did:chio:dataco".to_string(),
        authenticated_sender_kernel_id: "did:chio:buyer-kernel".to_string(),
        replay_window_ms: context.replay_window_ms,
        active_peers_in_treaty: context.active_peers_in_treaty,
        known_reputation_epochs: context.known_reputation_epochs.clone(),
        passports: context.passports.clone(),
        kernel_public_keys: context.kernel_public_keys.clone(),
        subject_classes: context.subject_classes.clone(),
        max_deposits_per_pair: context.max_deposits_per_pair,
    };
    let Some(object) = value.as_object_mut() else {
        return Err(ChiodosPackageError::Json(
            "transit policy did not serialize to an object".to_string(),
        ));
    };
    object.insert(
        "admission".to_string(),
        serde_json::to_value(admission)
            .map_err(|error| ChiodosPackageError::Json(error.to_string()))?,
    );
    Ok(value)
}

fn transit_hop(
    from_kernel_id: &str,
    to_kernel_id: &str,
    treaty_id: &str,
    manifest_id: &str,
    intersection_id: &str,
    generated_at_unix_ms: u64,
) -> PheromoneTransitHop {
    PheromoneTransitHop {
        from_kernel_id: from_kernel_id.to_string(),
        to_kernel_id: to_kernel_id.to_string(),
        treaty_id: treaty_id.to_string(),
        ladder_manifest_id: manifest_id.to_string(),
        ladder_manifest_sha256: sha256_hex(format!("{manifest_id}:{from_kernel_id}").as_bytes()),
        ladder_manifest_expires_at_unix_ms: generated_at_unix_ms.saturating_add(60_000),
        ladder_intersection_id: intersection_id.to_string(),
        action_class_id: "whisker.pheromone_deposit".to_string(),
        emitted_at_unix_ms: generated_at_unix_ms.saturating_add(100),
    }
}

fn canonical_sha256<T: serde::Serialize>(value: &T) -> Result<String, ChiodosPackageError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn write_json<T: serde::Serialize>(path: PathBuf, value: &T) -> Result<(), ChiodosPackageError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))?;
    fs::write(path, format!("{json}\n"))
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}
