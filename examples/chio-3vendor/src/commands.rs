use std::fs;
use std::path::PathBuf;

use chio_attest_loopback::{
    authority_issuance_request_for_package, authority_profile_document, authority_profile_json,
    authority_signing_keys_document, disclosure_policy, fresh_proof_package, issuance_request_json,
    package_json, peer_pins_document_for_package, peer_pins_json, proof_package_from_json,
    report_json, revocation_publication_request, revocation_publication_request_json,
    signing_keys_json, verification_context, verification_context_json,
    verifier_trust_bundle_document_for_package, verifier_trust_bundle_json, verify_package,
    write_signed_negative_case_inputs, ChioPackageError, ChioProofPackage, ChioVerificationContext,
    ChioVerifierTrustBundle, ChioVerifierTrustBundleDocument, VerifierReport,
};
use chio_core_types::merkle::MerkleTree;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex, Keypair, SigningAlgorithm};
use chio_federation::{
    pheromone_gossip::verify_pheromone_gossip_frame, pheromone_gossip::PheromoneDepositGossip,
    pheromone_gossip::PheromoneGossipBatch, pheromone_gossip::PheromoneTransitChain,
    pheromone_gossip::PheromoneTransitHop, pheromone_gossip::PheromoneTransitLadderPin,
    pheromone_gossip::PheromoneTransitPolicy, pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA,
    pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA, pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA,
};
use chio_pheromone::{
    agent_passport_jwk_thumbprint, agent_passport_key_hash, scarcity_policy_sha256,
    scarcity_window_id, sign_deposit, CostCommitmentPolicy, ObservationCostVerificationMode,
    PassportAdmission, PheromoneCostCommitment, PheromoneDeposit, PheromoneDepositBody,
    PheromoneObservationCostAmount, PheromoneObservationCostLeaf,
    PheromoneObservationCostStatement, PheromoneObservationCostTelemetryRoot,
    PheromoneObservationCostVerifierRoot, PheromoneObservationCostVerifierRootBody,
    PheromoneRuntimeTrustFloorState, PheromoneScarcityPolicy, PheromoneValidationContext,
    PheromoneWorkflowContext, Severity, SubjectClassPolicy, OBSERVATION_COST_TELEMETRY_ALGORITHM,
    OBSERVATION_COST_UNIT, PHEROMONE_COST_COMMITMENT_SCHEMA, PHEROMONE_DEPOSIT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA, PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA,
    PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA, PHEROMONE_SCARCITY_POLICY_SCHEMA,
    PHEROMONE_WORKFLOW_CONTEXT_SCHEMA,
};
use chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore;
use chio_pheromone_runtime::{
    runtime_policy_document_sha256, runtime_policy_from_json, ChioWorkflowProofPackage,
    ChioWorkflowVerificationContext, ChioWorkflowVerifierTrustBundle, PeerWeightEntry,
    PeerWeightsDocument, PheromoneAdmissionPolicyDocument, PheromoneReceiver,
    PheromoneRuntimeStore, StaticPeerWeightProvider, VerifiedChioWorkflowResolver,
    PHEROMONE_PEER_WEIGHTS_SCHEMA,
};

pub fn run_from_env() -> Result<(), ChioPackageError> {
    let args = std::env::args().collect::<Vec<_>>();
    run_with_args(&args)
}

pub fn run_with_args(args: &[String]) -> Result<(), ChioPackageError> {
    let command = Command::parse(args)?;
    execute_command(command)
}

enum Command {
    PrintPackage,
    PrintReport,
    SignTransitPolicy { body: PathBuf, out: PathBuf },
    WriteOutDir { dir: PathBuf },
    WriteSignedNegativeDir { dir: PathBuf },
    WriteAuthorityInputDir { dir: PathBuf },
    WriteAuthorityInputForPackage { package: PathBuf, dir: PathBuf },
    WritePheromoneOutDir { dir: PathBuf },
    WritePheromoneForPackage { package: PathBuf, dir: PathBuf },
}

impl Command {
    fn parse(args: &[String]) -> Result<Self, ChioPackageError> {
        let argv0 = args
            .first()
            .cloned()
            .unwrap_or_else(|| "generate-chio-three-vendor-fixtures".to_string());
        match args {
            [_] => Ok(Self::PrintPackage),
            [_, flag] if flag == "--report" => Ok(Self::PrintReport),
            [_, flag, body, out] if flag == "--sign-transit-policy" => {
                Ok(Self::SignTransitPolicy {
                    body: PathBuf::from(body),
                    out: PathBuf::from(out),
                })
            }
            [_, flag, dir] if flag == "--out-dir" => Ok(Self::WriteOutDir {
                dir: PathBuf::from(dir),
            }),
            [_, flag, dir] if flag == "--signed-negative-dir" => Ok(Self::WriteSignedNegativeDir {
                dir: PathBuf::from(dir),
            }),
            [_, flag, dir] if flag == "--authority-input-dir" => Ok(Self::WriteAuthorityInputDir {
                dir: PathBuf::from(dir),
            }),
            [_, flag, package, dir] if flag == "--authority-input-package" => {
                Ok(Self::WriteAuthorityInputForPackage {
                    package: PathBuf::from(package),
                    dir: PathBuf::from(dir),
                })
            }
            [_, flag, dir] if flag == "--pheromone-out-dir" => Ok(Self::WritePheromoneOutDir {
                dir: PathBuf::from(dir),
            }),
            [_, flag, package, dir] if flag == "--pheromone-package" => {
                Ok(Self::WritePheromoneForPackage {
                    package: PathBuf::from(package),
                    dir: PathBuf::from(dir),
                })
            }
            _ => Err(ChioPackageError::Json(usage(&argv0))),
        }
    }
}

fn execute_command(command: Command) -> Result<(), ChioPackageError> {
    match command {
        Command::PrintPackage => {
            let package = fresh_proof_package()?;
            println!("{}", package_json(&package)?);
        }
        Command::PrintReport => {
            let VerifiedFixture {
                report,
                context: _,
                trust_bundle_document: _,
                package: _,
            } = verified_fixture()?;
            println!("{}", report_json(&report)?);
        }
        Command::SignTransitPolicy { body, out } => {
            let body_json = fs::read_to_string(body)
                .map_err(|error| ChioPackageError::Json(error.to_string()))?;
            let body: serde_json::Value = serde_json::from_str(&body_json)
                .map_err(|error| ChioPackageError::Json(error.to_string()))?;
            let runtime_issuer_key = Keypair::from_seed(&[42; 32]);
            let signed = SignedExportEnvelope::sign(body, &runtime_issuer_key)
                .map_err(|error| ChioPackageError::Json(error.to_string()))?;
            write_json(out, &signed)?;
        }
        Command::WriteOutDir { dir } => {
            let VerifiedFixture {
                package,
                context,
                trust_bundle_document,
                report,
            } = verified_fixture()?;
            write_out_dir(&package, &context, &trust_bundle_document, &report, dir)?;
        }
        Command::WriteSignedNegativeDir { dir } => {
            write_signed_negative_case_inputs(&dir)?;
        }
        Command::WriteAuthorityInputDir { dir } => {
            let package = fresh_proof_package()?;
            write_authority_input_dir(&package, dir)?;
        }
        Command::WriteAuthorityInputForPackage { package, dir } => {
            let package_json = fs::read_to_string(package)
                .map_err(|error| ChioPackageError::Json(error.to_string()))?;
            let package = proof_package_from_json(&package_json)?;
            write_authority_input_dir(&package, dir)?;
        }
        Command::WritePheromoneOutDir { dir } => {
            let package = fresh_proof_package()?;
            write_pheromone_fixtures(&package, &dir)?;
        }
        Command::WritePheromoneForPackage { package, dir } => {
            let package_json = fs::read_to_string(package)
                .map_err(|error| ChioPackageError::Json(error.to_string()))?;
            let package = proof_package_from_json(&package_json)?;
            write_pheromone_fixtures(&package, &dir)?;
        }
    }
    Ok(())
}

fn usage(argv0: &str) -> String {
    format!(
        "usage: {argv0} [--report|--out-dir DIR|--signed-negative-dir DIR|--authority-input-dir DIR|--authority-input-package PACKAGE DIR|--pheromone-out-dir DIR|--pheromone-package PACKAGE DIR|--sign-transit-policy BODY OUT]"
    )
}

struct VerifiedFixture {
    package: ChioProofPackage,
    context: ChioVerificationContext,
    trust_bundle_document: ChioVerifierTrustBundleDocument,
    report: VerifierReport,
}

fn verified_fixture() -> Result<VerifiedFixture, ChioPackageError> {
    let package = fresh_proof_package()?;
    let context = verification_context();
    let runtime_issuer_key = Keypair::from_seed(&[42; 32]);
    let mut trust_bundle_document = verifier_trust_bundle_document_for_package(&package)?;
    trust_bundle_document.runtime_policy_issuer_public_keys = vec![runtime_issuer_key.public_key()];
    let trust_bundle = ChioVerifierTrustBundle::from_document(trust_bundle_document.clone())?;
    let report = verify_package(&package, &trust_bundle, &context)?;
    Ok(VerifiedFixture {
        package,
        context,
        trust_bundle_document,
        report,
    })
}

fn write_out_dir(
    package: &ChioProofPackage,
    context: &ChioVerificationContext,
    trust_bundle_document: &ChioVerifierTrustBundleDocument,
    report: &VerifierReport,
    dir: PathBuf,
) -> Result<(), ChioPackageError> {
    fs::create_dir_all(&dir).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("buyer-auditor-proof-package.json"),
        package_json(package)?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("selective-disclosure-proof.json"),
        serde_json::to_string_pretty(&package.selective_disclosure_proof)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("verifier-trust-bundle.json"),
        verifier_trust_bundle_json(trust_bundle_document)?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("verification-context.json"),
        verification_context_json(context)?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("verifier-report.json"),
        format!("{}\n", report_json(report)?),
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))
}

fn write_authority_input_dir(
    package: &ChioProofPackage,
    dir: PathBuf,
) -> Result<(), ChioPackageError> {
    fs::create_dir_all(&dir).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("authority-profile.json"),
        authority_profile_json(&authority_profile_document()?)?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("issuance-request.json"),
        issuance_request_json(&authority_issuance_request_for_package(package)?)?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("local-signing-keys.json"),
        signing_keys_json(&authority_signing_keys_document())?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("peer-pins.json"),
        peer_pins_json(&peer_pins_document_for_package(package))?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("workflow-intersection.json"),
        serde_json::to_string_pretty(&package.workflow_intersection)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("disclosure-policy.json"),
        serde_json::to_string_pretty(&disclosure_policy())
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(
        dir.join("revocation-publication-request.json"),
        revocation_publication_request_json(&revocation_publication_request(Vec::new()))?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))
}

fn write_pheromone_fixtures(
    package: &ChioProofPackage,
    dir: &PathBuf,
) -> Result<(), ChioPackageError> {
    fs::create_dir_all(dir).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let passport_key = Keypair::from_seed(&[31; 32]);
    let buyer_kernel_key = Keypair::from_seed(&[11; 32]);
    let verifier_key = Keypair::from_seed(&[41; 32]);
    let runtime_issuer_key = Keypair::from_seed(&[42; 32]);
    let step = package
        .workflow_receipt
        .steps
        .first()
        .ok_or_else(|| ChioPackageError::Json("workflow has no steps".to_string()))?;
    let workflow_receipt_sha256 = canonical_sha256(&package.workflow_receipt)?;
    let workflow_intersection_sha256 = canonical_sha256(&package.workflow_intersection)?;
    let workflow_context =
        PheromoneWorkflowContext {
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
                .ok_or_else(|| ChioPackageError::Json("step has no tool receipt".to_string()))?,
            bilateral_dsse_sha256: step.bilateral_dsse_sha256.clone().ok_or_else(|| {
                ChioPackageError::Json("step has no bilateral DSSE hash".to_string())
            })?,
            consistency_anchor: step.consistency_anchor.clone().ok_or_else(|| {
                ChioPackageError::Json("step has no consistency anchor".to_string())
            })?,
        };
    let public_key = passport_key.public_key();
    let mut deposit = sign_deposit(
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
            treaty_scope: vec![
                "treaty:buyer-llamaworks:support-ops".to_string(),
                "treaty:buyer-dataco:support-ops".to_string(),
            ],
            cost_commitment: None,
            workflow_context: Some(workflow_context),
        },
        &passport_key,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let policy = PheromoneTransitPolicy {
        schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
        accepted_hubs: vec!["did:chio:buyer-kernel".to_string()],
        allowed_ingress_treaties: vec!["treaty:buyer-llamaworks:support-ops".to_string()],
        allowed_egress_treaties: vec![
            "treaty:buyer-llamaworks:support-ops".to_string(),
            "treaty:buyer-dataco:support-ops".to_string(),
            "treaty:buyer-payswift:support-ops".to_string(),
        ],
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        valid_from_unix_ms: package.generated_at_unix_ms.saturating_sub(60_000),
        valid_until_unix_ms: package.generated_at_unix_ms.saturating_add(60_000),
        max_hops: 2,
        required_action_class_id: "whisker.pheromone_deposit".to_string(),
        pinned_ladder_refs: vec![
            PheromoneTransitLadderPin {
                ladder_manifest_id: "ladder:llamaworks:support:v1".to_string(),
                ladder_manifest_sha256:
                    "f3986da48b82e0d79dab80d1e6660a261e7efc6b06e1d96755bbbedb21d6e197".to_string(),
                ladder_manifest_expires_at_unix_ms: package
                    .generated_at_unix_ms
                    .saturating_add(60_000),
                ladder_intersection_id: "intersection:buyer:llamaworks".to_string(),
                ladder_intersection_sha256: sha256_hex(b"intersection:buyer:llamaworks:v1"),
            },
            PheromoneTransitLadderPin {
                ladder_manifest_id: "ladder:buyer:refund:v1".to_string(),
                ladder_manifest_sha256:
                    "baa26007ba6c2515c233c8bc78e4ea338d81a51e555bd58decdbdebbfd60c4f9".to_string(),
                ladder_manifest_expires_at_unix_ms: package
                    .generated_at_unix_ms
                    .saturating_add(60_000),
                ladder_intersection_id: "intersection:buyer:dataco".to_string(),
                ladder_intersection_sha256: sha256_hex(b"intersection:buyer:dataco:v1"),
            },
        ],
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
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let mut batch = PheromoneGossipBatch {
        schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
        recipient_kernel_id: "did:chio:dataco".to_string(),
        treaty_id: frame.treaty_id.clone(),
        frames: vec![frame],
        flushed_at_unix_ms: package.generated_at_unix_ms.saturating_add(500),
    };
    let mut scarcity_policy = PheromoneScarcityPolicy {
        schema: PHEROMONE_SCARCITY_POLICY_SCHEMA.to_string(),
        policy_id: "scarcity:buyer-dataco:support-ops:epoch42".to_string(),
        reputation_epoch: 42,
        window_id: String::new(),
        window_start_unix_ms: package.generated_at_unix_ms.saturating_sub(60_000),
        window_end_unix_ms: package.generated_at_unix_ms.saturating_add(60_000),
        token_capacity: 8,
        newcomer_horizon_epochs: 8,
        treaty_scope: vec!["treaty:buyer-dataco:support-ops".to_string()],
        subject_class_namespace: "dev.chio.support".to_string(),
        subject_class: "support.prompt_injection".to_string(),
        observation_cost_verification: ObservationCostVerificationMode::Required,
        verifier_id: "did:chio:dataco-cost-verifier".to_string(),
        runtime_policy_sha256: "0".repeat(64),
        policy_sha256: "0".repeat(64),
        active_peers_epoch: 42,
    };
    let scarcity_treaty_id = scarcity_policy
        .treaty_scope
        .first()
        .ok_or_else(|| ChioPackageError::Json("scarcity policy has no treaty".to_string()))?
        .clone();
    scarcity_policy.window_id = scarcity_window_id(&scarcity_policy, &scarcity_treaty_id)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;

    let trust_floor_state = PheromoneRuntimeTrustFloorState {
        schema: chio_pheromone::RUNTIME_TRUST_FLOOR_STATE_SCHEMA.to_string(),
        entries: vec![chio_pheromone::PheromoneRuntimeTrustFloorEntry {
            verifier_id: "did:chio:dataco-cost-verifier".to_string(),
            key_id: "cost-root-key-1".to_string(),
            highest_version: 1,
            latest_bundle_sha256: sha256_hex(b"dataco-cost-verifier-trust-bundle:v1"),
            latest_revocation_checkpoint_sha256: sha256_hex(
                b"dataco-cost-verifier-revocation-checkpoint:v1",
            ),
        }],
    };
    let validation_context = PheromoneValidationContext {
        now_unix_ms: package.generated_at_unix_ms.saturating_add(500),
        replay_window_ms: 86_400_000,
        active_peers_in_treaty: 9,
        active_reputation_epoch: 42,
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
            allowed_treaties: vec!["treaty:buyer-dataco:support-ops".to_string()],
            cost_commitment: CostCommitmentPolicy::NotRequired,
            destructive: false,
        }],
        max_deposits_per_pair: 8,
        scarcity_policies: vec![scarcity_policy],
        runtime_policy_sha256: Some("0".repeat(64)),
        runtime_policy_issuer_public_keys: vec![runtime_issuer_key.public_key()],
        observation_cost_verifier_roots: vec![observation_cost_verifier_root(
            &verifier_key,
            &runtime_issuer_key,
            "0",
            package.generated_at_unix_ms,
        )?],
        runtime_trust_floor_state: trust_floor_state,
    };
    let mut policy_document = transit_policy_document(&policy, &validation_context)?;
    seal_runtime_policy_document_hashes(&mut policy_document, &runtime_issuer_key)?;
    let signed_policy_document =
        SignedExportEnvelope::sign(policy_document.clone(), &runtime_issuer_key)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let (loaded_policy, receiver_config) = runtime_policy_from_json(
        &serde_json::to_string(&signed_policy_document)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
        package.generated_at_unix_ms.saturating_add(500),
        &[runtime_issuer_key.public_key()],
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let selected_policy = receiver_config
        .validation_context
        .scarcity_policies
        .first()
        .ok_or_else(|| {
            ChioPackageError::Json("sealed runtime policy has no scarcity policy".to_string())
        })?
        .clone();
    let runtime_policy_sha256 = receiver_config
        .validation_context
        .runtime_policy_sha256
        .as_deref()
        .ok_or_else(|| ChioPackageError::Json("sealed runtime policy has no hash".to_string()))?
        .to_string();
    deposit.body.cost_commitment = Some(signed_cost_commitment(
        &deposit,
        &selected_policy,
        &verifier_key,
        &runtime_policy_sha256,
        package.generated_at_unix_ms,
    )?);
    batch.frames[0].deposit = deposit.clone();
    verify_pheromone_gossip_frame(
        &batch.frames[0],
        &loaded_policy,
        package.generated_at_unix_ms.saturating_add(500),
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let mut trust_bundle_document = verifier_trust_bundle_document_for_package(package)?;
    trust_bundle_document.runtime_policy_issuer_public_keys = vec![runtime_issuer_key.public_key()];
    let context = verification_context();
    let chio_package = ChioWorkflowProofPackage::from_json(&package_json(package)?)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let chio_trust_bundle = ChioWorkflowVerifierTrustBundle::from_json(
        &verifier_trust_bundle_json(&trust_bundle_document)?,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let chio_context =
        ChioWorkflowVerificationContext::from_json(&verification_context_json(&context)?)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let resolver = VerifiedChioWorkflowResolver::from_verified_package(
        &chio_package,
        &chio_trust_bundle,
        &chio_context,
    )
    .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let store = SqlitePheromoneRuntimeStore::open_in_memory()
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let receiver = PheromoneReceiver::new(store, resolver, receiver_config);
    let receive_report = receiver
        .receive_batch(&batch, &loaded_policy)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
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
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
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
                "expected_failure_code": "observation_cost_commitment_missing"
            },
            {
                "id": "stale-transit-policy",
                "target": "policy",
                "mutation": {"op": "set", "path": ["body", "valid_until_unix_ms"], "value": package.generated_at_unix_ms},
                "expected_failure_code": "transit_policy_violation"
            }
        ]
    });

    write_json(dir.join("deposit.json"), &deposit)?;
    write_json(dir.join("gossip-batch.json"), &batch)?;
    write_json(dir.join("transit-policy.json"), &signed_policy_document)?;
    write_json(dir.join("receive-report.json"), &receive_report)?;
    write_json(dir.join("peer-weights.json"), &peer_weights)?;
    write_json(dir.join("query-report.json"), &query_report)?;
    write_json(dir.join("concentration.json"), &query_report.concentration)?;
    write_json(dir.join("negative-cases.json"), &negative_cases)?;
    let queried = receiver
        .store()
        .query_deposits(
            Some("support.prompt_injection"),
            Some("treaty:buyer-dataco:support-ops"),
        )
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    if queried.len() != 1 {
        return Err(ChioPackageError::Json(
            "pheromone fixture query did not return one deposit".to_string(),
        ));
    }
    Ok(())
}

fn transit_policy_document(
    policy: &PheromoneTransitPolicy,
    context: &PheromoneValidationContext,
) -> Result<serde_json::Value, ChioPackageError> {
    let mut value =
        serde_json::to_value(policy).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let admission = PheromoneAdmissionPolicyDocument {
        recipient_kernel_id: "did:chio:dataco".to_string(),
        authenticated_sender_kernel_id: "did:chio:buyer-kernel".to_string(),
        replay_window_ms: context.replay_window_ms,
        active_peers_in_treaty: context.active_peers_in_treaty,
        active_reputation_epoch: context.active_reputation_epoch,
        known_reputation_epochs: context.known_reputation_epochs.clone(),
        passports: context.passports.clone(),
        kernel_public_keys: context.kernel_public_keys.clone(),
        subject_classes: context.subject_classes.clone(),
        max_deposits_per_pair: context.max_deposits_per_pair,
        scarcity_policies: context.scarcity_policies.clone(),
        runtime_policy_issuer_public_keys: context.runtime_policy_issuer_public_keys.clone(),
        observation_cost_verifier_roots: context.observation_cost_verifier_roots.clone(),
        runtime_trust_floor_state: context.runtime_trust_floor_state.clone(),
    };
    let Some(object) = value.as_object_mut() else {
        return Err(ChioPackageError::Json(
            "transit policy did not serialize to an object".to_string(),
        ));
    };
    object.insert(
        "admission".to_string(),
        serde_json::to_value(admission)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
    );
    Ok(value)
}

fn seal_runtime_policy_document_hashes(
    value: &mut serde_json::Value,
    runtime_issuer_key: &Keypair,
) -> Result<(), ChioPackageError> {
    let policies = value
        .get_mut("admission")
        .and_then(|admission| admission.get_mut("scarcityPolicies"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| ChioPackageError::Json("missing scarcity policies".to_string()))?;
    for policy in policies {
        let reputation_epoch = policy
            .get("reputationEpoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ChioPackageError::Json("missing reputation epoch".to_string()))?;
        policy["activePeersEpoch"] = serde_json::json!(reputation_epoch);
        policy["runtimePolicySha256"] = serde_json::json!("0".repeat(64));
        policy["policySha256"] = serde_json::json!("0".repeat(64));
    }
    let runtime_policy_sha256 = runtime_policy_document_sha256(value)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let roots = value
        .get_mut("admission")
        .and_then(|admission| admission.get_mut("observationCostVerifierRoots"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| ChioPackageError::Json("missing verifier roots".to_string()))?;
    for root in roots {
        root["runtimePolicySha256"] = serde_json::json!(runtime_policy_sha256);
        let parsed: PheromoneObservationCostVerifierRoot = serde_json::from_value(root.clone())
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;
        let (signature, _) = runtime_issuer_key
            .sign_canonical(&parsed.body)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;
        root["issuerSignature"] = serde_json::json!(signature.to_hex());
    }
    let policies = value
        .get_mut("admission")
        .and_then(|admission| admission.get_mut("scarcityPolicies"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| ChioPackageError::Json("missing scarcity policies".to_string()))?;
    for policy in policies {
        policy["runtimePolicySha256"] = serde_json::json!(runtime_policy_sha256);
        let parsed: PheromoneScarcityPolicy = serde_json::from_value(policy.clone())
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;
        policy["policySha256"] = serde_json::json!(scarcity_policy_sha256(&parsed)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?);
    }
    Ok(())
}

fn observation_cost_verifier_root(
    verifier_key: &Keypair,
    runtime_issuer_key: &Keypair,
    runtime_policy_sha256: &str,
    generated_at_unix_ms: u64,
) -> Result<PheromoneObservationCostVerifierRoot, ChioPackageError> {
    let body = PheromoneObservationCostVerifierRootBody {
        schema: PHEROMONE_OBSERVATION_COST_VERIFIER_ROOT_SCHEMA.to_string(),
        verifier_id: "did:chio:dataco-cost-verifier".to_string(),
        verifier_key_id: "cost-root-key-1".to_string(),
        public_key: verifier_key.public_key(),
        signature_algorithm: SigningAlgorithm::Ed25519,
        valid_from_unix_ms: generated_at_unix_ms.saturating_sub(60_000),
        valid_until_unix_ms: generated_at_unix_ms.saturating_add(60_000),
        allowed_treaties: vec!["treaty:buyer-dataco:support-ops".to_string()],
        allowed_subject_class_namespaces: vec!["dev.chio.support".to_string()],
        allowed_subject_classes: vec!["support.prompt_injection".to_string()],
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
        issuer_kernel_id: "did:chio:dataco-runtime".to_string(),
    };
    let (issuer_signature, _) = runtime_issuer_key
        .sign_canonical(&body)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    Ok(PheromoneObservationCostVerifierRoot {
        body,
        issuer_signature,
    })
}

fn signed_cost_commitment(
    deposit: &PheromoneDeposit,
    policy: &PheromoneScarcityPolicy,
    verifier_key: &Keypair,
    runtime_policy_sha256: &str,
    generated_at_unix_ms: u64,
) -> Result<PheromoneCostCommitment, ChioPackageError> {
    let cost = PheromoneObservationCostAmount {
        unit: OBSERVATION_COST_UNIT.to_string(),
        amount: 125,
    };
    let leaf = PheromoneObservationCostLeaf {
        schema: PHEROMONE_OBSERVATION_COST_LEAF_SCHEMA.to_string(),
        deposit_body_sha256: deposit_body_sha256(deposit)?,
        deposit_signature_sha256: deposit_signature_sha256(deposit),
        kernel_id: deposit.body.kernel_id.clone(),
        agent_passport_key_hash: deposit.body.agent_passport_key_hash.clone(),
        treaty_id: policy
            .treaty_scope
            .first()
            .ok_or_else(|| ChioPackageError::Json("cost policy has no treaty".to_string()))?
            .clone(),
        subject_class_namespace: deposit.body.subject_class_namespace.clone(),
        subject_class: deposit.body.subject_class.clone(),
        observed_at_unix_ms: generated_at_unix_ms,
        event_digest_sha256: sha256_hex(b"llamaworks-observation-event"),
        cost: cost.clone(),
        scarcity_policy_sha256: scarcity_policy_sha256(policy)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
    };
    let leaf_bytes =
        canonical_json_bytes(&leaf).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let tree = MerkleTree::from_leaves(std::slice::from_ref(&leaf_bytes))
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    let statement = PheromoneObservationCostStatement {
        schema: PHEROMONE_OBSERVATION_COST_STATEMENT_SCHEMA.to_string(),
        commitment_id: "cost-commitment-llamaworks-001".to_string(),
        verifier_id: policy.verifier_id.clone(),
        verifier_key_id: "cost-root-key-1".to_string(),
        runtime_policy_sha256: runtime_policy_sha256.to_string(),
        scarcity_policy_sha256: leaf.scarcity_policy_sha256.clone(),
        deposit_body_sha256: leaf.deposit_body_sha256.clone(),
        deposit_signature_sha256: leaf.deposit_signature_sha256.clone(),
        kernel_id: leaf.kernel_id.clone(),
        agent_passport_key_hash: leaf.agent_passport_key_hash.clone(),
        treaty_id: leaf.treaty_id.clone(),
        subject_class_namespace: leaf.subject_class_namespace.clone(),
        subject_class: leaf.subject_class.clone(),
        observation_window_start_unix_ms: policy.window_start_unix_ms,
        observation_window_end_unix_ms: policy.window_end_unix_ms,
        observed_at_unix_ms: leaf.observed_at_unix_ms,
        event_digest_sha256: leaf.event_digest_sha256.clone(),
        cost,
        telemetry: PheromoneObservationCostTelemetryRoot {
            schema: PHEROMONE_OBSERVATION_COST_TELEMETRY_ROOT_SCHEMA.to_string(),
            algorithm: OBSERVATION_COST_TELEMETRY_ALGORITHM.to_string(),
            root_hash: tree.root(),
            tree_size: 1,
            verifier_id: policy.verifier_id.clone(),
            verifier_key_id: "cost-root-key-1".to_string(),
            closed_at_unix_ms: generated_at_unix_ms.saturating_add(250),
        },
        inclusion_proof: tree
            .inclusion_proof(0)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?,
        leaf_preimage_sha256: sha256_hex(&leaf_bytes),
    };
    let (signature, _) = verifier_key
        .sign_canonical(&statement)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    Ok(PheromoneCostCommitment {
        schema: PHEROMONE_COST_COMMITMENT_SCHEMA.to_string(),
        statement,
        signature,
    })
}

fn deposit_body_sha256(deposit: &PheromoneDeposit) -> Result<String, ChioPackageError> {
    let mut signed_body = deposit.body.clone();
    signed_body.cost_commitment = None;
    canonical_sha256(&signed_body)
}

fn deposit_signature_sha256(deposit: &PheromoneDeposit) -> String {
    sha256_hex(deposit.signature.to_hex().as_bytes())
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
        ladder_intersection_sha256: sha256_hex(format!("{intersection_id}:v1").as_bytes()),
        action_class_id: "whisker.pheromone_deposit".to_string(),
        emitted_at_unix_ms: generated_at_unix_ms.saturating_add(100),
    }
}

fn canonical_sha256<T: serde::Serialize>(value: &T) -> Result<String, ChioPackageError> {
    let bytes =
        canonical_json_bytes(value).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn write_json<T: serde::Serialize>(path: PathBuf, value: &T) -> Result<(), ChioPackageError> {
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ChioPackageError::Json(format!(
                "refusing symlinked output path {}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ChioPackageError::Json(error.to_string())),
    }
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| ChioPackageError::Json(error.to_string()))?;
    fs::write(path, format!("{json}\n")).map_err(|error| ChioPackageError::Json(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{run_with_args, write_json, ChioPackageError, Command};
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(prefix: &str) -> Result<PathBuf, ChioPackageError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?
            .as_nanos();
        Ok(std::env::temp_dir().join(format!("{prefix}-{nonce}")))
    }

    #[test]
    fn run_with_args_rejects_unknown_command_before_fixture_generation() {
        let args = vec![
            "generate-chio-three-vendor-fixtures".to_string(),
            "--bogus".to_string(),
        ];

        let error = match run_with_args(&args) {
            Err(error) => error,
            Ok(()) => panic!("unknown command should fail"),
        };

        assert!(error
            .to_string()
            .contains("usage: generate-chio-three-vendor-fixtures"));
    }

    #[test]
    fn command_parse_sign_transit_policy_preserves_paths() -> Result<(), ChioPackageError> {
        let args = vec![
            "generate-chio-three-vendor-fixtures".to_string(),
            "--sign-transit-policy".to_string(),
            "transit-policy-body.json".to_string(),
            "signed-transit-policy.json".to_string(),
        ];

        let command = Command::parse(&args)?;

        match command {
            Command::SignTransitPolicy { body, out } => {
                assert_eq!(body, PathBuf::from("transit-policy-body.json"));
                assert_eq!(out, PathBuf::from("signed-transit-policy.json"));
            }
            _ => panic!("expected sign-transit-policy command"),
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn write_json_rejects_symlinked_output_file() -> Result<(), ChioPackageError> {
        let dir = unique_dir("chio-three-vendor-output")?;
        let outside = unique_dir("chio-three-vendor-outside")?;
        fs::create_dir_all(&dir).map_err(|error| ChioPackageError::Json(error.to_string()))?;
        fs::create_dir_all(&outside).map_err(|error| ChioPackageError::Json(error.to_string()))?;
        let outside_target = outside.join("target.json");
        fs::write(&outside_target, "{}\n")
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;
        let link_path = dir.join("fixture.json");
        std::os::unix::fs::symlink(&outside_target, &link_path)
            .map_err(|error| ChioPackageError::Json(error.to_string()))?;

        let result = write_json(link_path, &json!({"escaped": true}));

        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
        match result {
            Err(ChioPackageError::Json(message)) => assert!(message.contains("symlink")),
            Err(error) => panic!("expected Json symlink error, got {error}"),
            Ok(()) => panic!("symlinked output file should fail closed"),
        }
        Ok(())
    }
}
