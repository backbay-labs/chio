use chio_core::crypto::Keypair;
use chio_core::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};
use chio_core::receipt::authoritative_spend::BudgetAuthorityReceiptRef;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::receipt::metadata::{
    DeliveryContract, DeliveryResult, DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_finding::{
    Finding, FindingAuthorityStatus, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms, SignedFindingVerifierReport,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use chio_finding_verifier::{
    sign_finding_verifier_report, verify_finding_evidence, FindingBondSnapshot,
    FindingBondStoreSnapshot, FindingCheckpointSignerStatusTrust, FindingEvidenceBundle,
    FindingNonceResolver, FindingVerifierTrustRoots, ResolvedReceiptEvidence,
    FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1,
};
use chio_kernel::checkpoint::{build_checkpoint_transparency, KernelCheckpoint};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;

pub(super) struct FindingReportInputs<'a> {
    pub(super) governance: &'a Keypair,
    pub(super) kernel: &'a Keypair,
    pub(super) profile: &'a SignedFindingChallengeVerifierProfile,
    pub(super) finding: &'a Finding,
    pub(super) raw_finding: &'a str,
    pub(super) receipts: &'a [ResolvedReceiptEvidence],
    pub(super) checkpoint: &'a KernelCheckpoint,
    pub(super) recipe_bytes: &'a [u8],
    pub(super) backing: &'a SignedFindingBondBacking,
    pub(super) terms: &'a SignedFindingMarketTerms,
    pub(super) fee_schedule: &'a SignedOpenMarketFeeSchedule,
    pub(super) collateral: &'a Keypair,
}

pub(super) fn make_signed_finding_report(
    inputs: &FindingReportInputs<'_>,
    trusted_time: u64,
) -> Result<SignedFindingVerifierReport, Box<dyn std::error::Error>> {
    let trust = FindingVerifierTrustRoots {
        governance_authority: inputs.governance.public_key(),
        profile: inputs.profile.clone(),
        admitted_kernel_keys: vec![inputs.kernel.public_key()],
        collateral_authority: inputs.collateral.public_key(),
        fee_schedule_authorities: vec![inputs.fee_schedule.signer_key.clone()],
        runtime_attestation_authority: None,
        appraisal_authority: None,
        attestation_trust_policy: None,
        status_operator_authorization: None,
        status_freshness_policy: None,
        checkpoint_signer_status: Some(checkpoint_status_trust(
            inputs.profile,
            inputs.governance,
            trusted_time,
        )?),
        trusted_time,
        trust_root_snapshot_sha256: hex64(),
        resolver_policy_sha256: hex64(),
        trusted_time_input_sha256: hex64(),
    };
    let nonce_resolver = signed_nonce_resolver(inputs.receipts, inputs.kernel)?;
    let bundle = FindingEvidenceBundle {
        receipts: inputs
            .receipts
            .iter()
            .map(|evidence| ResolvedReceiptEvidence {
                receipt: evidence.receipt.clone(),
                canonical_receipt_bytes: evidence.canonical_receipt_bytes.clone(),
                inclusion_proof: evidence.inclusion_proof.clone(),
            })
            .collect(),
        checkpoints: vec![inputs.checkpoint.clone()],
        checkpoint_transparency: build_checkpoint_transparency(std::slice::from_ref(
            inputs.checkpoint,
        ))?,
        finding_delivery: None,
        recipe_preimage: Some(inputs.recipe_bytes),
        status_proof_input: None,
        runtime_attestation: None,
        runtime_appraisal: None,
        bond_snapshot: Some(FindingBondSnapshot {
            backing: inputs.backing.clone(),
            terms: inputs.terms.clone(),
            fee_schedule: inputs.fee_schedule.clone(),
            store_snapshot: SignedExportEnvelope::sign(
                FindingBondStoreSnapshot {
                    schema: FINDING_BOND_STORE_SNAPSHOT_SCHEMA_V1.to_owned(),
                    finding_id: inputs.backing.body.finding_id.clone(),
                    bond_ref: inputs.finding.bond_ref.clone(),
                    allocation_id: inputs.backing.body.allocation_id.clone(),
                    backing_envelope_sha256: sha256_hex(&canonical_json_bytes(inputs.backing)?),
                    live: true,
                    accepted_at: trusted_time.saturating_sub(7_200),
                    observed_at: trusted_time,
                },
                inputs.collateral,
            )?,
        }),
        nonce_resolver: &nonce_resolver,
    };
    let draft = verify_finding_evidence(inputs.raw_finding, &trust, &bundle)?;
    if !draft.satisfies_required_facets(&trust.profile.body) {
        return Err(std::io::Error::other(format!(
            "draft does not satisfy the required profile facets: {:?}",
            draft.facets
        ))
        .into());
    }
    Ok(sign_finding_verifier_report(
        &draft,
        &trust,
        "chio-finding-verifier/0.1",
        &Keypair::from_seed(&[15; 32]),
    )?)
}

fn hex64() -> String {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned()
}

pub(super) fn checkpoint_at(
    mut checkpoint: KernelCheckpoint,
    issued_at: u64,
    signer: &Keypair,
) -> Result<KernelCheckpoint, Box<dyn std::error::Error>> {
    checkpoint.body.issued_at = issued_at;
    checkpoint.signature = signer.sign(&canonical_json_bytes(&checkpoint.body)?);
    Ok(checkpoint)
}

pub(super) fn checkpoint_status_trust(
    profile: &SignedFindingChallengeVerifierProfile,
    status_authority: &Keypair,
    observed_at: u64,
) -> Result<FindingCheckpointSignerStatusTrust, Box<dyn std::error::Error>> {
    let checkpoint_signer = &profile
        .body
        .checkpoint_logs
        .first()
        .ok_or("checkpoint signer policy missing")?
        .signer;
    let policies = std::iter::once(checkpoint_signer).chain(
        profile
            .body
            .receipt_signers
            .iter()
            .map(|signer| &signer.policy),
    );
    let mut signed_statuses = Vec::new();
    for policy in policies {
        let already_present =
            signed_statuses
                .iter()
                .any(|signed: &chio_finding::SignedFindingAuthorityStatus| {
                    signed.body.status_ref == policy.revocation_status_ref
                        && signed.body.authority_id == policy.authority_id
                        && signed.body.key == policy.key
                        && signed.body.key_epoch == policy.key_epoch
                });
        if already_present {
            continue;
        }
        signed_statuses.push(SignedExportEnvelope::sign(
            FindingAuthorityStatus {
                schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.to_owned(),
                status_ref: policy.revocation_status_ref.clone(),
                authority_id: policy.authority_id.clone(),
                key: policy.key.clone(),
                key_epoch: policy.key_epoch,
                revoked_from: None,
                observed_at,
            },
            status_authority,
        )?);
    }
    Ok(FindingCheckpointSignerStatusTrust {
        signed_statuses,
        status_authority: status_authority.public_key(),
        max_age_secs: 300,
    })
}

fn add_mediated_spend_metadata(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    index: u32,
) {
    metadata.insert(
        "budget_authority".to_owned(),
        serde_json::json!({
            "guarantee_level": "single_node_atomic",
            "authority_profile": "authoritative_hold_event",
            "metering_profile": "max_cost_preauthorize_then_reconcile_actual",
            "hold_id": format!("hold-evidence-{index}"),
            "execution_nonce_id": format!("nonce-evidence-{index}"),
            "mediated_spend": { "profile": "chio.mediated_spend.v1" },
            "authorize": {
                "event_id": format!("hold-evidence-{index}:authorize"),
                "exposure_units": 5,
                "committed_cost_units_after": 5
            },
            "terminal": {
                "disposition": "reconciled",
                "event_id": format!("hold-evidence-{index}:reconcile"),
                "exposure_units": 5,
                "realized_spend_units": 5,
                "committed_cost_units_after": 5
            }
        }),
    );
    metadata.insert(
        "financial".to_owned(),
        serde_json::json!({
            "grant_index": 0,
            "cost_charged": 5,
            "currency": "USD",
            "budget_remaining": 95,
            "budget_total": 100,
            "delegation_depth": 0,
            "root_budget_holder": "finding-producer",
            "settlement_status": "settled"
        }),
    );
}

pub(super) fn matched_delivery_metadata(
    content_hash: &str,
    index: u32,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut metadata = serde_json::Map::new();
    add_mediated_spend_metadata(&mut metadata, index);
    metadata.insert(
        DELIVERY_CONTRACT_METADATA_KEY.to_owned(),
        serde_json::to_value(DeliveryContract {
            schema: DELIVERY_CONTRACT_SCHEMA.to_owned(),
            expected_digest: content_hash.to_owned(),
            observed_digest: content_hash.to_owned(),
            result: DeliveryResult::Matched,
        })?,
    );
    Ok(serde_json::Value::Object(metadata))
}

pub(super) struct TestFindingNonceResolver {
    nonces: Vec<SignedExecutionNonce>,
}

impl FindingNonceResolver for TestFindingNonceResolver {
    fn nonce_for(&self, receipt: &ChioReceipt) -> Option<&SignedExecutionNonce> {
        let nonce_id = BudgetAuthorityReceiptRef::from_receipt(receipt)?.execution_nonce_id?;
        self.nonces
            .iter()
            .find(|nonce| nonce.nonce.nonce_id == nonce_id)
    }
}

pub(super) fn signed_nonce_resolver(
    receipts: &[ResolvedReceiptEvidence],
    kernel: &Keypair,
) -> Result<TestFindingNonceResolver, Box<dyn std::error::Error>> {
    let nonces = receipts
        .iter()
        .map(|evidence| signed_nonce(&evidence.receipt, kernel))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TestFindingNonceResolver { nonces })
}

fn signed_nonce(
    receipt: &ChioReceipt,
    kernel: &Keypair,
) -> Result<SignedExecutionNonce, Box<dyn std::error::Error>> {
    let budget = BudgetAuthorityReceiptRef::from_receipt(receipt)
        .ok_or("receipt budget authority missing")?;
    let nonce = ExecutionNonce {
        schema: "chio.execution_nonce.v1".to_owned(),
        nonce_id: budget
            .execution_nonce_id
            .ok_or("receipt execution nonce id missing")?,
        issued_at: i64::try_from(receipt.timestamp.saturating_sub(1))?,
        expires_at: i64::try_from(receipt.timestamp.saturating_add(60))?,
        bound_to: NonceBinding {
            subject_id: "finding-producer".to_owned(),
            request_id: format!("request-{}", receipt.id),
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            parameter_hash: receipt.action.parameter_hash.clone(),
        },
        reserved_hold_id: Some(budget.hold_id),
        reserving_request_id: None,
    };
    let signature = kernel.sign(&canonical_json_bytes(&nonce)?);
    Ok(SignedExecutionNonce { nonce, signature })
}
