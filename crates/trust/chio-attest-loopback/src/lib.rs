//! Offline Chio buyer and auditor proof package loopback harness.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub use chio_attest_buyer_core::claims::{
    ChioProofClaims, LeaseScopeBindingArtifact, PeerLadderBinding, VendorKeyBinding,
    WorkflowIntersectionArtifact, WorkflowPairwiseIntersectionRef, WorkflowRequiredVendorSigner,
    WorkflowStepClassBinding, LEASE_SCOPE_BINDING_SCHEMA, WORKFLOW_INTERSECTION_SCHEMA,
};
pub use chio_attest_buyer_core::context::{
    verification_context_from_json, verification_context_json, ChioVerificationContext,
    VERIFICATION_CONTEXT_SCHEMA,
};
pub use chio_attest_buyer_core::disclosure::ChioDisclosurePolicy;
pub use chio_attest_buyer_core::error::ChioPackageError;
pub use chio_attest_buyer_core::issuer::TrustedBbsIssuer;
pub use chio_attest_buyer_core::proof_package::{
    package_json, proof_package_from_json, ChioProofPackage, PROOF_PACKAGE_SCHEMA,
};
pub use chio_attest_buyer_core::report::{
    report_json, verifier_report_from_json, verify_package, VerifierReport, VERIFIER_REPORT_SCHEMA,
};
pub use chio_attest_buyer_core::revocation::{
    ChioRevocationCheckpoint, ChioRevocationMaterial, SignedChioRevocationCheckpoint,
    REVOCATION_CHECKPOINT_SCHEMA,
};
pub use chio_attest_buyer_core::trust_bundle::{
    verifier_trust_bundle_from_json, verifier_trust_bundle_json, ChioActionClassKind,
    ChioAuthorityStatus, ChioTrustedActionClass, ChioTrustedGovernanceAuthority,
    ChioTrustedLeaseAuthority, ChioTrustedWorkflowIntersection, ChioVerifierTrustBundle,
    ChioVerifierTrustBundleDocument, VERIFIER_TRUST_BUNDLE_SCHEMA,
    WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID, WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
};
use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::{
    bilateral_dsse::sign_chio_bilateral_dsse_envelope,
    bilateral_dsse::BilateralPredicateExtensions, bilateral_dsse::CapabilityLeaseRef,
    bilateral_dsse::DsseEnvelope, bilateral_dsse::GovernanceReceiptRef, bilateral_dsse::HashRecord,
    bilateral_dsse::Keyid, bilateral_dsse::PolicyEvaluationSummary, bilateral_dsse::PolicyVerdict,
    bilateral_dsse::PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION,
    trust_establishment::LadderManifestRef,
};
pub use chio_federation_authority::{
    assemble_verifier_trust_bundle, authority_profile_json, issuance_request_json,
    issue_authority_bundle, peer_pins_json, publish_revocation_checkpoint,
    revocation_publication_request_json, signing_keys_json, AuthorityProfileDocument,
    ChioIssuanceRequest, ChioIssuanceStepRequest, ChioRevocationAuthority,
    LocalAuthoritySigningKeysDocument, NamedSeedHex, PeerPinsDocument,
    RevocationPublicationRequest, AUTHORITY_PROFILE_SCHEMA, ISSUANCE_REQUEST_SCHEMA,
    LOCAL_SIGNING_KEYS_SCHEMA, PEER_PINS_SCHEMA, REVOCATION_PUBLICATION_REQUEST_SCHEMA,
};
use chio_governance::authorization::{GovernanceReceiptCaseKind, SignedGovernanceReceipt};
use chio_governance::lease::{CapabilityLeaseActionClass, SignedCapabilityLease};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_workflow_receipt_body,
    sign_projection, DisclosureSet, SelectiveDisclosureProof,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceipt, WorkflowReceiptBody,
    WORKFLOW_RECEIPT_SCHEMA,
};
use serde::Serialize;

pub const WORKFLOW_ID: &str = "wf-chio-refund-001";
pub const GENERATED_AT_UNIX_MS: u64 = 1_766_000_000_000;

const BUYER_KERNEL_ID: &str = "did:chio:buyer-kernel";
const GOVERNANCE_KERNEL_ID: &str = "did:chio:buyer-governance";
const SESSION_ID: &str = "sess-chio-refund";
const CAPABILITY_ID: &str = "cap-chio-workflow";
const CASE_REF: &str = "refund-250";
const LEASE_ISSUED_AT_UNIX_MS: u64 = GENERATED_AT_UNIX_MS - 30_000;
const LEASE_EXPIRES_AT_UNIX_MS: u64 = GENERATED_AT_UNIX_MS + 30_000;
const GOVERNANCE_ISSUED_AT_UNIX_MS: u64 = GENERATED_AT_UNIX_MS - 20_000;
const GOVERNANCE_EXPIRES_AT_UNIX_MS: u64 = GENERATED_AT_UNIX_MS + 20_000;
const AUTHORITY_VALID_FROM_UNIX_MS: u64 = GENERATED_AT_UNIX_MS - 600_000;
const AUTHORITY_VALID_UNTIL_UNIX_MS: u64 = GENERATED_AT_UNIX_MS + 600_000;
const BBS_KEY_MATERIAL: &[u8] = b"chio-conformance-bbs-key-material-0001";
const BBS_KEY_INFO: &[u8] = b"chio";

const BUYER_SEED: [u8; 32] = [11; 32];
const GOVERNANCE_SEED: [u8; 32] = [12; 32];
const REVOCATION_SEED: [u8; 32] = [13; 32];
const RUNTIME_POLICY_SEED: [u8; 32] = [42; 32];
const VENDOR_A_SEED: [u8; 32] = [21; 32];
const VENDOR_B_SEED: [u8; 32] = [22; 32];
const VENDOR_C_SEED: [u8; 32] = [23; 32];

#[derive(Debug, Clone)]
struct VendorFixture {
    vendor_id: &'static str,
    kernel_id: &'static str,
    server_id: &'static str,
    tool_name: &'static str,
    receipt_id: &'static str,
    lease_id: &'static str,
    ladder_manifest_id: &'static str,
    seed: [u8; 32],
    destructive: bool,
    duration_ms: u64,
    cost_units: u64,
    output_label: &'static [u8],
}

const VENDORS: [VendorFixture; 3] = [
    VendorFixture {
        vendor_id: "vendor-a",
        kernel_id: "did:chio:vendor-a",
        server_id: "vendor-a.files",
        tool_name: "read_refund_case",
        receipt_id: "rcpt-vendor-a",
        lease_id: "lease-vendor-a-read",
        ladder_manifest_id: "ladder:vendor-a:refund:v1",
        seed: VENDOR_A_SEED,
        destructive: false,
        duration_ms: 12,
        cost_units: 100,
        output_label: b"vendor-a-output",
    },
    VendorFixture {
        vendor_id: "vendor-b",
        kernel_id: "did:chio:vendor-b",
        server_id: "vendor-b.kyc",
        tool_name: "verify_customer",
        receipt_id: "rcpt-vendor-b",
        lease_id: "lease-vendor-b-kyc",
        ladder_manifest_id: "ladder:vendor-b:refund:v1",
        seed: VENDOR_B_SEED,
        destructive: false,
        duration_ms: 18,
        cost_units: 200,
        output_label: b"vendor-b-output",
    },
    VendorFixture {
        vendor_id: "vendor-c",
        kernel_id: "did:chio:vendor-c",
        server_id: "vendor-c.payments",
        tool_name: "stage_refund",
        receipt_id: "rcpt-vendor-c",
        lease_id: "lease-vendor-c-refund",
        ladder_manifest_id: "ladder:vendor-c:refund:v1",
        seed: VENDOR_C_SEED,
        destructive: true,
        duration_ms: 12,
        cost_units: 250,
        output_label: b"vendor-c-output",
    },
];

#[derive(Debug, Clone)]
pub struct RuntimeProofArtifact {
    pub tool_receipt: ChioReceipt,
    pub bilateral_envelope: DsseEnvelope,
    pub workflow_step: StepRecord,
}

enum ProofPackageInput {
    Fixture,
    RuntimeReceipts(Vec<ChioReceipt>),
    RuntimeArtifacts(Vec<RuntimeProofArtifact>),
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChioPackageError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn canonical_string<T: Serialize>(value: &T) -> Result<String, ChioPackageError> {
    canonical_json_string(value).map_err(|error| ChioPackageError::Canonical(error.to_string()))
}

fn key_id(public_key: &chio_core_types::crypto::PublicKey) -> String {
    Keyid::from_public_key(public_key).0
}

fn signed_governance_digest(receipt: &SignedGovernanceReceipt) -> Result<String, ChioPackageError> {
    Ok(sha256_hex(canonical_string(receipt)?.as_bytes()))
}

fn ladder_ref(manifest_id: &str, kernel_id: &str) -> LadderManifestRef {
    LadderManifestRef {
        manifest_id: manifest_id.to_string(),
        sha256: sha256_hex(format!("{manifest_id}:{kernel_id}:manifest").as_bytes()),
        issued_at_unix_ms: GENERATED_AT_UNIX_MS - 60_000,
        expires_at_unix_ms: GENERATED_AT_UNIX_MS + 60_000,
    }
}

fn buyer_ladder_ref() -> LadderManifestRef {
    ladder_ref("ladder:buyer:refund:v1", BUYER_KERNEL_ID)
}

fn receipt_body(
    vendor: &VendorFixture,
    vendor_key: &Keypair,
) -> Result<ChioReceiptBody, ChioPackageError> {
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "workflowId": WORKFLOW_ID,
        "caseRef": CASE_REF,
        "tool": vendor.tool_name,
    }))
    .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
    Ok(ChioReceiptBody {
        id: vendor.receipt_id.to_string(),
        timestamp: GENERATED_AT_UNIX_MS / 1000,
        capability_id: vendor.lease_id.to_string(),
        tool_server: vendor.server_id.to_string(),
        tool_name: vendor.tool_name.to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![ActorRef {
            actor_id: "agent:chio-loopback".to_string(),
            actor_kind: Some("agent".to_string()),
        }],
        content_hash: sha256_hex(vendor.output_label),
        policy_hash: sha256_hex(format!("policy:{}", vendor.tool_name).as_bytes()),
        evidence: Vec::new(),
        metadata: Some(serde_json::json!({
            "workflow_id": WORKFLOW_ID,
            "vendor_id": vendor.vendor_id,
        })),
        trust_level: TrustLevel::Mediated,
        tenant_id: Some("buyer-tenant".to_string()),
        kernel_key: vendor_key.public_key(),
        bbs_projection_version: None,
    })
}

fn policy_summary(vendor: &VendorFixture) -> PolicyEvaluationSummary {
    let policy_version = "chio-ladder-v1".to_string();
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: format!("buyer-policy:{}", vendor.tool_name),
            policy_version: policy_version.clone(),
            rationale_code: Some("lease-bound".to_string()),
        },
        server_b_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: format!("{}-policy:{}", vendor.vendor_id, vendor.tool_name),
            policy_version,
            rationale_code: Some("manifest-bound".to_string()),
        },
        joint_disposition: Some("allow".to_string()),
    }
}

fn action_class_for_vendor(vendor: &VendorFixture) -> CapabilityLeaseActionClass {
    if vendor.destructive {
        CapabilityLeaseActionClass::NarrowDestructive
    } else {
        CapabilityLeaseActionClass::DelegatedAction
    }
}

fn issuance_step_request(
    vendor: &VendorFixture,
    step_index: usize,
    action_class: CapabilityLeaseActionClass,
    tool_args_hash: String,
    step_sha256: Option<String>,
) -> Result<ChioIssuanceStepRequest, ChioPackageError> {
    if vendor.destructive && step_sha256.is_none() {
        return Err(ChioPackageError::Governance(format!(
            "destructive vendor {} is missing step hash",
            vendor.vendor_id
        )));
    }
    Ok(ChioIssuanceStepRequest {
        lease_id: vendor.lease_id.to_string(),
        step_index,
        tool_name: vendor.tool_name.to_string(),
        peer_kernel_id: vendor.kernel_id.to_string(),
        action_class_id: vendor.tool_name.to_string(),
        subject: vendor.kernel_id.to_string(),
        action_class,
        tool_args_hash,
        destructive: vendor.destructive,
        lease_issued_at_unix_ms: LEASE_ISSUED_AT_UNIX_MS,
        lease_expires_at_unix_ms: LEASE_EXPIRES_AT_UNIX_MS,
        governance_receipt_id: vendor
            .destructive
            .then_some("gov-refund-stage-authorization".to_string()),
        governance_issued_at_unix_ms: vendor.destructive.then_some(GOVERNANCE_ISSUED_AT_UNIX_MS),
        governance_expires_at_unix_ms: vendor.destructive.then_some(GOVERNANCE_EXPIRES_AT_UNIX_MS),
        step_sha256,
    })
}

fn step_record(
    index: usize,
    vendor: &VendorFixture,
    receipt: &ChioReceipt,
    envelope_sha256: &str,
    parent_receipt_sha256: Option<String>,
    governance_receipt_id: Option<String>,
) -> StepRecord {
    StepRecord {
        step_index: index,
        server_id: vendor.server_id.to_string(),
        tool_name: vendor.tool_name.to_string(),
        allowed: true,
        tool_receipt_id: Some(receipt.id.clone()),
        outcome: StepOutcome::Success,
        duration_ms: vendor.duration_ms,
        cost: Some(MonetaryAmount {
            units: vendor.cost_units,
            currency: "USD".to_string(),
        }),
        output_hash: Some(receipt.content_hash.clone()),
        bilateral_dsse_sha256: Some(envelope_sha256.to_string()),
        governance_receipt_id,
        parent_receipt_sha256,
        consistency_anchor: Some(format!("chio:consistency:{WORKFLOW_ID}:{index}")),
        destructive: vendor.destructive.then_some(true),
    }
}

fn disclosure_proof_for_workflow(
    workflow_body: &WorkflowReceiptBody,
    context: &ChioVerificationContext,
) -> Result<SelectiveDisclosureProof, ChioPackageError> {
    let projection = project_workflow_receipt_body(workflow_body)
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    let bbs_keypair = generate_bbs_keypair(BBS_KEY_MATERIAL, BBS_KEY_INFO)
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    let signed = sign_projection(&projection, &bbs_keypair)
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    derive_selective_disclosure_proof(
        &signed,
        &projection,
        &bbs_keypair,
        &DisclosureSet(vec![4, 8, 9, 10]),
        &context.expected_bbs_proof_nonce()?,
    )
    .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))
}

pub fn verification_context() -> ChioVerificationContext {
    ChioVerificationContext {
        schema: VERIFICATION_CONTEXT_SCHEMA.to_string(),
        audience: "buyer-auditor-offline-verifier".to_string(),
        challenge: "refund-workflow-001-audit".to_string(),
        proof_purpose: "buyer-auditor-workflow-disclosure".to_string(),
        issued_at_unix_ms: GENERATED_AT_UNIX_MS - 5_000,
        expires_at_unix_ms: GENERATED_AT_UNIX_MS + 60_000,
    }
}

fn trusted_bbs_issuers() -> Result<Vec<TrustedBbsIssuer>, ChioPackageError> {
    let bbs_keypair = generate_bbs_keypair(BBS_KEY_MATERIAL, BBS_KEY_INFO)
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    Ok(vec![TrustedBbsIssuer {
        issuer_fingerprint: bbs_keypair.issuer_fingerprint,
        public_key_hex: bbs_keypair.public_key_hex,
    }])
}

pub fn authority_profile_document() -> Result<AuthorityProfileDocument, ChioPackageError> {
    let buyer_key = Keypair::from_seed(&BUYER_SEED);
    let governance_key = Keypair::from_seed(&GOVERNANCE_SEED);
    let revocation_key = Keypair::from_seed(&REVOCATION_SEED);
    let runtime_policy_key = Keypair::from_seed(&RUNTIME_POLICY_SEED);
    Ok(AuthorityProfileDocument {
        schema: AUTHORITY_PROFILE_SCHEMA.to_string(),
        trusted_bbs_issuers: trusted_bbs_issuers()?,
        lease_authorities: vec![ChioTrustedLeaseAuthority {
            issuer: BUYER_KERNEL_ID.to_string(),
            key_id: Some(key_id(&buyer_key.public_key())),
            public_key: buyer_key.public_key(),
            valid_from_unix_ms: Some(AUTHORITY_VALID_FROM_UNIX_MS),
            valid_until_unix_ms: Some(AUTHORITY_VALID_UNTIL_UNIX_MS),
            status: Some(ChioAuthorityStatus::Active),
            allowed_action_classes: vec![
                CapabilityLeaseActionClass::DelegatedAction,
                CapabilityLeaseActionClass::NarrowDestructive,
            ],
        }],
        governance_authorities: vec![ChioTrustedGovernanceAuthority {
            authorizing_kernel: GOVERNANCE_KERNEL_ID.to_string(),
            key_id: Some(key_id(&governance_key.public_key())),
            public_key: governance_key.public_key(),
            valid_from_unix_ms: Some(AUTHORITY_VALID_FROM_UNIX_MS),
            valid_until_unix_ms: Some(AUTHORITY_VALID_UNTIL_UNIX_MS),
            status: Some(ChioAuthorityStatus::Active),
            allowed_case_kinds: vec![GovernanceReceiptCaseKind::DestructiveAuthorization],
        }],
        runtime_policy_issuer_public_keys: vec![runtime_policy_key.public_key()],
        revocation_authority: ChioRevocationAuthority {
            authority_id: BUYER_KERNEL_ID.to_string(),
            key_id: key_id(&revocation_key.public_key()),
            public_key: revocation_key.public_key(),
            valid_from_unix_ms: AUTHORITY_VALID_FROM_UNIX_MS,
            valid_until_unix_ms: AUTHORITY_VALID_UNTIL_UNIX_MS,
            status: ChioAuthorityStatus::Active,
        },
    })
}

pub fn authority_signing_keys_document() -> LocalAuthoritySigningKeysDocument {
    LocalAuthoritySigningKeysDocument {
        schema: LOCAL_SIGNING_KEYS_SCHEMA.to_string(),
        lease_authority_seeds: vec![NamedSeedHex {
            id: BUYER_KERNEL_ID.to_string(),
            seed_hex: hex_encode_seed(BUYER_SEED),
        }],
        governance_authority_seeds: vec![NamedSeedHex {
            id: GOVERNANCE_KERNEL_ID.to_string(),
            seed_hex: hex_encode_seed(GOVERNANCE_SEED),
        }],
        revocation_authority_seed_hex: hex_encode_seed(REVOCATION_SEED),
    }
}

fn hex_encode_seed(seed: [u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in seed {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn issuance_request(steps: Vec<ChioIssuanceStepRequest>) -> ChioIssuanceRequest {
    ChioIssuanceRequest {
        schema: ISSUANCE_REQUEST_SCHEMA.to_string(),
        workflow_id: WORKFLOW_ID.to_string(),
        workflow_grant_id: CAPABILITY_ID.to_string(),
        lease_authority_issuer: BUYER_KERNEL_ID.to_string(),
        governance_authority_kernel: GOVERNANCE_KERNEL_ID.to_string(),
        verification_context: verification_context(),
        steps,
    }
}

pub fn authority_issuance_request() -> Result<ChioIssuanceRequest, ChioPackageError> {
    let mut steps = Vec::new();
    for (index, vendor) in VENDORS.iter().enumerate() {
        let vendor_key = Keypair::from_seed(&vendor.seed);
        let body = receipt_body(vendor, &vendor_key)?;
        let tool_args_hash = body.action.parameter_hash.clone();
        let step_sha256 = if vendor.destructive {
            let receipt = ChioReceipt::sign(body, &vendor_key)
                .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
            Some(canonical_sha256(&receipt.body())?)
        } else {
            None
        };
        steps.push(issuance_step_request(
            vendor,
            index,
            action_class_for_vendor(vendor),
            tool_args_hash,
            step_sha256,
        )?);
    }
    Ok(issuance_request(steps))
}

pub fn authority_issuance_request_for_package(
    package: &ChioProofPackage,
) -> Result<ChioIssuanceRequest, ChioPackageError> {
    let receipts_by_id = package
        .tool_receipts
        .iter()
        .map(|receipt| (receipt.id.as_str(), receipt))
        .collect::<HashMap<_, _>>();
    let governance_by_id = package
        .governance_receipts
        .iter()
        .map(|receipt| (receipt.body.receipt_id.as_str(), receipt))
        .collect::<HashMap<_, _>>();
    let mut request = authority_issuance_request()?;
    for step in &mut request.steps {
        let workflow_step = package
            .workflow_receipt
            .steps
            .iter()
            .find(|workflow_step| workflow_step.step_index == step.step_index)
            .ok_or_else(|| {
                ChioPackageError::Workflow(format!(
                    "package is missing workflow step {}",
                    step.step_index
                ))
            })?;
        let tool_receipt_id = workflow_step.tool_receipt_id.as_deref().ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "workflow step {} is missing tool receipt id",
                step.step_index
            ))
        })?;
        let receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "tool receipt {tool_receipt_id} is not present in package"
            ))
        })?;
        step.tool_args_hash = receipt.action.parameter_hash.clone();
        if step.destructive {
            let governance_receipt_id =
                workflow_step
                    .governance_receipt_id
                    .as_ref()
                    .ok_or_else(|| {
                        ChioPackageError::Governance(format!(
                            "destructive workflow step {} is missing governance receipt id",
                            step.step_index
                        ))
                    })?;
            let governance_receipt = governance_by_id
                .get(governance_receipt_id.as_str())
                .ok_or_else(|| {
                    ChioPackageError::Governance(format!(
                        "governance receipt {governance_receipt_id} is not present in package"
                    ))
                })?;
            let step_sha256 = canonical_sha256(&receipt.body())?;
            if governance_receipt.body.step_sha256 != step_sha256 {
                return Err(ChioPackageError::Governance(format!(
                    "governance receipt {governance_receipt_id} step hash does not match tool receipt {tool_receipt_id}"
                )));
            }
            step.governance_receipt_id = Some(governance_receipt_id.clone());
            step.step_sha256 = Some(step_sha256);
        } else {
            step.governance_receipt_id = None;
            step.governance_issued_at_unix_ms = None;
            step.governance_expires_at_unix_ms = None;
            step.step_sha256 = None;
        }
    }
    Ok(request)
}

pub fn revocation_publication_request(
    revoked_key_fingerprints: Vec<String>,
) -> RevocationPublicationRequest {
    RevocationPublicationRequest {
        schema: REVOCATION_PUBLICATION_REQUEST_SCHEMA.to_string(),
        checkpoint_id: "revocation-checkpoint:chio-refund:001".to_string(),
        issued_at_unix_ms: GENERATED_AT_UNIX_MS,
        expires_at_unix_ms: GENERATED_AT_UNIX_MS + 120_000,
        epoch_height: 64,
        previous_epoch_height: Some(63),
        revoked_key_fingerprints,
    }
}

pub fn disclosure_policy() -> ChioDisclosurePolicy {
    ChioDisclosurePolicy {
        projection_version: "chio.bbs-projection.workflow.v1".to_string(),
        ciphersuite: "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_".to_string(),
        message_count: 14,
        required_disclosed_indices: vec![4, 8, 9, 10],
        required_disclosed_fields: vec![
            "id".to_string(),
            "session_id".to_string(),
            "skill_id".to_string(),
            "skill_version".to_string(),
        ],
    }
}

fn signed_revocation_checkpoint(
    revoked_key_fingerprints: Vec<String>,
) -> Result<SignedChioRevocationCheckpoint, ChioPackageError> {
    publish_revocation_checkpoint(
        &authority_profile_document()?,
        &revocation_publication_request(revoked_key_fingerprints),
        &authority_signing_keys_document(),
    )
    .map_err(ChioPackageError::from)
}

pub fn peer_pins_document_for_package(package: &ChioProofPackage) -> PeerPinsDocument {
    let mut action_classes: Vec<ChioTrustedActionClass> = VENDORS
        .iter()
        .map(|vendor| ChioTrustedActionClass {
            action_class_id: vendor.tool_name.to_string(),
            tool_name: vendor.tool_name.to_string(),
            kind: if vendor.destructive {
                ChioActionClassKind::ReceiptBacked
            } else {
                ChioActionClassKind::Routine
            },
        })
        .collect();
    action_classes.push(ChioTrustedActionClass {
        action_class_id: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
        tool_name: WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID.to_string(),
        kind: ChioActionClassKind::Routine,
    });
    action_classes.push(ChioTrustedActionClass {
        action_class_id: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
        tool_name: WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID.to_string(),
        kind: ChioActionClassKind::Routine,
    });
    PeerPinsDocument {
        schema: PEER_PINS_SCHEMA.to_string(),
        peers: package.peer_ladder_bindings.clone(),
        vendors: package.vendor_keys.clone(),
        action_classes,
    }
}

pub fn verifier_trust_bundle_document_for_package(
    package: &ChioProofPackage,
) -> Result<ChioVerifierTrustBundleDocument, ChioPackageError> {
    assemble_verifier_trust_bundle(
        &authority_profile_document()?,
        &peer_pins_document_for_package(package),
        &package.workflow_intersection,
        disclosure_policy(),
        signed_revocation_checkpoint(Vec::new())?,
    )
    .map_err(ChioPackageError::from)
}

pub fn verifier_trust_bundle_document() -> Result<ChioVerifierTrustBundleDocument, ChioPackageError>
{
    let package = fresh_proof_package()?;
    verifier_trust_bundle_document_for_package(&package)
}

pub fn verifier_trust_bundle() -> Result<ChioVerifierTrustBundle, ChioPackageError> {
    ChioVerifierTrustBundle::from_document(verifier_trust_bundle_document()?)
}

pub fn build_proof_package(
    selective_disclosure_proof: SelectiveDisclosureProof,
) -> Result<ChioProofPackage, ChioPackageError> {
    let package =
        build_proof_package_unchecked(ProofPackageInput::Fixture, selective_disclosure_proof)?;
    ensure_disclosure_subject_matches_workflow(&package)?;
    Ok(package)
}

pub fn fresh_proof_package() -> Result<ChioProofPackage, ChioPackageError> {
    let context = verification_context();
    let mut package =
        build_proof_package_unchecked(ProofPackageInput::Fixture, empty_disclosure_proof())?;
    package.selective_disclosure_proof =
        disclosure_proof_for_workflow(&package.workflow_receipt.body(), &context)?;
    ensure_disclosure_subject_matches_workflow(&package)?;
    Ok(package)
}

pub fn proof_package_from_runtime_receipts(
    tool_receipts: Vec<ChioReceipt>,
) -> Result<ChioProofPackage, ChioPackageError> {
    let context = verification_context();
    let mut package = build_proof_package_unchecked(
        ProofPackageInput::RuntimeReceipts(tool_receipts),
        empty_disclosure_proof(),
    )?;
    package.selective_disclosure_proof =
        disclosure_proof_for_workflow(&package.workflow_receipt.body(), &context)?;
    ensure_disclosure_subject_matches_workflow(&package)?;
    Ok(package)
}

pub fn proof_package_from_runtime_artifacts(
    runtime_artifacts: Vec<RuntimeProofArtifact>,
) -> Result<ChioProofPackage, ChioPackageError> {
    let context = verification_context();
    let mut package = build_proof_package_unchecked(
        ProofPackageInput::RuntimeArtifacts(runtime_artifacts),
        empty_disclosure_proof(),
    )?;
    package.selective_disclosure_proof =
        disclosure_proof_for_workflow(&package.workflow_receipt.body(), &context)?;
    ensure_disclosure_subject_matches_workflow(&package)?;
    Ok(package)
}

pub fn runtime_vendor_keypair(step_index: usize) -> Result<Keypair, ChioPackageError> {
    let vendor = runtime_vendor(step_index)?;
    Ok(Keypair::from_seed(&vendor.seed))
}

pub fn runtime_buyer_keypair() -> Keypair {
    Keypair::from_seed(&BUYER_SEED)
}

pub fn runtime_vendor_binding(
    step_index: usize,
) -> Result<(&'static str, &'static str, &'static str), ChioPackageError> {
    let vendor = runtime_vendor(step_index)?;
    Ok((vendor.kernel_id, vendor.server_id, vendor.tool_name))
}

fn runtime_vendor(step_index: usize) -> Result<&'static VendorFixture, ChioPackageError> {
    VENDORS.get(step_index).ok_or_else(|| {
        ChioPackageError::Inconsistent(format!("unknown runtime vendor step {step_index}"))
    })
}

pub fn fixture_proof_package() -> Result<ChioProofPackage, ChioPackageError> {
    proof_package_from_json(include_str!("../fixtures/buyer-auditor-proof-package.json"))
}

pub fn fixture_verifier_report() -> Result<VerifierReport, ChioPackageError> {
    verifier_report_from_json(include_str!("../fixtures/verifier-report.json"))
}

fn resign_workflow_receipt(package: &mut ChioProofPackage) -> Result<(), ChioPackageError> {
    let buyer_key = Keypair::from_seed(&BUYER_SEED);
    let mut workflow = WorkflowReceipt::sign(package.workflow_receipt.body(), &buyer_key)
        .map_err(|error| ChioPackageError::Workflow(error.to_string()))?;
    for vendor in &VENDORS {
        let key = Keypair::from_seed(&vendor.seed);
        workflow
            .add_vendor_signature(vendor.vendor_id, &key)
            .map_err(|error| ChioPackageError::Workflow(error.to_string()))?;
    }
    package.workflow_receipt = workflow;
    Ok(())
}

fn refresh_verifier_material_for_package(
    package: &mut ChioProofPackage,
    context: &ChioVerificationContext,
) -> Result<ChioVerifierTrustBundleDocument, ChioPackageError> {
    package
        .workflow_intersection
        .aggregate_workflow_receipt_sha256 = canonical_sha256(&package.workflow_receipt.body())?;
    package.selective_disclosure_proof =
        disclosure_proof_for_workflow(&package.workflow_receipt.body(), context)?;
    verifier_trust_bundle_document_for_package(package)
}

fn write_json_document(path: &Path, json: String) -> Result<(), ChioPackageError> {
    fs::write(path, json).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn write_signed_negative_case_inputs(out_dir: &Path) -> Result<(), ChioPackageError> {
    fs::create_dir_all(out_dir).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    for case_id in [
        "step-parent-hash-mismatch",
        "step-tool-receipt-mismatch",
        "step-output-hash-mismatch",
        "step-dsse-hash-mismatch",
        "step-consistency-anchor-mismatch",
    ] {
        let mut package = fresh_proof_package()?;
        let context = verification_context();
        match case_id {
            "step-parent-hash-mismatch" => {
                package.workflow_receipt.steps[1].parent_receipt_sha256 = Some("0".repeat(64));
            }
            "step-tool-receipt-mismatch" => {
                package.workflow_receipt.steps[0].tool_receipt_id =
                    package.workflow_receipt.steps[1].tool_receipt_id.clone();
            }
            "step-output-hash-mismatch" => {
                package.workflow_receipt.steps[0].output_hash = Some("0".repeat(64));
            }
            "step-dsse-hash-mismatch" => {
                package.workflow_receipt.steps[0].bilateral_dsse_sha256 = Some("0".repeat(64));
            }
            "step-consistency-anchor-mismatch" => {
                package.workflow_receipt.steps[0].consistency_anchor =
                    Some("chio:consistency:wf-chio-refund-001:wrong".to_string());
            }
            _ => {
                return Err(ChioPackageError::Json(format!(
                    "unsupported signed negative case {case_id}"
                )));
            }
        }
        resign_workflow_receipt(&mut package)?;
        let trust_bundle_document = refresh_verifier_material_for_package(&mut package, &context)?;
        write_json_document(
            &out_dir.join(format!("{case_id}-package.json")),
            package_json(&package)?,
        )?;
        write_json_document(
            &out_dir.join(format!("{case_id}-trust-bundle.json")),
            verifier_trust_bundle_json(&trust_bundle_document)?,
        )?;
        write_json_document(
            &out_dir.join(format!("{case_id}-context.json")),
            verification_context_json(&context)?,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

mod package;
mod runtime_validation;

use package::build_proof_package_unchecked;
use runtime_validation::{empty_disclosure_proof, ensure_disclosure_subject_matches_workflow};
