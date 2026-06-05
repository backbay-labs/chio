//! Offline Chio buyer and auditor proof package loopback harness.

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

pub use chio_attest_buyer_core::{
    package_json, proof_package_from_json, report_json, verification_context_from_json,
    verification_context_json, verifier_report_from_json, verifier_trust_bundle_from_json,
    verifier_trust_bundle_json, verify_package, ChioActionClassKind, ChioAuthorityStatus,
    ChioDisclosurePolicy, ChioPackageError, ChioProofClaims, ChioProofPackage,
    ChioRevocationCheckpoint, ChioRevocationMaterial, ChioTrustedActionClass,
    ChioTrustedGovernanceAuthority, ChioTrustedLeaseAuthority, ChioTrustedWorkflowIntersection,
    ChioVerificationContext, ChioVerifierTrustBundle, ChioVerifierTrustBundleDocument,
    LeaseScopeBindingArtifact, PeerLadderBinding, SignedChioRevocationCheckpoint, TrustedBbsIssuer,
    VendorKeyBinding, VerifierReport, WorkflowIntersectionArtifact,
    WorkflowPairwiseIntersectionRef, WorkflowRequiredVendorSigner, WorkflowStepClassBinding,
    LEASE_SCOPE_BINDING_SCHEMA, PROOF_PACKAGE_SCHEMA, REVOCATION_CHECKPOINT_SCHEMA,
    VERIFICATION_CONTEXT_SCHEMA, VERIFIER_REPORT_SCHEMA, VERIFIER_TRUST_BUNDLE_SCHEMA,
    WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID, WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID,
    WORKFLOW_INTERSECTION_SCHEMA,
};
use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::capability::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    ActorRef, BoundaryClass, ChioReceipt, ChioReceiptBody, Decision, ReceiptKind, RedactionMode,
    ToolCallAction, ToolOrigin, TrustLevel,
};
use chio_federation::{
    sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    DsseEnvelope, GovernanceReceiptRef, HashRecord, Keyid, LadderManifestRef,
    PolicyEvaluationSummary, PolicyVerdict, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION,
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
use chio_governance::{
    CapabilityLeaseActionClass, GovernanceReceiptCaseKind, SignedCapabilityLease,
    SignedGovernanceReceipt,
};
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

fn empty_disclosure_proof() -> SelectiveDisclosureProof {
    SelectiveDisclosureProof {
        schema: String::new(),
        projection_version: String::new(),
        subject_sha256_hex: String::new(),
        ciphersuite: String::new(),
        issuer_fingerprint: String::new(),
        issuer_public_key_hex: String::new(),
        message_count: 0,
        disclosed_indices: Vec::new(),
        disclosed: Vec::new(),
        proof_nonce_hex: String::new(),
        proof_bytes_hex: String::new(),
    }
}

fn ensure_disclosure_subject_matches_workflow(
    package: &ChioProofPackage,
) -> Result<(), ChioPackageError> {
    let projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex != projection.subject_sha256_hex {
        return Err(ChioPackageError::SelectiveDisclosure(format!(
            "proof subject {} does not match workflow body {}",
            package.selective_disclosure_proof.subject_sha256_hex, projection.subject_sha256_hex
        )));
    }
    Ok(())
}

fn validate_runtime_receipt_for_vendor(
    receipt: &ChioReceipt,
    vendor: &VendorFixture,
    vendor_key: &Keypair,
) -> Result<(), ChioPackageError> {
    if receipt.tool_server.as_str() != vendor.server_id {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} server {} does not match {}",
            receipt.id, receipt.tool_server, vendor.server_id
        )));
    }
    if receipt.tool_name.as_str() != vendor.tool_name {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} tool {} does not match {}",
            receipt.id, receipt.tool_name, vendor.tool_name
        )));
    }
    if receipt.capability_id.as_str() != vendor.lease_id {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} capability {} does not match {}",
            receipt.id, receipt.capability_id, vendor.lease_id
        )));
    }
    if !matches!(&receipt.decision, Some(Decision::Allow)) {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} was not an allow receipt",
            receipt.id
        )));
    }
    validate_runtime_receipt_action_payload(receipt, vendor)?;
    validate_runtime_receipt_metadata(receipt, vendor)?;
    let expected_public_key = vendor_key.public_key();
    if receipt.kernel_key != expected_public_key {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} key does not match {}",
            receipt.id, vendor.kernel_id
        )));
    }
    let verified = receipt
        .verify_signature()
        .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
    if !verified {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} signature is invalid",
            receipt.id
        )));
    }
    Ok(())
}

fn validate_runtime_receipt_action_payload(
    receipt: &ChioReceipt,
    vendor: &VendorFixture,
) -> Result<(), ChioPackageError> {
    let action_hash_valid = receipt
        .action
        .verify_hash()
        .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
    if !action_hash_valid {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} action parameter hash is invalid",
            receipt.id
        )));
    }
    validate_json_string_field(
        &receipt.action.parameters,
        "workflowId",
        WORKFLOW_ID,
        "runtime receipt action payload",
    )?;
    validate_json_string_field(
        &receipt.action.parameters,
        "caseRef",
        CASE_REF,
        "runtime receipt action payload",
    )?;
    validate_json_string_field(
        &receipt.action.parameters,
        "tool",
        vendor.tool_name,
        "runtime receipt action payload",
    )
}

fn validate_runtime_receipt_metadata(
    receipt: &ChioReceipt,
    vendor: &VendorFixture,
) -> Result<(), ChioPackageError> {
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        ChioPackageError::Inconsistent(format!(
            "runtime receipt {} is missing loopback metadata",
            receipt.id
        ))
    })?;
    validate_json_string_field(
        metadata,
        "workflow_id",
        WORKFLOW_ID,
        "runtime receipt metadata",
    )?;
    validate_json_string_field(
        metadata,
        "vendor_id",
        vendor.vendor_id,
        "runtime receipt metadata",
    )
}

fn validate_json_string_field(
    value: &serde_json::Value,
    field: &'static str,
    expected: &str,
    context: &str,
) -> Result<(), ChioPackageError> {
    match value.get(field).and_then(serde_json::Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ChioPackageError::Inconsistent(format!(
            "{context} field {field} value {actual} does not match {expected}"
        ))),
        None => Err(ChioPackageError::Inconsistent(format!(
            "{context} field {field} is missing"
        ))),
    }
}

struct RuntimeIssuedMaterialValidation<'a> {
    index: usize,
    vendor: &'a VendorFixture,
    receipt: &'a ChioReceipt,
    envelope: &'a DsseEnvelope,
    step: &'a StepRecord,
    expected_parent_sha256: Option<&'a str>,
    lease: &'a SignedCapabilityLease,
    governance_receipt: Option<&'a SignedGovernanceReceipt>,
}

fn validate_runtime_artifact_for_issued_material(
    validation: RuntimeIssuedMaterialValidation<'_>,
) -> Result<(), ChioPackageError> {
    let RuntimeIssuedMaterialValidation {
        index,
        vendor,
        receipt,
        envelope,
        step,
        expected_parent_sha256,
        lease,
        governance_receipt,
    } = validation;

    if step.step_index != index {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step index {} does not match position {}",
            step.step_index, index
        )));
    }
    if step.tool_receipt_id.as_deref() != Some(receipt.id.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} does not reference receipt {}",
            index, receipt.id
        )));
    }
    if step.server_id.as_str() != receipt.tool_server.as_str()
        || step.server_id.as_str() != vendor.server_id
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} server does not match receipt and fixture",
            index
        )));
    }
    if step.tool_name.as_str() != receipt.tool_name.as_str()
        || step.tool_name.as_str() != vendor.tool_name
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} tool does not match receipt and fixture",
            index
        )));
    }
    if step.output_hash.as_deref() != Some(receipt.content_hash.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} output hash does not match receipt",
            index
        )));
    }
    if step.destructive.unwrap_or(false) != vendor.destructive {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} destructive flag does not match fixture",
            index
        )));
    }
    let envelope_sha256 = canonical_sha256(envelope)?;
    if step.bilateral_dsse_sha256.as_deref() != Some(envelope_sha256.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE hash does not match envelope",
            index
        )));
    }
    if step.parent_receipt_sha256.as_deref() != expected_parent_sha256 {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} parent hash does not match previous step",
            index
        )));
    }
    let expected_anchor = format!("chio:consistency:{WORKFLOW_ID}:{index}");
    if step.consistency_anchor.as_deref() != Some(expected_anchor.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} consistency anchor must be {}",
            index, expected_anchor
        )));
    }

    let (statement, _) = envelope
        .decode_statement()
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(ChioPackageError::Federation(format!(
            "runtime step {} DSSE predicate type {} is not strict Chio",
            index, statement.predicate_type
        )));
    }
    let predicate = &statement.predicate;
    if predicate.invocation_id.as_str() != receipt.id.as_str() {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE invocation does not match receipt",
            index
        )));
    }
    if predicate.tool_name.as_str() != receipt.tool_name.as_str() {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE tool does not match receipt",
            index
        )));
    }
    if predicate.tool_server_b.kernel_id.as_str() != vendor.kernel_id {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE peer kernel does not match fixture",
            index
        )));
    }
    if predicate
        .tool_args_hash
        .as_ref()
        .map(|hash| hash.value.as_str())
        != Some(receipt.action.parameter_hash.as_str())
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE args hash does not match receipt",
            index
        )));
    }
    if predicate.consistency_anchor.as_deref() != Some(expected_anchor.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE consistency anchor must be {}",
            index, expected_anchor
        )));
    }
    let lease_ref = predicate.capability_lease_ref.as_ref().ok_or_else(|| {
        ChioPackageError::Workflow(format!("runtime step {} DSSE has no lease ref", index))
    })?;
    if lease_ref.lease_id.as_str() != lease.body.lease_id.as_str()
        || lease_ref.issuer.as_str() != lease.body.issuer.as_str()
        || lease_ref.expires_at_unix_ms != lease.body.expires_at_unix_ms
        || lease_ref
            .scope_digest
            .as_ref()
            .map(|hash| hash.value.as_str())
            != Some(lease.body.scope_digest.as_str())
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE lease ref does not match issued lease",
            index
        )));
    }

    match (
        governance_receipt,
        predicate.governance_receipt_ref.as_ref(),
    ) {
        (Some(receipt), Some(predicate_ref)) => {
            if step.governance_receipt_id.as_deref() != Some(receipt.body.receipt_id.as_str())
                || predicate_ref.receipt_id.as_str() != receipt.body.receipt_id.as_str()
            {
                return Err(ChioPackageError::Workflow(format!(
                    "runtime step {} governance ref does not match issued receipt",
                    index
                )));
            }
        }
        (None, None) if step.governance_receipt_id.is_none() => {}
        _ => {
            return Err(ChioPackageError::Workflow(format!(
                "runtime step {} governance material does not match issued receipt",
                index
            )));
        }
    }

    Ok(())
}

fn build_proof_package_unchecked(
    input: ProofPackageInput,
    selective_disclosure_proof: SelectiveDisclosureProof,
) -> Result<ChioProofPackage, ChioPackageError> {
    let buyer_key = Keypair::from_seed(&BUYER_SEED);
    match &input {
        ProofPackageInput::Fixture => {}
        ProofPackageInput::RuntimeReceipts(receipts) => {
            if receipts.len() != VENDORS.len() {
                return Err(ChioPackageError::Inconsistent(format!(
                    "runtime receipt count {} does not match vendor count {}",
                    receipts.len(),
                    VENDORS.len()
                )));
            }
        }
        ProofPackageInput::RuntimeArtifacts(artifacts) => {
            if artifacts.len() != VENDORS.len() {
                return Err(ChioPackageError::Inconsistent(format!(
                    "runtime artifact count {} does not match vendor count {}",
                    artifacts.len(),
                    VENDORS.len()
                )));
            }
        }
    }

    let mut tool_receipts = Vec::new();
    let mut leases = Vec::new();
    let mut lease_scope_bindings = Vec::new();
    let mut governance_receipts = Vec::new();
    let mut envelopes = Vec::new();
    let mut steps = Vec::new();
    let mut vendor_keys = Vec::new();
    let mut peer_bindings = vec![PeerLadderBinding {
        kernel_id: BUYER_KERNEL_ID.to_string(),
        public_key: buyer_key.public_key(),
        ladder_manifest_ref: buyer_ladder_ref(),
    }];
    let mut issuance_steps = Vec::new();
    let mut prepared_artifacts = Vec::new();

    for (index, vendor) in VENDORS.iter().enumerate() {
        let vendor_key = Keypair::from_seed(&vendor.seed);
        let (receipt, runtime_envelope, runtime_step) = match &input {
            ProofPackageInput::Fixture => {
                let receipt_body = receipt_body(vendor, &vendor_key)?;
                let receipt = ChioReceipt::sign(receipt_body, &vendor_key)
                    .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
                (receipt, None, None)
            }
            ProofPackageInput::RuntimeReceipts(receipts) => {
                let receipt = receipts.get(index).ok_or_else(|| {
                    ChioPackageError::Inconsistent(format!(
                        "runtime receipt for step {} is missing",
                        index
                    ))
                })?;
                validate_runtime_receipt_for_vendor(receipt, vendor, &vendor_key)?;
                (receipt.clone(), None, None)
            }
            ProofPackageInput::RuntimeArtifacts(artifacts) => {
                let artifact = artifacts.get(index).ok_or_else(|| {
                    ChioPackageError::Inconsistent(format!(
                        "runtime artifact for step {} is missing",
                        index
                    ))
                })?;
                validate_runtime_receipt_for_vendor(&artifact.tool_receipt, vendor, &vendor_key)?;
                (
                    artifact.tool_receipt.clone(),
                    Some(artifact.bilateral_envelope.clone()),
                    Some(artifact.workflow_step.clone()),
                )
            }
        };
        let step_sha256 = vendor
            .destructive
            .then(|| canonical_sha256(&receipt.body()))
            .transpose()?;
        issuance_steps.push(issuance_step_request(
            vendor,
            index,
            action_class_for_vendor(vendor),
            receipt.action.parameter_hash.clone(),
            step_sha256,
        )?);
        prepared_artifacts.push((vendor, receipt, runtime_envelope, runtime_step));

        peer_bindings.push(PeerLadderBinding {
            kernel_id: vendor.kernel_id.to_string(),
            public_key: vendor_key.public_key(),
            ladder_manifest_ref: ladder_ref(vendor.ladder_manifest_id, vendor.kernel_id),
        });
        vendor_keys.push(VendorKeyBinding {
            vendor_id: vendor.vendor_id.to_string(),
            public_key: vendor_key.public_key(),
        });
    }

    let issued = issue_authority_bundle(
        &authority_profile_document()?,
        &issuance_request(issuance_steps),
        &authority_signing_keys_document(),
    )
    .map_err(ChioPackageError::from)?;
    let mut leases_by_id = issued
        .capability_leases
        .into_iter()
        .map(|lease| (lease.body.lease_id.clone(), lease))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut scope_bindings_by_lease = issued
        .lease_scope_bindings
        .into_iter()
        .map(|binding| (binding.lease_id.clone(), binding))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut governance_by_lease = issued
        .governance_receipts
        .into_iter()
        .map(|receipt| (receipt.body.authorized_lease_id.clone(), receipt))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut previous_step_sha256: Option<String> = None;
    for (index, (vendor, receipt, runtime_envelope, runtime_step)) in
        prepared_artifacts.into_iter().enumerate()
    {
        let vendor_key = Keypair::from_seed(&vendor.seed);
        let lease = leases_by_id.remove(vendor.lease_id).ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "issued bundle is missing lease {}",
                vendor.lease_id
            ))
        })?;
        let lease_scope_binding =
            scope_bindings_by_lease
                .remove(vendor.lease_id)
                .ok_or_else(|| {
                    ChioPackageError::Governance(format!(
                        "issued bundle is missing scope binding {}",
                        vendor.lease_id
                    ))
                })?;
        let governance_receipt = governance_by_lease.remove(vendor.lease_id);
        if vendor.destructive && governance_receipt.is_none() {
            return Err(ChioPackageError::Governance(format!(
                "issued bundle is missing governance receipt for {}",
                vendor.lease_id
            )));
        }
        let (envelope, step) = match (runtime_envelope, runtime_step) {
            (Some(envelope), Some(step)) => {
                validate_runtime_artifact_for_issued_material(RuntimeIssuedMaterialValidation {
                    index,
                    vendor,
                    receipt: &receipt,
                    envelope: &envelope,
                    step: &step,
                    expected_parent_sha256: previous_step_sha256.as_deref(),
                    lease: &lease,
                    governance_receipt: governance_receipt.as_ref(),
                })?;
                (envelope, step)
            }
            (None, None) => {
                let governance_ref = if let Some(governance_receipt) = governance_receipt.as_ref() {
                    Some(GovernanceReceiptRef {
                        receipt_id: governance_receipt.body.receipt_id.clone(),
                        kernel_id: governance_receipt.body.authorizing_kernel.clone(),
                        digest: HashRecord {
                            alg: "sha256".to_string(),
                            value: signed_governance_digest(governance_receipt)?,
                        },
                    })
                } else {
                    None
                };
                let extensions = BilateralPredicateExtensions {
                    capability_lease_ref: Some(CapabilityLeaseRef {
                        lease_id: lease.body.lease_id.clone(),
                        issuer: lease.body.issuer.clone(),
                        expires_at_unix_ms: lease.body.expires_at_unix_ms,
                        scope_digest: Some(HashRecord {
                            alg: "sha256".to_string(),
                            value: lease.body.scope_digest.clone(),
                        }),
                    }),
                    policy_evaluation_summary: Some(policy_summary(vendor)),
                    governance_receipt_ref: governance_ref,
                    consistency_anchor: Some(format!("chio:consistency:{WORKFLOW_ID}:{index}")),
                    consistency_model: None,
                    cross_org_visibility: None,
                    treaty_binding_ref: None,
                };
                let envelope = sign_chio_bilateral_dsse_envelope(
                    &receipt,
                    &buyer_key,
                    &vendor_key,
                    BUYER_KERNEL_ID,
                    vendor.kernel_id,
                    vendor.tool_name,
                    GENERATED_AT_UNIX_MS,
                    extensions,
                )
                .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
                let envelope_sha256 = canonical_sha256(&envelope)?;
                let step = step_record(
                    index,
                    vendor,
                    &receipt,
                    &envelope_sha256,
                    previous_step_sha256.clone(),
                    governance_receipt
                        .as_ref()
                        .map(|receipt| receipt.body.receipt_id.clone()),
                );
                (envelope, step)
            }
            _ => {
                return Err(ChioPackageError::Inconsistent(format!(
                    "runtime artifact {} must include both DSSE envelope and workflow step",
                    index
                )));
            }
        };
        previous_step_sha256 = Some(canonical_sha256(&step)?);

        tool_receipts.push(receipt);
        leases.push(lease);
        lease_scope_bindings.push(lease_scope_binding);
        if let Some(governance_receipt) = governance_receipt {
            governance_receipts.push(governance_receipt);
        }
        envelopes.push(envelope);
        steps.push(step);
    }

    let workflow_body = WorkflowReceiptBody {
        id: WORKFLOW_ID.to_string(),
        schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
        started_at: GENERATED_AT_UNIX_MS / 1000,
        completed_at: (GENERATED_AT_UNIX_MS / 1000) + 42,
        skill_id: "refund-underwriting".to_string(),
        skill_version: "0.1.0".to_string(),
        agent_id: "buyer-agent".to_string(),
        session_id: Some(SESSION_ID.to_string()),
        capability_id: CAPABILITY_ID.to_string(),
        outcome: WorkflowOutcome::Completed,
        steps,
        total_cost: Some(MonetaryAmount {
            units: 550,
            currency: "USD".to_string(),
        }),
        duration_ms: 42_000,
        kernel_key: buyer_key.public_key(),
    };

    let mut workflow_receipt = WorkflowReceipt::sign(workflow_body, &buyer_key)
        .map_err(|error| ChioPackageError::Workflow(error.to_string()))?;
    for vendor in &VENDORS {
        let key = Keypair::from_seed(&vendor.seed);
        workflow_receipt
            .add_vendor_signature(vendor.vendor_id, &key)
            .map_err(|error| ChioPackageError::Workflow(error.to_string()))?;
    }
    let workflow_intersection = WorkflowIntersectionArtifact {
        schema: WORKFLOW_INTERSECTION_SCHEMA.to_string(),
        intersection_id: "workflow-intersection:buyer-refund:001".to_string(),
        workflow_id: WORKFLOW_ID.to_string(),
        workflow_grant_id: CAPABILITY_ID.to_string(),
        pairwise_intersection_refs: VENDORS
            .iter()
            .map(|vendor| WorkflowPairwiseIntersectionRef {
                peer_kernel_id: vendor.kernel_id.to_string(),
                intersection_id: format!("intersection:buyer:{}", vendor.vendor_id),
                ladder_manifest_ref: ladder_ref(vendor.ladder_manifest_id, vendor.kernel_id),
            })
            .collect(),
        step_class_bindings: VENDORS
            .iter()
            .enumerate()
            .map(|(index, vendor)| WorkflowStepClassBinding {
                step_index: index,
                tool_name: vendor.tool_name.to_string(),
                action_class_id: vendor.tool_name.to_string(),
                peer_kernel_id: vendor.kernel_id.to_string(),
            })
            .collect(),
        required_vendor_signers: VENDORS
            .iter()
            .map(|vendor| {
                let key = Keypair::from_seed(&vendor.seed);
                WorkflowRequiredVendorSigner {
                    vendor_id: vendor.vendor_id.to_string(),
                    public_key: key.public_key(),
                }
            })
            .collect(),
        aggregate_workflow_receipt_sha256: canonical_sha256(&workflow_receipt.body())?,
    };

    Ok(ChioProofPackage {
        schema: PROOF_PACKAGE_SCHEMA.to_string(),
        generated_at_unix_ms: GENERATED_AT_UNIX_MS,
        workflow_id: WORKFLOW_ID.to_string(),
        claims: ChioProofClaims::supported(),
        peer_ladder_bindings: peer_bindings,
        vendor_keys,
        tool_receipts,
        workflow_receipt,
        bilateral_envelopes: envelopes,
        capability_leases: leases,
        lease_scope_bindings,
        governance_receipts,
        workflow_intersection,
        selective_disclosure_proof,
    })
}

#[cfg(test)]
fn resign_bilateral_envelope_unanimous_deny(
    envelope: &mut DsseEnvelope,
    buyer_key: &Keypair,
    vendor_key: &Keypair,
) -> Result<(), ChioPackageError> {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use chio_core_types::crypto::{Ed25519Backend, SigningBackend};
    use chio_federation::bilateral_dsse::{pae, PAYLOAD_TYPE_IN_TOTO};

    let (mut statement, _) = envelope
        .decode_statement()
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    let summary = statement
        .predicate
        .policy_evaluation_summary
        .as_mut()
        .ok_or_else(|| {
            ChioPackageError::Federation(
                "bilateral envelope missing policy_evaluation_summary".to_string(),
            )
        })?;
    summary.server_a_verdict.verdict = "deny".to_string();
    summary.server_b_verdict.verdict = "deny".to_string();
    summary.joint_disposition = Some("deny".to_string());
    let statement_bytes = statement
        .canonical_bytes()
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    envelope.payload = BASE64_STANDARD.encode(&statement_bytes);
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
    let sig_a = Ed25519Backend::new(buyer_key.clone())
        .sign_bytes(&pae_bytes)
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    let sig_b = Ed25519Backend::new(vendor_key.clone())
        .sign_bytes(&pae_bytes)
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    envelope.signatures[0].sig = BASE64_STANDARD.encode(sig_a.to_bytes());
    envelope.signatures[1].sig = BASE64_STANDARD.encode(sig_b.to_bytes());
    Ok(())
}

#[cfg(test)]
fn refresh_workflow_step_parent_chain(steps: &mut [StepRecord]) -> Result<(), ChioPackageError> {
    let mut previous: Option<String> = None;
    for step in steps.iter_mut() {
        step.parent_receipt_sha256 = previous.clone();
        previous = Some(canonical_sha256(step)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use chio_core_types::receipt::SignedExportEnvelope;

    fn rebuild_verifier_material(
        package: &mut ChioProofPackage,
        context: &ChioVerificationContext,
    ) -> ChioVerifierTrustBundle {
        let document =
            refresh_verifier_material_for_package(package, context).expect("trust bundle rebuilds");
        ChioVerifierTrustBundle::from_document(document).expect("trust bundle parses")
    }

    fn runtime_artifacts_from_package(
        package: &ChioProofPackage,
    ) -> Result<Vec<RuntimeProofArtifact>, String> {
        let receipt_count = package.tool_receipts.len();
        let envelope_count = package.bilateral_envelopes.len();
        let step_count = package.workflow_receipt.steps.len();
        if receipt_count != envelope_count || receipt_count != step_count {
            return Err(format!(
                "runtime artifact fixture length mismatch: receipts={receipt_count}, envelopes={envelope_count}, steps={step_count}"
            ));
        }
        Ok(package
            .tool_receipts
            .iter()
            .cloned()
            .zip(package.bilateral_envelopes.iter().cloned())
            .zip(package.workflow_receipt.steps.iter().cloned())
            .map(
                |((tool_receipt, bilateral_envelope), workflow_step)| RuntimeProofArtifact {
                    tool_receipt,
                    bilateral_envelope,
                    workflow_step,
                },
            )
            .collect())
    }

    fn refresh_runtime_parent_chain(artifacts: &mut [RuntimeProofArtifact]) {
        let mut parent = None;
        for artifact in artifacts {
            artifact.workflow_step.parent_receipt_sha256 = parent;
            parent = Some(canonical_sha256(&artifact.workflow_step).expect("step hashes"));
        }
    }

    #[test]
    fn runtime_vendor_helper_reports_unknown_step() {
        let error = runtime_vendor(VENDORS.len()).expect_err("unknown step must fail");
        assert!(error.to_string().contains("unknown runtime vendor step 3"));
    }

    #[test]
    fn fresh_proof_package_binds_disclosure_subject_to_workflow() {
        let package = fresh_proof_package().expect("fresh package builds");
        let projection = project_workflow_receipt_body(&package.workflow_receipt.body())
            .expect("workflow projection derives");

        assert_eq!(
            package.selective_disclosure_proof.subject_sha256_hex,
            projection.subject_sha256_hex
        );
    }

    #[test]
    fn runtime_artifacts_from_package_rejects_fixture_length_mismatch() {
        let mut package = fresh_proof_package().expect("fresh package builds");
        package.bilateral_envelopes.pop();

        let error = runtime_artifacts_from_package(&package)
            .expect_err("mismatched runtime artifacts were silently truncated");

        assert!(error.contains("runtime artifact fixture length mismatch"));
        assert!(error.contains("receipts=3"));
        assert!(error.contains("envelopes=2"));
        assert!(error.contains("steps=3"));
    }

    #[test]
    fn fresh_package_verifies() {
        let package = fresh_proof_package().expect("fresh package builds");
        let trust_bundle = verifier_trust_bundle().expect("verifier trust bundle builds");
        let context = verification_context();
        let report =
            verify_package(&package, &trust_bundle, &context).expect("fresh package verifies");
        assert!(report.accepted);
        assert!(report
            .checks
            .iter()
            .any(|check| check.code == "workflow.intersection"));
    }

    #[test]
    fn authority_issuance_request_hashes_signed_receipt_body_for_governance(
    ) -> Result<(), ChioPackageError> {
        let package = fresh_proof_package()?;
        let request = authority_issuance_request()?;
        let destructive_step = request
            .steps
            .iter()
            .find(|step| step.destructive)
            .ok_or_else(|| ChioPackageError::Inconsistent("destructive step missing".into()))?;
        let governance_receipt = package
            .governance_receipts
            .first()
            .ok_or_else(|| ChioPackageError::Inconsistent("governance receipt missing".into()))?;

        assert_eq!(
            destructive_step.step_sha256.as_deref(),
            Some(governance_receipt.body.step_sha256.as_str())
        );
        Ok(())
    }

    #[test]
    fn authority_profile_pins_fixture_runtime_policy_signer() -> Result<(), ChioPackageError> {
        let fixture_runtime_policy_key = Keypair::from_seed(&[42; 32]);
        let profile = authority_profile_document()?;

        assert_eq!(
            profile.runtime_policy_issuer_public_keys,
            vec![fixture_runtime_policy_key.public_key()]
        );
        Ok(())
    }

    #[test]
    fn runtime_artifact_package_uses_supplied_envelopes_and_steps() {
        let baseline = fresh_proof_package().expect("fresh package builds");
        let mut artifacts = runtime_artifacts_from_package(&baseline).expect("runtime artifacts");
        artifacts[0].bilateral_envelope.signatures.reverse();
        let supplied_envelope_hash =
            canonical_sha256(&artifacts[0].bilateral_envelope).expect("envelope hashes");
        artifacts[0].workflow_step.bilateral_dsse_sha256 = Some(supplied_envelope_hash.clone());
        artifacts[0].workflow_step.duration_ms = 77;
        refresh_runtime_parent_chain(&mut artifacts);
        let supplied_steps = canonical_string(
            &artifacts
                .iter()
                .map(|artifact| &artifact.workflow_step)
                .collect::<Vec<_>>(),
        )
        .expect("steps canonicalize");
        let supplied_signature_order = artifacts[0].bilateral_envelope.signatures.clone();

        let package = proof_package_from_runtime_artifacts(artifacts).expect("package builds");

        assert_eq!(
            package.bilateral_envelopes[0].signatures,
            supplied_signature_order
        );
        assert_eq!(package.workflow_receipt.steps[0].duration_ms, 77);
        assert_eq!(
            package.workflow_receipt.steps[0]
                .bilateral_dsse_sha256
                .as_deref(),
            Some(supplied_envelope_hash.as_str())
        );
        let packaged_steps =
            canonical_string(&package.workflow_receipt.steps.iter().collect::<Vec<_>>())
                .expect("steps canonicalize");
        assert_eq!(packaged_steps, supplied_steps);

        let trust_bundle_document =
            verifier_trust_bundle_document_for_package(&package).expect("trust bundle builds");
        let trust_bundle = ChioVerifierTrustBundle::from_document(trust_bundle_document).unwrap();
        let context = verification_context();
        let report = verify_package(&package, &trust_bundle, &context)
            .expect("runtime artifact package verifies");
        assert!(report.accepted);
    }

    #[test]
    fn runtime_artifact_package_rejects_step_dsse_hash_mismatch() {
        let baseline = fresh_proof_package().expect("fresh package builds");
        let mut artifacts = runtime_artifacts_from_package(&baseline).expect("runtime artifacts");
        artifacts[0].workflow_step.bilateral_dsse_sha256 = Some("0".repeat(64));

        let error = proof_package_from_runtime_artifacts(artifacts).unwrap_err();

        assert!(error.to_string().contains("DSSE hash"));
    }

    #[test]
    fn runtime_artifact_package_rejects_step_consistency_anchor_mismatch() {
        let baseline = fresh_proof_package().expect("fresh package builds");
        let mut artifacts = runtime_artifacts_from_package(&baseline).expect("runtime artifacts");
        artifacts[0].workflow_step.consistency_anchor =
            Some("chio:consistency:wf-chio-refund-001:wrong".to_string());
        refresh_runtime_parent_chain(&mut artifacts);

        let error = proof_package_from_runtime_artifacts(artifacts).unwrap_err();

        assert!(error.to_string().contains("consistency anchor"));
    }

    #[test]
    fn runtime_receipt_package_rejects_cross_workflow_action_payload(
    ) -> Result<(), ChioPackageError> {
        let baseline = fresh_proof_package()?;
        let mut receipts = baseline.tool_receipts;
        let mut body = receipts[0].body();
        body.action = ToolCallAction::from_parameters(serde_json::json!({
            "workflowId": "wf-other",
            "caseRef": CASE_REF,
            "tool": VENDORS[0].tool_name,
        }))
        .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
        receipts[0] = ChioReceipt::sign(body, &Keypair::from_seed(&VENDOR_A_SEED))
            .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;

        let Err(error) = proof_package_from_runtime_receipts(receipts) else {
            return Err(ChioPackageError::Inconsistent(
                "cross-workflow receipt was accepted".to_string(),
            ));
        };

        assert!(error.to_string().contains("workflow"));
        Ok(())
    }

    #[test]
    fn missing_ladder_ref_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package
            .workflow_intersection
            .pairwise_intersection_refs
            .retain(|peer| peer.peer_kernel_id != "did:chio:vendor-a");
        let trust_bundle = verifier_trust_bundle().unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("pairwise ref") || error.to_string().contains("hash"));
    }

    #[test]
    fn package_peer_pin_not_present_in_trust_bundle_fails_closed() {
        let package = fresh_proof_package().unwrap();
        let mut document = verifier_trust_bundle_document().unwrap();
        document
            .peers
            .retain(|binding| binding.kernel_id != "did:chio:vendor-a");
        let trust_bundle = ChioVerifierTrustBundle::from_document(document).unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("did:chio:vendor-a"));
        assert!(error.to_string().contains("trusted"));
    }

    #[test]
    fn workflow_intersection_hash_mismatch_fails_closed() {
        let package = fresh_proof_package().unwrap();
        let mut document = verifier_trust_bundle_document().unwrap();
        document.workflow_intersections[0].sha256 = "f".repeat(64);
        let trust_bundle = ChioVerifierTrustBundle::from_document(document).unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("workflow intersection"));
    }

    #[test]
    fn stale_lease_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.capability_leases[0].body.expires_at_unix_ms = GENERATED_AT_UNIX_MS;
        package.lease_scope_bindings[0].expires_at_unix_ms = GENERATED_AT_UNIX_MS;
        package.capability_leases[0].body.scope_digest = package.lease_scope_bindings[0]
            .scope_digest()
            .expect("scope digest rebuilds");
        package.capability_leases[0] = SignedExportEnvelope::sign(
            package.capability_leases[0].body.clone(),
            &Keypair::from_seed(&BUYER_SEED),
        )
        .expect("lease re-signs");
        let trust_bundle = verifier_trust_bundle().unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("expired") || error.to_string().contains("signature"));
    }

    #[test]
    fn mismatched_governance_receipt_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.governance_receipts[0].body.workflow_id = "wf-other".to_string();
        let trust_bundle = verifier_trust_bundle().unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("signature") || error.to_string().contains("workflow"));
    }

    #[test]
    fn tampered_step_parent_hash_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.workflow_receipt.steps[1].parent_receipt_sha256 = Some("0".repeat(64));
        resign_workflow_receipt(&mut package).expect("workflow resigns");
        let trust_bundle = verifier_trust_bundle().unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(
            error.to_string().contains("parent hash")
                || error.to_string().contains("workflow intersection")
        );
    }

    #[test]
    fn bad_vendor_signature_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.workflow_receipt.vendor_signatures[0].signature =
            Keypair::from_seed(&[99; 32]).sign(b"not the workflow body");
        let trust_bundle = verifier_trust_bundle().unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("vendor signature"));
    }

    #[test]
    fn unsupported_claims_fail_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.claims.zkvm = true;
        let trust_bundle = verifier_trust_bundle().unwrap();
        let context = verification_context();
        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("zkVM"));
    }

    #[test]
    fn committed_fixtures_verify() {
        let package =
            proof_package_from_json(include_str!("../fixtures/buyer-auditor-proof-package.json"))
                .expect("package fixture parses");
        let trust_bundle =
            verifier_trust_bundle_from_json(include_str!("../fixtures/verifier-trust-bundle.json"))
                .expect("verifier trust bundle fixture parses");
        let context =
            verification_context_from_json(include_str!("../fixtures/verification-context.json"))
                .expect("verification context fixture parses");
        let report =
            verify_package(&package, &trust_bundle, &context).expect("package fixture verifies");
        let committed_report =
            verifier_report_from_json(include_str!("../fixtures/verifier-report.json"))
                .expect("report fixture parses");
        assert_eq!(report, committed_report);
    }

    #[test]
    fn step_tool_receipt_mismatch_fails_closed() {
        let mut package = fresh_proof_package().expect("fresh package builds");
        package.workflow_receipt.steps[0].tool_receipt_id =
            package.workflow_receipt.steps[1].tool_receipt_id.clone();
        resign_workflow_receipt(&mut package).expect("workflow resigns");
        let context = verification_context();
        let trust_bundle = rebuild_verifier_material(&mut package, &context);

        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("tool receipt"));
    }

    #[test]
    fn step_output_hash_mismatch_fails_closed() {
        let mut package = fresh_proof_package().expect("fresh package builds");
        package.workflow_receipt.steps[0].output_hash = Some("0".repeat(64));
        resign_workflow_receipt(&mut package).expect("workflow resigns");
        let context = verification_context();
        let trust_bundle = rebuild_verifier_material(&mut package, &context);

        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("output hash"));
    }

    #[test]
    fn step_consistency_anchor_mismatch_fails_closed() {
        let mut package = fresh_proof_package().expect("fresh package builds");
        package.workflow_receipt.steps[0].consistency_anchor =
            Some("chio:consistency:wf-chio-refund-001:wrong".to_string());
        resign_workflow_receipt(&mut package).expect("workflow resigns");
        let context = verification_context();
        let trust_bundle = rebuild_verifier_material(&mut package, &context);

        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        assert!(error.to_string().contains("consistency anchor"));
    }

    #[test]
    fn bilateral_envelope_deny_verdict_fails_package_verification() {
        let mut package = fresh_proof_package().expect("fresh package builds");
        let buyer_key = Keypair::from_seed(&BUYER_SEED);
        let vendor_key = Keypair::from_seed(&VENDOR_A_SEED);
        resign_bilateral_envelope_unanimous_deny(
            &mut package.bilateral_envelopes[0],
            &buyer_key,
            &vendor_key,
        )
        .expect("deny bilateral envelope resigns");
        package.workflow_receipt.steps[0].bilateral_dsse_sha256 = Some(
            canonical_sha256(&package.bilateral_envelopes[0]).expect("envelope hash computes"),
        );
        refresh_workflow_step_parent_chain(&mut package.workflow_receipt.steps)
            .expect("step parent chain refreshes");
        resign_workflow_receipt(&mut package).expect("workflow resigns");
        let context = verification_context();
        let trust_bundle = rebuild_verifier_material(&mut package, &context);

        let error = verify_package(&package, &trust_bundle, &context).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("bilateral envelope policy verdict"),
            "expected admission gate failure, got: {message}"
        );
        assert!(
            message.contains("deny"),
            "expected deny verdict, got: {message}"
        );
    }
}
