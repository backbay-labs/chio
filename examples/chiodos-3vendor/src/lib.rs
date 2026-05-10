//! Offline Chiodos buyer and auditor proof package fixture.

use std::collections::{BTreeMap, HashMap};

use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::capability::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, SignedExportEnvelope, ToolCallAction, TrustLevel,
};
use chio_federation::{
    sign_dsse_envelope_full, verify_chiodos_bilateral_invocation, ActionClassKind,
    BilateralPredicateExtensions, CapabilityLeaseRef, DemoAllowAllRevocationOracle, DsseEnvelope,
    GovernanceReceiptRef, HashRecord, InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry,
    InMemoryReceiptStore, LadderManifestRef, PeerPinSet, PinnedEpoch, PinnedPeer,
    PolicyEvaluationSummary, PolicyVerdict, ResolvedGovernanceReceipt, ResolvedLease,
    StrictChiodosVerifierConfig, UnknownActionClassPolicy, VerifierConfig,
};
use chio_governance::{
    verify_capability_lease, verify_destructive_authorization, verify_step_governance_boundary,
    CapabilityLeaseActionClass, CapabilityLeaseArtifact, GovernanceReceiptArtifact,
    GovernanceReceiptCaseKind, SignedCapabilityLease, SignedGovernanceReceipt,
    CAPABILITY_LEASE_SCHEMA_V1, GOVERNANCE_RECEIPT_SCHEMA_V1,
};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_workflow_receipt_body,
    sign_projection, verify_selective_disclosure_proof, DisclosureSet, InMemoryIssuerRegistry,
    SelectiveDisclosureProof,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, VendorSignatureRequirement, WorkflowOutcome, WorkflowReceipt,
    WorkflowReceiptBody, WORKFLOW_RECEIPT_SCHEMA_V2,
};
use serde::{Deserialize, Serialize};

pub const PROOF_PACKAGE_SCHEMA: &str = "chio.chiodos.proof-package.v1";
pub const VERIFIER_REPORT_SCHEMA: &str = "chio.chiodos.verifier-report.v1";
pub const WORKFLOW_ID: &str = "wf-chiodos-refund-001";
pub const GENERATED_AT_UNIX_MS: u64 = 1_766_000_000_000;
pub const PROOF_NONCE: &[u8] = b"buyer-auditor-proof-package";

const BUYER_KERNEL_ID: &str = "did:chio:buyer-kernel";
const GOVERNANCE_KERNEL_ID: &str = "did:chio:buyer-governance";
const SESSION_ID: &str = "sess-chiodos-refund";
const CAPABILITY_ID: &str = "cap-chiodos-workflow";
const BBS_KEY_MATERIAL: &[u8] = b"chiodos-conformance-bbs-key-material-0001";
const BBS_KEY_INFO: &[u8] = b"chiodos";

const BUYER_SEED: [u8; 32] = [11; 32];
const GOVERNANCE_SEED: [u8; 32] = [12; 32];
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosProofClaims {
    pub bbs_reveal_set: bool,
    pub hidden_range_predicates: bool,
    pub vc_data_integrity_bbs: bool,
    pub zkvm: bool,
}

impl ChiodosProofClaims {
    pub fn supported() -> Self {
        Self {
            bbs_reveal_set: true,
            hidden_range_predicates: false,
            vc_data_integrity_bbs: false,
            zkvm: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerLadderBinding {
    pub kernel_id: String,
    pub public_key: PublicKey,
    pub ladder_manifest_ref: LadderManifestRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VendorKeyBinding {
    pub vendor_id: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChiodosProofPackage {
    pub schema: String,
    pub generated_at_unix_ms: u64,
    pub workflow_id: String,
    pub claims: ChiodosProofClaims,
    pub peer_ladder_bindings: Vec<PeerLadderBinding>,
    pub vendor_keys: Vec<VendorKeyBinding>,
    pub tool_receipts: Vec<ChioReceipt>,
    pub workflow_receipt: WorkflowReceipt,
    pub bilateral_envelopes: Vec<DsseEnvelope>,
    pub capability_leases: Vec<SignedCapabilityLease>,
    pub governance_receipts: Vec<SignedGovernanceReceipt>,
    pub selective_disclosure_proof: SelectiveDisclosureProof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierCheck {
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierReport {
    pub schema: String,
    pub package_sha256: String,
    pub accepted: bool,
    pub checks: Vec<VerifierCheck>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChiodosPackageError {
    #[error("canonical JSON failed: {0}")]
    Canonical(String),
    #[error("package schema is unsupported: {0}")]
    UnsupportedSchema(String),
    #[error("unsupported proof claim: {0}")]
    UnsupportedClaim(String),
    #[error("workflow verification failed: {0}")]
    Workflow(String),
    #[error("governance verification failed: {0}")]
    Governance(String),
    #[error("federation verification failed: {0}")]
    Federation(String),
    #[error("selective disclosure verification failed: {0}")]
    SelectiveDisclosure(String),
    #[error("fixture data is inconsistent: {0}")]
    Inconsistent(String),
    #[error("JSON operation failed: {0}")]
    Json(String),
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ChiodosPackageError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| ChiodosPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn canonical_string<T: Serialize>(value: &T) -> Result<String, ChiodosPackageError> {
    canonical_json_string(value).map_err(|error| ChiodosPackageError::Canonical(error.to_string()))
}

fn signed_governance_digest(
    receipt: &SignedGovernanceReceipt,
) -> Result<String, ChiodosPackageError> {
    Ok(sha256_hex(canonical_string(receipt)?.as_bytes()))
}

fn workflow_scope_digest(
    step_index: usize,
    tool_name: &str,
) -> Result<String, ChiodosPackageError> {
    let scope = serde_json::json!({
        "workflowId": WORKFLOW_ID,
        "sessionId": SESSION_ID,
        "stepIndex": step_index,
        "toolName": tool_name,
    });
    canonical_sha256(&scope)
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
) -> Result<ChioReceiptBody, ChiodosPackageError> {
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "workflowId": WORKFLOW_ID,
        "caseRef": "refund-250",
        "tool": vendor.tool_name,
    }))
    .map_err(|error| ChiodosPackageError::Inconsistent(error.to_string()))?;
    Ok(ChioReceiptBody {
        id: vendor.receipt_id.to_string(),
        timestamp: GENERATED_AT_UNIX_MS / 1000,
        capability_id: vendor.lease_id.to_string(),
        tool_server: vendor.server_id.to_string(),
        tool_name: vendor.tool_name.to_string(),
        action,
        decision: Decision::Allow,
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
    let policy_version = "chiodos-ladder-v1".to_string();
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

fn lease_artifact(
    vendor: &VendorFixture,
    step_index: usize,
) -> Result<CapabilityLeaseArtifact, ChiodosPackageError> {
    Ok(CapabilityLeaseArtifact {
        schema: CAPABILITY_LEASE_SCHEMA_V1.to_string(),
        lease_id: vendor.lease_id.to_string(),
        issuer: BUYER_KERNEL_ID.to_string(),
        subject: vendor.kernel_id.to_string(),
        scope_digest: workflow_scope_digest(step_index, vendor.tool_name)?,
        action_class: if vendor.destructive {
            CapabilityLeaseActionClass::NarrowDestructive
        } else {
            CapabilityLeaseActionClass::DelegatedAction
        },
        issued_at_unix_ms: GENERATED_AT_UNIX_MS - 30_000,
        expires_at_unix_ms: GENERATED_AT_UNIX_MS + 30_000,
    })
}

fn governance_receipt_artifact(lease_id: &str, step_sha256: &str) -> GovernanceReceiptArtifact {
    GovernanceReceiptArtifact {
        schema: GOVERNANCE_RECEIPT_SCHEMA_V1.to_string(),
        receipt_id: "gov-refund-stage-authorization".to_string(),
        authorizing_kernel: GOVERNANCE_KERNEL_ID.to_string(),
        case_kind: GovernanceReceiptCaseKind::DestructiveAuthorization,
        authorized_lease_id: lease_id.to_string(),
        workflow_id: WORKFLOW_ID.to_string(),
        step_sha256: step_sha256.to_string(),
        issued_at_unix_ms: GENERATED_AT_UNIX_MS - 20_000,
        expires_at_unix_ms: GENERATED_AT_UNIX_MS + 20_000,
    }
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
        output_hash: Some(sha256_hex(vendor.output_label)),
        bilateral_dsse_sha256: Some(envelope_sha256.to_string()),
        governance_receipt_id,
        parent_receipt_sha256,
        consistency_anchor: Some(format!("chiodos:consistency:{WORKFLOW_ID}:{index}")),
        destructive: vendor.destructive.then_some(true),
    }
}

fn disclosure_proof_for_workflow(
    workflow_body: &WorkflowReceiptBody,
) -> Result<SelectiveDisclosureProof, ChiodosPackageError> {
    let projection = project_workflow_receipt_body(workflow_body)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    let bbs_keypair = generate_bbs_keypair(BBS_KEY_MATERIAL, BBS_KEY_INFO)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    let signed = sign_projection(&projection, &bbs_keypair)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    derive_selective_disclosure_proof(
        &signed,
        &projection,
        &bbs_keypair,
        &DisclosureSet(vec![4, 8, 9, 10]),
        PROOF_NONCE,
    )
    .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))
}

fn verify_claims(claims: &ChiodosProofClaims) -> Result<(), ChiodosPackageError> {
    if !claims.bbs_reveal_set {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "bbs reveal-set support must be claimed for this package".to_string(),
        ));
    }
    if claims.hidden_range_predicates {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "hidden range predicates are not supported by this package".to_string(),
        ));
    }
    if claims.vc_data_integrity_bbs {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "VC Data Integrity BBS interop is not supported by this package".to_string(),
        ));
    }
    if claims.zkvm {
        return Err(ChiodosPackageError::UnsupportedClaim(
            "zkVM support is not supported by this package".to_string(),
        ));
    }
    Ok(())
}

pub fn build_proof_package(
    selective_disclosure_proof: SelectiveDisclosureProof,
) -> Result<ChiodosProofPackage, ChiodosPackageError> {
    let package = build_proof_package_unchecked(selective_disclosure_proof)?;
    ensure_disclosure_subject_matches_workflow(&package)?;
    Ok(package)
}

pub fn fresh_proof_package() -> Result<ChiodosProofPackage, ChiodosPackageError> {
    let mut package = build_proof_package_unchecked(empty_disclosure_proof())?;
    package.selective_disclosure_proof =
        disclosure_proof_for_workflow(&package.workflow_receipt.body())?;
    Ok(package)
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
    package: &ChiodosProofPackage,
) -> Result<(), ChiodosPackageError> {
    let projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex != projection.subject_sha256_hex {
        return Err(ChiodosPackageError::SelectiveDisclosure(format!(
            "proof subject {} does not match workflow body {}",
            package.selective_disclosure_proof.subject_sha256_hex, projection.subject_sha256_hex
        )));
    }
    Ok(())
}

fn build_proof_package_unchecked(
    selective_disclosure_proof: SelectiveDisclosureProof,
) -> Result<ChiodosProofPackage, ChiodosPackageError> {
    let buyer_key = Keypair::from_seed(&BUYER_SEED);
    let governance_key = Keypair::from_seed(&GOVERNANCE_SEED);

    let mut tool_receipts = Vec::new();
    let mut leases = Vec::new();
    let mut governance_receipts = Vec::new();
    let mut envelopes = Vec::new();
    let mut steps = Vec::new();
    let mut vendor_keys = Vec::new();
    let mut peer_bindings = vec![PeerLadderBinding {
        kernel_id: BUYER_KERNEL_ID.to_string(),
        public_key: buyer_key.public_key(),
        ladder_manifest_ref: buyer_ladder_ref(),
    }];

    let mut previous_step_sha256: Option<String> = None;
    for (index, vendor) in VENDORS.iter().enumerate() {
        let vendor_key = Keypair::from_seed(&vendor.seed);
        let receipt_body = receipt_body(vendor, &vendor_key)?;
        let receipt = ChioReceipt::sign(receipt_body, &vendor_key)
            .map_err(|error| ChiodosPackageError::Inconsistent(error.to_string()))?;
        let lease = SignedExportEnvelope::sign(lease_artifact(vendor, index)?, &buyer_key)
            .map_err(|error| ChiodosPackageError::Inconsistent(error.to_string()))?;
        lease
            .body
            .validate()
            .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;

        let destructive_step_sha256 = canonical_sha256(&receipt.body())?;
        let governance_receipt = if vendor.destructive {
            Some(
                SignedExportEnvelope::sign(
                    governance_receipt_artifact(vendor.lease_id, &destructive_step_sha256),
                    &governance_key,
                )
                .map_err(|error| ChiodosPackageError::Inconsistent(error.to_string()))?,
            )
        } else {
            None
        };

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
            consistency_anchor: Some(format!("chiodos:anchor:{WORKFLOW_ID}:{index}")),
            consistency_model: None,
            cross_org_visibility: None,
        };
        let envelope = sign_dsse_envelope_full(
            &receipt,
            &buyer_key,
            &vendor_key,
            BUYER_KERNEL_ID,
            vendor.kernel_id,
            vendor.tool_name,
            GENERATED_AT_UNIX_MS,
            extensions,
        )
        .map_err(|error| ChiodosPackageError::Federation(error.to_string()))?;
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
        previous_step_sha256 = Some(canonical_sha256(&step)?);

        peer_bindings.push(PeerLadderBinding {
            kernel_id: vendor.kernel_id.to_string(),
            public_key: vendor_key.public_key(),
            ladder_manifest_ref: ladder_ref(vendor.ladder_manifest_id, vendor.kernel_id),
        });
        vendor_keys.push(VendorKeyBinding {
            vendor_id: vendor.vendor_id.to_string(),
            public_key: vendor_key.public_key(),
        });
        tool_receipts.push(receipt);
        leases.push(lease);
        if let Some(governance_receipt) = governance_receipt {
            governance_receipts.push(governance_receipt);
        }
        envelopes.push(envelope);
        steps.push(step);
    }

    let workflow_body = WorkflowReceiptBody {
        id: WORKFLOW_ID.to_string(),
        schema: WORKFLOW_RECEIPT_SCHEMA_V2.to_string(),
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
        duration_ms: 42,
        kernel_key: buyer_key.public_key(),
    };

    let mut workflow_receipt = WorkflowReceipt::sign(workflow_body, &buyer_key)
        .map_err(|error| ChiodosPackageError::Workflow(error.to_string()))?;
    for vendor in &VENDORS {
        let key = Keypair::from_seed(&vendor.seed);
        workflow_receipt
            .add_vendor_signature(vendor.vendor_id, &key)
            .map_err(|error| ChiodosPackageError::Workflow(error.to_string()))?;
    }

    Ok(ChiodosProofPackage {
        schema: PROOF_PACKAGE_SCHEMA.to_string(),
        generated_at_unix_ms: GENERATED_AT_UNIX_MS,
        workflow_id: WORKFLOW_ID.to_string(),
        claims: ChiodosProofClaims::supported(),
        peer_ladder_bindings: peer_bindings,
        vendor_keys,
        tool_receipts,
        workflow_receipt,
        bilateral_envelopes: envelopes,
        capability_leases: leases,
        governance_receipts,
        selective_disclosure_proof,
    })
}

pub fn package_from_fixture_json(json: &str) -> Result<ChiodosProofPackage, ChiodosPackageError> {
    serde_json::from_str(json).map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn report_from_fixture_json(json: &str) -> Result<VerifierReport, ChiodosPackageError> {
    serde_json::from_str(json).map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn package_json(package: &ChiodosProofPackage) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(package)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn report_json(report: &VerifierReport) -> Result<String, ChiodosPackageError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ChiodosPackageError::Json(error.to_string()))
}

pub fn package_sha256(package: &ChiodosProofPackage) -> Result<String, ChiodosPackageError> {
    let bytes = canonical_json_bytes(package)
        .map_err(|error| ChiodosPackageError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn verify_package(
    package: &ChiodosProofPackage,
) -> Result<VerifierReport, ChiodosPackageError> {
    if package.schema != PROOF_PACKAGE_SCHEMA {
        return Err(ChiodosPackageError::UnsupportedSchema(
            package.schema.clone(),
        ));
    }
    verify_claims(&package.claims)?;

    let mut checks = Vec::new();
    let mut add_check = |name: &str| {
        checks.push(VerifierCheck {
            name: name.to_string(),
            passed: true,
            detail: None,
        });
    };

    if !package
        .workflow_receipt
        .verify()
        .map_err(|error| ChiodosPackageError::Workflow(error.to_string()))?
    {
        return Err(ChiodosPackageError::Workflow(
            "workflow signature is invalid".to_string(),
        ));
    }
    add_check("workflow-kernel-signature");

    let vendor_requirements = package
        .vendor_keys
        .iter()
        .map(|binding| VendorSignatureRequirement {
            vendor_id: binding.vendor_id.clone(),
            public_key: binding.public_key.clone(),
        })
        .collect::<Vec<_>>();
    package
        .workflow_receipt
        .verify_vendor_signatures(&vendor_requirements)
        .map_err(|error| ChiodosPackageError::Workflow(error.to_string()))?;
    add_check("workflow-vendor-cosignatures");

    verify_step_links(package)?;
    add_check("workflow-step-links");

    let mut receipt_store = InMemoryReceiptStore::new();
    for receipt in &package.tool_receipts {
        receipt_store.insert(receipt.clone());
    }
    let mut lease_registry = InMemoryLeaseRegistry::new();
    for lease in &package.capability_leases {
        verify_capability_lease(
            lease,
            GENERATED_AT_UNIX_MS,
            Some(lease.body.scope_digest.clone()),
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        lease_registry.insert(ResolvedLease {
            lease_id: lease.body.lease_id.clone(),
            issuer: lease.body.issuer.clone(),
            expires_at_unix_ms: lease.body.expires_at_unix_ms,
            scope_digest_hex: Some(lease.body.scope_digest.clone()),
        });
    }
    add_check("capability-leases");

    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    for receipt in &package.governance_receipts {
        verify_step_governance_boundary(true, Some(receipt), GENERATED_AT_UNIX_MS)
            .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: receipt.body.receipt_id.clone(),
            kernel_id: receipt.body.authorizing_kernel.clone(),
            canonical_json: canonical_string(receipt)?,
        });
    }
    verify_destructive_steps(package)?;
    add_check("governance-receipts");

    let mut peer_pin_set = PeerPinSet::new();
    for peer in &package.peer_ladder_bindings {
        peer_pin_set.insert(PinnedPeer {
            kernel_id: peer.kernel_id.clone(),
            public_key: peer.public_key.clone(),
            ladder_manifest_ref: Some(peer.ladder_manifest_ref.clone()),
        });
    }
    let revocation_oracle = DemoAllowAllRevocationOracle;
    let mut action_classes = BTreeMap::new();
    for step in &package.workflow_receipt.steps {
        let class = if step.destructive.unwrap_or(false) {
            ActionClassKind::ReceiptBacked
        } else {
            ActionClassKind::Routine
        };
        action_classes.insert(step.tool_name.clone(), class);
    }
    let verifier_config = VerifierConfig {
        peer_pin_set: &peer_pin_set,
        receipt_store: &receipt_store,
        lease_registry: &lease_registry,
        governance_receipt_store: &governance_store,
        revocation_oracle: &revocation_oracle,
        pinned_epoch: PinnedEpoch {
            now_unix_ms: GENERATED_AT_UNIX_MS,
            epoch_height: 0,
        },
        action_classes,
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    };
    for envelope in &package.bilateral_envelopes {
        verify_chiodos_bilateral_invocation(
            envelope,
            &StrictChiodosVerifierConfig {
                base: &verifier_config,
            },
        )
        .map_err(|error| ChiodosPackageError::Federation(error.to_string()))?;
    }
    add_check("strict-bilateral-invocations");

    let workflow_projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex
        != workflow_projection.subject_sha256_hex
    {
        return Err(ChiodosPackageError::SelectiveDisclosure(
            "BBS proof subject does not match workflow receipt body".to_string(),
        ));
    }
    let mut issuer_registry = InMemoryIssuerRegistry::default();
    issuer_registry.insert(
        package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone(),
        package
            .selective_disclosure_proof
            .issuer_public_key_hex
            .clone(),
    );
    verify_selective_disclosure_proof(&package.selective_disclosure_proof, &issuer_registry)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    add_check("bbs-selective-disclosure");

    Ok(VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package)?,
        accepted: true,
        checks,
    })
}

fn verify_step_links(package: &ChiodosProofPackage) -> Result<(), ChiodosPackageError> {
    if package.workflow_receipt.steps.len() != package.bilateral_envelopes.len() {
        return Err(ChiodosPackageError::Workflow(
            "step count does not match bilateral envelope count".to_string(),
        ));
    }
    let mut previous_step_sha256: Option<String> = None;
    for (step, envelope) in package
        .workflow_receipt
        .steps
        .iter()
        .zip(package.bilateral_envelopes.iter())
    {
        let envelope_sha256 = canonical_sha256(envelope)?;
        if step.bilateral_dsse_sha256.as_deref() != Some(envelope_sha256.as_str()) {
            return Err(ChiodosPackageError::Workflow(format!(
                "step {} DSSE hash does not match envelope",
                step.step_index
            )));
        }
        if step.parent_receipt_sha256 != previous_step_sha256 {
            return Err(ChiodosPackageError::Workflow(format!(
                "step {} parent hash does not match previous step",
                step.step_index
            )));
        }
        previous_step_sha256 = Some(canonical_sha256(step)?);
    }
    Ok(())
}

fn verify_destructive_steps(package: &ChiodosProofPackage) -> Result<(), ChiodosPackageError> {
    let leases_by_id = package
        .capability_leases
        .iter()
        .map(|lease| (lease.body.lease_id.clone(), lease))
        .collect::<HashMap<_, _>>();
    let governance_by_id = package
        .governance_receipts
        .iter()
        .map(|receipt| (receipt.body.receipt_id.clone(), receipt))
        .collect::<HashMap<_, _>>();
    let receipts_by_id = package
        .tool_receipts
        .iter()
        .map(|receipt| (receipt.id.clone(), receipt))
        .collect::<HashMap<_, _>>();
    for step in &package.workflow_receipt.steps {
        if !step.destructive.unwrap_or(false) {
            continue;
        }
        let governance_id = step.governance_receipt_id.as_ref().ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "destructive step {} has no governance receipt id",
                step.step_index
            ))
        })?;
        let governance_receipt = governance_by_id.get(governance_id).ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "governance receipt {governance_id} is not present in package"
            ))
        })?;
        let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "destructive step {} has no tool receipt id",
                step.step_index
            ))
        })?;
        let tool_receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChiodosPackageError::Governance(format!(
                "tool receipt {tool_receipt_id} is not present in package"
            ))
        })?;
        let step_sha256 = canonical_sha256(&tool_receipt.body())?;
        let lease = leases_by_id
            .get(&governance_receipt.body.authorized_lease_id)
            .ok_or_else(|| {
                ChiodosPackageError::Governance(format!(
                    "lease {} is not present in package",
                    governance_receipt.body.authorized_lease_id
                ))
            })?;
        verify_capability_lease(
            lease,
            GENERATED_AT_UNIX_MS,
            Some(lease.body.scope_digest.clone()),
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
        verify_destructive_authorization(
            governance_receipt,
            &lease.body.lease_id,
            WORKFLOW_ID,
            &step_sha256,
            GENERATED_AT_UNIX_MS,
        )
        .map_err(|error| ChiodosPackageError::Governance(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn resign_workflow(package: &mut ChiodosProofPackage) {
        let buyer_key = Keypair::from_seed(&BUYER_SEED);
        let mut workflow = WorkflowReceipt::sign(package.workflow_receipt.body(), &buyer_key)
            .expect("workflow resigns");
        for vendor in &VENDORS {
            let key = Keypair::from_seed(&vendor.seed);
            workflow
                .add_vendor_signature(vendor.vendor_id, &key)
                .expect("vendor cosigns");
        }
        package.workflow_receipt = workflow;
    }

    #[test]
    fn fresh_package_verifies() {
        let package = fresh_proof_package().expect("fresh package builds");
        let report = verify_package(&package).expect("fresh package verifies");
        assert!(report.accepted);
        assert_eq!(report.checks.len(), 7);
    }

    #[test]
    fn missing_ladder_ref_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package
            .peer_ladder_bindings
            .retain(|peer| peer.kernel_id != BUYER_KERNEL_ID);
        let error = verify_package(&package).unwrap_err();
        assert!(error.to_string().contains("unpinned") || error.to_string().contains("ladder"));
    }

    #[test]
    fn stale_lease_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.capability_leases[0].body.expires_at_unix_ms = GENERATED_AT_UNIX_MS;
        let error = verify_package(&package).unwrap_err();
        assert!(error.to_string().contains("expired") || error.to_string().contains("signature"));
    }

    #[test]
    fn mismatched_governance_receipt_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.governance_receipts[0].body.workflow_id = "wf-other".to_string();
        let error = verify_package(&package).unwrap_err();
        assert!(error.to_string().contains("signature") || error.to_string().contains("workflow"));
    }

    #[test]
    fn tampered_step_parent_hash_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.workflow_receipt.steps[1].parent_receipt_sha256 = Some("0".repeat(64));
        resign_workflow(&mut package);
        let error = verify_package(&package).unwrap_err();
        assert!(error.to_string().contains("parent hash"));
    }

    #[test]
    fn bad_vendor_signature_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.vendor_keys[0].public_key = Keypair::from_seed(&[99; 32]).public_key();
        let error = verify_package(&package).unwrap_err();
        assert!(error.to_string().contains("unexpected key"));
    }

    #[test]
    fn unsupported_claims_fail_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.claims.zkvm = true;
        let error = verify_package(&package).unwrap_err();
        assert!(error.to_string().contains("zkVM"));
    }

    #[test]
    fn committed_fixtures_verify() {
        let package =
            package_from_fixture_json(include_str!("../fixtures/buyer-auditor-proof-package.json"))
                .expect("package fixture parses");
        let report = verify_package(&package).expect("package fixture verifies");
        let committed_report =
            report_from_fixture_json(include_str!("../fixtures/verifier-report.json"))
                .expect("report fixture parses");
        assert_eq!(report, committed_report);
    }
}
