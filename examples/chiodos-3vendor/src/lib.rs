//! Offline Chiodos buyer and auditor proof package fixture.

pub use chio_chiodos::{
    package_from_fixture_json, package_json, report_from_fixture_json, report_json,
    verifier_trust_bundle_from_json, verifier_trust_bundle_json, verify_package,
    ChiodosActionClassKind, ChiodosPackageError, ChiodosPinnedRevocationEpoch, ChiodosProofClaims,
    ChiodosProofPackage, ChiodosTrustedActionClass, ChiodosTrustedWorkflowIntersection,
    ChiodosVerifierTrustBundle, ChiodosVerifierTrustBundleDocument, PeerLadderBinding,
    TrustedBbsIssuer, VendorKeyBinding, VerifierReport, WorkflowIntersectionArtifact,
    WorkflowPairwiseIntersectionRef, WorkflowRequiredVendorSigner, WorkflowStepClassBinding,
    PROOF_PACKAGE_SCHEMA, VERIFIER_REPORT_SCHEMA, VERIFIER_TRUST_BUNDLE_SCHEMA,
    WORKFLOW_INTERSECTION_SCHEMA,
};
use chio_core_types::canonical::{canonical_json_bytes, canonical_json_string};
use chio_core_types::capability::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, SignedExportEnvelope, ToolCallAction, TrustLevel,
};
use chio_federation::{
    sign_chiodos_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    GovernanceReceiptRef, HashRecord, LadderManifestRef, PolicyEvaluationSummary, PolicyVerdict,
};
use chio_governance::{
    CapabilityLeaseActionClass, CapabilityLeaseArtifact, GovernanceReceiptArtifact,
    GovernanceReceiptCaseKind, SignedGovernanceReceipt, CAPABILITY_LEASE_SCHEMA_V1,
    GOVERNANCE_RECEIPT_SCHEMA_V1,
};
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_workflow_receipt_body,
    sign_projection, DisclosureSet, SelectiveDisclosureProof,
};
use chio_workflow::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceipt, WorkflowReceiptBody,
    WORKFLOW_RECEIPT_SCHEMA_V2,
};
use serde::Serialize;

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

pub fn verifier_trust_bundle_document_for_package(
    package: &ChiodosProofPackage,
) -> Result<ChiodosVerifierTrustBundleDocument, ChiodosPackageError> {
    let bbs_keypair = generate_bbs_keypair(BBS_KEY_MATERIAL, BBS_KEY_INFO)
        .map_err(|error| ChiodosPackageError::SelectiveDisclosure(error.to_string()))?;
    Ok(ChiodosVerifierTrustBundleDocument {
        schema: VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        trusted_bbs_issuers: vec![TrustedBbsIssuer {
            issuer_fingerprint: bbs_keypair.issuer_fingerprint,
            public_key_hex: bbs_keypair.public_key_hex,
        }],
        peers: package.peer_ladder_bindings.clone(),
        vendors: package.vendor_keys.clone(),
        action_classes: VENDORS
            .iter()
            .map(|vendor| ChiodosTrustedActionClass {
                action_class_id: vendor.tool_name.to_string(),
                tool_name: vendor.tool_name.to_string(),
                kind: if vendor.destructive {
                    ChiodosActionClassKind::ReceiptBacked
                } else {
                    ChiodosActionClassKind::Routine
                },
            })
            .collect(),
        workflow_intersections: vec![ChiodosTrustedWorkflowIntersection {
            intersection_id: package.workflow_intersection.intersection_id.clone(),
            sha256: canonical_sha256(&package.workflow_intersection)?,
        }],
        revocation: ChiodosPinnedRevocationEpoch {
            now_unix_ms: GENERATED_AT_UNIX_MS,
            epoch_height: 0,
        },
    })
}

pub fn verifier_trust_bundle_document(
) -> Result<ChiodosVerifierTrustBundleDocument, ChiodosPackageError> {
    let package = fresh_proof_package()?;
    verifier_trust_bundle_document_for_package(&package)
}

pub fn verifier_trust_bundle() -> Result<ChiodosVerifierTrustBundle, ChiodosPackageError> {
    ChiodosVerifierTrustBundle::from_document(verifier_trust_bundle_document()?)
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
        let envelope = sign_chiodos_dsse_envelope(
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
        aggregate_workflow_receipt_sha256: canonical_sha256(&workflow_receipt)?,
    };

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
        workflow_intersection,
        selective_disclosure_proof,
    })
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
        let trust_bundle = verifier_trust_bundle().expect("verifier trust bundle builds");
        let report = verify_package(&package, &trust_bundle).expect("fresh package verifies");
        assert!(report.accepted);
        assert!(report
            .checks
            .iter()
            .any(|check| check.code == "workflow.intersection"));
    }

    #[test]
    fn missing_ladder_ref_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package
            .workflow_intersection
            .pairwise_intersection_refs
            .retain(|peer| peer.peer_kernel_id != "did:chio:vendor-a");
        let trust_bundle = verifier_trust_bundle().unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("pairwise ref") || error.to_string().contains("hash"));
    }

    #[test]
    fn package_peer_pin_not_present_in_trust_bundle_fails_closed() {
        let package = fresh_proof_package().unwrap();
        let mut document = verifier_trust_bundle_document().unwrap();
        document
            .peers
            .retain(|binding| binding.kernel_id != "did:chio:vendor-a");
        let trust_bundle = ChiodosVerifierTrustBundle::from_document(document).unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("did:chio:vendor-a"));
        assert!(error.to_string().contains("trusted"));
    }

    #[test]
    fn workflow_intersection_hash_mismatch_fails_closed() {
        let package = fresh_proof_package().unwrap();
        let mut document = verifier_trust_bundle_document().unwrap();
        document.workflow_intersections[0].sha256 = "f".repeat(64);
        let trust_bundle = ChiodosVerifierTrustBundle::from_document(document).unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("workflow intersection"));
    }

    #[test]
    fn stale_lease_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.capability_leases[0].body.expires_at_unix_ms = GENERATED_AT_UNIX_MS;
        let trust_bundle = verifier_trust_bundle().unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("expired") || error.to_string().contains("signature"));
    }

    #[test]
    fn mismatched_governance_receipt_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.governance_receipts[0].body.workflow_id = "wf-other".to_string();
        let trust_bundle = verifier_trust_bundle().unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("signature") || error.to_string().contains("workflow"));
    }

    #[test]
    fn tampered_step_parent_hash_fails_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.workflow_receipt.steps[1].parent_receipt_sha256 = Some("0".repeat(64));
        resign_workflow(&mut package);
        let trust_bundle = verifier_trust_bundle().unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
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
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(
            error.to_string().contains("vendor signature")
                || error.to_string().contains("workflow intersection")
        );
    }

    #[test]
    fn unsupported_claims_fail_closed() {
        let mut package = fresh_proof_package().unwrap();
        package.claims.zkvm = true;
        let trust_bundle = verifier_trust_bundle().unwrap();
        let error = verify_package(&package, &trust_bundle).unwrap_err();
        assert!(error.to_string().contains("zkVM"));
    }

    #[test]
    fn committed_fixtures_verify() {
        let package =
            package_from_fixture_json(include_str!("../fixtures/buyer-auditor-proof-package.json"))
                .expect("package fixture parses");
        let trust_bundle =
            verifier_trust_bundle_from_json(include_str!("../fixtures/verifier-trust-bundle.json"))
                .expect("verifier trust bundle fixture parses");
        let report = verify_package(&package, &trust_bundle).expect("package fixture verifies");
        let committed_report =
            report_from_fixture_json(include_str!("../fixtures/verifier-report.json"))
                .expect("report fixture parses");
        assert_eq!(report, committed_report);
    }
}
