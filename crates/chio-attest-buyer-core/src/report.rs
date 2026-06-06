use std::collections::{BTreeMap, BTreeSet, HashMap};

use chio_federation::{
    verify_chio_bilateral_invocation, ChioBilateralVerifierConfig, InMemoryGovernanceReceiptStore,
    InMemoryLeaseRegistry, InMemoryReceiptStore, PeerPinSet, PinnedPeer, ResolvedGovernanceReceipt,
    ResolvedLease, UnknownActionClassPolicy, VerifierConfig,
};
use chio_governance::authorization::{
    verify_destructive_authorization, verify_step_governance_boundary, SignedGovernanceReceipt,
};
use chio_governance::lease::{
    verify_capability_lease, CapabilityLeaseActionClass, SignedCapabilityLease,
};
use chio_selective_disclosure::{verify_selective_disclosure_proof, InMemoryIssuerRegistry};
use chio_workflow::receipt::VendorSignatureRequirement;
use serde::{Deserialize, Serialize};

use crate::claims::WORKFLOW_INTERSECTION_SCHEMA;
use crate::context::{verification_context_sha256, ChioVerificationContext};
use crate::disclosure::{disclosure_projection_for_proof, verify_disclosure_contract};
use crate::error::ChioPackageError;
use crate::oracle::OfflineRevocationOracle;
use crate::proof_package::{package_sha256, verify_claims, ChioProofPackage, PROOF_PACKAGE_SCHEMA};
use crate::trust_bundle::ChioVerifierTrustBundle;
use crate::validation::{authority_window, canonical_sha256, canonical_string};

pub const VERIFIER_REPORT_SCHEMA: &str = "chio.attest.verifier-report.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierCheck {
    pub code: String,
    pub name: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierFailure {
    pub code: String,
    pub phase: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifierReport {
    pub schema: String,
    pub package_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_bundle_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_epoch_height: Option<u64>,
    pub accepted: bool,
    pub checks: Vec<VerifierCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<VerifierFailure>,
}

pub fn verifier_report_from_json(json: &str) -> Result<VerifierReport, ChioPackageError> {
    serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn report_json(report: &VerifierReport) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(report).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verify_package(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
) -> Result<VerifierReport, ChioPackageError> {
    let mut checks = Vec::new();
    match verify_package_inner(package, trust_bundle, context, &mut checks) {
        Ok(()) => accepted_report(package, trust_bundle, context, checks),
        Err(error) => Err(error),
    }
}

pub fn verify_package_report(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
) -> VerifierReport {
    let mut checks = Vec::new();
    match verify_package_inner(package, trust_bundle, context, &mut checks) {
        Ok(()) => {
            let accepted_checks = checks.clone();
            accepted_report(package, trust_bundle, context, checks).unwrap_or_else(|error| {
                rejected_report(
                    package,
                    trust_bundle,
                    Some(context),
                    accepted_checks,
                    &error,
                )
            })
        }
        Err(error) => rejected_report(package, trust_bundle, Some(context), checks, &error),
    }
}

fn verify_package_inner(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
    checks: &mut Vec<VerifierCheck>,
) -> Result<(), ChioPackageError> {
    if package.schema != PROOF_PACKAGE_SCHEMA {
        return Err(ChioPackageError::UnsupportedSchema(package.schema.clone()));
    }
    verify_claims(&package.claims)?;
    context.validate()?;
    if context.issued_at_unix_ms > trust_bundle.verification_time_unix_ms() {
        return Err(ChioPackageError::VerificationContext(
            "verification context is issued after the pinned revocation epoch".to_string(),
        ));
    }
    if context.expires_at_unix_ms <= trust_bundle.verification_time_unix_ms() {
        return Err(ChioPackageError::VerificationContext(
            "verification context is expired".to_string(),
        ));
    }
    trust_bundle.ensure_checkpoint_covers_context(context)?;

    let add_check = |checks: &mut Vec<VerifierCheck>, code: &str, name: &str| {
        checks.push(VerifierCheck {
            code: code.to_string(),
            name: name.to_string(),
            passed: true,
            detail: None,
        });
    };

    if !package
        .workflow_receipt
        .verify()
        .map_err(|error| ChioPackageError::Workflow(error.to_string()))?
    {
        return Err(ChioPackageError::Workflow(
            "workflow signature is invalid".to_string(),
        ));
    }
    add_check(
        checks,
        "workflow.kernel_signature",
        "workflow-kernel-signature",
    );

    verify_package_hints_match_trust(package, trust_bundle)?;
    add_check(checks, "trust.package_hints", "package-trust-hints");

    verify_workflow_intersection(package, trust_bundle)?;
    add_check(checks, "workflow.intersection", "workflow-intersection");

    let vendor_requirements = package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|binding| VendorSignatureRequirement {
            vendor_id: binding.vendor_id.clone(),
            public_key: binding.public_key.clone(),
        })
        .collect::<Vec<_>>();
    package
        .workflow_receipt
        .verify_vendor_signatures(&vendor_requirements)
        .map_err(|error| ChioPackageError::Workflow(error.to_string()))?;
    add_check(
        checks,
        "workflow.vendor_cosignatures",
        "workflow-vendor-cosignatures",
    );

    verify_step_links(package)?;
    add_check(checks, "workflow.step_links", "workflow-step-links");

    let mut receipt_store = InMemoryReceiptStore::new();
    for receipt in &package.tool_receipts {
        receipt_store.insert(receipt.clone());
    }
    let lease_scope_digests = verify_lease_scope_bindings(package)?;
    add_check(
        checks,
        "governance.lease_scope_bindings",
        "lease-scope-bindings",
    );

    let mut lease_registry = InMemoryLeaseRegistry::new();
    let mut seen_lease_ids = BTreeSet::new();
    for lease in &package.capability_leases {
        if !seen_lease_ids.insert(lease.body.lease_id.clone()) {
            return Err(ChioPackageError::Governance(format!(
                "duplicate capability lease {}",
                lease.body.lease_id
            )));
        }
        let scope_digest = lease_scope_digests
            .get(&lease.body.lease_id)
            .ok_or_else(|| {
                ChioPackageError::LeaseScopeBinding(format!(
                    "lease {} has no scope binding",
                    lease.body.lease_id
                ))
            })?
            .clone();
        verify_trusted_capability_lease(lease, trust_bundle, &scope_digest)?;
        lease_registry.insert(ResolvedLease {
            lease_id: lease.body.lease_id.clone(),
            issuer: lease.body.issuer.clone(),
            expires_at_unix_ms: lease.body.expires_at_unix_ms,
            scope_digest_hex: Some(scope_digest),
        });
    }
    add_check(checks, "governance.capability_leases", "capability-leases");

    let mut governance_store = InMemoryGovernanceReceiptStore::new();
    let mut seen_governance_ids = BTreeSet::new();
    for receipt in &package.governance_receipts {
        if !seen_governance_ids.insert(receipt.body.receipt_id.clone()) {
            return Err(ChioPackageError::Governance(format!(
                "duplicate governance receipt {}",
                receipt.body.receipt_id
            )));
        }
        verify_trusted_governance_receipt(receipt, trust_bundle)?;
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: receipt.body.receipt_id.clone(),
            kernel_id: receipt.body.authorizing_kernel.clone(),
            canonical_json: canonical_string(receipt)?,
        });
    }
    verify_destructive_steps(package, trust_bundle, &lease_scope_digests)?;
    add_check(checks, "governance.receipts", "governance-receipts");

    let mut peer_pin_set = PeerPinSet::new();
    for peer in trust_bundle.peers.values() {
        peer_pin_set.insert(PinnedPeer {
            kernel_id: peer.kernel_id.clone(),
            public_key: peer.public_key.clone(),
            ladder_manifest_ref: Some(peer.ladder_manifest_ref.clone()),
        });
    }
    let revocation_oracle = OfflineRevocationOracle {
        revoked_key_fingerprints: trust_bundle.revoked_key_fingerprints.clone(),
    };
    let verifier_config = VerifierConfig {
        peer_pin_set: &peer_pin_set,
        receipt_store: &receipt_store,
        lease_registry: &lease_registry,
        governance_receipt_store: &governance_store,
        revocation_oracle: &revocation_oracle,
        pinned_epoch: trust_bundle.pinned_epoch(),
        action_classes: trust_bundle.action_class_map(),
        unknown_action_class_policy: UnknownActionClassPolicy::Reject,
    };
    for envelope in &package.bilateral_envelopes {
        let verified = verify_chio_bilateral_invocation(
            envelope,
            &ChioBilateralVerifierConfig {
                base: &verifier_config,
            },
        )
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
        if verified.joint_verdict != "allow" {
            return Err(ChioPackageError::Federation(format!(
                "bilateral envelope policy verdict {:?} is not allow",
                verified.joint_verdict
            )));
        }
    }
    add_check(
        checks,
        "federation.strict_bilateral_invocations",
        "strict-bilateral-invocations",
    );

    let disclosure_projection =
        disclosure_projection_for_proof(package, &package.selective_disclosure_proof)?;
    let trusted_issuer_key = trust_bundle
        .issuer_public_key_hex(&package.selective_disclosure_proof.issuer_fingerprint)
        .ok_or_else(|| {
            ChioPackageError::TrustedIssuer(format!(
                "issuer {} is not trusted",
                package.selective_disclosure_proof.issuer_fingerprint
            ))
        })?;
    trust_bundle.ensure_not_revoked(
        &package.selective_disclosure_proof.issuer_fingerprint,
        "BBS issuer",
    )?;
    if trusted_issuer_key != package.selective_disclosure_proof.issuer_public_key_hex {
        return Err(ChioPackageError::TrustedIssuer(format!(
            "issuer public key for {} does not match trusted registry",
            package.selective_disclosure_proof.issuer_fingerprint
        )));
    }
    add_check(checks, "trust.bbs_issuer", "trusted-bbs-issuer");

    verify_disclosure_contract(
        &package.selective_disclosure_proof,
        &disclosure_projection,
        &trust_bundle.disclosure_policy,
        context,
    )?;

    let mut issuer_registry = InMemoryIssuerRegistry::default();
    issuer_registry.insert(
        package
            .selective_disclosure_proof
            .issuer_fingerprint
            .clone(),
        trusted_issuer_key.to_string(),
    );
    verify_selective_disclosure_proof(&package.selective_disclosure_proof, &issuer_registry)
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    add_check(
        checks,
        "bbs.selective_disclosure",
        "bbs-selective-disclosure",
    );

    Ok(())
}

fn accepted_report(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: &ChioVerificationContext,
    checks: Vec<VerifierCheck>,
) -> Result<VerifierReport, ChioPackageError> {
    Ok(VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package)?,
        trust_bundle_sha256: Some(trust_bundle.document_sha256.clone()),
        context_sha256: Some(verification_context_sha256(context)?),
        revocation_epoch_height: Some(trust_bundle.revocation_epoch_height()),
        accepted: true,
        checks,
        failure: None,
    })
}

fn rejected_report(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    context: Option<&ChioVerificationContext>,
    checks: Vec<VerifierCheck>,
    error: &ChioPackageError,
) -> VerifierReport {
    VerifierReport {
        schema: VERIFIER_REPORT_SCHEMA.to_string(),
        package_sha256: package_sha256(package).unwrap_or_else(|_| "unavailable".to_string()),
        trust_bundle_sha256: Some(trust_bundle.document_sha256.clone()),
        context_sha256: context.and_then(|context| verification_context_sha256(context).ok()),
        revocation_epoch_height: Some(trust_bundle.revocation_epoch_height()),
        accepted: false,
        checks,
        failure: Some(VerifierFailure {
            code: failure_code(error).to_string(),
            phase: failure_phase(error).to_string(),
            detail: error.to_string(),
        }),
    }
}

fn failure_code(error: &ChioPackageError) -> &'static str {
    match error {
        ChioPackageError::Canonical(_) => "canonical_json",
        ChioPackageError::UnsupportedSchema(_) => "package.schema",
        ChioPackageError::UnsupportedClaim(_) => "package.claim",
        ChioPackageError::Workflow(_) => "workflow",
        ChioPackageError::Governance(_) => "governance",
        ChioPackageError::Federation(_) => "federation",
        ChioPackageError::SelectiveDisclosure(message) if message.contains("proof nonce") => {
            "bbs.context_nonce"
        }
        ChioPackageError::SelectiveDisclosure(_) => "bbs",
        ChioPackageError::TrustedIssuer(_) => "trust.bbs_issuer",
        ChioPackageError::TrustBundle(_) => "trust.bundle",
        ChioPackageError::WorkflowIntersection(_) => "workflow.intersection",
        ChioPackageError::LeaseScopeBinding(_) => "lease.scope_binding",
        ChioPackageError::VerificationContext(_) => "verification.context",
        ChioPackageError::Inconsistent(_) => "package.inconsistent",
        ChioPackageError::Json(_) => "json",
    }
}

fn failure_phase(error: &ChioPackageError) -> &'static str {
    match error {
        ChioPackageError::Canonical(_) | ChioPackageError::Json(_) => "parse",
        ChioPackageError::UnsupportedSchema(_)
        | ChioPackageError::UnsupportedClaim(_)
        | ChioPackageError::Inconsistent(_) => "package",
        ChioPackageError::TrustBundle(_)
        | ChioPackageError::TrustedIssuer(_)
        | ChioPackageError::VerificationContext(_) => "trust",
        ChioPackageError::Workflow(_)
        | ChioPackageError::WorkflowIntersection(_)
        | ChioPackageError::LeaseScopeBinding(_) => "workflow",
        ChioPackageError::Governance(_) => "governance",
        ChioPackageError::Federation(_) => "federation",
        ChioPackageError::SelectiveDisclosure(_) => "bbs",
    }
}

fn verify_package_hints_match_trust(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
) -> Result<(), ChioPackageError> {
    if package.peer_ladder_bindings.is_empty() {
        return Err(ChioPackageError::TrustBundle(
            "package carries no peer ladder hints".to_string(),
        ));
    }
    let mut package_peer_ids = BTreeSet::new();
    for peer in &package.peer_ladder_bindings {
        if !package_peer_ids.insert(peer.kernel_id.clone()) {
            return Err(ChioPackageError::TrustBundle(format!(
                "package carries duplicate peer hint {}",
                peer.kernel_id
            )));
        }
        let trusted = trust_bundle.peer(&peer.kernel_id).ok_or_else(|| {
            ChioPackageError::TrustBundle(format!(
                "package peer {} is not trusted by verifier trust bundle",
                peer.kernel_id
            ))
        })?;
        trust_bundle.ensure_public_key_not_revoked(&trusted.public_key, "peer key")?;
        if trusted.public_key != peer.public_key {
            return Err(ChioPackageError::TrustBundle(format!(
                "package peer {} public key does not match verifier trust bundle",
                peer.kernel_id
            )));
        }
        if trusted.ladder_manifest_ref != peer.ladder_manifest_ref {
            return Err(ChioPackageError::TrustBundle(format!(
                "package peer {} ladder ref does not match verifier trust bundle",
                peer.kernel_id
            )));
        }
        if !trusted
            .ladder_manifest_ref
            .is_fresh(trust_bundle.verification_time_unix_ms())
        {
            return Err(ChioPackageError::TrustBundle(format!(
                "trusted ladder ref for {} is stale",
                peer.kernel_id
            )));
        }
    }

    if package.vendor_keys.is_empty() {
        return Err(ChioPackageError::TrustBundle(
            "package carries no vendor key hints".to_string(),
        ));
    }
    let mut package_vendor_ids = BTreeSet::new();
    for vendor in &package.vendor_keys {
        if !package_vendor_ids.insert(vendor.vendor_id.clone()) {
            return Err(ChioPackageError::TrustBundle(format!(
                "package carries duplicate vendor hint {}",
                vendor.vendor_id
            )));
        }
        let trusted = trust_bundle.vendors.get(&vendor.vendor_id).ok_or_else(|| {
            ChioPackageError::TrustBundle(format!(
                "package vendor {} is not trusted by verifier trust bundle",
                vendor.vendor_id
            ))
        })?;
        trust_bundle.ensure_public_key_not_revoked(&trusted.public_key, "vendor key")?;
        if trusted.public_key != vendor.public_key {
            return Err(ChioPackageError::TrustBundle(format!(
                "package vendor {} public key does not match verifier trust bundle",
                vendor.vendor_id
            )));
        }
    }
    Ok(())
}

fn verify_workflow_intersection(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
) -> Result<(), ChioPackageError> {
    let intersection = &package.workflow_intersection;
    if intersection.schema != WORKFLOW_INTERSECTION_SCHEMA {
        return Err(ChioPackageError::WorkflowIntersection(format!(
            "workflow intersection schema {} is unsupported",
            intersection.schema
        )));
    }
    if intersection.workflow_id != package.workflow_id {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection workflow id does not match package".to_string(),
        ));
    }
    if intersection.workflow_grant_id != package.workflow_receipt.capability_id {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection grant id does not match workflow receipt".to_string(),
        ));
    }

    let aggregate_hash = canonical_sha256(&package.workflow_receipt.body())?;
    if intersection.aggregate_workflow_receipt_sha256 != aggregate_hash {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection aggregate workflow receipt hash mismatch".to_string(),
        ));
    }

    let artifact_hash = canonical_sha256(intersection)?;
    let trusted_hash = trust_bundle
        .workflow_intersection_hash(&intersection.intersection_id)
        .ok_or_else(|| {
            ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection {} is not trusted",
                intersection.intersection_id
            ))
        })?;
    if trusted_hash != artifact_hash {
        return Err(ChioPackageError::WorkflowIntersection(format!(
            "workflow intersection {} hash does not match verifier trust bundle",
            intersection.intersection_id
        )));
    }

    let mut seen_vendor_ids = BTreeSet::new();
    for signer in &intersection.required_vendor_signers {
        let trusted = trust_bundle.vendors.get(&signer.vendor_id).ok_or_else(|| {
            ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection signer {} is not trusted",
                signer.vendor_id
            ))
        })?;
        if !seen_vendor_ids.insert(signer.vendor_id.clone()) {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate signer {}",
                signer.vendor_id
            )));
        }
        if trusted.public_key != signer.public_key {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection signer {} key mismatch",
                signer.vendor_id
            )));
        }
    }

    let mut pairwise_by_peer = BTreeMap::new();
    for pairwise in &intersection.pairwise_intersection_refs {
        let trusted = trust_bundle.peer(&pairwise.peer_kernel_id).ok_or_else(|| {
            ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection peer {} is not trusted",
                pairwise.peer_kernel_id
            ))
        })?;
        if trusted.ladder_manifest_ref != pairwise.ladder_manifest_ref {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection peer {} ladder ref mismatch",
                pairwise.peer_kernel_id
            )));
        }
        if pairwise_by_peer
            .insert(pairwise.peer_kernel_id.clone(), pairwise)
            .is_some()
        {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate peer {}",
                pairwise.peer_kernel_id
            )));
        }
    }

    if intersection.step_class_bindings.len() != package.workflow_receipt.steps.len() {
        return Err(ChioPackageError::WorkflowIntersection(
            "workflow intersection step binding count does not match workflow receipt".to_string(),
        ));
    }
    let mut seen_steps = BTreeSet::new();
    for binding in &intersection.step_class_bindings {
        if !seen_steps.insert(binding.step_index) {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection carries duplicate step {}",
                binding.step_index
            )));
        }
        let step = package
            .workflow_receipt
            .steps
            .get(binding.step_index)
            .ok_or_else(|| {
                ChioPackageError::WorkflowIntersection(format!(
                    "workflow intersection references missing step {}",
                    binding.step_index
                ))
            })?;
        if step.tool_name != binding.tool_name {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection step {} tool mismatch",
                binding.step_index
            )));
        }
        if !pairwise_by_peer.contains_key(&binding.peer_kernel_id) {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection step {} references peer {} without pairwise ref",
                binding.step_index, binding.peer_kernel_id
            )));
        }
        let trusted_class = trust_bundle
            .action_classes
            .get(&binding.tool_name)
            .ok_or_else(|| {
                ChioPackageError::WorkflowIntersection(format!(
                    "workflow intersection tool {} has no trusted action class",
                    binding.tool_name
                ))
            })?;
        if trusted_class.action_class_id != binding.action_class_id {
            return Err(ChioPackageError::WorkflowIntersection(format!(
                "workflow intersection tool {} action class mismatch",
                binding.tool_name
            )));
        }
    }
    Ok(())
}

fn verify_step_links(package: &ChioProofPackage) -> Result<(), ChioPackageError> {
    if package.workflow_receipt.steps.len() != package.bilateral_envelopes.len() {
        return Err(ChioPackageError::Workflow(
            "step count does not match bilateral envelope count".to_string(),
        ));
    }
    let mut receipts_by_id = HashMap::new();
    for receipt in &package.tool_receipts {
        if receipts_by_id.insert(receipt.id.clone(), receipt).is_some() {
            return Err(ChioPackageError::Workflow(format!(
                "duplicate tool receipt {}",
                receipt.id
            )));
        }
    }
    let mut leases_by_id = HashMap::new();
    for lease in &package.capability_leases {
        if leases_by_id
            .insert(lease.body.lease_id.clone(), lease)
            .is_some()
        {
            return Err(ChioPackageError::Workflow(format!(
                "duplicate capability lease {}",
                lease.body.lease_id
            )));
        }
    }
    let mut step_classes = HashMap::new();
    for binding in &package.workflow_intersection.step_class_bindings {
        if step_classes.insert(binding.step_index, binding).is_some() {
            return Err(ChioPackageError::Workflow(format!(
                "duplicate workflow step class binding {}",
                binding.step_index
            )));
        }
    }
    let mut previous_step_sha256: Option<String> = None;
    for (expected_index, (step, envelope)) in package
        .workflow_receipt
        .steps
        .iter()
        .zip(package.bilateral_envelopes.iter())
        .enumerate()
    {
        if step.step_index != expected_index {
            return Err(ChioPackageError::Workflow(format!(
                "step index {} does not match position {}",
                step.step_index, expected_index
            )));
        }
        let envelope_sha256 = canonical_sha256(envelope)?;
        if step.bilateral_dsse_sha256.as_deref() != Some(envelope_sha256.as_str()) {
            return Err(ChioPackageError::Workflow(format!(
                "step {} DSSE hash does not match envelope",
                step.step_index
            )));
        }
        if step.parent_receipt_sha256 != previous_step_sha256 {
            return Err(ChioPackageError::Workflow(format!(
                "step {} parent hash does not match previous step",
                step.step_index
            )));
        }
        let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
            ChioPackageError::Workflow(format!("step {} has no tool receipt id", step.step_index))
        })?;
        let tool_receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} tool receipt {} is not present in package",
                step.step_index, tool_receipt_id
            ))
        })?;
        let (statement, _) = envelope.decode_statement().map_err(|error| {
            ChioPackageError::Federation(format!("step {} DSSE payload: {error}", step.step_index))
        })?;
        let predicate = &statement.predicate;
        if predicate.invocation_id != *tool_receipt_id {
            return Err(ChioPackageError::Workflow(format!(
                "step {} tool receipt id {} does not match DSSE invocation {}",
                step.step_index, tool_receipt_id, predicate.invocation_id
            )));
        }
        if step.tool_name != tool_receipt.tool_name {
            return Err(ChioPackageError::Workflow(format!(
                "step {} tool name {} does not match tool receipt {}",
                step.step_index, step.tool_name, tool_receipt.tool_name
            )));
        }
        if step.tool_name != predicate.tool_name {
            return Err(ChioPackageError::Workflow(format!(
                "step {} tool name {} does not match DSSE predicate {}",
                step.step_index, step.tool_name, predicate.tool_name
            )));
        }
        if step.server_id != tool_receipt.tool_server {
            return Err(ChioPackageError::Workflow(format!(
                "step {} server id {} does not match tool receipt server {}",
                step.step_index, step.server_id, tool_receipt.tool_server
            )));
        }
        if step.output_hash.as_deref() != Some(tool_receipt.content_hash.as_str()) {
            return Err(ChioPackageError::Workflow(format!(
                "step {} output hash does not match tool receipt content hash",
                step.step_index
            )));
        }
        let expected_anchor = format!(
            "chio:consistency:{}:{}",
            package.workflow_id, step.step_index
        );
        if step.consistency_anchor.as_deref() != Some(expected_anchor.as_str()) {
            return Err(ChioPackageError::Workflow(format!(
                "step {} consistency anchor must be {}",
                step.step_index, expected_anchor
            )));
        }
        if predicate.consistency_anchor.as_deref() != step.consistency_anchor.as_deref() {
            return Err(ChioPackageError::Workflow(format!(
                "step {} consistency anchor does not match DSSE predicate",
                step.step_index
            )));
        }
        let class_binding = step_classes.get(&step.step_index).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} has no workflow class binding",
                step.step_index
            ))
        })?;
        if class_binding.tool_name != step.tool_name {
            return Err(ChioPackageError::Workflow(format!(
                "step {} class binding tool does not match step",
                step.step_index
            )));
        }
        if class_binding.peer_kernel_id != predicate.tool_server_b.kernel_id {
            return Err(ChioPackageError::Workflow(format!(
                "step {} peer kernel does not match DSSE tool_server_b",
                step.step_index
            )));
        }
        let lease_ref = predicate.capability_lease_ref.as_ref().ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} DSSE predicate has no capability lease ref",
                step.step_index
            ))
        })?;
        let lease = leases_by_id.get(&lease_ref.lease_id).ok_or_else(|| {
            ChioPackageError::Workflow(format!(
                "step {} lease {} is not present in package",
                step.step_index, lease_ref.lease_id
            ))
        })?;
        if lease.body.subject != class_binding.peer_kernel_id {
            return Err(ChioPackageError::Workflow(format!(
                "step {} lease subject does not match workflow peer binding",
                step.step_index
            )));
        }
        let destructive = step.destructive.unwrap_or(false);
        let lease_destructive =
            lease.body.action_class == CapabilityLeaseActionClass::NarrowDestructive;
        if destructive != lease_destructive {
            return Err(ChioPackageError::Workflow(format!(
                "step {} destructive flag does not match lease action class",
                step.step_index
            )));
        }
        match (
            destructive,
            step.governance_receipt_id.as_ref(),
            predicate.governance_receipt_ref.as_ref(),
        ) {
            (true, Some(step_receipt_id), Some(predicate_receipt)) => {
                if step_receipt_id != &predicate_receipt.receipt_id {
                    return Err(ChioPackageError::Workflow(format!(
                        "step {} governance receipt id does not match DSSE predicate",
                        step.step_index
                    )));
                }
            }
            (true, None, _) => {
                return Err(ChioPackageError::Workflow(format!(
                    "step {} destructive action has no governance receipt id",
                    step.step_index
                )));
            }
            (true, _, None) => {
                return Err(ChioPackageError::Workflow(format!(
                    "step {} destructive action has no DSSE governance receipt ref",
                    step.step_index
                )));
            }
            (false, Some(_), _) | (false, _, Some(_)) => {
                return Err(ChioPackageError::Workflow(format!(
                    "step {} non-destructive action carries governance receipt material",
                    step.step_index
                )));
            }
            (false, None, None) => {}
        }
        previous_step_sha256 = Some(canonical_sha256(step)?);
    }
    Ok(())
}

fn verify_lease_scope_bindings(
    package: &ChioProofPackage,
) -> Result<BTreeMap<String, String>, ChioPackageError> {
    if package.lease_scope_bindings.len() != package.capability_leases.len() {
        return Err(ChioPackageError::LeaseScopeBinding(
            "lease scope binding count does not match capability lease count".to_string(),
        ));
    }
    let leases_by_id = package
        .capability_leases
        .iter()
        .map(|lease| (lease.body.lease_id.clone(), lease))
        .collect::<HashMap<_, _>>();
    let step_classes = package
        .workflow_intersection
        .step_class_bindings
        .iter()
        .map(|binding| (binding.step_index, binding))
        .collect::<HashMap<_, _>>();
    let receipts_by_step = package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| {
            let receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
                ChioPackageError::LeaseScopeBinding(format!(
                    "step {} has no tool receipt id",
                    step.step_index
                ))
            })?;
            let receipt = package
                .tool_receipts
                .iter()
                .find(|receipt| &receipt.id == receipt_id)
                .ok_or_else(|| {
                    ChioPackageError::LeaseScopeBinding(format!(
                        "step {} tool receipt {} is not present",
                        step.step_index, receipt_id
                    ))
                })?;
            Ok((step.step_index, (step, receipt)))
        })
        .collect::<Result<HashMap<_, _>, ChioPackageError>>()?;

    let mut scope_digests = BTreeMap::new();
    for binding in &package.lease_scope_bindings {
        binding.validate()?;
        if scope_digests.contains_key(&binding.lease_id) {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "duplicate lease scope binding {}",
                binding.lease_id
            )));
        }
        let lease = leases_by_id.get(&binding.lease_id).ok_or_else(|| {
            ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} has no matching lease",
                binding.lease_id
            ))
        })?;
        let (step, receipt) = receipts_by_step.get(&binding.step_index).ok_or_else(|| {
            ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} references missing step {}",
                binding.lease_id, binding.step_index
            ))
        })?;
        let class_binding = step_classes.get(&binding.step_index).ok_or_else(|| {
            ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} references step without class binding",
                binding.lease_id
            ))
        })?;
        if binding.workflow_id != package.workflow_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} workflow id mismatch",
                binding.lease_id
            )));
        }
        if binding.workflow_grant_id != package.workflow_receipt.capability_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} workflow grant mismatch",
                binding.lease_id
            )));
        }
        if binding.tool_name != step.tool_name || binding.tool_name != receipt.tool_name {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} tool mismatch",
                binding.lease_id
            )));
        }
        if binding.peer_kernel_id != class_binding.peer_kernel_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} peer mismatch",
                binding.lease_id
            )));
        }
        if binding.action_class_id != class_binding.action_class_id {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} action class id mismatch",
                binding.lease_id
            )));
        }
        if binding.subject != lease.body.subject {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} subject mismatch",
                binding.lease_id
            )));
        }
        if binding.action_class != lease.body.action_class {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} action class mismatch",
                binding.lease_id
            )));
        }
        if binding.tool_args_hash != receipt.action.parameter_hash {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} tool args hash mismatch",
                binding.lease_id
            )));
        }
        if binding.destructive != step.destructive.unwrap_or(false) {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} destructive flag mismatch",
                binding.lease_id
            )));
        }
        if binding.issued_at_unix_ms != lease.body.issued_at_unix_ms
            || binding.expires_at_unix_ms != lease.body.expires_at_unix_ms
        {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} time window mismatch",
                binding.lease_id
            )));
        }
        let scope_digest = binding.scope_digest()?;
        if lease.body.scope_digest != scope_digest {
            return Err(ChioPackageError::LeaseScopeBinding(format!(
                "lease scope binding {} digest mismatch",
                binding.lease_id
            )));
        }
        scope_digests.insert(binding.lease_id.clone(), scope_digest);
    }
    Ok(scope_digests)
}

fn verify_trusted_capability_lease(
    lease: &SignedCapabilityLease,
    trust_bundle: &ChioVerifierTrustBundle,
    scope_digest: &str,
) -> Result<(), ChioPackageError> {
    let authority = trust_bundle
        .lease_authority(&lease.body.issuer)
        .ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "lease authority {} is not trusted",
                lease.body.issuer
            ))
        })?;
    trust_bundle.ensure_public_key_not_revoked(&authority.public_key, "lease authority")?;
    let (valid_from, valid_until) = authority_window(
        authority.valid_from_unix_ms,
        authority.valid_until_unix_ms,
        "lease authority",
    )?;
    let now_unix_ms = trust_bundle.verification_time_unix_ms();
    if now_unix_ms < valid_from || now_unix_ms >= valid_until {
        return Err(ChioPackageError::Governance(format!(
            "lease authority {} is not active at the verifier epoch",
            lease.body.issuer
        )));
    }
    if lease.body.issued_at_unix_ms > now_unix_ms {
        return Err(ChioPackageError::Governance(format!(
            "lease {} is issued in the future",
            lease.body.lease_id
        )));
    }
    if lease.body.issued_at_unix_ms < valid_from || lease.body.issued_at_unix_ms >= valid_until {
        return Err(ChioPackageError::Governance(format!(
            "lease {} is outside the lease authority validity window",
            lease.body.lease_id
        )));
    }
    if lease.signer_key != authority.public_key {
        return Err(ChioPackageError::Governance(format!(
            "lease authority {} signer key mismatch",
            lease.body.issuer
        )));
    }
    if !authority
        .allowed_action_classes
        .contains(&lease.body.action_class)
    {
        return Err(ChioPackageError::Governance(format!(
            "lease authority {} is not trusted for action class {:?}",
            lease.body.issuer, lease.body.action_class
        )));
    }
    verify_capability_lease(lease, now_unix_ms, Some(scope_digest.to_string()))
        .map_err(|error| ChioPackageError::Governance(error.to_string()))
}

fn verify_trusted_governance_receipt(
    receipt: &SignedGovernanceReceipt,
    trust_bundle: &ChioVerifierTrustBundle,
) -> Result<(), ChioPackageError> {
    let authority = trust_bundle
        .governance_authority(&receipt.body.authorizing_kernel)
        .ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "governance authority {} is not trusted",
                receipt.body.authorizing_kernel
            ))
        })?;
    trust_bundle.ensure_public_key_not_revoked(&authority.public_key, "governance authority")?;
    let (valid_from, valid_until) = authority_window(
        authority.valid_from_unix_ms,
        authority.valid_until_unix_ms,
        "governance authority",
    )?;
    let now_unix_ms = trust_bundle.verification_time_unix_ms();
    if now_unix_ms < valid_from || now_unix_ms >= valid_until {
        return Err(ChioPackageError::Governance(format!(
            "governance authority {} is not active at the verifier epoch",
            receipt.body.authorizing_kernel
        )));
    }
    if receipt.body.issued_at_unix_ms > now_unix_ms {
        return Err(ChioPackageError::Governance(format!(
            "governance receipt {} is issued in the future",
            receipt.body.receipt_id
        )));
    }
    if receipt.body.issued_at_unix_ms < valid_from || receipt.body.issued_at_unix_ms >= valid_until
    {
        return Err(ChioPackageError::Governance(format!(
            "governance receipt {} is outside the governance authority validity window",
            receipt.body.receipt_id
        )));
    }
    if receipt.signer_key != authority.public_key {
        return Err(ChioPackageError::Governance(format!(
            "governance authority {} signer key mismatch",
            receipt.body.authorizing_kernel
        )));
    }
    if !authority
        .allowed_case_kinds
        .contains(&receipt.body.case_kind)
    {
        return Err(ChioPackageError::Governance(format!(
            "governance authority {} is not trusted for case kind {:?}",
            receipt.body.authorizing_kernel, receipt.body.case_kind
        )));
    }
    verify_step_governance_boundary(true, Some(receipt), now_unix_ms)
        .map_err(|error| ChioPackageError::Governance(error.to_string()))
}

fn verify_destructive_steps(
    package: &ChioProofPackage,
    trust_bundle: &ChioVerifierTrustBundle,
    lease_scope_digests: &BTreeMap<String, String>,
) -> Result<(), ChioPackageError> {
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
            ChioPackageError::Governance(format!(
                "destructive step {} has no governance receipt id",
                step.step_index
            ))
        })?;
        let governance_receipt = governance_by_id.get(governance_id).ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "governance receipt {governance_id} is not present in package"
            ))
        })?;
        let tool_receipt_id = step.tool_receipt_id.as_ref().ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "destructive step {} has no tool receipt id",
                step.step_index
            ))
        })?;
        let tool_receipt = receipts_by_id.get(tool_receipt_id).ok_or_else(|| {
            ChioPackageError::Governance(format!(
                "tool receipt {tool_receipt_id} is not present in package"
            ))
        })?;
        let step_sha256 = canonical_sha256(&tool_receipt.body())?;
        let lease = leases_by_id
            .get(&governance_receipt.body.authorized_lease_id)
            .ok_or_else(|| {
                ChioPackageError::Governance(format!(
                    "lease {} is not present in package",
                    governance_receipt.body.authorized_lease_id
                ))
            })?;
        let scope_digest = lease_scope_digests
            .get(&lease.body.lease_id)
            .ok_or_else(|| {
                ChioPackageError::LeaseScopeBinding(format!(
                    "lease {} has no scope binding",
                    lease.body.lease_id
                ))
            })?;
        verify_capability_lease(
            lease,
            trust_bundle.verification_time_unix_ms(),
            Some(scope_digest.clone()),
        )
        .map_err(|error| ChioPackageError::Governance(error.to_string()))?;
        if governance_receipt.body.issued_at_unix_ms < lease.body.issued_at_unix_ms
            || governance_receipt.body.expires_at_unix_ms > lease.body.expires_at_unix_ms
        {
            return Err(ChioPackageError::Governance(format!(
                "governance receipt {} is outside lease {} validity window",
                governance_receipt.body.receipt_id, lease.body.lease_id
            )));
        }
        verify_destructive_authorization(
            governance_receipt,
            &lease.body.lease_id,
            &package.workflow_id,
            &step_sha256,
            trust_bundle.verification_time_unix_ms(),
        )
        .map_err(|error| ChioPackageError::Governance(error.to_string()))?;
    }
    Ok(())
}
