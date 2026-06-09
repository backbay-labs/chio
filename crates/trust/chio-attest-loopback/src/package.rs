use super::*;
use crate::runtime_validation::{
    validate_runtime_artifact_for_issued_material, validate_runtime_receipt_for_vendor,
    RuntimeIssuedMaterialValidation,
};

pub(super) fn build_proof_package_unchecked(
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
