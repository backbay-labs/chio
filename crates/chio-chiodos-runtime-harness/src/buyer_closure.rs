use crate::evidence_io::canonical_sha256_json;
use crate::kernel::runtime_loopback_policy_summary;
use crate::scenario::RuntimeLoopbackStep;
use crate::treaty::RuntimeLoopbackTreatyContext;
use crate::RuntimeLoopbackError;

pub(crate) struct RuntimeLoopbackBuyerClosure {
    pub(crate) step_index: usize,
    pub(crate) admission_report: chio_chiodos_runtime::CrossBoundaryAdmissionReport,
    pub(crate) admission_report_sha256: String,
    pub(crate) continuation: chio_chiodos_runtime::CrossKernelContinuation,
    pub(crate) lineage_statement: chio_chiodos_runtime::ReceiptLineageStatement,
    pub(crate) lineage_statement_sha256: String,
    pub(crate) lineage_bundle: chio_chiodos_runtime::ReceiptLineageBundle,
    pub(crate) bilateral_invocation: chio_chiodos_runtime::BilateralInvocation,
    pub(crate) bilateral_invocation_binding_sha256: String,
    pub(crate) bilateral_dsse: chio_federation::DsseEnvelope,
    pub(crate) bilateral_dsse_sha256: String,
}

pub(crate) fn build_runtime_loopback_buyer_closure(
    step_index: usize,
    step: &RuntimeLoopbackStep,
    treaty_context: &RuntimeLoopbackTreatyContext,
    baseline_package: &chio_chiodos::ChiodosProofPackage,
    now_unix_ms: u64,
) -> Result<
    (
        chio_chiodos::ChiodosProofPackage,
        RuntimeLoopbackBuyerClosure,
    ),
    RuntimeLoopbackError,
> {
    let workflow_step = baseline_package
        .workflow_receipt
        .steps
        .get(step_index)
        .ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure missing workflow step {step_index}"
            ))
        })?;
    let tool_receipt_id = workflow_step.tool_receipt_id.as_ref().ok_or_else(|| {
        RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure step {} is missing tool receipt id",
            workflow_step.step_index
        ))
    })?;
    let receipt = baseline_package
        .tool_receipts
        .iter()
        .find(|receipt| receipt.id == *tool_receipt_id)
        .ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure missing tool receipt {tool_receipt_id}"
            ))
        })?;
    let tool_receipt_sha256 =
        canonical_sha256_json(receipt, "Chiodos runtime buyer closure receipt hash")?;
    let local_receipt_sha256 = workflow_step.parent_receipt_sha256.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chiodos runtime buyer closure requires a parent workflow receipt hash".to_string(),
        )
    })?;
    let outcome_sha256 = workflow_step.output_hash.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chiodos runtime buyer closure step is missing an output hash".to_string(),
        )
    })?;
    let action_class_id = treaty_context
        .ladder_intersection
        .action_classes
        .first()
        .map(|action| action.action_class_id.clone())
        .ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chiodos runtime buyer closure treaty intersection has no action class".to_string(),
            )
        })?;
    let mut bilateral_invocation = chio_chiodos_runtime::BilateralInvocation {
        schema: chio_chiodos_runtime::CHIODOS_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: format!("bilateral:runtime-loopback:closure:{step_index}"),
        treaty_id: treaty_context.treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
        continuation_sha256: treaty_context.continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: step.request.capability_id.clone(),
        request_sha256: receipt.action.parameter_hash.clone(),
        outcome_sha256: outcome_sha256.clone(),
        local_receipt_sha256: local_receipt_sha256.clone(),
        remote_receipt_sha256: tool_receipt_sha256.clone(),
        signer_kernel_ids: vec![
            treaty_context.continuation.source_kernel_id.clone(),
            treaty_context.continuation.target_kernel_id.clone(),
        ],
    };
    let bilateral_invocation_binding_sha256 =
        chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure bilateral invocation binding hash: {error}"
                ))
            },
        )?;
    let lineage_statement = chio_chiodos_runtime::ReceiptLineageStatement {
        schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: format!("lineage:runtime-loopback:closure:{step_index}"),
        parent_receipt_sha256: local_receipt_sha256.clone(),
        child_receipt_sha256: tool_receipt_sha256.clone(),
        continuation_sha256: treaty_context.continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_binding_sha256.clone(),
        evidence_class: "verified".to_string(),
        source_kernel_id: treaty_context.continuation.source_kernel_id.clone(),
        target_kernel_id: treaty_context.continuation.target_kernel_id.clone(),
    };
    let lineage_statement_sha256 = canonical_sha256_json(
        &lineage_statement,
        "Chiodos runtime buyer closure lineage statement hash",
    )?;
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
    let rebound_bilateral_invocation_sha256 =
        chio_chiodos_runtime::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime buyer closure rebound bilateral invocation binding hash: {error}"
                ))
            },
        )?;
    if rebound_bilateral_invocation_sha256 != bilateral_invocation_binding_sha256 {
        return Err(RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure bilateral invocation binding changed after lineage back-fill: expected {bilateral_invocation_binding_sha256}, got {rebound_bilateral_invocation_sha256}"
        )));
    }
    let lineage_bundle = chio_chiodos_runtime::ReceiptLineageBundle {
        schema: chio_chiodos_runtime::CHIODOS_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: format!("{}:closure", treaty_context.lineage_bundle_id),
        root_receipt_sha256: local_receipt_sha256.clone(),
        leaf_receipt_sha256: tool_receipt_sha256.clone(),
        statements: vec![lineage_statement.clone()],
    };
    let lineage_bundle_sha256 = canonical_sha256_json(
        &lineage_bundle,
        "Chiodos runtime buyer closure lineage bundle hash",
    )?;
    let admission_report = chio_chiodos_runtime::evaluate_cross_boundary_admission(
        chio_chiodos_runtime::CrossBoundaryAdmissionInput {
            treaty_scope: &treaty_context.treaty_scope,
            ladder_intersection: &treaty_context.ladder_intersection,
            expected_ladder_intersection_sha256: Some(
                treaty_context.ladder_intersection_sha256.clone(),
            ),
            action_class_id: &action_class_id,
            present_evidence: vec![
                "receipt_lineage".to_string(),
                "bilateral_invocation".to_string(),
            ],
            verified_evidence: vec![
                chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                    evidence_class: "receipt_lineage".to_string(),
                    artifact_sha256: lineage_statement_sha256.clone(),
                    verified: true,
                },
                chio_chiodos_runtime::CrossBoundaryEvidenceRef {
                    evidence_class: "bilateral_invocation".to_string(),
                    artifact_sha256: bilateral_invocation_binding_sha256.clone(),
                    verified: true,
                },
            ],
            now_unix_ms,
        },
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure admission report: {error}"
        ))
    })?;
    if !admission_report.accepted {
        return Err(RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure admission rejected: {}",
            admission_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_treaty_closure_failure")
        )));
    }
    let admission_report_sha256 = canonical_sha256_json(
        &admission_report,
        "Chiodos runtime buyer closure admission report hash",
    )?;
    let lease_id = step.admission_bundle.lease_id.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chiodos runtime buyer closure requires a capability lease".to_string(),
        )
    })?;
    let lease = baseline_package
        .capability_leases
        .iter()
        .find(|lease| lease.body.lease_id == lease_id)
        .ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure missing lease {lease_id}"
            ))
        })?;
    let expected_governance_receipt_ids = workflow_step
        .governance_receipt_id
        .as_deref()
        .into_iter()
        .chain(step.admission_bundle.governance_receipt_id.as_deref())
        .collect::<Vec<_>>();
    let governance_receipt_id = select_governance_receipt_id(
        &expected_governance_receipt_ids,
        baseline_package
            .governance_receipts
            .iter()
            .map(|receipt| receipt.body.receipt_id.as_str()),
    )?;
    let governance_receipt = baseline_package
        .governance_receipts
        .iter()
        .find(|receipt| receipt.body.receipt_id.as_str() == governance_receipt_id)
        .ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure missing governance receipt {governance_receipt_id}"
            ))
        })?;
    let governance_digest = canonical_sha256_json(
        governance_receipt,
        "Chiodos runtime buyer closure governance receipt digest",
    )?;
    let buyer_key = chio_chiodos_loopback::runtime_buyer_keypair();
    let vendor_key =
        chio_chiodos_loopback::runtime_vendor_keypair(step_index).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure vendor key: {error}"
            ))
        })?;
    let bilateral_dsse = chio_federation::sign_chiodos_dsse_envelope(
        receipt,
        &buyer_key,
        &vendor_key,
        &treaty_context.continuation.source_kernel_id,
        &treaty_context.continuation.target_kernel_id,
        &step.request.tool_name,
        now_unix_ms,
        chio_federation::BilateralPredicateExtensions {
            capability_lease_ref: Some(chio_federation::CapabilityLeaseRef {
                lease_id: lease.body.lease_id.clone(),
                issuer: lease.body.issuer.clone(),
                expires_at_unix_ms: lease.body.expires_at_unix_ms,
                scope_digest: Some(chio_federation::HashRecord {
                    alg: "sha256".to_string(),
                    value: lease.body.scope_digest.clone(),
                }),
            }),
            policy_evaluation_summary: Some(runtime_loopback_policy_summary(step)),
            governance_receipt_ref: Some(chio_federation::GovernanceReceiptRef {
                receipt_id: governance_receipt.body.receipt_id.clone(),
                kernel_id: governance_receipt.body.authorizing_kernel.clone(),
                digest: chio_federation::HashRecord {
                    alg: "sha256".to_string(),
                    value: governance_digest,
                },
            }),
            consistency_anchor: workflow_step.consistency_anchor.clone(),
            consistency_model: Some(admission_report.consistency_model.clone()),
            cross_org_visibility: None,
            treaty_binding_ref: Some(chio_federation::TreatyBindingRef {
                treaty_id: admission_report.treaty_id.clone(),
                treaty_scope_sha256: treaty_context.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
                admission_report_sha256: admission_report_sha256.clone(),
                continuation_sha256: treaty_context.continuation_sha256.clone(),
                lineage_bundle_sha256,
                action_class_id: admission_report.action_class_id.clone(),
                consistency_model: admission_report.consistency_model.clone(),
                request_sha256: bilateral_invocation.request_sha256.clone(),
                outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                lease_refs: vec![lease.body.lease_id.clone()],
                governance_refs: vec![governance_receipt.body.receipt_id.clone()],
                signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
            }),
        },
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure strict DSSE signing: {error}"
        ))
    })?;
    let bilateral_dsse_sha256 =
        canonical_sha256_json(&bilateral_dsse, "Chiodos runtime buyer closure DSSE hash")?;
    let mut runtime_artifacts = baseline_package
        .tool_receipts
        .iter()
        .cloned()
        .zip(baseline_package.bilateral_envelopes.iter().cloned())
        .zip(baseline_package.workflow_receipt.steps.iter().cloned())
        .map(|((tool_receipt, bilateral_envelope), workflow_step)| {
            chio_chiodos_loopback::RuntimeProofArtifact {
                tool_receipt,
                bilateral_envelope,
                workflow_step,
            }
        })
        .collect::<Vec<_>>();
    let artifact = runtime_artifacts.get_mut(step_index).ok_or_else(|| {
        RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure missing artifact {step_index}"
        ))
    })?;
    artifact.bilateral_envelope = bilateral_dsse.clone();
    artifact.workflow_step.bilateral_dsse_sha256 = Some(bilateral_dsse_sha256.clone());
    let mut parent = None;
    for artifact in &mut runtime_artifacts {
        artifact.workflow_step.parent_receipt_sha256 = parent.clone();
        parent = Some(canonical_sha256_json(
            &artifact.workflow_step,
            "Chiodos runtime buyer closure workflow step hash",
        )?);
    }
    let package = chio_chiodos_loopback::proof_package_from_runtime_artifacts(runtime_artifacts)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime buyer closure proof package: {error}"
            ))
        })?;
    Ok((
        package,
        RuntimeLoopbackBuyerClosure {
            step_index,
            admission_report,
            admission_report_sha256,
            continuation: treaty_context.continuation.clone(),
            lineage_statement,
            lineage_statement_sha256,
            lineage_bundle,
            bilateral_invocation,
            bilateral_invocation_binding_sha256,
            bilateral_dsse,
            bilateral_dsse_sha256,
        },
    ))
}

fn select_governance_receipt_id<'a>(
    expected_ids: &[&'a str],
    package_receipt_ids: impl IntoIterator<Item = &'a str>,
) -> Result<String, RuntimeLoopbackError> {
    let package_receipt_ids = package_receipt_ids.into_iter().collect::<Vec<_>>();
    let expected_ids = expected_ids.to_vec();

    if !expected_ids.is_empty() {
        if let Some(expected_id) = expected_ids
            .iter()
            .find(|expected_id| package_receipt_ids.contains(expected_id))
        {
            return Ok(expected_id.to_string());
        }
        return Err(RuntimeLoopbackError::message(format!(
            "Chiodos runtime buyer closure missing expected governance receipt matching {}",
            expected_ids.join(", ")
        )));
    }

    if package_receipt_ids.len() == 1 {
        return Ok(package_receipt_ids[0].to_string());
    }

    Err(RuntimeLoopbackError::message(
        "Chiodos runtime buyer closure requires a package governance receipt".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::select_governance_receipt_id;

    #[test]
    fn governance_receipt_selection_uses_single_fallback_only_without_expected_id(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let selected = select_governance_receipt_id(&[], ["gov-only"])?;

        assert_eq!(selected, "gov-only");
        Ok(())
    }

    #[test]
    fn governance_receipt_selection_rejects_missing_expected_id_even_with_single_receipt() {
        let error = match select_governance_receipt_id(&["gov-expected"], ["gov-other"]) {
            Ok(selected) => panic!("selected unexpected governance receipt {selected}"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("missing expected governance receipt matching gov-expected"));
    }

    #[test]
    fn governance_receipt_selection_accepts_any_matching_expected_id_without_fallback(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let selected = select_governance_receipt_id(&["gov-a", "gov-b"], ["gov-b"])?;

        assert_eq!(selected, "gov-b");
        Ok(())
    }
}
