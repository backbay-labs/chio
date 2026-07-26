use crate::evidence_io::canonical_sha256_json;
use crate::kernel::runtime_loopback_policy_summary;
use crate::scenario::RuntimeLoopbackStep;
use crate::treaty::RuntimeLoopbackTreatyContext;
use crate::RuntimeLoopbackError;

pub(crate) struct RuntimeLoopbackBuyerClosure {
    pub(crate) step_index: usize,
    pub(crate) admission_report: chio_runtime_core::CrossBoundaryAdmissionReport,
    pub(crate) admission_report_sha256: String,
    pub(crate) continuation: chio_runtime_core::CrossKernelContinuation,
    pub(crate) lineage_statement: chio_runtime_core::ReceiptLineageStatement,
    pub(crate) lineage_statement_sha256: String,
    pub(crate) lineage_bundle: chio_runtime_core::ReceiptLineageBundle,
    pub(crate) bilateral_invocation: chio_runtime_core::BilateralInvocation,
    pub(crate) bilateral_invocation_binding_sha256: String,
    pub(crate) bilateral_dsse: chio_federation::bilateral_dsse::DsseEnvelope,
    pub(crate) bilateral_dsse_sha256: String,
}

pub(crate) fn build_runtime_loopback_buyer_closure(
    step_index: usize,
    step: &RuntimeLoopbackStep,
    treaty_context: &RuntimeLoopbackTreatyContext,
    baseline_package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
    now_unix_ms: u64,
) -> Result<
    (
        chio_attest_buyer_core::proof_package::ChioProofPackage,
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
                "Chio runtime buyer closure missing workflow step {step_index}"
            ))
        })?;
    let tool_receipt_id = workflow_step.tool_receipt_id.as_ref().ok_or_else(|| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime buyer closure step {} is missing tool receipt id",
            workflow_step.step_index
        ))
    })?;
    let receipt = baseline_package
        .tool_receipts
        .iter()
        .find(|receipt| receipt.id == *tool_receipt_id)
        .ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime buyer closure missing tool receipt {tool_receipt_id}"
            ))
        })?;
    let tool_receipt_sha256 =
        canonical_sha256_json(receipt, "Chio runtime buyer closure receipt hash")?;
    let local_receipt_sha256 = workflow_step.parent_receipt_sha256.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chio runtime buyer closure requires a parent workflow receipt hash".to_string(),
        )
    })?;
    let outcome_sha256 = workflow_step.output_hash.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chio runtime buyer closure step is missing an output hash".to_string(),
        )
    })?;
    let action_class_id = treaty_context
        .ladder_intersection
        .action_classes
        .first()
        .map(|action| action.action_class_id.clone())
        .ok_or_else(|| {
            RuntimeLoopbackError::message(
                "Chio runtime buyer closure treaty intersection has no action class".to_string(),
            )
        })?;
    let mut bilateral_invocation = chio_runtime_core::BilateralInvocation {
        schema: chio_runtime_core::CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: format!("bilateral:runtime-loopback:closure:{step_index}"),
        treaty_id: treaty_context.treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
        continuation_sha256: treaty_context.continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: action_class_id.clone(),
        consistency_model: "totally-ordered".to_string(),
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
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime buyer closure bilateral invocation binding hash: {error}"
                ))
            },
        )?;
    let lineage_statement = chio_runtime_core::ReceiptLineageStatement {
        schema: chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
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
        "Chio runtime buyer closure lineage statement hash",
    )?;
    bilateral_invocation.lineage_statement_sha256 = lineage_statement_sha256.clone();
    let rebound_bilateral_invocation_sha256 =
        chio_runtime_core::bilateral_invocation_binding_sha256(&bilateral_invocation).map_err(
            |error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime buyer closure rebound bilateral invocation binding hash: {error}"
                ))
            },
        )?;
    if rebound_bilateral_invocation_sha256 != bilateral_invocation_binding_sha256 {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime buyer closure bilateral invocation binding changed after lineage back-fill: expected {bilateral_invocation_binding_sha256}, got {rebound_bilateral_invocation_sha256}"
        )));
    }
    let lineage_bundle = chio_runtime_core::ReceiptLineageBundle {
        schema: chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: format!("{}:closure", treaty_context.lineage_bundle_id),
        root_receipt_sha256: local_receipt_sha256.clone(),
        leaf_receipt_sha256: tool_receipt_sha256.clone(),
        statements: vec![lineage_statement.clone()],
    };
    let lineage_bundle_sha256 = canonical_sha256_json(
        &lineage_bundle,
        "Chio runtime buyer closure lineage bundle hash",
    )?;
    let admission_report = chio_runtime_core::evaluate_cross_boundary_admission(
        chio_runtime_core::CrossBoundaryAdmissionInput {
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
                chio_runtime_core::CrossBoundaryEvidenceRef {
                    evidence_class: "receipt_lineage".to_string(),
                    artifact_sha256: lineage_statement_sha256.clone(),
                    verified: true,
                },
                chio_runtime_core::CrossBoundaryEvidenceRef {
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
            "Chio runtime buyer closure admission report: {error}"
        ))
    })?;
    if !admission_report.accepted {
        return Err(RuntimeLoopbackError::message(format!(
            "Chio runtime buyer closure admission rejected: {}",
            admission_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_treaty_closure_failure")
        )));
    }
    let admission_report_sha256 = canonical_sha256_json(
        &admission_report,
        "Chio runtime buyer closure admission report hash",
    )?;
    let lease_id = step.admission_bundle.lease_id.clone().ok_or_else(|| {
        RuntimeLoopbackError::message(
            "Chio runtime buyer closure requires a capability lease".to_string(),
        )
    })?;
    let lease = baseline_package
        .capability_leases
        .iter()
        .find(|lease| lease.body.lease_id == lease_id)
        .ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime buyer closure missing lease {lease_id}"
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
                "Chio runtime buyer closure missing governance receipt {governance_receipt_id}"
            ))
        })?;
    let governance_digest = canonical_sha256_json(
        governance_receipt,
        "Chio runtime buyer closure governance receipt digest",
    )?;
    let dsse_consistency_model =
        chio_runtime_core::bilateral_dsse_consistency_model(&admission_report.consistency_model)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime buyer closure DSSE consistency model: {error}"
                ))
            })?
            .to_string();
    let buyer_key = chio_attest_loopback::runtime_buyer_keypair();
    let vendor_key = chio_attest_loopback::runtime_vendor_keypair(step_index).map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime buyer closure vendor key: {error}"))
    })?;
    let bilateral_dsse = chio_federation::bilateral_dsse::sign_chio_bilateral_dsse_envelope(
        receipt,
        &buyer_key,
        &vendor_key,
        &treaty_context.continuation.source_kernel_id,
        &treaty_context.continuation.target_kernel_id,
        &step.request.tool_name,
        now_unix_ms,
        chio_federation::bilateral_dsse::BilateralPredicateExtensions {
            capability_lease_ref: Some(chio_federation::bilateral_dsse::CapabilityLeaseRef {
                lease_id: lease.body.lease_id.clone(),
                issuer: lease.body.issuer.clone(),
                expires_at_unix_ms: lease.body.expires_at_unix_ms,
                scope_digest: Some(chio_federation::bilateral_dsse::HashRecord {
                    alg: "sha256".to_string(),
                    value: lease.body.scope_digest.clone(),
                }),
            }),
            policy_evaluation_summary: Some(runtime_loopback_policy_summary(step)),
            governance_receipt_ref: Some(chio_federation::bilateral_dsse::GovernanceReceiptRef {
                receipt_id: governance_receipt.body.receipt_id.clone(),
                kernel_id: governance_receipt.body.authorizing_kernel.clone(),
                digest: chio_federation::bilateral_dsse::HashRecord {
                    alg: "sha256".to_string(),
                    value: governance_digest,
                },
            }),
            consistency_anchor: workflow_step.consistency_anchor.clone(),
            consistency_model: Some(dsse_consistency_model.clone()),
            cross_org_visibility: None,
            treaty_binding_ref: Some(chio_federation::bilateral_dsse::TreatyBindingRef {
                treaty_id: admission_report.treaty_id.clone(),
                treaty_scope_sha256: treaty_context.treaty_scope_sha256.clone(),
                ladder_intersection_sha256: treaty_context.ladder_intersection_sha256.clone(),
                admission_report_sha256: admission_report_sha256.clone(),
                continuation_sha256: treaty_context.continuation_sha256.clone(),
                lineage_bundle_sha256,
                action_class_id: admission_report.action_class_id.clone(),
                consistency_model: dsse_consistency_model,
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
            "Chio runtime buyer closure strict DSSE signing: {error}"
        ))
    })?;
    let bilateral_dsse_sha256 =
        canonical_sha256_json(&bilateral_dsse, "Chio runtime buyer closure DSSE hash")?;
    let mut runtime_artifacts = baseline_package
        .tool_receipts
        .iter()
        .cloned()
        .zip(baseline_package.bilateral_envelopes.iter().cloned())
        .zip(baseline_package.workflow_receipt.steps.iter().cloned())
        .map(|((tool_receipt, bilateral_envelope), workflow_step)| {
            chio_attest_loopback::RuntimeProofArtifact {
                tool_receipt,
                bilateral_envelope,
                workflow_step,
            }
        })
        .collect::<Vec<_>>();
    let artifact = runtime_artifacts.get_mut(step_index).ok_or_else(|| {
        RuntimeLoopbackError::message(format!(
            "Chio runtime buyer closure missing artifact {step_index}"
        ))
    })?;
    artifact.bilateral_envelope = bilateral_dsse.clone();
    artifact.workflow_step.bilateral_dsse_sha256 = Some(bilateral_dsse_sha256.clone());
    let mut parent = None;
    for artifact in &mut runtime_artifacts {
        artifact.workflow_step.parent_receipt_sha256 = parent.clone();
        parent = Some(canonical_sha256_json(
            &artifact.workflow_step,
            "Chio runtime buyer closure workflow step hash",
        )?);
    }
    let package = chio_attest_loopback::proof_package_from_runtime_artifacts(runtime_artifacts)
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime buyer closure proof package: {error}"
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
            "Chio runtime buyer closure missing expected governance receipt matching {}",
            expected_ids.join(", ")
        )));
    }

    if package_receipt_ids.len() == 1 {
        return Ok(package_receipt_ids[0].to_string());
    }

    Err(RuntimeLoopbackError::message(
        "Chio runtime buyer closure requires a package governance receipt".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{build_runtime_loopback_buyer_closure, select_governance_receipt_id};
    use crate::scenario::RuntimeLoopbackStep;
    use crate::treaty::insert_runtime_loopback_treaty_context;

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn destructive_runtime_loopback_step() -> RuntimeLoopbackStep {
        let request = chio_runtime_core::RuntimeRequestBinding {
            request_id: "req-loopback-buyer-closure".to_string(),
            capability_id: "cap-chio-workflow".to_string(),
            server_id: "vendor-c.payments".to_string(),
            tool_name: "stage_refund".to_string(),
            tool_args_sha256: "47e6e096b5d5888a3f90d057de3bce595d8ea5dd8624ccde387bb739d5a6464b"
                .to_string(),
            origin_kernel_id: Some("did:chio:buyer-kernel".to_string()),
            host_kernel_id: "did:chio:vendor-c".to_string(),
        };
        RuntimeLoopbackStep {
            admission_profile: chio_runtime_core::RuntimeAdmissionProfile {
                schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
                profile_id: "profile-loopback-buyer-closure".to_string(),
                local_kernel_id: "did:chio:vendor-c".to_string(),
                verifier_id: "did:chio:buyer-verifier".to_string(),
                issued_at_unix_ms: 1_800_000_000_000,
                expires_at_unix_ms: 1_800_003_600_000,
            },
            admission_bundle: chio_runtime_core::RuntimeAdmissionBundle {
                schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
                admission_id: "adm-loopback-buyer-closure".to_string(),
                binding: request.clone(),
                workflow_id: "wf-chio-refund-001".to_string(),
                workflow_grant_id: "cap-chio-workflow".to_string(),
                step_index: 2,
                destructive: true,
                lease_id: Some("lease-vendor-c-refund".to_string()),
                governance_receipt_id: Some("gov-refund-stage-authorization".to_string()),
                trust_bundle_sha256: fixed_hash('b'),
                verification_context_sha256: fixed_hash('c'),
            },
            request,
            arguments: Some(serde_json::json!({
                "caseRef": "refund-250",
                "tool": "stage_refund",
                "workflowId": "wf-chio-refund-001"
            })),
        }
    }

    #[test]
    fn buyer_closure_emits_chio_federation_schemas() -> Result<(), crate::RuntimeLoopbackError> {
        let step = destructive_runtime_loopback_step();
        let store = chio_runtime_core::InMemoryRuntimeAdmissionStore::new();
        let vendor_key = chio_attest_loopback::runtime_vendor_keypair(2).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback vendor key failed: {error}"
            ))
        })?;
        let treaty_context = insert_runtime_loopback_treaty_context(
            &store,
            2,
            &step,
            &vendor_key,
            step.arguments.as_ref().ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback test step missing arguments".to_string(),
                )
            })?,
        )?;
        let baseline_package = chio_attest_loopback::fixture_proof_package().map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback fixture package failed: {error}"
            ))
        })?;

        let (_package, closure) = build_runtime_loopback_buyer_closure(
            2,
            &step,
            &treaty_context,
            &baseline_package,
            1_800_000_001_000,
        )?;

        assert_eq!(
            closure.bilateral_invocation.schema,
            chio_runtime_core::CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA
        );
        assert_eq!(
            closure.lineage_statement.schema,
            chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA
        );
        assert_eq!(
            closure.lineage_bundle.schema,
            chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA
        );
        assert_eq!(
            closure.continuation.schema,
            chio_runtime_core::CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA
        );
        assert_eq!(
            closure.admission_report.schema,
            chio_runtime_core::CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA
        );
        Ok(())
    }

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
