use crate::evidence_io::canonical_sha256_json;
use crate::RuntimeLoopbackError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedBuyerClosureParity {
    pub(crate) step_index: usize,
    pub(crate) consistency_model: String,
}

pub(crate) fn materialize_final_runtime_proof_parity_report(
    run_id: &str,
    now_unix_ms: u64,
    static_package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
    static_report: &chio_attest_buyer_core::report::VerifierReport,
    final_runtime_package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
    context: &chio_attest_buyer_core::context::ChioVerificationContext,
    expected_buyer_closure: Option<&ExpectedBuyerClosureParity>,
) -> Result<chio_runtime_core::RuntimeProofParityReport, RuntimeLoopbackError> {
    let parity_trust_bundle_document =
        chio_attest_loopback::verifier_trust_bundle_document_for_package(final_runtime_package)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime parity trust bundle build: {error}"
                ))
            })?;
    let parity_trust_bundle =
        chio_attest_buyer_core::trust_bundle::ChioVerifierTrustBundle::from_document(
            parity_trust_bundle_document,
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime parity trust bundle parse: {error}"
            ))
        })?;
    let parity_verifier_report = chio_attest_buyer_core::report::verify_package_report(
        final_runtime_package,
        &parity_trust_bundle,
        context,
    );
    let (compared_fields, mismatches) = runtime_proof_parity(
        static_package,
        final_runtime_package,
        expected_buyer_closure,
    )?;
    let static_proof_package_sha256 =
        chio_attest_buyer_core::proof_package::package_sha256(static_package).map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio static proof package hash: {error}"))
        })?;
    let runtime_proof_package_sha256 = chio_attest_buyer_core::proof_package::package_sha256(
        final_runtime_package,
    )
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime parity proof package hash: {error}"))
    })?;
    let static_verifier_report_sha256 =
        canonical_sha256_json(static_report, "Chio static verifier report canonical hash")?;
    let runtime_verifier_report_sha256 = canonical_sha256_json(
        &parity_verifier_report,
        "Chio runtime parity verifier report hash",
    )?;
    let parity_accepted = mismatches.is_empty()
        && parity_verifier_report.accepted
        && static_proof_package_sha256 == runtime_proof_package_sha256
        && static_verifier_report_sha256 == runtime_verifier_report_sha256;

    Ok(chio_runtime_core::RuntimeProofParityReport {
        schema: chio_runtime_core::CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        accepted: parity_accepted,
        failure_code: if parity_accepted {
            None
        } else {
            Some("runtime_proof_semantic_parity_mismatch".to_string())
        },
        generated_at_unix_ms: now_unix_ms,
        static_proof_package_sha256,
        runtime_proof_package_sha256,
        static_verifier_report_sha256,
        runtime_verifier_report_sha256,
        compared_fields,
        mismatches,
    })
}

pub(crate) fn runtime_proof_parity(
    static_package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
    runtime_package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
    expected_buyer_closure: Option<&ExpectedBuyerClosureParity>,
) -> Result<
    (
        Vec<String>,
        Vec<chio_runtime_core::RuntimeProofParityMismatch>,
    ),
    RuntimeLoopbackError,
> {
    let compared_fields = vec![
        "proof_claims".to_string(),
        "workflow_id".to_string(),
        "workflow_step_count".to_string(),
        "workflow_step_semantics".to_string(),
        "workflow_intersection_id".to_string(),
        "workflow_step_class_bindings".to_string(),
        "workflow_required_vendor_signers".to_string(),
        "tool_receipt_targets".to_string(),
        "tool_receipt_semantics".to_string(),
        "bilateral_dsse_predicate_semantics".to_string(),
        "lease_scope_semantics".to_string(),
        "governance_authorization_presence".to_string(),
        "destructive_step_flags".to_string(),
    ];
    let mut compared_fields = compared_fields;
    if expected_buyer_closure.is_some() {
        compared_fields.push("buyer_closure_treaty_binding_delta".to_string());
    }
    let mut mismatches = Vec::new();
    compare_runtime_proof_field(
        "proof_claims",
        &static_package.claims,
        &runtime_package.claims,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_id",
        &static_package.workflow_id,
        &runtime_package.workflow_id,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_count",
        &static_package.workflow_receipt.steps.len(),
        &runtime_package.workflow_receipt.steps.len(),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_semantics",
        &workflow_step_semantics(static_package),
        &workflow_step_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_intersection_id",
        &static_package.workflow_intersection.intersection_id,
        &runtime_package.workflow_intersection.intersection_id,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "workflow_step_class_bindings",
        &static_package.workflow_intersection.step_class_bindings,
        &runtime_package.workflow_intersection.step_class_bindings,
        &mut mismatches,
    )?;
    let static_signers: Vec<&str> = static_package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|signer| signer.vendor_id.as_str())
        .collect();
    let runtime_signers: Vec<&str> = runtime_package
        .workflow_intersection
        .required_vendor_signers
        .iter()
        .map(|signer| signer.vendor_id.as_str())
        .collect();
    compare_runtime_proof_field(
        "workflow_required_vendor_signers",
        &static_signers,
        &runtime_signers,
        &mut mismatches,
    )?;
    let static_receipt_targets: Vec<(&str, &str, &str)> = static_package
        .tool_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.as_str(),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
            )
        })
        .collect();
    let runtime_receipt_targets: Vec<(&str, &str, &str)> = runtime_package
        .tool_receipts
        .iter()
        .map(|receipt| {
            (
                receipt.capability_id.as_str(),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
            )
        })
        .collect();
    compare_runtime_proof_field(
        "tool_receipt_targets",
        &static_receipt_targets,
        &runtime_receipt_targets,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "tool_receipt_semantics",
        &tool_receipt_semantics(static_package),
        &tool_receipt_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_bilateral_dsse_predicate_semantics(
        "bilateral_dsse_predicate_semantics",
        bilateral_dsse_predicate_semantics(static_package)?,
        bilateral_dsse_predicate_semantics(runtime_package)?,
        expected_buyer_closure,
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "lease_scope_semantics",
        &lease_scope_semantics(static_package),
        &lease_scope_semantics(runtime_package),
        &mut mismatches,
    )?;
    compare_runtime_proof_field(
        "governance_authorization_presence",
        &governance_authorization_presence(static_package),
        &governance_authorization_presence(runtime_package),
        &mut mismatches,
    )?;
    let static_destructive: Vec<Option<bool>> = static_package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.destructive)
        .collect();
    let runtime_destructive: Vec<Option<bool>> = runtime_package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.destructive)
        .collect();
    compare_runtime_proof_field(
        "destructive_step_flags",
        &static_destructive,
        &runtime_destructive,
        &mut mismatches,
    )?;
    Ok((compared_fields, mismatches))
}

#[derive(Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WorkflowStepParityBinding {
    step_index: usize,
    server_id: String,
    tool_name: String,
    allowed: bool,
    has_tool_receipt: bool,
    has_output_hash: bool,
    has_bilateral_dsse: bool,
    has_governance_receipt: bool,
    has_parent_receipt: bool,
    has_consistency_anchor: bool,
    destructive: Option<bool>,
}

#[derive(Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ToolReceiptParityBinding {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    action_parameter_hash: String,
    decision_allowed: bool,
}

#[derive(Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct BilateralDssePredicateParityBinding {
    predicate_type: String,
    tool_server_a: String,
    tool_server_b: String,
    tool_name: String,
    co_sign: String,
    consistency_model: String,
    tool_args_hash: Option<String>,
    has_capability_lease_ref: bool,
    has_capability_lease_scope_digest: bool,
    has_governance_receipt_ref: bool,
    has_consistency_anchor: bool,
    has_treaty_binding: bool,
}

#[derive(Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LeaseScopeParityBinding {
    workflow_id: String,
    workflow_grant_id: String,
    step_index: usize,
    tool_name: String,
    peer_kernel_id: String,
    action_class_id: String,
    subject: String,
    action_class: String,
    tool_args_hash: String,
    destructive: bool,
}

fn workflow_step_semantics(
    package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
) -> Vec<WorkflowStepParityBinding> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| WorkflowStepParityBinding {
            step_index: step.step_index,
            server_id: step.server_id.clone(),
            tool_name: step.tool_name.clone(),
            allowed: step.allowed,
            has_tool_receipt: step.tool_receipt_id.is_some(),
            has_output_hash: step.output_hash.is_some(),
            has_bilateral_dsse: step.bilateral_dsse_sha256.is_some(),
            has_governance_receipt: step.governance_receipt_id.is_some(),
            has_parent_receipt: step.parent_receipt_sha256.is_some(),
            has_consistency_anchor: step.consistency_anchor.is_some(),
            destructive: step.destructive,
        })
        .collect()
}

fn tool_receipt_semantics(
    package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
) -> Vec<ToolReceiptParityBinding> {
    package
        .tool_receipts
        .iter()
        .map(|receipt| ToolReceiptParityBinding {
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            action_parameter_hash: receipt.action.parameter_hash.clone(),
            decision_allowed: matches!(
                &receipt.decision,
                Some(chio_core::receipt::decision::Decision::Allow)
            ),
        })
        .collect()
}

fn bilateral_dsse_predicate_semantics(
    package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
) -> Result<Vec<BilateralDssePredicateParityBinding>, RuntimeLoopbackError> {
    package
        .bilateral_envelopes
        .iter()
        .map(|envelope| {
            let (statement, _) = envelope.decode_statement().map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime parity DSSE statement decode: {error}"
                ))
            })?;
            let predicate = statement.predicate;
            Ok(BilateralDssePredicateParityBinding {
                predicate_type: statement.predicate_type,
                tool_server_a: predicate.tool_server_a.kernel_id,
                tool_server_b: predicate.tool_server_b.kernel_id,
                tool_name: predicate.tool_name,
                co_sign: predicate.co_sign,
                consistency_model: predicate.consistency_model,
                tool_args_hash: predicate.tool_args_hash.map(|hash| hash.value),
                has_capability_lease_ref: predicate.capability_lease_ref.is_some(),
                has_capability_lease_scope_digest: predicate
                    .capability_lease_ref
                    .is_some_and(|lease| lease.scope_digest.is_some()),
                has_governance_receipt_ref: predicate.governance_receipt_ref.is_some(),
                has_consistency_anchor: predicate.consistency_anchor.is_some(),
                has_treaty_binding: predicate.treaty_binding_ref.is_some(),
            })
        })
        .collect()
}

fn lease_scope_semantics(
    package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
) -> Vec<LeaseScopeParityBinding> {
    package
        .lease_scope_bindings
        .iter()
        .map(|binding| LeaseScopeParityBinding {
            workflow_id: binding.workflow_id.clone(),
            workflow_grant_id: binding.workflow_grant_id.clone(),
            step_index: binding.step_index,
            tool_name: binding.tool_name.clone(),
            peer_kernel_id: binding.peer_kernel_id.clone(),
            action_class_id: binding.action_class_id.clone(),
            subject: binding.subject.clone(),
            action_class: format!("{:?}", binding.action_class),
            tool_args_hash: binding.tool_args_hash.clone(),
            destructive: binding.destructive,
        })
        .collect()
}

fn governance_authorization_presence(
    package: &chio_attest_buyer_core::proof_package::ChioProofPackage,
) -> Vec<bool> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.governance_receipt_id.is_some())
        .collect()
}

fn compare_bilateral_dsse_predicate_semantics(
    field: &str,
    static_value: Vec<BilateralDssePredicateParityBinding>,
    runtime_value: Vec<BilateralDssePredicateParityBinding>,
    expected_buyer_closure: Option<&ExpectedBuyerClosureParity>,
    mismatches: &mut Vec<chio_runtime_core::RuntimeProofParityMismatch>,
) -> Result<(), RuntimeLoopbackError> {
    let Some(expected_buyer_closure) = expected_buyer_closure else {
        return compare_runtime_proof_field(field, &static_value, &runtime_value, mismatches);
    };
    if static_value.len() != runtime_value.len()
        || expected_buyer_closure.step_index >= static_value.len()
    {
        return compare_runtime_proof_field(field, &static_value, &runtime_value, mismatches);
    }

    let mut normalized_runtime_value = runtime_value.clone();
    let step_index = expected_buyer_closure.step_index;
    if buyer_closure_predicate_delta_matches(
        &static_value[step_index],
        &runtime_value[step_index],
        expected_buyer_closure,
    ) {
        normalized_runtime_value[step_index] = static_value[step_index].clone();
    }
    compare_runtime_proof_field(field, &static_value, &normalized_runtime_value, mismatches)
}

fn buyer_closure_predicate_delta_matches(
    static_value: &BilateralDssePredicateParityBinding,
    runtime_value: &BilateralDssePredicateParityBinding,
    expected_buyer_closure: &ExpectedBuyerClosureParity,
) -> bool {
    if static_value.has_treaty_binding
        || !runtime_value.has_treaty_binding
        || expected_buyer_closure.consistency_model.is_empty()
    {
        return false;
    }
    let mut expected_runtime_value = static_value.clone();
    expected_runtime_value.has_treaty_binding = true;
    expected_runtime_value.consistency_model = expected_buyer_closure.consistency_model.clone();
    runtime_value == &expected_runtime_value
}

fn compare_runtime_proof_field<T: serde::Serialize + PartialEq>(
    field: &str,
    static_value: &T,
    runtime_value: &T,
    mismatches: &mut Vec<chio_runtime_core::RuntimeProofParityMismatch>,
) -> Result<(), RuntimeLoopbackError> {
    if static_value != runtime_value {
        mismatches.push(chio_runtime_core::RuntimeProofParityMismatch {
            field: field.to_string(),
            static_value_sha256: canonical_sha256_json(
                static_value,
                "Chio runtime static parity field hash",
            )?,
            runtime_value_sha256: canonical_sha256_json(
                runtime_value,
                "Chio runtime regenerated parity field hash",
            )?,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        compare_bilateral_dsse_predicate_semantics, materialize_final_runtime_proof_parity_report,
        BilateralDssePredicateParityBinding, ExpectedBuyerClosureParity,
    };

    fn predicate_binding() -> BilateralDssePredicateParityBinding {
        BilateralDssePredicateParityBinding {
            predicate_type: "https://chio.world/predicate/chio-bilateral/v1".to_string(),
            tool_server_a: "did:chio:buyer-kernel".to_string(),
            tool_server_b: "did:chio:vendor-kernel".to_string(),
            tool_name: "vendor.receipt".to_string(),
            co_sign: "required".to_string(),
            consistency_model: "crdt-commutative".to_string(),
            tool_args_hash: Some("a".repeat(64)),
            has_capability_lease_ref: true,
            has_capability_lease_scope_digest: true,
            has_governance_receipt_ref: true,
            has_consistency_anchor: true,
            has_treaty_binding: false,
        }
    }

    #[test]
    fn buyer_closure_parity_accepts_exact_treaty_binding_delta(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let static_value = predicate_binding();
        let mut runtime_value = static_value.clone();
        runtime_value.has_treaty_binding = true;
        runtime_value.consistency_model = "totally-ordered".to_string();
        let expected = ExpectedBuyerClosureParity {
            step_index: 0,
            consistency_model: "totally-ordered".to_string(),
        };
        let mut mismatches = Vec::new();

        compare_bilateral_dsse_predicate_semantics(
            "bilateral_dsse_predicate_semantics",
            vec![static_value],
            vec![runtime_value],
            Some(&expected),
            &mut mismatches,
        )?;

        assert!(mismatches.is_empty(), "{mismatches:#?}");
        Ok(())
    }

    #[test]
    fn buyer_closure_parity_rejects_unexpected_treaty_step_drift(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let static_value = predicate_binding();
        let mut runtime_value = static_value.clone();
        runtime_value.has_treaty_binding = true;
        runtime_value.consistency_model = "totally-ordered".to_string();
        runtime_value.tool_name = "vendor.other".to_string();
        let expected = ExpectedBuyerClosureParity {
            step_index: 0,
            consistency_model: "totally-ordered".to_string(),
        };
        let mut mismatches = Vec::new();

        compare_bilateral_dsse_predicate_semantics(
            "bilateral_dsse_predicate_semantics",
            vec![static_value],
            vec![runtime_value],
            Some(&expected),
            &mut mismatches,
        )?;

        assert_eq!(mismatches.len(), 1, "{mismatches:#?}");
        assert_eq!(mismatches[0].field, "bilateral_dsse_predicate_semantics");
        Ok(())
    }

    #[test]
    fn materialized_parity_hashes_final_runtime_package() -> Result<(), crate::RuntimeLoopbackError>
    {
        let static_package = chio_attest_loopback::fixture_proof_package().map_err(|error| {
            crate::RuntimeLoopbackError::message(format!("fixture package build failed: {error}"))
        })?;
        let static_report = chio_attest_loopback::fixture_verifier_report().map_err(|error| {
            crate::RuntimeLoopbackError::message(format!("fixture report build failed: {error}"))
        })?;
        let context = chio_attest_loopback::verification_context();
        let mut final_package = static_package.clone();
        final_package.claims.hidden_range_predicates =
            !final_package.claims.hidden_range_predicates;

        let report = materialize_final_runtime_proof_parity_report(
            "run-final-package",
            1_747_500_000_000,
            &static_package,
            &static_report,
            &final_package,
            &context,
            None,
        )?;
        let final_package_sha256 = chio_attest_buyer_core::proof_package::package_sha256(
            &final_package,
        )
        .map_err(|error| {
            crate::RuntimeLoopbackError::message(format!("final package hash failed: {error}"))
        })?;
        let static_package_sha256 = chio_attest_buyer_core::proof_package::package_sha256(
            &static_package,
        )
        .map_err(|error| {
            crate::RuntimeLoopbackError::message(format!("static package hash failed: {error}"))
        })?;

        assert_eq!(report.runtime_proof_package_sha256, final_package_sha256);
        assert_ne!(report.runtime_proof_package_sha256, static_package_sha256);
        assert!(!report.accepted);
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_proof_semantic_parity_mismatch")
        );
        Ok(())
    }
}
