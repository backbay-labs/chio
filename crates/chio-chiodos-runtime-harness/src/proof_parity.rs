use crate::evidence_io::canonical_sha256_json;
use crate::RuntimeLoopbackError;

pub(crate) fn runtime_proof_parity(
    static_package: &chio_chiodos::ChiodosProofPackage,
    runtime_package: &chio_chiodos::ChiodosProofPackage,
) -> Result<
    (
        Vec<String>,
        Vec<chio_chiodos_runtime::RuntimeProofParityMismatch>,
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
    compare_runtime_proof_field(
        "bilateral_dsse_predicate_semantics",
        &bilateral_dsse_predicate_semantics(static_package)?,
        &bilateral_dsse_predicate_semantics(runtime_package)?,
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

#[derive(serde::Serialize, PartialEq, Eq)]
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

#[derive(serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ToolReceiptParityBinding {
    capability_id: String,
    tool_server: String,
    tool_name: String,
    action_parameter_hash: String,
    decision_allowed: bool,
}

#[derive(serde::Serialize, PartialEq, Eq)]
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

#[derive(serde::Serialize, PartialEq, Eq)]
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
    package: &chio_chiodos::ChiodosProofPackage,
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
    package: &chio_chiodos::ChiodosProofPackage,
) -> Vec<ToolReceiptParityBinding> {
    package
        .tool_receipts
        .iter()
        .map(|receipt| ToolReceiptParityBinding {
            capability_id: receipt.capability_id.clone(),
            tool_server: receipt.tool_server.clone(),
            tool_name: receipt.tool_name.clone(),
            action_parameter_hash: receipt.action.parameter_hash.clone(),
            decision_allowed: matches!(&receipt.decision, chio_core::receipt::Decision::Allow),
        })
        .collect()
}

fn bilateral_dsse_predicate_semantics(
    package: &chio_chiodos::ChiodosProofPackage,
) -> Result<Vec<BilateralDssePredicateParityBinding>, RuntimeLoopbackError> {
    package
        .bilateral_envelopes
        .iter()
        .map(|envelope| {
            let (statement, _) = envelope.decode_statement().map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chiodos runtime parity DSSE statement decode: {error}"
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
    package: &chio_chiodos::ChiodosProofPackage,
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

fn governance_authorization_presence(package: &chio_chiodos::ChiodosProofPackage) -> Vec<bool> {
    package
        .workflow_receipt
        .steps
        .iter()
        .map(|step| step.governance_receipt_id.is_some())
        .collect()
}

fn compare_runtime_proof_field<T: serde::Serialize + PartialEq>(
    field: &str,
    static_value: &T,
    runtime_value: &T,
    mismatches: &mut Vec<chio_chiodos_runtime::RuntimeProofParityMismatch>,
) -> Result<(), RuntimeLoopbackError> {
    if static_value != runtime_value {
        mismatches.push(chio_chiodos_runtime::RuntimeProofParityMismatch {
            field: field.to_string(),
            static_value_sha256: canonical_sha256_json(
                static_value,
                "Chiodos runtime static parity field hash",
            )?,
            runtime_value_sha256: canonical_sha256_json(
                runtime_value,
                "Chiodos runtime regenerated parity field hash",
            )?,
        });
    }
    Ok(())
}
