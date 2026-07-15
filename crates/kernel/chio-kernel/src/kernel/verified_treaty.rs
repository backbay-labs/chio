use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::ToolCallAction;
use chio_core::PublicKey;
use chio_federation::bilateral_dsse::{
    verify_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, DsseEnvelope,
};

use crate::{KernelError, ToolCallRequest};

pub struct FederationTreatyAdmissionBinding<'a> {
    pub accepted: bool,
    pub treaty_id: &'a str,
    pub treaty_scope_sha256: &'a str,
    pub ladder_intersection_sha256: &'a str,
    pub action_class_id: &'a str,
    pub consistency_model: &'a str,
    pub co_sign: &'a str,
}

pub struct FederationTreatyVerification<'a> {
    pub envelope: &'a DsseEnvelope,
    pub participant_kernel_ids: [&'a str; 2],
    pub participant_public_keys: [&'a PublicKey; 2],
    pub request: &'a ToolCallRequest,
    pub local_kernel_id: &'a str,
    pub admission: FederationTreatyAdmissionBinding<'a>,
    pub now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFederationTreatyMaterial {
    request_id: String,
    server_id: String,
    tool_name: String,
    request_sha256: String,
    origin_kernel_id: String,
    local_kernel_id: String,
    origin_public_key: PublicKey,
    local_public_key: PublicKey,
    extensions: BilateralPredicateExtensions,
    receipt_metadata: serde_json::Value,
}

impl VerifiedFederationTreatyMaterial {
    pub fn verify(input: FederationTreatyVerification<'_>) -> Result<Self, KernelError> {
        let origin_kernel_id = input
            .request
            .federated_origin_kernel_id
            .as_deref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "verified federation treaty material requires a federated request".to_string(),
                )
            })?;
        if input.participant_kernel_ids[0] != origin_kernel_id
            || input.participant_kernel_ids[1] != input.local_kernel_id
            || input.participant_kernel_ids[0] == input.participant_kernel_ids[1]
        {
            return Err(KernelError::Internal(
                "federation treaty participants do not match the current request boundary"
                    .to_string(),
            ));
        }
        if input.participant_public_keys[0] == input.participant_public_keys[1] {
            return Err(KernelError::Internal(
                "federation treaty participant keys are not independent".to_string(),
            ));
        }

        let statement = verify_chio_bilateral_dsse_envelope(
            input.envelope,
            input.participant_public_keys[0],
            input.participant_public_keys[1],
        )
        .map_err(|error| {
            KernelError::Internal(format!(
                "federation treaty DSSE signature verification failed: {error}"
            ))
        })?;
        let predicate = statement.predicate;
        if predicate.tool_server_a.kernel_id != input.participant_kernel_ids[0]
            || predicate.tool_server_b.kernel_id != input.participant_kernel_ids[1]
            || predicate.tool_name != input.request.tool_name
        {
            return Err(KernelError::Internal(
                "federation treaty DSSE does not match the current participants and tool"
                    .to_string(),
            ));
        }

        let action =
            ToolCallAction::from_parameters(input.request.arguments.clone()).map_err(|error| {
                KernelError::Internal(format!(
                    "federation treaty request canonicalization failed: {error}"
                ))
            })?;
        let tool_args_hash = predicate
            .tool_args_hash
            .as_ref()
            .map(|hash| hash.value.as_str());
        let treaty_binding_ref = predicate.treaty_binding_ref.clone().ok_or_else(|| {
            KernelError::Internal(
                "federation treaty DSSE is missing treaty binding material".to_string(),
            )
        })?;
        if tool_args_hash != Some(action.parameter_hash.as_str())
            || treaty_binding_ref.request_sha256 != action.parameter_hash
        {
            return Err(KernelError::Internal(
                "federation treaty DSSE request hash does not match the current request"
                    .to_string(),
            ));
        }

        let policy_evaluation_summary =
            predicate.policy_evaluation_summary.clone().ok_or_else(|| {
                KernelError::Internal(
                    "federation treaty DSSE is missing a policy evaluation summary".to_string(),
                )
            })?;
        chio_federation::bilateral_dsse::require_policy_evaluation_allow_admission(
            &policy_evaluation_summary,
        )
        .map_err(|error| {
            KernelError::Internal(format!(
                "federation treaty DSSE policy does not admit the request: {error}"
            ))
        })?;

        let capability_lease_ref = predicate.capability_lease_ref.clone().ok_or_else(|| {
            KernelError::Internal(
                "federation treaty DSSE is missing a capability lease".to_string(),
            )
        })?;
        if capability_lease_ref.expires_at_unix_ms <= input.now_unix_ms
            || !input
                .participant_kernel_ids
                .contains(&capability_lease_ref.issuer.as_str())
        {
            return Err(KernelError::Internal(
                "federation treaty DSSE capability lease is stale or has an unknown issuer"
                    .to_string(),
            ));
        }

        if !input.admission.accepted
            || !is_sha256_hex(&treaty_binding_ref.admission_report_sha256)
            || !matches!(
                input.admission.co_sign,
                "bilateral_required" | "bilateral_if_cross_org"
            )
            || predicate.co_sign != input.admission.co_sign
            || treaty_binding_ref.treaty_id != input.admission.treaty_id
            || treaty_binding_ref.treaty_scope_sha256 != input.admission.treaty_scope_sha256
            || treaty_binding_ref.ladder_intersection_sha256
                != input.admission.ladder_intersection_sha256
            || treaty_binding_ref.action_class_id != input.admission.action_class_id
            || treaty_binding_ref.consistency_model != input.admission.consistency_model
            || predicate.consistency_model != input.admission.consistency_model
        {
            return Err(KernelError::Internal(
                "federation treaty DSSE does not match the accepted admission report".to_string(),
            ));
        }

        let extensions = BilateralPredicateExtensions {
            capability_lease_ref: Some(capability_lease_ref.clone()),
            policy_evaluation_summary: Some(policy_evaluation_summary.clone()),
            governance_receipt_ref: predicate.governance_receipt_ref.clone(),
            consistency_anchor: predicate.consistency_anchor.clone(),
            consistency_model: Some(predicate.consistency_model.clone()),
            cross_org_visibility: Some(predicate.cross_org_visibility.clone()),
            treaty_binding_ref: Some(treaty_binding_ref.clone()),
        };
        let receipt_metadata = serde_json::json!({
            "chio_runtime": {
                "federation_treaty_dsse": {
                    "capability_lease_ref": capability_lease_ref,
                    "policy_evaluation_summary": policy_evaluation_summary,
                    "governance_receipt_ref": predicate.governance_receipt_ref,
                    "consistency_anchor": predicate.consistency_anchor,
                    "consistency_model": predicate.consistency_model,
                    "cross_org_visibility": predicate.cross_org_visibility,
                    "treaty_binding_ref": treaty_binding_ref,
                }
            }
        });

        Ok(Self {
            request_id: input.request.request_id.clone(),
            server_id: input.request.server_id.clone(),
            tool_name: input.request.tool_name.clone(),
            request_sha256: action.parameter_hash,
            origin_kernel_id: origin_kernel_id.to_string(),
            local_kernel_id: input.local_kernel_id.to_string(),
            origin_public_key: input.participant_public_keys[0].clone(),
            local_public_key: input.participant_public_keys[1].clone(),
            extensions,
            receipt_metadata,
        })
    }

    pub(crate) fn receipt_metadata(&self) -> serde_json::Value {
        self.receipt_metadata.clone()
    }

    pub(crate) fn validate_cosign_participants(
        &self,
        origin_kernel_id: &str,
        origin_public_key: &PublicKey,
        local_kernel_id: &str,
        local_public_key: &PublicKey,
    ) -> Result<(), KernelError> {
        if self.origin_kernel_id != origin_kernel_id
            || self.origin_public_key != *origin_public_key
            || self.local_kernel_id != local_kernel_id
            || self.local_public_key != *local_public_key
        {
            return Err(KernelError::Internal(
                "verified federation treaty participants do not match the admitted peer snapshot"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn extensions_for_receipt(
        &self,
        request: &ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<BilateralPredicateExtensions, KernelError> {
        let request_origin = request.federated_origin_kernel_id.as_deref();
        if request.request_id != self.request_id
            || request.server_id != self.server_id
            || request.tool_name != self.tool_name
            || request_origin != Some(self.origin_kernel_id.as_str())
            || receipt.tool_server != self.server_id
            || receipt.tool_name != self.tool_name
            || receipt.action.parameter_hash != self.request_sha256
        {
            return Err(KernelError::Internal(
                "verified federation treaty material does not match the signed receipt".to_string(),
            ));
        }
        let mut extensions = self.extensions.clone();
        let treaty_binding_ref = extensions.treaty_binding_ref.as_mut().ok_or_else(|| {
            KernelError::Internal(
                "verified federation treaty material lost its treaty binding".to_string(),
            )
        })?;
        treaty_binding_ref.outcome_sha256 = receipt.content_hash.clone();
        treaty_binding_ref.remote_receipt_sha256 = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(receipt).map_err(|error| {
                KernelError::Internal(format!(
                    "federation treaty DSSE receipt canonicalization failed: {error}"
                ))
            })?,
        );
        Ok(extensions)
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
