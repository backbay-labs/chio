use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::PublicKey;
use chio_core::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicContentV1, EconomicEffectSlotV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorViewV1, EconomicStateBatchV1,
    VerifiedEconomicStateBatchAdvance,
};
use chio_core::receipt::{body::ChioReceipt, decision::Decision};
use chio_settle::channel::{
    derive_channel_receipt_authority_digest, ChannelEscrowReservationViewV1,
    ChannelLifecycleViewV1, SignedChannelReservationV1, SignedChannelStateV1,
    VerifiedChannelTerminalAdvanceV1, CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
};

use crate::receipt_store::{AuthorizationReceiptConsumption, PendingSettlementObservation};
use crate::tool_outcome::{
    SettlementDispositionV1, ToolOutcomeTerminalEvidenceV1, VerifiedPreDispatchNoEffect,
    VerifiedTransportNotAccepted,
};

use super::*;

mod participant_evidence;
pub use participant_evidence::*;
mod channel_terminal;
pub use channel_terminal::*;
mod channel_terminal_authority;
pub use channel_terminal_authority::*;
mod economic_cancellation;
pub use economic_cancellation::*;
mod factor_assignment;
pub use factor_assignment::*;
mod pre_dispatch_compensation;
pub use pre_dispatch_compensation::*;
mod outcome_unknown;
pub use outcome_unknown::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionReceiptSchema {
    #[serde(rename = "chio.admission-receipt.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionCompensationStatus {
    NotCompensated,
    CompensatedBeforeDispatch,
    NotAcceptedAfterDispatchCommit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceiptMetadataV1 {
    pub schema: AdmissionReceiptSchema,
    pub operation_id: AdmissionOperationId,
    pub request_id: AdmissionIdentifier,
    pub request_namespace_digest: RequestNamespaceDigest,
    pub request_binding_hash: AdmissionDigest,
    pub projected_operation_version: u64,
    pub projected_state: AdmissionOperationState,
    pub projected_dispatch_state: AdmissionDispatchState,
    pub trusted_time_unix_ms: u64,
    pub coordinator_lease_id: AdmissionIdentifier,
    pub coordinator_lease_epoch: u64,
    pub store_fence: StoreMutationFence,
    pub retained_dispatch_commit: Option<AdmissionDispatchCommitBindingV1>,
    pub compensation_status: AdmissionCompensationStatus,
    pub tool_outcome_id: Option<AdmissionDigest>,
    pub tool_outcome_version: Option<u64>,
}

/// A receipt qualified by the kernel against the exact admission projection.
///
/// Raw participant and post-return evidence constructors are absent from the
/// production API until their authority verifier ports are available.
///
/// ```compile_fail
/// use chio_kernel::admission_operation::PaymentTerminalEvidence;
/// use chio_kernel::tool_outcome::EvaluationStepResultV1;
///
/// let _ = PaymentTerminalEvidence::from_source_verified;
/// let _ = EvaluationStepResultV1::pure;
/// ```
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct VerifiedAdmissionReceipt(ChioReceipt);

impl VerifiedAdmissionReceipt {
    #[allow(dead_code)]
    pub(crate) fn from_kernel_verified(
        receipt: ChioReceipt,
        expected_kernel_public_key: &PublicKey,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        tool_outcome: &ToolOutcomeTerminalEvidenceV1,
    ) -> Result<Self, AdmissionOperationError> {
        Self::from_kernel_verified_terminal(
            receipt,
            expected_kernel_public_key,
            &Decision::Allow,
            operation,
            context,
            tool_outcome,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn from_kernel_verified_terminal(
        receipt: ChioReceipt,
        expected_kernel_public_key: &PublicKey,
        expected_decision: &Decision,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        tool_outcome: &ToolOutcomeTerminalEvidenceV1,
    ) -> Result<Self, AdmissionOperationError> {
        tool_outcome
            .validate_against(operation, context)
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
        Self::qualify(
            receipt,
            expected_kernel_public_key,
            expected_decision,
            tool_outcome.tool_server().as_str(),
            tool_outcome.tool_name().as_str(),
            operation.binding.action_parameter_hash(),
            tool_outcome.resolved_output_digest(),
            operation,
            context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            Some((tool_outcome.outcome_id(), tool_outcome.outcome_version())),
        )
    }

    /// Qualify a signed Deny that a delivery-digest mismatch produced after
    /// the tool returned. The terminal carries no completed-tool-outcome
    /// attachment: the actual output remains in privileged durable outcome
    /// evidence while the public receipt carries only the deterministic
    /// redaction binding, mirroring the other non-`Completed` terminals.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_kernel_verified_denied_after_delivery(
        receipt: ChioReceipt,
        expected_kernel_public_key: &PublicKey,
        expected_decision: &Decision,
        expected_tool_server: &str,
        expected_tool_name: &str,
        expected_content_hash: &AdmissionDigest,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<Self, AdmissionOperationError> {
        Self::qualify(
            receipt,
            expected_kernel_public_key,
            expected_decision,
            expected_tool_server,
            expected_tool_name,
            operation.binding.action_parameter_hash(),
            expected_content_hash,
            operation,
            context,
            AdmissionOperationState::DeniedAfterDelivery,
            AdmissionCompensationStatus::NotCompensated,
            None,
        )
    }

    #[cfg(any(test, feature = "admission-test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn from_kernel_verified_for_test(
        receipt: ChioReceipt,
        expected_kernel_public_key: &PublicKey,
        expected_decision: &Decision,
        expected_tool_server: &str,
        expected_tool_name: &str,
        expected_parameter_hash: &AdmissionDigest,
        expected_content_hash: &AdmissionDigest,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
        compensation_status: AdmissionCompensationStatus,
        tool_outcome: Option<(&AdmissionDigest, u64)>,
    ) -> Result<Self, AdmissionOperationError> {
        Self::qualify(
            receipt,
            expected_kernel_public_key,
            expected_decision,
            expected_tool_server,
            expected_tool_name,
            expected_parameter_hash,
            expected_content_hash,
            operation,
            context,
            projected_state,
            compensation_status,
            tool_outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn qualify(
        receipt: ChioReceipt,
        expected_kernel_public_key: &PublicKey,
        expected_decision: &Decision,
        expected_tool_server: &str,
        expected_tool_name: &str,
        expected_parameter_hash: &AdmissionDigest,
        expected_content_hash: &AdmissionDigest,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
        compensation_status: AdmissionCompensationStatus,
        tool_outcome: Option<(&AdmissionDigest, u64)>,
    ) -> Result<Self, AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        if receipt.kernel_key != *expected_kernel_public_key
            || !receipt.verify_signature().map_err(|_| mismatch())?
            || receipt.decision.as_ref() != Some(expected_decision)
            || (projected_state == AdmissionOperationState::Completed
                && !matches!(
                    expected_decision,
                    Decision::Allow | Decision::Incomplete { .. }
                ))
            || (projected_state == AdmissionOperationState::DeniedAfterDelivery
                && !matches!(expected_decision, Decision::Deny { .. }))
            || receipt.tool_server != expected_tool_server
            || receipt.tool_name != expected_tool_name
            || receipt.action.parameter_hash != expected_parameter_hash.as_str()
            || !receipt.action.verify_hash().map_err(|_| mismatch())?
            || receipt.content_hash != expected_content_hash.as_str()
        {
            return Err(mismatch());
        }
        validate_receipt_projection(
            &receipt,
            operation,
            context,
            projected_state,
            compensation_status,
            tool_outcome,
        )?;
        Ok(Self(receipt))
    }

    #[must_use]
    pub const fn receipt(&self) -> &ChioReceipt {
        &self.0
    }

    pub(crate) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
        compensation_status: AdmissionCompensationStatus,
        tool_outcome: Option<(&AdmissionDigest, u64)>,
    ) -> Result<(), AdmissionOperationError> {
        validate_receipt_projection(
            &self.0,
            operation,
            context,
            projected_state,
            compensation_status,
            tool_outcome,
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmissionProjectionCapabilities {
    pub operation_terminal: bool,
    pub incident_terminal: bool,
    pub tool_outcome: bool,
    pub payment_terminal: bool,
    pub authorization_consumption: bool,
    pub outcome_eligibility: bool,
    pub observation_attempt_zero: bool,
    pub obligation: bool,
    pub channel_terminal: bool,
    pub credit_exposure_terminal: bool,
    pub economic_mutation_terminal: bool,
}

impl AdmissionProjectionCapabilities {
    pub fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
        projection: &AdmissionTerminalProjection,
    ) -> Result<(), AdmissionOperationError> {
        let requirements = operation.binding.participant_requirements();
        let require = |supported, capability| {
            if supported {
                Ok(())
            } else {
                Err(AdmissionOperationError::MissingProjectionCapability { capability })
            }
        };
        require(self.operation_terminal, "operation_terminal")?;
        require(
            !requirements.credit_exposure || self.credit_exposure_terminal,
            "credit_exposure_terminal",
        )?;
        match projection {
            AdmissionTerminalProjection::Completed(_) => {
                require(
                    operation.binding.kind != AdmissionOperationKind::ToolDispatch
                        || self.tool_outcome,
                    "tool_outcome",
                )?;
                require(
                    !requirements.payment || self.payment_terminal,
                    "payment_terminal",
                )?;
                require(
                    !requirements.authorization_consumption || self.authorization_consumption,
                    "authorization_consumption",
                )?;
                require(
                    !requirements.outcome_eligibility || self.outcome_eligibility,
                    "outcome_eligibility",
                )?;
                require(
                    !requirements.observation_attempt_zero || self.observation_attempt_zero,
                    "observation_attempt_zero",
                )?;
                require(!requirements.obligation || self.obligation, "obligation")?;
                require(
                    !requirements.channel || self.channel_terminal,
                    "channel_terminal",
                )
            }
            AdmissionTerminalProjection::CompensatedBeforeDispatch { evidence, .. }
            | AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit { evidence, .. } => {
                require(
                    !matches!(evidence.as_ref(), AdmissionReceiptOrIncident::Incident(_))
                        || self.incident_terminal,
                    "incident_terminal",
                )
            }
            AdmissionTerminalProjection::DeniedAfterDelivery { evidence, .. } => {
                require(
                    !matches!(evidence.as_ref(), AdmissionReceiptOrIncident::Incident(_))
                        || self.incident_terminal,
                    "incident_terminal",
                )?;
                require(
                    !requirements.payment || self.payment_terminal,
                    "payment_terminal",
                )?;
                require(
                    !requirements.observation_attempt_zero || self.observation_attempt_zero,
                    "observation_attempt_zero",
                )
            }
            AdmissionTerminalProjection::OutcomeUnknownAfterDispatch { .. } => {
                require(self.incident_terminal, "incident_terminal")
            }
            AdmissionTerminalProjection::EconomicMutationApplied { .. }
            | AdmissionTerminalProjection::EconomicMutationNotApplied { .. } => require(
                self.economic_mutation_terminal,
                "economic_mutation_terminal",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionProjectionRecordKind {
    Receipt,
    Incident,
    ToolOutcome,
    PaymentTerminal,
    AuthorizationConsumption,
    OutcomeEligibility,
    ObservationAttemptZero,
    Obligation,
    ChannelTerminal,
    ReleaseProof,
    EconomicMutationResult,
    MutationAudit,
}

impl AdmissionProjectionRecordKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receipt => "receipt",
            Self::Incident => "incident",
            Self::ToolOutcome => "tool_outcome",
            Self::PaymentTerminal => "payment_terminal",
            Self::AuthorizationConsumption => "authorization_consumption",
            Self::OutcomeEligibility => "outcome_eligibility",
            Self::ObservationAttemptZero => "observation_attempt_zero",
            Self::Obligation => "obligation",
            Self::ChannelTerminal => "channel_terminal",
            Self::ReleaseProof => "release_proof",
            Self::EconomicMutationResult => "economic_mutation_result",
            Self::MutationAudit => "mutation_audit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionProjectionManifestSchema {
    #[serde(rename = "chio.admission-projection-manifest.v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProjectionRecordCommitmentV1 {
    kind: AdmissionProjectionRecordKind,
    record_id: AdmissionIdentifier,
    record_digest: AdmissionDigest,
}

impl AdmissionProjectionRecordCommitmentV1 {
    #[must_use]
    pub const fn kind(&self) -> AdmissionProjectionRecordKind {
        self.kind
    }

    #[must_use]
    pub const fn record_id(&self) -> &AdmissionIdentifier {
        &self.record_id
    }

    #[must_use]
    pub const fn record_digest(&self) -> &AdmissionDigest {
        &self.record_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProjectionManifestV1 {
    schema: AdmissionProjectionManifestSchema,
    projection_body_digest: AdmissionDigest,
    records: Vec<AdmissionProjectionRecordCommitmentV1>,
}

impl AdmissionProjectionManifestV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AdmissionOperationError> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
        manifest.validate()?;
        if canonical_json_bytes(&manifest)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
            != bytes
        {
            return Err(AdmissionOperationError::CanonicalJson(
                "admission projection manifest is not canonical".to_string(),
            ));
        }
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdmissionOperationError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))
    }

    pub fn projection_digest(&self) -> Result<AdmissionDigest, AdmissionOperationError> {
        AdmissionDigest::try_new(
            "terminal_projection_digest",
            sha256_hex(&self.canonical_bytes()?),
        )
    }

    pub fn verify_projection_body(&self, bytes: &[u8]) -> Result<(), AdmissionOperationError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
        if canonical_json_bytes(&value)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
            != bytes
            || sha256_hex(bytes) != self.projection_body_digest.as_str()
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn projection_body_digest(&self) -> &AdmissionDigest {
        &self.projection_body_digest
    }

    #[must_use]
    pub fn records(&self) -> &[AdmissionProjectionRecordCommitmentV1] {
        &self.records
    }

    fn validate(&self) -> Result<(), AdmissionOperationError> {
        if self.records.is_empty()
            || self.records.windows(2).any(|pair| {
                let left = (pair[0].kind.as_str(), pair[0].record_id.as_str());
                let right = (pair[1].kind.as_str(), pair[1].record_id.as_str());
                left >= right
            })
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAdmissionProjectionRecord {
    commitment: AdmissionProjectionRecordCommitmentV1,
    canonical_bytes: Vec<u8>,
}

impl CanonicalAdmissionProjectionRecord {
    #[must_use]
    pub const fn commitment(&self) -> &AdmissionProjectionRecordCommitmentV1 {
        &self.commitment
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAdmissionTerminalProjection {
    projection_bytes: Vec<u8>,
    manifest: AdmissionProjectionManifestV1,
    manifest_bytes: Vec<u8>,
    projection_digest: AdmissionDigest,
    records: Vec<CanonicalAdmissionProjectionRecord>,
}

impl CanonicalAdmissionTerminalProjection {
    #[must_use]
    pub fn projection_bytes(&self) -> &[u8] {
        &self.projection_bytes
    }

    #[must_use]
    pub const fn manifest(&self) -> &AdmissionProjectionManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    #[must_use]
    pub const fn projection_digest(&self) -> &AdmissionDigest {
        &self.projection_digest
    }

    #[must_use]
    pub fn records(&self) -> &[CanonicalAdmissionProjectionRecord] {
        &self.records
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionProjectionContext {
    pub operation_id: AdmissionOperationId,
    pub request_id: AdmissionIdentifier,
    pub expected_operation_version: u64,
    pub trusted_time_unix_ms: u64,
    pub coordinator_lease_id: AdmissionIdentifier,
    pub coordinator_lease_epoch: u64,
    pub store_fence: StoreMutationFence,
}

impl AdmissionProjectionContext {
    pub fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_positive_ijson(
            "expected_operation_version",
            self.expected_operation_version,
        )?;
        validate_positive_ijson("trusted_time_unix_ms", self.trusted_time_unix_ms)?;
        validate_positive_ijson("coordinator_lease_epoch", self.coordinator_lease_epoch)?;
        AdmissionIdentifier::try_new(
            "projection_context.coordinator_lease_id",
            self.coordinator_lease_id.as_str().to_owned(),
        )?;
        validate_store_fence(&self.store_fence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionExactProjectionBindingV1 {
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    request_binding_hash: AdmissionDigest,
    source_operation_version: u64,
    projected_operation_version: u64,
    projected_state: AdmissionOperationState,
    trusted_time_unix_ms: u64,
    coordinator_lease_id: AdmissionIdentifier,
    coordinator_lease_epoch: u64,
    store_fence: StoreMutationFence,
    retained_dispatch_commit: Option<AdmissionDispatchCommitBindingV1>,
}

impl AdmissionExactProjectionBindingV1 {
    fn from_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
    ) -> Result<Self, AdmissionOperationError> {
        validate_projection_context(operation, context, projected_state)?;
        Ok(Self {
            operation_id: operation.binding.operation_id.clone(),
            request_id: operation.binding.request_id.clone(),
            request_binding_hash: operation.binding.request_binding_hash().clone(),
            source_operation_version: operation.version,
            projected_operation_version: next_version(operation.version)?,
            projected_state,
            trusted_time_unix_ms: context.trusted_time_unix_ms,
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch,
            store_fence: context.store_fence.clone(),
            retained_dispatch_commit: operation.dispatch_commit.clone(),
        })
    }

    pub fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
    ) -> Result<(), AdmissionOperationError> {
        validate_projection_context(operation, context, projected_state)?;
        if self.operation_id != operation.binding.operation_id
            || self.request_id != operation.binding.request_id
            || self.request_binding_hash != *operation.binding.request_binding_hash()
            || self.source_operation_version != operation.version
            || self.projected_operation_version != next_version(operation.version)?
            || self.projected_state != projected_state
            || self.trusted_time_unix_ms != context.trusted_time_unix_ms
            || self.coordinator_lease_id != context.coordinator_lease_id
            || self.coordinator_lease_epoch != context.coordinator_lease_epoch
            || self.store_fence != context.store_fence
            || self.retained_dispatch_commit != operation.dispatch_commit
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn request_id(&self) -> &AdmissionIdentifier {
        &self.request_id
    }

    #[must_use]
    pub const fn request_binding_hash(&self) -> &AdmissionDigest {
        &self.request_binding_hash
    }

    #[must_use]
    pub const fn source_operation_version(&self) -> u64 {
        self.source_operation_version
    }

    #[must_use]
    pub const fn projected_operation_version(&self) -> u64 {
        self.projected_operation_version
    }

    #[must_use]
    pub const fn store_fence(&self) -> &StoreMutationFence {
        &self.store_fence
    }
}

fn validate_projection_context(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projected_state: AdmissionOperationState,
) -> Result<(), AdmissionOperationError> {
    operation.validate()?;
    context.validate()?;
    if context.operation_id != operation.binding.operation_id
        || context.request_id != operation.binding.request_id
        || context.expected_operation_version != operation.version
        || context.coordinator_lease_epoch != operation.coordinator_lease_epoch
        || !projected_state.is_terminal()
        || !is_legal_transition(
            operation.binding.kind,
            operation.binding.participant_requirements(),
            operation.state,
            projected_state,
        )
        || operation.dispatch_commit.as_ref().is_some_and(|commit| {
            !projection_fence_follows(&commit.store_fence, &context.store_fence)
        })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn projection_fence_follows(historical: &StoreMutationFence, current: &StoreMutationFence) -> bool {
    historical.store_uuid == current.store_uuid
        && (current.owner_epoch > historical.owner_epoch || current == historical)
}

macro_rules! admission_projection_binding {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        pub struct $name {
            binding: AdmissionExactProjectionBindingV1,
            record_id: AdmissionIdentifier,
            record_digest: AdmissionDigest,
        }

        impl $name {
            #[cfg(any(test, feature = "admission-test-support"))]
            #[allow(dead_code)]
            pub fn from_verified(
                operation: &AdmissionOperationV1,
                context: &AdmissionProjectionContext,
                projected_state: AdmissionOperationState,
                record_id: AdmissionIdentifier,
                record_digest: AdmissionDigest,
            ) -> Result<Self, AdmissionOperationError> {
                Ok(Self {
                    binding: AdmissionExactProjectionBindingV1::from_verified(
                        operation,
                        context,
                        projected_state,
                    )?,
                    record_id,
                    record_digest,
                })
            }

            pub(super) fn validate_against(
                &self,
                operation: &AdmissionOperationV1,
                context: &AdmissionProjectionContext,
                projected_state: AdmissionOperationState,
            ) -> Result<(), AdmissionOperationError> {
                self.binding
                    .validate_against(operation, context, projected_state)
            }
        }
    };
}

admission_projection_binding!(GovernedMutationAuditEvent);
admission_projection_binding!(AdmissionIncident);

pub(super) fn receipt_digest(
    receipt: &ChioReceipt,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    let bytes = canonical_json_bytes(receipt)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    AdmissionDigest::try_new("consumer_receipt_digest", sha256_hex(&bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicMutationTerminalStatus {
    Applied,
    PermanentlyNotApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedEconomicMutationResultBinding {
    binding: AdmissionExactProjectionBindingV1,
    record_id: AdmissionIdentifier,
    record_digest: AdmissionDigest,
    participant_id: AdmissionIdentifier,
    participant_key_epoch: u64,
    resource_id: AdmissionIdentifier,
    expected_resource_version: u64,
    resulting_resource_version: u64,
    expected_resource_fence: AdmissionIdentifier,
    resulting_resource_fence: AdmissionIdentifier,
    immutable_request_digest: AdmissionDigest,
    signature_digest: AdmissionDigest,
    status: EconomicMutationTerminalStatus,
    #[serde(default)]
    anchored_effect: bool,
}

impl GovernedEconomicMutationResultBinding {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        record_id: AdmissionIdentifier,
        record_digest: AdmissionDigest,
        participant_id: AdmissionIdentifier,
        participant_key_epoch: u64,
        resource_id: AdmissionIdentifier,
        expected_resource_version: u64,
        resulting_resource_version: u64,
        expected_resource_fence: AdmissionIdentifier,
        resulting_resource_fence: AdmissionIdentifier,
        immutable_request_digest: AdmissionDigest,
        signature_digest: AdmissionDigest,
        status: EconomicMutationTerminalStatus,
    ) -> Result<Self, AdmissionOperationError> {
        let projected_state = match status {
            EconomicMutationTerminalStatus::Applied => {
                AdmissionOperationState::EconomicMutationApplied
            }
            EconomicMutationTerminalStatus::PermanentlyNotApplied => {
                AdmissionOperationState::EconomicMutationNotApplied
            }
        };
        let binding = Self {
            binding: AdmissionExactProjectionBindingV1::from_verified(
                operation,
                context,
                projected_state,
            )?,
            record_id,
            record_digest,
            participant_id,
            participant_key_epoch,
            resource_id,
            expected_resource_version,
            resulting_resource_version,
            expected_resource_fence,
            resulting_resource_fence,
            immutable_request_digest,
            signature_digest,
            status,
            anchored_effect: false,
        };
        binding.validate_against(operation, context)?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_positive_ijson("participant_key_epoch", self.participant_key_epoch)
            .map_err(|_| AdmissionOperationError::InvalidEconomicMutationBinding)?;
        validate_positive_ijson("expected_resource_version", self.expected_resource_version)
            .map_err(|_| AdmissionOperationError::InvalidEconomicMutationBinding)?;
        validate_positive_ijson(
            "resulting_resource_version",
            self.resulting_resource_version,
        )
        .map_err(|_| AdmissionOperationError::InvalidEconomicMutationBinding)?;
        Ok(())
    }

    pub(super) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), AdmissionOperationError> {
        self.validate()?;
        let projected_state = match self.status {
            EconomicMutationTerminalStatus::Applied => {
                AdmissionOperationState::EconomicMutationApplied
            }
            EconomicMutationTerminalStatus::PermanentlyNotApplied => {
                AdmissionOperationState::EconomicMutationNotApplied
            }
        };
        self.binding
            .validate_against(operation, context, projected_state)?;
        if self.immutable_request_digest != *operation.binding.request_binding_hash() {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(())
    }

    pub(in crate::admission_operation) fn validate_remote_terminal(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        terminal: &AdmissionOperationV1,
        record_id: &AdmissionIdentifier,
    ) -> Result<bool, AdmissionOperationError> {
        self.validate_against(operation, context)?;
        let projected_state = match self.status {
            EconomicMutationTerminalStatus::Applied => {
                AdmissionOperationState::EconomicMutationApplied
            }
            EconomicMutationTerminalStatus::PermanentlyNotApplied => {
                AdmissionOperationState::EconomicMutationNotApplied
            }
        };
        let replay_matches = matches!(
            terminal.terminal_replay(),
            Some(AdmissionTerminalReplay::EconomicMutation {
                result_id,
                result_digest,
                ..
            }) if result_id == &self.record_id && result_digest == &self.record_digest
        );
        if terminal.state() != projected_state || record_id != &self.record_id || !replay_matches {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(self.anchored_effect)
    }

    pub(in crate::admission_operation) fn verify_anchored_cancellation(
        &self,
        slot: &EconomicEffectSlotV1,
        expected_head: &EconomicResourceHeadV1,
        resulting_head: &EconomicResourceHeadV1,
        checkpoint_digest: &str,
    ) -> Result<(), AdmissionOperationError> {
        if !self.anchored_effect
            || self.status != EconomicMutationTerminalStatus::PermanentlyNotApplied
            || self.participant_id.as_str() != slot.target.target_id.as_str()
            || self.participant_key_epoch != slot.target.target_key_epoch
            || self.resource_id.as_str() != slot.slot_id.as_str()
            || self.expected_resource_version != expected_head.resource_version
            || self.resulting_resource_version != resulting_head.resource_version
            || self.expected_resource_fence.as_str()
                != format!("effect-slot-fence:{}", expected_head.lifecycle_fence)
            || self.resulting_resource_fence.as_str()
                != format!("effect-slot-fence:{}", resulting_head.lifecycle_fence)
            || self.signature_digest.as_str() != checkpoint_digest
        {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedEconomicMutationApplied(GovernedEconomicMutationResultBinding);

#[derive(Debug, Clone, Serialize)]
pub struct VerifiedEconomicMutationNotApplied(GovernedEconomicMutationResultBinding);

impl VerifiedEconomicMutationApplied {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_verified(
        binding: GovernedEconomicMutationResultBinding,
    ) -> Result<Self, AdmissionOperationError> {
        binding.validate()?;
        if binding.status != EconomicMutationTerminalStatus::Applied {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(Self(binding))
    }

    fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), AdmissionOperationError> {
        self.0.validate_against(operation, context)?;
        if self.0.status != EconomicMutationTerminalStatus::Applied {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(())
    }
}

impl VerifiedEconomicMutationNotApplied {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_verified(
        binding: GovernedEconomicMutationResultBinding,
    ) -> Result<Self, AdmissionOperationError> {
        binding.validate()?;
        if binding.status != EconomicMutationTerminalStatus::PermanentlyNotApplied {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(Self(binding))
    }

    fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
    ) -> Result<(), AdmissionOperationError> {
        self.0.validate_against(operation, context)?;
        if self.0.status != EconomicMutationTerminalStatus::PermanentlyNotApplied {
            return Err(AdmissionOperationError::InvalidEconomicMutationBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedAuthorizationReceiptConsumption {
    binding: AdmissionExactProjectionBindingV1,
    consumption: AuthorizationReceiptConsumption,
    source_receipt_digest: AdmissionDigest,
    authorization_capability_hash: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

impl VerifiedAuthorizationReceiptConsumption {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_source_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        consumption: AuthorizationReceiptConsumption,
        source_authorization_receipt_id: &AdmissionIdentifier,
        source_session_id: &AdmissionIdentifier,
        source_tool_call_id: &AdmissionIdentifier,
        source_tenant_id: Option<&AdmissionIdentifier>,
        source_parameter_hash: &AdmissionDigest,
        source_receipt_digest: AdmissionDigest,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
    ) -> Result<Self, AdmissionOperationError> {
        let receipt = receipt.receipt();
        let expected_tenant = expected_receipt_tenant(operation);
        if consumption.authorization_receipt_id != source_authorization_receipt_id.as_str()
            || consumption.consumer_receipt_id != receipt.id
            || consumption.request_id != operation.binding.request_id.as_str()
            || consumption.session_id != source_session_id.as_str()
            || consumption.tool_call_id != source_tool_call_id.as_str()
            || consumption.tenant_id.as_deref() != source_tenant_id.map(AdmissionIdentifier::as_str)
            || consumption.tenant_id.as_deref() != expected_tenant
            || receipt.tenant_id.as_deref() != expected_tenant
            || consumption.parameter_hash != source_parameter_hash.as_str()
            || consumption.consumed_at_unix_ms != context.trusted_time_unix_ms
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        validate_positive_ijson("authorization_outcome_version", outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(&outcome_id)?;
        Ok(Self {
            binding: AdmissionExactProjectionBindingV1::from_verified(
                operation,
                context,
                AdmissionOperationState::Completed,
            )?,
            consumption,
            source_receipt_digest,
            authorization_capability_hash: operation.binding.authorization_capability_hash.clone(),
            outcome_id,
            outcome_version,
        })
    }

    pub(super) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: &AdmissionDigest,
        outcome_version: u64,
    ) -> Result<(), AdmissionOperationError> {
        let receipt = receipt.receipt();
        self.binding
            .validate_against(operation, context, AdmissionOperationState::Completed)?;
        validate_positive_ijson("authorization_outcome_version", self.outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(outcome_id)?;
        let expected_tenant = expected_receipt_tenant(operation);
        if AdmissionIdentifier::try_new(
            "authorization_receipt_id",
            self.consumption.authorization_receipt_id.clone(),
        )
        .is_err()
            || AdmissionIdentifier::try_new("session_id", self.consumption.session_id.clone())
                .is_err()
            || AdmissionIdentifier::try_new("tool_call_id", self.consumption.tool_call_id.clone())
                .is_err()
            || AdmissionDigest::try_new(
                "authorization_parameter_hash",
                self.consumption.parameter_hash.clone(),
            )
            .is_err()
            || self.consumption.consumer_receipt_id != receipt.id
            || self.consumption.request_id != operation.binding.request_id.as_str()
            || self.consumption.tenant_id.as_deref() != expected_tenant
            || receipt.tenant_id.as_deref() != expected_tenant
            || self.consumption.consumed_at_unix_ms != context.trusted_time_unix_ms
            || self.authorization_capability_hash != operation.binding.authorization_capability_hash
            || self.outcome_id != *outcome_id
            || self.outcome_version != outcome_version
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn consumption(&self) -> &AuthorizationReceiptConsumption {
        &self.consumption
    }
}

fn expected_receipt_tenant(operation: &AdmissionOperationV1) -> Option<&str> {
    (operation.binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
        .then_some(operation.binding.authenticated_tenant_id.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationAttemptZero {
    binding: AdmissionExactProjectionBindingV1,
    pending: PendingSettlementObservation,
    consumer_receipt_id: AdmissionIdentifier,
    consumer_receipt_digest: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

/// The two terminal states whose settlement is observable: a completed
/// capture and a denied delivery's zero-charge release. Both retain the
/// delivered tool outcome the observation binds against.
fn validate_observed_terminal_state(
    projected_state: AdmissionOperationState,
) -> Result<(), AdmissionOperationError> {
    if !matches!(
        projected_state,
        AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery
    ) {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

impl ObservationAttemptZero {
    pub(crate) fn from_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
        projected_state: AdmissionOperationState,
    ) -> Result<Self, AdmissionOperationError> {
        let receipt = receipt.receipt();
        validate_observed_terminal_state(projected_state)?;
        validate_positive_ijson("observation_outcome_version", outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(&outcome_id)?;
        Ok(Self {
            binding: AdmissionExactProjectionBindingV1::from_verified(
                operation,
                context,
                projected_state,
            )?,
            pending: PendingSettlementObservation {
                next_visible_at_ms: context.trusted_time_unix_ms,
            },
            consumer_receipt_id: AdmissionIdentifier::try_new(
                "consumer_receipt_id",
                receipt.id.clone(),
            )?,
            consumer_receipt_digest: receipt_digest(receipt)?,
            outcome_id,
            outcome_version,
        })
    }

    #[cfg(feature = "admission-test-support")]
    pub fn from_verified_for_test(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
    ) -> Result<Self, AdmissionOperationError> {
        Self::from_verified(
            operation,
            context,
            receipt,
            outcome_id,
            outcome_version,
            AdmissionOperationState::Completed,
        )
    }

    pub(super) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: &AdmissionDigest,
        outcome_version: u64,
        projected_state: AdmissionOperationState,
    ) -> Result<(), AdmissionOperationError> {
        let receipt = receipt.receipt();
        validate_observed_terminal_state(projected_state)?;
        self.binding
            .validate_against(operation, context, projected_state)?;
        validate_positive_ijson("observation_outcome_version", self.outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(outcome_id)?;
        if self.pending.next_visible_at_ms != context.trusted_time_unix_ms
            || self.consumer_receipt_id.as_str() != receipt.id
            || self.consumer_receipt_digest != receipt_digest(receipt)?
            || self.outcome_id != *outcome_id
            || self.outcome_version != outcome_version
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }

    pub(super) const fn outcome_version(&self) -> u64 {
        self.outcome_version
    }

    #[must_use]
    pub const fn pending(&self) -> &PendingSettlementObservation {
        &self.pending
    }

    #[cfg(test)]
    pub(super) fn with_visibility_for_test(mut self, next_visible_at_ms: u64) -> Self {
        self.pending.next_visible_at_ms = next_visible_at_ms;
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionCompletedProjection {
    pub context: AdmissionProjectionContext,
    pub receipt: VerifiedAdmissionReceipt,
    pub tool_outcome: Option<ToolOutcomeTerminalEvidenceV1>,
    pub payment_evidence: Option<PaymentTerminalEvidence>,
    pub authorization: Option<VerifiedAuthorizationReceiptConsumption>,
    pub eligibility: Option<OutcomeEligibilityFinalization>,
    pub observer_work: Option<ObservationAttemptZero>,
    pub obligation: Option<ObligationProjection>,
    pub channel_terminal: Option<VerifiedChannelTerminalProjectionV1>,
}

/// The presence rule for the denied-after-delivery terminal, the analogue
/// of [`validate_completed_participant_presence`]: a paid operation must
/// carry the payment evidence binding its released journal, an observed
/// operation must carry its observation attempt, and a requirement this
/// terminal cannot represent (authorization consumption, outcome
/// eligibility, obligation, channel) denies the projection outright.
pub(super) fn validate_denied_after_delivery_participant_presence(
    requirements: AdmissionParticipantRequirements,
    payment_evidence: Option<&PaymentTerminalEvidence>,
    observer_work: Option<&ObservationAttemptZero>,
) -> Result<(), AdmissionOperationError> {
    if requirements.authorization_consumption
        || requirements.outcome_eligibility
        || requirements.obligation
        || requirements.channel
        || payment_evidence.is_some() != requirements.payment
        || observer_work.is_some() != requirements.observation_attempt_zero
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

pub(super) fn validate_completed_participant_presence(
    requirements: AdmissionParticipantRequirements,
    completed: &AdmissionCompletedProjection,
) -> Result<(), AdmissionOperationError> {
    let obligation_required = if requirements.channel {
        completed
            .channel_terminal
            .as_ref()
            .is_some_and(|channel| channel.actual_charge().units > 0)
    } else {
        requirements.obligation
    };
    if completed.payment_evidence.is_some() != requirements.payment
        || completed.authorization.is_some() != requirements.authorization_consumption
        || completed.eligibility.is_some() != requirements.outcome_eligibility
        || completed.observer_work.is_some() != requirements.observation_attempt_zero
        || completed.channel_terminal.is_some() != requirements.channel
        || completed.obligation.is_some() != obligation_required
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdmissionReceiptOrIncident {
    Receipt(Box<VerifiedAdmissionReceipt>),
    Incident(Box<AdmissionIncident>),
}

/// Why a delivery was denied after the output was produced. Closed and
/// extended additively by later milestones (for example a finding
/// media-type or operator-policy denial), so downstream evidence can key
/// on the reason without re-deriving it from prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryDenialReason {
    /// The final post-transform output hash did not equal the grant's
    /// committed output digest.
    DigestMismatch,
    /// The delivered value was not the strict two-field reveal envelope a
    /// purchased delivery commits to.
    EnvelopeMalformed,
    /// The reveal envelope advertised a different media type than the
    /// signed finding.
    MediaTypeMismatch,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "terminal", rename_all = "snake_case")]
pub enum AdmissionTerminalProjection {
    Completed(Box<AdmissionCompletedProjection>),
    CompensatedBeforeDispatch {
        context: AdmissionProjectionContext,
        proof: Box<VerifiedPreDispatchNoEffect>,
        evidence: Box<AdmissionReceiptOrIncident>,
    },
    NotAcceptedAfterDispatchCommit {
        context: AdmissionProjectionContext,
        proof: Box<VerifiedTransportNotAccepted>,
        evidence: Box<AdmissionReceiptOrIncident>,
    },
    DeniedAfterDelivery {
        context: AdmissionProjectionContext,
        reason: DeliveryDenialReason,
        evidence: Box<AdmissionReceiptOrIncident>,
        payment_evidence: Option<Box<PaymentTerminalEvidence>>,
        observer_work: Option<Box<ObservationAttemptZero>>,
    },
    OutcomeUnknownAfterDispatch {
        context: AdmissionProjectionContext,
        incident: Box<AdmissionIncident>,
    },
    EconomicMutationApplied {
        context: AdmissionProjectionContext,
        result: Box<VerifiedEconomicMutationApplied>,
        audit_event: Box<GovernedMutationAuditEvent>,
    },
    EconomicMutationNotApplied {
        context: AdmissionProjectionContext,
        result: Box<VerifiedEconomicMutationNotApplied>,
        audit_event: Box<GovernedMutationAuditEvent>,
    },
}

impl AdmissionReceiptOrIncident {
    fn replay(
        &self,
        projection_digest: &AdmissionDigest,
    ) -> Result<AdmissionTerminalReplay, AdmissionOperationError> {
        match self {
            Self::Receipt(receipt) => Ok(AdmissionTerminalReplay::Receipt {
                receipt_id: AdmissionIdentifier::try_new(
                    "receipt_id",
                    receipt.receipt().id.clone(),
                )?,
                projection_digest: projection_digest.clone(),
            }),
            Self::Incident(incident) => Ok(AdmissionTerminalReplay::Incident {
                incident_id: incident.record_id.clone(),
                projection_digest: projection_digest.clone(),
            }),
        }
    }

    fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        projected_state: AdmissionOperationState,
        compensation_status: AdmissionCompensationStatus,
    ) -> Result<(), AdmissionOperationError> {
        match self {
            Self::Receipt(receipt) => receipt.validate_against(
                operation,
                context,
                projected_state,
                compensation_status,
                None,
            ),
            Self::Incident(incident) => {
                incident.validate_against(operation, context, projected_state)
            }
        }
    }
}

pub(super) fn validate_receipt_projection(
    receipt: &ChioReceipt,
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projected_state: AdmissionOperationState,
    compensation_status: AdmissionCompensationStatus,
    tool_outcome: Option<(&AdmissionDigest, u64)>,
) -> Result<(), AdmissionOperationError> {
    let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
    validate_projection_context(operation, context, projected_state)?;
    if projected_state == AdmissionOperationState::Completed {
        let tool_outcome_required = operation.binding.kind == AdmissionOperationKind::ToolDispatch;
        if tool_outcome.is_some() != tool_outcome_required {
            return Err(mismatch());
        }
        if let Some((outcome_id, outcome_version)) = tool_outcome {
            validate_positive_ijson("receipt_tool_outcome_version", outcome_version)?;
            operation.validate_completed_tool_outcome_attachment(outcome_id)?;
        }
    } else if tool_outcome.is_some() {
        return Err(mismatch());
    }
    let expected_tenant = (operation.binding.authenticated_tenant_id.as_str()
        != LOCAL_SYSTEM_TENANT_ID)
        .then_some(operation.binding.authenticated_tenant_id.as_str());
    if receipt.timestamp != context.trusted_time_unix_ms / 1_000
        || receipt.capability_id != operation.binding.capability_id.as_str()
        || receipt.policy_hash != operation.binding.policy_hash.as_str()
        || receipt.tenant_id.as_deref() != expected_tenant
        || !receipt.verify_signature().map_err(|_| mismatch())?
    {
        return Err(mismatch());
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(ADMISSION_RECEIPT_METADATA_KEY))
        .cloned()
        .ok_or_else(mismatch)
        .and_then(|value| {
            serde_json::from_value::<AdmissionReceiptMetadataV1>(value).map_err(|_| mismatch())
        })?;
    let projected_operation_version = next_version(operation.version)?;
    let projected_dispatch_state = dispatch_state_for(operation.binding.kind, projected_state)?;
    let (tool_outcome_id, tool_outcome_version) = tool_outcome
        .map(|(id, version)| (Some(id), Some(version)))
        .unwrap_or((None, None));
    if metadata.schema != AdmissionReceiptSchema::V1
        || metadata.operation_id != operation.binding.operation_id
        || metadata.request_id != operation.binding.request_id
        || metadata.request_namespace_digest != operation.binding.request_namespace_digest
        || metadata.request_binding_hash != *operation.binding.request_binding_hash()
        || metadata.projected_operation_version != projected_operation_version
        || metadata.projected_state != projected_state
        || metadata.projected_dispatch_state != projected_dispatch_state
        || metadata.trusted_time_unix_ms != context.trusted_time_unix_ms
        || metadata.coordinator_lease_id != context.coordinator_lease_id
        || metadata.coordinator_lease_epoch != context.coordinator_lease_epoch
        || metadata.store_fence != context.store_fence
        || metadata.retained_dispatch_commit != operation.dispatch_commit
        || metadata.compensation_status != compensation_status
        || metadata.tool_outcome_id.as_ref() != tool_outcome_id
        || metadata.tool_outcome_version != tool_outcome_version
    {
        return Err(mismatch());
    }
    Ok(())
}

impl AdmissionTerminalProjection {
    #[must_use]
    pub fn context(&self) -> &AdmissionProjectionContext {
        match self {
            Self::Completed(projection) => &projection.context,
            Self::CompensatedBeforeDispatch { context, .. }
            | Self::NotAcceptedAfterDispatchCommit { context, .. }
            | Self::DeniedAfterDelivery { context, .. }
            | Self::OutcomeUnknownAfterDispatch { context, .. }
            | Self::EconomicMutationApplied { context, .. }
            | Self::EconomicMutationNotApplied { context, .. } => context,
        }
    }

    #[must_use]
    pub fn pre_dispatch_release_proof(&self) -> Option<&VerifiedPreDispatchNoEffect> {
        match self {
            Self::CompensatedBeforeDispatch { proof, .. } => Some(proof),
            _ => None,
        }
    }

    #[must_use]
    pub fn requires_anchored_economic_commit(&self) -> bool {
        matches!(
            self,
            Self::Completed(projection) if projection.channel_terminal.is_some()
        ) || matches!(
            self,
            Self::NotAcceptedAfterDispatchCommit { proof, .. }
                if proof.uses_economic_effect_cancellation()
        ) || matches!(
            self,
            Self::EconomicMutationApplied { result, .. } if result.0.anchored_effect
        ) || matches!(
            self,
            Self::EconomicMutationNotApplied { result, .. } if result.0.anchored_effect
        )
    }

    pub fn canonical_projection(
        &self,
    ) -> Result<CanonicalAdmissionTerminalProjection, AdmissionOperationError> {
        let projection_bytes = canonical_json_bytes(self)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
        let projection_body_digest = AdmissionDigest::try_new(
            "terminal_projection_body_digest",
            sha256_hex(&projection_bytes),
        )?;
        let mut records = self.canonical_records()?;
        records.sort_by(|left, right| {
            let left = (
                left.commitment.kind.as_str(),
                left.commitment.record_id.as_str(),
            );
            let right = (
                right.commitment.kind.as_str(),
                right.commitment.record_id.as_str(),
            );
            left.cmp(&right)
        });
        let manifest = AdmissionProjectionManifestV1 {
            schema: AdmissionProjectionManifestSchema::V1,
            projection_body_digest,
            records: records
                .iter()
                .map(|record| record.commitment.clone())
                .collect(),
        };
        let manifest_bytes = manifest.canonical_bytes()?;
        let projection_digest =
            AdmissionDigest::try_new("terminal_projection_digest", sha256_hex(&manifest_bytes))?;
        Ok(CanonicalAdmissionTerminalProjection {
            projection_bytes,
            manifest,
            manifest_bytes,
            projection_digest,
            records,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdmissionOperationError> {
        self.canonical_projection()
            .map(|projection| projection.projection_bytes)
    }

    pub fn projection_digest(&self) -> Result<AdmissionDigest, AdmissionOperationError> {
        self.canonical_projection()
            .map(|projection| projection.projection_digest)
    }

    fn canonical_records(
        &self,
    ) -> Result<Vec<CanonicalAdmissionProjectionRecord>, AdmissionOperationError> {
        let mut records = Vec::new();
        match self {
            Self::Completed(completed) => {
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::Receipt,
                    AdmissionIdentifier::try_new(
                        "projection_receipt_id",
                        completed.receipt.receipt().id.clone(),
                    )?,
                    completed.receipt.receipt(),
                )?);
                if let Some(outcome) = &completed.tool_outcome {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::ToolOutcome,
                        AdmissionIdentifier::try_new(
                            "projection_tool_outcome_id",
                            outcome.outcome_id().as_str().to_owned(),
                        )?,
                        outcome,
                    )?);
                }
                let operation_record_id = || {
                    AdmissionIdentifier::try_new(
                        "projection_operation_record_id",
                        completed.context.operation_id.as_str().to_owned(),
                    )
                };
                if let Some(payment) = &completed.payment_evidence {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::PaymentTerminal,
                        operation_record_id()?,
                        payment,
                    )?);
                }
                if let Some(authorization) = &completed.authorization {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::AuthorizationConsumption,
                        AdmissionIdentifier::try_new(
                            "projection_authorization_receipt_id",
                            authorization.consumption().authorization_receipt_id.clone(),
                        )?,
                        authorization.consumption(),
                    )?);
                }
                if let Some(eligibility) = &completed.eligibility {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::OutcomeEligibility,
                        operation_record_id()?,
                        eligibility,
                    )?);
                }
                if let Some(observer) = &completed.observer_work {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::ObservationAttemptZero,
                        AdmissionIdentifier::try_new(
                            "projection_observer_receipt_id",
                            completed.receipt.receipt().id.clone(),
                        )?,
                        observer.pending(),
                    )?);
                }
                if let Some(obligation) = &completed.obligation {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::Obligation,
                        operation_record_id()?,
                        obligation,
                    )?);
                }
                if let Some(channel) = &completed.channel_terminal {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::ChannelTerminal,
                        channel.record_id().clone(),
                        channel,
                    )?);
                }
            }
            Self::CompensatedBeforeDispatch {
                context,
                proof,
                evidence,
            } => {
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::ReleaseProof,
                    AdmissionIdentifier::try_new(
                        "projection_release_proof_id",
                        context.operation_id.as_str().to_owned(),
                    )?,
                    proof,
                )?);
                records.push(canonical_receipt_or_incident_record(evidence)?);
            }
            Self::NotAcceptedAfterDispatchCommit {
                context,
                proof,
                evidence,
            } => {
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::ReleaseProof,
                    AdmissionIdentifier::try_new(
                        "projection_release_proof_id",
                        context.operation_id.as_str().to_owned(),
                    )?,
                    proof,
                )?);
                records.push(canonical_receipt_or_incident_record(evidence)?);
            }
            Self::DeniedAfterDelivery {
                context,
                evidence,
                payment_evidence,
                observer_work,
                ..
            } => {
                let AdmissionReceiptOrIncident::Receipt(receipt) = evidence.as_ref() else {
                    return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
                };
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::Receipt,
                    AdmissionIdentifier::try_new(
                        "projection_receipt_id",
                        receipt.receipt().id.clone(),
                    )?,
                    receipt.receipt(),
                )?);
                if let Some(payment) = payment_evidence {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::PaymentTerminal,
                        AdmissionIdentifier::try_new(
                            "projection_operation_record_id",
                            context.operation_id.as_str().to_owned(),
                        )?,
                        payment,
                    )?);
                }
                if let Some(observer) = observer_work {
                    records.push(canonical_projection_record(
                        AdmissionProjectionRecordKind::ObservationAttemptZero,
                        AdmissionIdentifier::try_new(
                            "projection_observer_receipt_id",
                            receipt.receipt().id.clone(),
                        )?,
                        observer.pending(),
                    )?);
                }
            }
            Self::OutcomeUnknownAfterDispatch { incident, .. } => {
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::Incident,
                    incident.record_id.clone(),
                    incident,
                )?);
            }
            Self::EconomicMutationApplied {
                result,
                audit_event,
                ..
            } => {
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::EconomicMutationResult,
                    result.0.record_id.clone(),
                    result,
                )?);
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::MutationAudit,
                    audit_event.record_id.clone(),
                    audit_event,
                )?);
            }
            Self::EconomicMutationNotApplied {
                result,
                audit_event,
                ..
            } => {
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::EconomicMutationResult,
                    result.0.record_id.clone(),
                    result,
                )?);
                records.push(canonical_projection_record(
                    AdmissionProjectionRecordKind::MutationAudit,
                    audit_event.record_id.clone(),
                    audit_event,
                )?);
            }
        }
        Ok(records)
    }
}

fn canonical_receipt_or_incident_record(
    evidence: &AdmissionReceiptOrIncident,
) -> Result<CanonicalAdmissionProjectionRecord, AdmissionOperationError> {
    match evidence {
        AdmissionReceiptOrIncident::Receipt(receipt) => canonical_projection_record(
            AdmissionProjectionRecordKind::Receipt,
            AdmissionIdentifier::try_new("projection_receipt_id", receipt.receipt().id.clone())?,
            receipt.receipt(),
        ),
        AdmissionReceiptOrIncident::Incident(incident) => canonical_projection_record(
            AdmissionProjectionRecordKind::Incident,
            incident.record_id.clone(),
            incident,
        ),
    }
}

fn canonical_projection_record<T: Serialize>(
    kind: AdmissionProjectionRecordKind,
    record_id: AdmissionIdentifier,
    value: &T,
) -> Result<CanonicalAdmissionProjectionRecord, AdmissionOperationError> {
    let canonical_bytes = canonical_json_bytes(value)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let record_digest =
        AdmissionDigest::try_new("projection_record_digest", sha256_hex(&canonical_bytes))?;
    Ok(CanonicalAdmissionProjectionRecord {
        commitment: AdmissionProjectionRecordCommitmentV1 {
            kind,
            record_id,
            record_digest,
        },
        canonical_bytes,
    })
}

impl AdmissionOperationV1 {
    pub(super) fn validate_completed_tool_outcome_attachment(
        &self,
        outcome_id: &AdmissionDigest,
    ) -> Result<(), AdmissionOperationError> {
        if self.binding.kind != AdmissionOperationKind::ToolDispatch
            || self
                .attachments
                .tool_outcome_id()
                .is_none_or(|attached| attached.as_str() != outcome_id.as_str())
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }

    pub fn apply_terminal_projection(
        &self,
        projection: &AdmissionTerminalProjection,
        capabilities: &AdmissionProjectionCapabilities,
    ) -> Result<Self, AdmissionOperationError> {
        self.validate()?;
        capabilities.validate_for(self, projection)?;
        let context = projection.context();
        let projection_digest = projection.projection_digest()?;
        context.validate()?;
        if context.operation_id != self.binding.operation_id
            || context.request_id != self.binding.request_id
            || context.expected_operation_version != self.version
            || context.coordinator_lease_epoch != self.coordinator_lease_epoch
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        let requirements = self.binding.participant_requirements();
        let (next_state, replay) = match projection {
            AdmissionTerminalProjection::Completed(completed) => {
                let tool_outcome_required =
                    self.binding.kind == AdmissionOperationKind::ToolDispatch;
                if completed.tool_outcome.is_some() != tool_outcome_required {
                    return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
                }
                validate_completed_participant_presence(requirements, completed)?;
                if let Some(tool_outcome) = &completed.tool_outcome {
                    tool_outcome
                        .validate_against(self, context)
                        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    self.validate_completed_tool_outcome_attachment(tool_outcome.outcome_id())?;
                }
                let outcome = completed
                    .tool_outcome
                    .as_ref()
                    .map(|value| (value.outcome_id(), value.outcome_version()));
                if let Some(payment) = &completed.payment_evidence {
                    let (outcome_id, outcome_version) = outcome
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    payment.validate_against(
                        self,
                        context,
                        &completed.receipt,
                        outcome_id,
                        outcome_version,
                        AdmissionOperationState::Completed,
                    )?;
                }
                if let Some(eligibility) = &completed.eligibility {
                    let (outcome_id, outcome_version) = outcome
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    eligibility.validate_against(
                        self,
                        context,
                        &completed.receipt,
                        outcome_id,
                        outcome_version,
                        AdmissionOperationState::Completed,
                    )?;
                }
                if let Some(obligation) = &completed.obligation {
                    let (outcome_id, outcome_version) = outcome
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    obligation.validate_against(
                        self,
                        context,
                        &completed.receipt,
                        outcome_id,
                        outcome_version,
                    )?;
                }
                if let Some(authorization) = &completed.authorization {
                    let (outcome_id, outcome_version) = outcome
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    authorization.validate_against(
                        self,
                        context,
                        &completed.receipt,
                        outcome_id,
                        outcome_version,
                    )?;
                }
                if let Some(observer_work) = &completed.observer_work {
                    let (outcome_id, outcome_version) = outcome
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    observer_work.validate_against(
                        self,
                        context,
                        &completed.receipt,
                        outcome_id,
                        outcome_version,
                        AdmissionOperationState::Completed,
                    )?;
                }
                if let Some(channel) = &completed.channel_terminal {
                    let tool_outcome = completed
                        .tool_outcome
                        .as_ref()
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    channel.validate_against(
                        self,
                        context,
                        &completed.receipt,
                        tool_outcome,
                        completed.obligation.as_ref(),
                    )?;
                }
                completed.receipt.validate_against(
                    self,
                    context,
                    AdmissionOperationState::Completed,
                    AdmissionCompensationStatus::NotCompensated,
                    completed
                        .tool_outcome
                        .as_ref()
                        .map(|outcome| (outcome.outcome_id(), outcome.outcome_version())),
                )?;
                (
                    AdmissionOperationState::Completed,
                    AdmissionTerminalReplay::Receipt {
                        receipt_id: AdmissionIdentifier::try_new(
                            "receipt_id",
                            completed.receipt.receipt().id.clone(),
                        )?,
                        projection_digest: projection_digest.clone(),
                    },
                )
            }
            AdmissionTerminalProjection::CompensatedBeforeDispatch {
                proof, evidence, ..
            } => {
                proof
                    .validate_against(self, context)
                    .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                evidence.validate_against(
                    self,
                    context,
                    AdmissionOperationState::CompensatedBeforeDispatch,
                    AdmissionCompensationStatus::CompensatedBeforeDispatch,
                )?;
                (
                    AdmissionOperationState::CompensatedBeforeDispatch,
                    evidence.replay(&projection_digest)?,
                )
            }
            AdmissionTerminalProjection::DeniedAfterDelivery {
                evidence,
                payment_evidence,
                observer_work,
                ..
            } => {
                // The delivered output was produced but rejected, so the
                // hold was released rather than compensated: nothing was
                // captured to compensate. The participant records bind the
                // released journal and the observation of that release to
                // this exact terminal and to the retained tool outcome.

                validate_denied_after_delivery_participant_presence(
                    requirements,
                    payment_evidence.as_deref(),
                    observer_work.as_deref(),
                )?;
                let AdmissionReceiptOrIncident::Receipt(receipt) = evidence.as_ref() else {
                    return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
                };
                evidence.validate_against(
                    self,
                    context,
                    AdmissionOperationState::DeniedAfterDelivery,
                    AdmissionCompensationStatus::NotCompensated,
                )?;
                if payment_evidence.is_some() || observer_work.is_some() {
                    let outcome_id = self
                        .tool_outcome_id()
                        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                    if let (Some(payment), Some(observer)) = (payment_evidence, observer_work) {
                        if payment.outcome_version() != observer.outcome_version() {
                            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
                        }
                    }
                    if let Some(payment) = payment_evidence {
                        payment.validate_against(
                            self,
                            context,
                            receipt,
                            outcome_id,
                            payment.outcome_version(),
                            AdmissionOperationState::DeniedAfterDelivery,
                        )?;
                    }
                    if let Some(observer) = observer_work {
                        observer.validate_against(
                            self,
                            context,
                            receipt,
                            outcome_id,
                            observer.outcome_version(),
                            AdmissionOperationState::DeniedAfterDelivery,
                        )?;
                    }
                }
                (
                    AdmissionOperationState::DeniedAfterDelivery,
                    evidence.replay(&projection_digest)?,
                )
            }
            AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit {
                proof, evidence, ..
            } => {
                proof
                    .validate_against(self, context)
                    .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
                evidence.validate_against(
                    self,
                    context,
                    AdmissionOperationState::NotAcceptedAfterDispatchCommit,
                    AdmissionCompensationStatus::NotAcceptedAfterDispatchCommit,
                )?;
                (
                    AdmissionOperationState::NotAcceptedAfterDispatchCommit,
                    evidence.replay(&projection_digest)?,
                )
            }
            AdmissionTerminalProjection::OutcomeUnknownAfterDispatch { incident, .. } => {
                incident.validate_against(
                    self,
                    context,
                    AdmissionOperationState::OutcomeUnknownAfterDispatch,
                )?;
                (
                    AdmissionOperationState::OutcomeUnknownAfterDispatch,
                    AdmissionTerminalReplay::Incident {
                        incident_id: incident.record_id.clone(),
                        projection_digest: projection_digest.clone(),
                    },
                )
            }
            AdmissionTerminalProjection::EconomicMutationApplied {
                result,
                audit_event,
                ..
            } => {
                result.validate_against(self, context)?;
                audit_event.validate_against(
                    self,
                    context,
                    AdmissionOperationState::EconomicMutationApplied,
                )?;
                (
                    AdmissionOperationState::EconomicMutationApplied,
                    AdmissionTerminalReplay::EconomicMutation {
                        result_id: result.0.record_id.clone(),
                        result_digest: result.0.record_digest.clone(),
                        projection_digest: projection_digest.clone(),
                    },
                )
            }
            AdmissionTerminalProjection::EconomicMutationNotApplied {
                result,
                audit_event,
                ..
            } => {
                result.validate_against(self, context)?;
                audit_event.validate_against(
                    self,
                    context,
                    AdmissionOperationState::EconomicMutationNotApplied,
                )?;
                (
                    AdmissionOperationState::EconomicMutationNotApplied,
                    AdmissionTerminalReplay::EconomicMutation {
                        result_id: result.0.record_id.clone(),
                        result_digest: result.0.record_digest.clone(),
                        projection_digest,
                    },
                )
            }
        };
        if let Some(commit) = &self.dispatch_commit {
            if !projection_fence_follows(&commit.store_fence, &context.store_fence) {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
            }
        }
        if !is_legal_transition(self.binding.kind, requirements, self.state, next_state) {
            return Err(AdmissionOperationError::IllegalTransition {
                from: self.state,
                to: next_state,
            });
        }
        validate_terminal_replay(self.binding.kind, next_state, Some(&replay))?;
        let mut updated = self.clone();
        updated.state = next_state;
        updated.dispatch_state = dispatch_state_for(self.binding.kind, next_state)?;
        updated.terminal_replay = Some(replay);
        updated.version = next_version(self.version)?;
        updated.validate()?;
        Ok(updated)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionTerminal {
    pub operation_id: AdmissionOperationId,
    pub state: AdmissionOperationState,
    pub replay: AdmissionTerminalReplay,
}
pub(super) fn validate_terminal_replay(
    kind: AdmissionOperationKind,
    state: AdmissionOperationState,
    terminal_replay: Option<&AdmissionTerminalReplay>,
) -> Result<(), AdmissionOperationError> {
    let valid = match (kind, state, terminal_replay) {
        (_, state, None) if !state.is_terminal() => true,
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::Completed,
            Some(AdmissionTerminalReplay::Receipt { .. }),
        ) => true,
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::CompensatedBeforeDispatch
            | AdmissionOperationState::NotAcceptedAfterDispatchCommit,
            Some(
                AdmissionTerminalReplay::Receipt { .. } | AdmissionTerminalReplay::Incident { .. },
            ),
        ) => true,
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            Some(AdmissionTerminalReplay::Incident { .. }),
        ) => true,
        (
            AdmissionOperationKind::ToolDispatch | AdmissionOperationKind::GovernedActiveResponse,
            AdmissionOperationState::DeniedAfterDelivery,
            Some(AdmissionTerminalReplay::Receipt { .. }),
        ) => true,
        (
            AdmissionOperationKind::GovernedEconomicMutation,
            AdmissionOperationState::EconomicMutationApplied
            | AdmissionOperationState::EconomicMutationNotApplied,
            Some(AdmissionTerminalReplay::EconomicMutation { .. }),
        ) => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AdmissionOperationError::TerminalReplayMismatch)
    }
}

#[cfg(test)]
#[path = "projection/channel_terminal_tests.rs"]
mod channel_terminal_projection_tests;

#[cfg(test)]
#[path = "projection/factor_assignment_tests.rs"]
mod factor_assignment_projection_tests;
