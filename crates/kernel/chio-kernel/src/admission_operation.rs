use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
pub use chio_core_types::provider_attempt::ProviderAttemptBindingV1;
pub use chio_core_types::StoreMutationFence;
use serde::{Deserialize, Deserializer, Serialize};

mod capture;
mod identity;
mod projection;
mod remote_projection;
mod sequencer;
mod state;
mod store;

use state::*;

pub use capture::*;
pub use identity::*;
pub use projection::*;
pub use remote_projection::*;
pub use sequencer::*;
pub use store::*;

pub const ADMISSION_OPERATION_SCHEMA: &str = "chio.admission-operation.v1";
pub const ADMISSION_OPERATION_DOMAIN: &[u8] = b"chio.admission-operation.v1\0";
pub const ADMISSION_REQUEST_NAMESPACE_SCHEMA: &str = "chio.admission-request-namespace.v1";
pub const ADMISSION_REQUEST_NAMESPACE_DOMAIN: &[u8] = b"chio.admission-request-namespace.v1\0";
pub const ADMISSION_REQUEST_BINDING_DOMAIN: &[u8] = b"chio.admission-request-binding.v1\0";
pub const ADMISSION_RECEIPT_METADATA_KEY: &str = "admission_operation";
pub const ADMISSION_RECEIPT_SCHEMA: &str = "chio.admission-receipt.v1";
pub const MAX_ADMISSION_IDENTIFIER_BYTES: usize = 512;
pub const MAX_ADMISSION_TENANT_BYTES: usize = 256;
pub const MAX_ADMISSION_ERROR_BYTES: usize = 2_048;
pub const MAX_AUTHORIZATION_ARTIFACT_DIGESTS: usize = 8;
pub const LOCAL_SYSTEM_TENANT_ID: &str = "local-system";
pub(super) const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

pub type AdmissionIdentifier = BoundedAdmissionText<MAX_ADMISSION_IDENTIFIER_BYTES>;
pub type AdmissionErrorDetail = BoundedAdmissionText<MAX_ADMISSION_ERROR_BYTES>;

pub fn expected_dispatch_committed_version(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    prepared_version: u64,
) -> Result<u64, AdmissionOperationError> {
    requirements.validate_for_kind(kind)?;
    state::dispatch_committed_version_from_prepared(kind, requirements, prepared_version)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionOperationError {
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its {maximum}-byte limit")]
    TooLong { field: &'static str, maximum: usize },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} must not have leading or trailing whitespace")]
    Padded { field: &'static str },
    #[error("{field} must be lowercase SHA-256 hex")]
    InvalidDigest { field: &'static str },
    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),
    #[error("operation version and coordinator lease epoch must be nonzero")]
    ZeroVersionOrEpoch,
    #[error("{field} must be an I-JSON safe positive integer")]
    UnsafeInteger { field: &'static str },
    #[error("operation version overflow")]
    VersionOverflow,
    #[error(
        "durable admission may be disabled only for unsafe development with ephemeral receipts"
    )]
    UnsafeDurableAdmissionOff,
    #[error("operation id does not match its immutable binding")]
    OperationIdMismatch,
    #[error("request namespace digest does not match its authenticated tenant binding")]
    RequestNamespaceMismatch,
    #[error("authenticated tenant id is reserved for the local-system namespace")]
    ReservedLocalSystemTenant,
    #[error("state {state:?} is invalid for operation kind {kind:?}")]
    StateKindMismatch {
        kind: AdmissionOperationKind,
        state: AdmissionOperationState,
    },
    #[error("stored dispatch state does not match operation state")]
    DispatchStateMismatch,
    #[error("terminal replay reference does not match operation state")]
    TerminalReplayMismatch,
    #[error("command targets a different operation")]
    WrongOperation,
    #[error("recovery lease was not issued for this command version")]
    LeaseVersionMismatch,
    #[error("recovery lease is fenced by coordinator epoch")]
    CoordinatorFenced,
    #[error("recovery lease expired")]
    LeaseExpired,
    #[error("store mutation fence is invalid")]
    InvalidStoreFence,
    #[error("stale operation version: expected {expected}, actual {actual}")]
    StaleVersion { expected: u64, actual: u64 },
    #[error("illegal operation transition from {from:?} to {to:?}")]
    IllegalTransition {
        from: AdmissionOperationState,
        to: AdmissionOperationState,
    },
    #[error("attachment {field} is already bound to a different value")]
    AttachmentConflict { field: &'static str },
    #[error("attachment {field} is not legal in state {state:?}")]
    AttachmentPhase {
        field: &'static str,
        state: AdmissionOperationState,
    },
    #[error("attachment {field} is not allowed by the immutable operation binding")]
    ForbiddenAttachment { field: &'static str },
    #[error("stored threshold proposal does not match its bound digest")]
    ThresholdProposalMismatch,
    #[error("provider attempt does not match the immutable admission operation")]
    ProviderAttemptBindingMismatch,
    #[error("authorization artifact digests must be bounded, sorted, and unique")]
    InvalidAuthorizationArtifactDigests,
    #[error("capture decision does not match its record disposition")]
    CaptureDispositionMismatch,
    #[error("combined capture requires the exact CapturePending operation snapshot")]
    CapturePreconditionMismatch,
    #[error("combined capture participant binding does not match the operation")]
    CaptureBindingMismatch,
    #[error("combined capture authority does not match its fenced store")]
    CaptureAuthorityMismatch,
    #[error("combined capture global authority commit is invalid")]
    CaptureCommitMismatch,
    #[error("combined capture response digest is invalid")]
    CaptureResponseDigestMismatch,
    #[error("combined capture quota mutation is invalid")]
    CaptureQuotaMismatch,
    #[error("combined capture authorization expiry disposition is invalid")]
    CaptureExpiryMismatch,
    #[error("combined capture authority time is ahead of its qualified clock")]
    CaptureAuthorityTimeMismatch,
    #[error("admission operation command contains no mutation")]
    EmptyCommand,
    #[error("admission operation command attaches {field} more than once")]
    DuplicateAttachment { field: &'static str },
    #[error("verified economic mutation result binding is invalid")]
    InvalidEconomicMutationBinding,
    #[error("state transition requires attachment {field}")]
    MissingParticipantAttachment { field: &'static str },
    #[error("admission participant requirements are inconsistent")]
    InvalidParticipantRequirements,
    #[error("request binding hash does not cover its immutable request and requirements")]
    RequestBindingMismatch,
    #[error("terminal operation states require the atomic receipt-side projection")]
    TerminalProjectionRequired,
    #[error("terminal projection does not match the operation binding")]
    TerminalProjectionBindingMismatch,
    #[error("terminal projection store lacks required capability {capability}")]
    MissingProjectionCapability { capability: &'static str },
    #[error("durable admission mutation sequencer is poisoned")]
    MutationSequencerPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionOperationState {
    Prepared,
    BrokerAttemptRegistered,
    ApprovalRequired,
    BudgetAuthorized,
    ApprovalReserved,
    ReadyToDispatch,
    CapturePending,
    DispatchCommitted,
    Finalizing,
    Completed,
    CompensatedBeforeDispatch,
    NotAcceptedAfterDispatchCommit,
    OutcomeUnknownAfterDispatch,
    /// The delivered output did not match a grant's committed output
    /// digest. A signed Deny is persisted; the open hold is released and
    /// zero is captured.
    DeniedAfterDelivery,
    MutationReady,
    MutationSubmitted,
    EconomicMutationApplied,
    EconomicMutationNotApplied,
}

impl AdmissionOperationState {
    pub const ALL: [Self; 18] = [
        Self::Prepared,
        Self::BrokerAttemptRegistered,
        Self::ApprovalRequired,
        Self::BudgetAuthorized,
        Self::ApprovalReserved,
        Self::ReadyToDispatch,
        Self::CapturePending,
        Self::DispatchCommitted,
        Self::Finalizing,
        Self::Completed,
        Self::CompensatedBeforeDispatch,
        Self::NotAcceptedAfterDispatchCommit,
        Self::OutcomeUnknownAfterDispatch,
        Self::DeniedAfterDelivery,
        Self::MutationReady,
        Self::MutationSubmitted,
        Self::EconomicMutationApplied,
        Self::EconomicMutationNotApplied,
    ];

    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::CompensatedBeforeDispatch
                | Self::NotAcceptedAfterDispatchCommit
                | Self::OutcomeUnknownAfterDispatch
                | Self::DeniedAfterDelivery
                | Self::EconomicMutationApplied
                | Self::EconomicMutationNotApplied
        )
    }

    fn is_pre_dispatch(self) -> bool {
        matches!(
            self,
            Self::Prepared
                | Self::BrokerAttemptRegistered
                | Self::ApprovalRequired
                | Self::BudgetAuthorized
                | Self::ApprovalReserved
                | Self::ReadyToDispatch
                | Self::CapturePending
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDispatchState {
    NotCommitted,
    CapturePending,
    Committed,
    Finalizing,
    Terminal,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionDispatchCommitBindingV1 {
    pub committed_version: u64,
    pub coordinator_lease_id: AdmissionIdentifier,
    pub coordinator_lease_epoch: u64,
    pub store_fence: StoreMutationFence,
    pub provider_attempt: Option<ProviderAttemptBindingV1>,
}

impl<'de> Deserialize<'de> for AdmissionDispatchCommitBindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Persisted {
            committed_version: u64,
            coordinator_lease_id: AdmissionIdentifier,
            coordinator_lease_epoch: u64,
            store_fence: StoreMutationFence,
            provider_attempt: Option<ProviderAttemptBindingV1>,
        }
        let value = Persisted::deserialize(deserializer)?;
        let binding = Self {
            committed_version: value.committed_version,
            coordinator_lease_id: value.coordinator_lease_id,
            coordinator_lease_epoch: value.coordinator_lease_epoch,
            store_fence: value.store_fence,
            provider_attempt: value.provider_attempt,
        };
        binding.validate().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

impl AdmissionDispatchCommitBindingV1 {
    fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_positive_ijson("committed_version", self.committed_version)?;
        validate_positive_ijson("coordinator_lease_epoch", self.coordinator_lease_epoch)?;
        validate_store_fence(&self.store_fence)?;
        self.provider_attempt
            .as_ref()
            .map_or(Ok(()), ProviderAttemptBindingV1::validate)
            .map_err(|_| AdmissionOperationError::ProviderAttemptBindingMismatch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionAttachment {
    ThresholdProposalHash(AdmissionDigest),
    ThresholdProposal(Box<chio_core::capability::governance::ThresholdApprovalProposal>),
    SupplementalAuthorizationDigest(AdmissionDigest),
    BrokerAttempt(ProviderAttemptBindingV1),
    BudgetHoldId(AdmissionIdentifier),
    ApprovalSetHash(AdmissionDigest),
    ExecutionNonceId(AdmissionIdentifier),
    OutcomeEligibilityDigest(AdmissionDigest),
    PaymentParticipantId(AdmissionIdentifier),
    ToolOutcomeId(AdmissionDigest),
    ChannelReservationProposalDigest(AdmissionDigest),
    ChannelReservationDigest(AdmissionDigest),
    CreditExposureReservationDigest(AdmissionDigest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionAttachmentKind {
    ThresholdProposal,
    ThresholdProposalBody,
    SupplementalAuthorization,
    BrokerAttempt,
    BudgetHold,
    ApprovalSet,
    ExecutionNonce,
    OutcomeEligibility,
    PaymentParticipant,
    ToolOutcome,
    ChannelReservationProposal,
    ChannelReservation,
    CreditExposureReservation,
}

impl AdmissionAttachment {
    fn kind(&self) -> AdmissionAttachmentKind {
        match self {
            Self::ThresholdProposalHash(_) => AdmissionAttachmentKind::ThresholdProposal,
            Self::ThresholdProposal(_) => AdmissionAttachmentKind::ThresholdProposalBody,
            Self::SupplementalAuthorizationDigest(_) => {
                AdmissionAttachmentKind::SupplementalAuthorization
            }
            Self::BrokerAttempt(_) => AdmissionAttachmentKind::BrokerAttempt,
            Self::BudgetHoldId(_) => AdmissionAttachmentKind::BudgetHold,
            Self::ApprovalSetHash(_) => AdmissionAttachmentKind::ApprovalSet,
            Self::ExecutionNonceId(_) => AdmissionAttachmentKind::ExecutionNonce,
            Self::OutcomeEligibilityDigest(_) => AdmissionAttachmentKind::OutcomeEligibility,
            Self::PaymentParticipantId(_) => AdmissionAttachmentKind::PaymentParticipant,
            Self::ToolOutcomeId(_) => AdmissionAttachmentKind::ToolOutcome,
            Self::ChannelReservationProposalDigest(_) => {
                AdmissionAttachmentKind::ChannelReservationProposal
            }
            Self::ChannelReservationDigest(_) => AdmissionAttachmentKind::ChannelReservation,
            Self::CreditExposureReservationDigest(_) => {
                AdmissionAttachmentKind::CreditExposureReservation
            }
        }
    }

    fn slot(&self) -> u8 {
        self.kind().slot()
    }

    fn field_name(&self) -> &'static str {
        match self {
            Self::ThresholdProposalHash(_) => "threshold_proposal_hash",
            Self::ThresholdProposal(_) => "threshold_proposal",
            Self::SupplementalAuthorizationDigest(_) => "supplemental_authorization_digest",
            Self::BrokerAttempt(_) => "broker_attempt",
            Self::BudgetHoldId(_) => "budget_hold_id",
            Self::ApprovalSetHash(_) => "approval_set_hash",
            Self::ExecutionNonceId(_) => "execution_nonce_id",
            Self::OutcomeEligibilityDigest(_) => "outcome_eligibility_digest",
            Self::PaymentParticipantId(_) => "payment_participant_id",
            Self::ToolOutcomeId(_) => "tool_outcome_id",
            Self::ChannelReservationProposalDigest(_) => "channel_reservation_proposal_digest",
            Self::ChannelReservationDigest(_) => "channel_reservation_digest",
            Self::CreditExposureReservationDigest(_) => "credit_exposure_reservation_digest",
        }
    }
}

impl AdmissionAttachmentKind {
    fn slot(self) -> u8 {
        match self {
            Self::ThresholdProposal => 0,
            Self::SupplementalAuthorization => 1,
            Self::BrokerAttempt => 2,
            Self::BudgetHold => 3,
            Self::ApprovalSet => 4,
            Self::ExecutionNonce => 5,
            Self::OutcomeEligibility => 6,
            Self::PaymentParticipant => 7,
            Self::ToolOutcome => 8,
            Self::ChannelReservationProposal => 9,
            Self::ChannelReservation => 10,
            Self::CreditExposureReservation => 11,
            Self::ThresholdProposalBody => 12,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct AdmissionOperationAttachmentsV1(Vec<AdmissionAttachment>);

impl AdmissionOperationAttachmentsV1 {
    fn has_slot(&self, slot: u8) -> bool {
        self.0.iter().any(|attachment| attachment.slot() == slot)
    }

    fn existing_matches(&self, attachment: &AdmissionAttachment) -> Option<bool> {
        self.0
            .iter()
            .find(|existing| existing.slot() == attachment.slot())
            .map(|existing| existing == attachment)
    }

    fn tool_outcome_id(&self) -> Option<&AdmissionDigest> {
        self.0.iter().find_map(|attachment| match attachment {
            AdmissionAttachment::ToolOutcomeId(id) => Some(id),
            _ => None,
        })
    }

    fn attach(&mut self, attachment: AdmissionAttachment) {
        let index = self
            .0
            .partition_point(|existing| existing.slot() < attachment.slot());
        self.0.insert(index, attachment);
    }

    fn validate(&self) -> Result<(), AdmissionOperationError> {
        if self.0.len() > 13
            || self
                .0
                .windows(2)
                .any(|pair| pair[0].slot() >= pair[1].slot())
        {
            return Err(AdmissionOperationError::DuplicateAttachment {
                field: "persisted_attachment_set",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AdmissionOperationAttachmentsV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let attachments = Self(Vec::deserialize(deserializer)?);
        attachments.validate().map_err(serde::de::Error::custom)?;
        Ok(attachments)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionTerminalReplay {
    Receipt {
        receipt_id: AdmissionIdentifier,
        projection_digest: AdmissionDigest,
    },
    Incident {
        incident_id: AdmissionIdentifier,
        projection_digest: AdmissionDigest,
    },
    EconomicMutation {
        result_id: AdmissionIdentifier,
        result_digest: AdmissionDigest,
        projection_digest: AdmissionDigest,
    },
}

impl AdmissionTerminalReplay {
    #[must_use]
    pub const fn projection_digest(&self) -> &AdmissionDigest {
        match self {
            Self::Receipt {
                projection_digest, ..
            }
            | Self::Incident {
                projection_digest, ..
            }
            | Self::EconomicMutation {
                projection_digest, ..
            } => projection_digest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionOperationSchema {
    #[serde(rename = "chio.admission-operation.v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedAdmissionOperationV1 {
    pub schema: AdmissionOperationSchema,
    pub binding: PersistedAdmissionOperationBindingV1,
    pub attachments: AdmissionOperationAttachmentsV1,
    pub state: AdmissionOperationState,
    pub dispatch_state: AdmissionDispatchState,
    pub dispatch_commit: Option<AdmissionDispatchCommitBindingV1>,
    pub coordinator_lease_epoch: u64,
    pub version: u64,
    pub last_error: Option<AdmissionErrorDetail>,
    pub terminal_replay: Option<AdmissionTerminalReplay>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionOperationV1 {
    binding: AdmissionOperationBindingV1,
    attachments: AdmissionOperationAttachmentsV1,
    state: AdmissionOperationState,
    dispatch_state: AdmissionDispatchState,
    dispatch_commit: Option<AdmissionDispatchCommitBindingV1>,
    coordinator_lease_epoch: u64,
    version: u64,
    last_error: Option<AdmissionErrorDetail>,
    terminal_replay: Option<AdmissionTerminalReplay>,
}

impl AdmissionOperationV1 {
    pub fn prepare(
        binding: AdmissionOperationBindingV1,
        coordinator_lease_epoch: u64,
    ) -> Result<Self, AdmissionOperationError> {
        validate_positive_ijson("coordinator_lease_epoch", coordinator_lease_epoch)?;
        binding.validate()?;
        let dispatch_state = dispatch_state_for(binding.kind, AdmissionOperationState::Prepared)?;
        Ok(Self {
            binding,
            attachments: AdmissionOperationAttachmentsV1::default(),
            state: AdmissionOperationState::Prepared,
            dispatch_state,
            dispatch_commit: None,
            coordinator_lease_epoch,
            version: 1,
            last_error: None,
            terminal_replay: None,
        })
    }

    pub fn with_initial_channel_reservation_proposal_digest(
        mut self,
        proposal_digest: AdmissionDigest,
    ) -> Result<Self, AdmissionOperationError> {
        self.validate()?;
        if self.state != AdmissionOperationState::Prepared
            || self.version != 1
            || !self.binding.participant_requirements().channel
            || !self.attachments.0.is_empty()
        {
            return Err(AdmissionOperationError::ForbiddenAttachment {
                field: "channel_reservation_proposal_digest",
            });
        }
        self.attachments
            .0
            .push(AdmissionAttachment::ChannelReservationProposalDigest(
                proposal_digest,
            ));
        self.validate()?;
        Ok(self)
    }

    /// Decode and validate a persisted operation value.
    ///
    /// This checks the operation's internal invariants but does not authenticate
    /// its storage provenance. Authority-sensitive callers must obtain the value
    /// from a fenced [`AdmissionOperationStore`] operation.
    pub fn from_persisted(
        persisted: PersistedAdmissionOperationV1,
    ) -> Result<Self, AdmissionOperationError> {
        match persisted.schema {
            AdmissionOperationSchema::V1 => {}
        }
        let operation = Self {
            binding: AdmissionOperationBindingV1::from_persisted(persisted.binding)?,
            attachments: persisted.attachments,
            state: persisted.state,
            dispatch_state: persisted.dispatch_state,
            dispatch_commit: persisted.dispatch_commit,
            coordinator_lease_epoch: persisted.coordinator_lease_epoch,
            version: persisted.version,
            last_error: persisted.last_error,
            terminal_replay: persisted.terminal_replay,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_positive_ijson("operation_version", self.version)?;
        validate_positive_ijson("coordinator_lease_epoch", self.coordinator_lease_epoch)?;
        self.binding.validate()?;
        self.attachments.validate()?;
        if let Some(attempt) = self.provider_attempt() {
            attempt
                .validate()
                .map_err(|_| AdmissionOperationError::ProviderAttemptBindingMismatch)?;
            if attempt.operation_id != self.binding.operation_id.as_str() {
                return Err(AdmissionOperationError::ProviderAttemptBindingMismatch);
            }
        }
        validate_state_requirements(
            self.binding.kind,
            self.binding.participant_requirements(),
            self.state,
        )?;
        validate_state_attachments(
            self.binding.kind,
            self.binding.participant_requirements(),
            self.state,
            &self.attachments,
        )?;
        let expected_dispatch = dispatch_state_for(self.binding.kind, self.state)?;
        if expected_dispatch != self.dispatch_state {
            return Err(AdmissionOperationError::DispatchStateMismatch);
        }
        validate_dispatch_commit(self)?;
        validate_terminal_replay(self.binding.kind, self.state, self.terminal_replay.as_ref())
    }

    #[must_use]
    pub fn binding(&self) -> &AdmissionOperationBindingV1 {
        &self.binding
    }

    #[must_use]
    pub fn state(&self) -> AdmissionOperationState {
        self.state
    }

    #[must_use]
    pub fn dispatch_state(&self) -> AdmissionDispatchState {
        self.dispatch_state
    }

    #[must_use]
    pub fn dispatch_commit(&self) -> Option<&AdmissionDispatchCommitBindingV1> {
        self.dispatch_commit.as_ref()
    }

    #[must_use]
    pub fn coordinator_lease_epoch(&self) -> u64 {
        self.coordinator_lease_epoch
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn terminal_replay(&self) -> Option<&AdmissionTerminalReplay> {
        self.terminal_replay.as_ref()
    }

    #[must_use]
    pub fn tool_outcome_id(&self) -> Option<&AdmissionDigest> {
        self.attachments.tool_outcome_id()
    }

    #[must_use]
    pub fn supplemental_authorization_digest(&self) -> Option<&AdmissionDigest> {
        match self.attachment(AdmissionAttachmentKind::SupplementalAuthorization) {
            Some(AdmissionAttachment::SupplementalAuthorizationDigest(digest)) => Some(digest),
            _ => None,
        }
    }

    #[must_use]
    pub fn threshold_proposal_hash(&self) -> Option<&AdmissionDigest> {
        match self.attachment(AdmissionAttachmentKind::ThresholdProposal) {
            Some(AdmissionAttachment::ThresholdProposalHash(digest)) => Some(digest),
            _ => None,
        }
    }

    #[must_use]
    pub fn threshold_proposal(
        &self,
    ) -> Option<&chio_core::capability::governance::ThresholdApprovalProposal> {
        match self.attachment(AdmissionAttachmentKind::ThresholdProposalBody) {
            Some(AdmissionAttachment::ThresholdProposal(proposal)) => Some(proposal.as_ref()),
            _ => None,
        }
    }

    #[must_use]
    pub fn approval_set_hash(&self) -> Option<&AdmissionDigest> {
        match self.attachment(AdmissionAttachmentKind::ApprovalSet) {
            Some(AdmissionAttachment::ApprovalSetHash(digest)) => Some(digest),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn has_attachment(&self, kind: AdmissionAttachmentKind) -> bool {
        self.attachments.has_slot(kind.slot())
    }

    pub(crate) fn attachment(&self, kind: AdmissionAttachmentKind) -> Option<&AdmissionAttachment> {
        self.attachments
            .0
            .iter()
            .find(|attachment| attachment.kind() == kind)
    }

    pub(crate) fn provider_attempt(&self) -> Option<&ProviderAttemptBindingV1> {
        match self.attachment(AdmissionAttachmentKind::BrokerAttempt) {
            Some(AdmissionAttachment::BrokerAttempt(attempt)) => Some(attempt),
            _ => None,
        }
    }

    #[must_use]
    pub fn budget_hold_id(&self) -> Option<&AdmissionIdentifier> {
        match self.attachment(AdmissionAttachmentKind::BudgetHold) {
            Some(AdmissionAttachment::BudgetHoldId(hold_id)) => Some(hold_id),
            _ => None,
        }
    }

    #[must_use]
    pub fn channel_reservation_proposal_digest(&self) -> Option<&AdmissionDigest> {
        match self.attachment(AdmissionAttachmentKind::ChannelReservationProposal) {
            Some(AdmissionAttachment::ChannelReservationProposalDigest(digest)) => Some(digest),
            _ => None,
        }
    }

    #[must_use]
    pub fn channel_reservation_digest(&self) -> Option<&AdmissionDigest> {
        match self.attachment(AdmissionAttachmentKind::ChannelReservation) {
            Some(AdmissionAttachment::ChannelReservationDigest(digest)) => Some(digest),
            _ => None,
        }
    }

    #[must_use]
    pub fn credit_exposure_reservation_digest(&self) -> Option<&AdmissionDigest> {
        match self.attachment(AdmissionAttachmentKind::CreditExposureReservation) {
            Some(AdmissionAttachment::CreditExposureReservationDigest(digest)) => Some(digest),
            _ => None,
        }
    }

    #[must_use]
    pub fn replay_key(&self) -> AdmissionReplayKey {
        self.binding.replay_key()
    }

    #[must_use]
    pub fn to_persisted(&self) -> PersistedAdmissionOperationV1 {
        self.into()
    }

    #[must_use]
    pub fn classify_replay(&self, candidate: &Self) -> AdmissionReplayClassification {
        if self.replay_key() == candidate.replay_key()
            && self.binding.operation_id == candidate.binding.operation_id
            && self.binding == candidate.binding
        {
            AdmissionReplayClassification::Exact {
                terminal_replay: self.terminal_replay.clone(),
            }
        } else {
            AdmissionReplayClassification::Conflict
        }
    }

    pub fn apply_command(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationError> {
        command
            .recovery_lease
            .validate_for(self, command, trusted_now_unix_ms)?;
        let mut updated = self.clone();
        let mut changed = false;
        for attachment in &command.attachments {
            match self.attachments.existing_matches(attachment) {
                Some(true) => continue,
                Some(false) => {
                    return Err(AdmissionOperationError::AttachmentConflict {
                        field: attachment.field_name(),
                    });
                }
                None if attachment_allowed(
                    self.binding.kind,
                    self.binding.participant_requirements(),
                    self.state,
                    attachment,
                ) =>
                {
                    updated.attachments.attach(attachment.clone());
                    changed = true;
                }
                None => {
                    return Err(
                        if !attachment_supported(
                            self.binding.kind,
                            self.binding.participant_requirements(),
                            attachment,
                        ) {
                            AdmissionOperationError::ForbiddenAttachment {
                                field: attachment.field_name(),
                            }
                        } else {
                            AdmissionOperationError::AttachmentPhase {
                                field: attachment.field_name(),
                                state: self.state,
                            }
                        },
                    );
                }
            }
        }
        if let Some(next_state) = command.next_state {
            if next_state.is_terminal() {
                return Err(AdmissionOperationError::TerminalProjectionRequired);
            }
            if self.state == next_state {
                if self.terminal_replay != command.terminal_replay
                    || self.last_error != command.last_error
                {
                    return Err(AdmissionOperationError::TerminalReplayMismatch);
                }
            } else {
                if !is_legal_transition(
                    self.binding.kind,
                    self.binding.participant_requirements(),
                    self.state,
                    next_state,
                ) {
                    return Err(AdmissionOperationError::IllegalTransition {
                        from: self.state,
                        to: next_state,
                    });
                }
                validate_terminal_replay(
                    self.binding.kind,
                    next_state,
                    command.terminal_replay.as_ref(),
                )?;
                updated.state = next_state;
                updated.dispatch_state = dispatch_state_for(self.binding.kind, next_state)?;
                if next_state == AdmissionOperationState::DispatchCommitted {
                    let provider_attempt =
                        if self.binding.kind == AdmissionOperationKind::ToolDispatch {
                            Some(updated.provider_attempt().cloned().ok_or(
                                AdmissionOperationError::MissingParticipantAttachment {
                                    field: "broker_attempt",
                                },
                            )?)
                        } else {
                            None
                        };
                    updated.dispatch_commit = Some(AdmissionDispatchCommitBindingV1 {
                        committed_version: next_version(self.version)?,
                        coordinator_lease_id: command.recovery_lease.coordinator_lease_id().clone(),
                        coordinator_lease_epoch: command.recovery_lease.coordinator_lease_epoch(),
                        store_fence: command.recovery_lease.store_fence().clone(),
                        provider_attempt,
                    });
                }
                updated.terminal_replay.clone_from(&command.terminal_replay);
                updated.last_error.clone_from(&command.last_error);
                validate_state_attachments(
                    self.binding.kind,
                    self.binding.participant_requirements(),
                    next_state,
                    &updated.attachments,
                )?;
                changed = true;
            }
        }
        if !changed {
            return Ok(AdmissionCommandResult::Idempotent(updated));
        }
        self.require_version(command.expected_version)?;
        updated.version = next_version(self.version)?;
        updated.validate()?;
        Ok(AdmissionCommandResult::Applied(updated))
    }

    fn require_version(&self, expected_version: u64) -> Result<(), AdmissionOperationError> {
        if self.version != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: self.version,
            });
        }
        Ok(())
    }
}

impl From<&AdmissionOperationV1> for PersistedAdmissionOperationV1 {
    fn from(operation: &AdmissionOperationV1) -> Self {
        Self {
            schema: AdmissionOperationSchema::V1,
            binding: PersistedAdmissionOperationBindingV1::from(&operation.binding),
            attachments: operation.attachments.clone(),
            state: operation.state,
            dispatch_state: operation.dispatch_state,
            dispatch_commit: operation.dispatch_commit.clone(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch,
            version: operation.version,
            last_error: operation.last_error.clone(),
            terminal_replay: operation.terminal_replay.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionReplayClassification {
    Exact {
        terminal_replay: Option<AdmissionTerminalReplay>,
    },
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOperationCommand {
    operation_id: AdmissionOperationId,
    expected_version: u64,
    recovery_lease: AdmissionRecoveryLease,
    attachments: Vec<AdmissionAttachment>,
    next_state: Option<AdmissionOperationState>,
    terminal_replay: Option<AdmissionTerminalReplay>,
    last_error: Option<AdmissionErrorDetail>,
}

impl AdmissionOperationCommand {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: AdmissionOperationId,
        expected_version: u64,
        recovery_lease: AdmissionRecoveryLease,
        attachments: Vec<AdmissionAttachment>,
        next_state: Option<AdmissionOperationState>,
        terminal_replay: Option<AdmissionTerminalReplay>,
        last_error: Option<AdmissionErrorDetail>,
    ) -> Result<Self, AdmissionOperationError> {
        validate_positive_ijson("expected_operation_version", expected_version)?;
        if attachments.is_empty() && next_state.is_none() {
            return Err(AdmissionOperationError::EmptyCommand);
        }
        if next_state.is_none() && (terminal_replay.is_some() || last_error.is_some()) {
            return Err(AdmissionOperationError::TerminalReplayMismatch);
        }
        if next_state.is_some_and(AdmissionOperationState::is_terminal) {
            return Err(AdmissionOperationError::TerminalProjectionRequired);
        }
        for (index, attachment) in attachments.iter().enumerate() {
            if attachments[..index]
                .iter()
                .any(|prior| prior.field_name() == attachment.field_name())
            {
                return Err(AdmissionOperationError::DuplicateAttachment {
                    field: attachment.field_name(),
                });
            }
        }
        Ok(Self {
            operation_id,
            expected_version,
            recovery_lease,
            attachments,
            next_state,
            terminal_replay,
            last_error,
        })
    }

    #[must_use]
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    #[must_use]
    pub fn expected_version(&self) -> u64 {
        self.expected_version
    }

    #[must_use]
    pub fn recovery_lease(&self) -> &AdmissionRecoveryLease {
        &self.recovery_lease
    }

    #[must_use]
    pub fn attachments(&self) -> &[AdmissionAttachment] {
        &self.attachments
    }

    #[must_use]
    pub fn next_state(&self) -> Option<AdmissionOperationState> {
        self.next_state
    }

    #[must_use]
    pub fn terminal_replay(&self) -> Option<&AdmissionTerminalReplay> {
        self.terminal_replay.as_ref()
    }

    #[must_use]
    pub fn last_error(&self) -> Option<&AdmissionErrorDetail> {
        self.last_error.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCommandResult {
    Applied(AdmissionOperationV1),
    Idempotent(AdmissionOperationV1),
}

impl AdmissionCommandResult {
    #[must_use]
    pub fn into_operation(self) -> AdmissionOperationV1 {
        match self {
            Self::Applied(operation) | Self::Idempotent(operation) => operation,
        }
    }
}

/// Structurally checked claim returned by an admission-operation store.
///
/// This value is not authority and cannot be used to build a command until a
/// qualified store rechecks it against durable operation and lease state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedAdmissionRecoveryClaim {
    operation_id: AdmissionOperationId,
    claimant_id: AdmissionIdentifier,
    coordinator_lease_id: AdmissionIdentifier,
    coordinator_lease_epoch: u64,
    claimed_version: u64,
    expires_at_unix_ms: u64,
    store_fence: StoreMutationFence,
}

impl UntrustedAdmissionRecoveryClaim {
    pub fn new(
        operation_id: AdmissionOperationId,
        claimant_id: AdmissionIdentifier,
        coordinator_lease_id: AdmissionIdentifier,
        coordinator_lease_epoch: u64,
        claimed_version: u64,
        expires_at_unix_ms: u64,
        store_fence: StoreMutationFence,
    ) -> Result<Self, AdmissionOperationError> {
        validate_positive_ijson("coordinator_lease_epoch", coordinator_lease_epoch)?;
        validate_positive_ijson("claimed_version", claimed_version)?;
        validate_positive_ijson("expires_at_unix_ms", expires_at_unix_ms)?;
        validate_store_fence(&store_fence)?;
        Ok(Self {
            operation_id,
            claimant_id,
            coordinator_lease_id,
            coordinator_lease_epoch,
            claimed_version,
            expires_at_unix_ms,
            store_fence,
        })
    }

    fn validate_for_qualification(
        &self,
        operation: &AdmissionOperationV1,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationError> {
        operation.validate()?;
        validate_store_fence(&self.store_fence)?;
        validate_store_fence(current_store_fence)?;
        if self.operation_id != operation.binding.operation_id {
            return Err(AdmissionOperationError::WrongOperation);
        }
        if self.claimed_version != expected_version {
            return Err(AdmissionOperationError::LeaseVersionMismatch);
        }
        if operation.version != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: operation.version,
            });
        }
        if self.claimant_id != *claimant_id
            || self.expires_at_unix_ms > expires_at_unix_ms
            || self.store_fence != *current_store_fence
            || self.coordinator_lease_epoch != operation.coordinator_lease_epoch
        {
            return Err(AdmissionOperationError::CoordinatorFenced);
        }
        if trusted_now_unix_ms >= self.expires_at_unix_ms {
            return Err(AdmissionOperationError::LeaseExpired);
        }
        Ok(())
    }

    #[must_use]
    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    #[must_use]
    pub fn claimant_id(&self) -> &AdmissionIdentifier {
        &self.claimant_id
    }

    #[must_use]
    pub fn coordinator_lease_id(&self) -> &AdmissionIdentifier {
        &self.coordinator_lease_id
    }

    #[must_use]
    pub fn coordinator_lease_epoch(&self) -> u64 {
        self.coordinator_lease_epoch
    }

    #[must_use]
    pub fn claimed_version(&self) -> u64 {
        self.claimed_version
    }

    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub fn store_fence(&self) -> &StoreMutationFence {
        &self.store_fence
    }
}

/// Store-qualified recovery authority required by an operation command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRecoveryLease(UntrustedAdmissionRecoveryClaim);

impl AdmissionRecoveryLease {
    fn from_qualified(claim: UntrustedAdmissionRecoveryClaim) -> Self {
        Self(claim)
    }

    #[must_use]
    pub fn operation_id(&self) -> &AdmissionOperationId {
        self.0.operation_id()
    }

    #[must_use]
    pub fn claimant_id(&self) -> &AdmissionIdentifier {
        self.0.claimant_id()
    }

    #[must_use]
    pub fn coordinator_lease_id(&self) -> &AdmissionIdentifier {
        self.0.coordinator_lease_id()
    }

    #[must_use]
    pub fn coordinator_lease_epoch(&self) -> u64 {
        self.0.coordinator_lease_epoch()
    }

    #[must_use]
    pub fn claimed_version(&self) -> u64 {
        self.0.claimed_version()
    }

    #[must_use]
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.0.expires_at_unix_ms()
    }

    #[must_use]
    pub fn store_fence(&self) -> &StoreMutationFence {
        self.0.store_fence()
    }

    #[must_use]
    pub fn untrusted_claim(&self) -> &UntrustedAdmissionRecoveryClaim {
        &self.0
    }

    fn validate_for(
        &self,
        operation: &AdmissionOperationV1,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<(), AdmissionOperationError> {
        validate_store_fence(self.store_fence())?;
        if self.operation_id() != &operation.binding.operation_id
            || command.operation_id != operation.binding.operation_id
        {
            return Err(AdmissionOperationError::WrongOperation);
        }
        if self.claimed_version() != command.expected_version {
            return Err(AdmissionOperationError::LeaseVersionMismatch);
        }
        operation.require_version(command.expected_version)?;
        if self.coordinator_lease_epoch() != operation.coordinator_lease_epoch {
            return Err(AdmissionOperationError::CoordinatorFenced);
        }
        if trusted_now_unix_ms >= self.expires_at_unix_ms() {
            return Err(AdmissionOperationError::LeaseExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn qualify_recovery_claim_for_test(
    operation: &AdmissionOperationV1,
    claim: UntrustedAdmissionRecoveryClaim,
    trusted_now_unix_ms: u64,
    current_store_fence: &StoreMutationFence,
) -> Result<AdmissionRecoveryLease, AdmissionOperationError> {
    claim.validate_for_qualification(
        operation,
        claim.claimed_version,
        &claim.claimant_id,
        trusted_now_unix_ms,
        claim.expires_at_unix_ms,
        current_store_fence,
    )?;
    Ok(AdmissionRecoveryLease::from_qualified(claim))
}

#[cfg(test)]
#[path = "admission_operation_tests.rs"]
mod tests;
