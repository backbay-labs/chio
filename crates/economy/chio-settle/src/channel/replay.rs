use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::PublicKey;
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view, EconomicRequestBindingV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError,
    EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
    EconomicStateTransitionV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateView,
};
use chio_core::receipt::body::ChioReceipt;
use chio_credit::obligation::ObligationAtomV1;
use serde::{Deserialize, Deserializer, Serialize};

use super::validation::{digest, validate_digest, validate_positive};
use super::{
    compose_channel_cancellation_transition, compose_channel_dispatch_transition,
    compose_channel_reservation_transition, compose_channel_terminal_transition,
    verify_admitted_channel_open, verify_admitted_channel_reservation, verify_channel_open_consent,
    verify_channel_open_intent, verify_channel_prepared_reservation,
    verify_channel_receipt_binding, verify_channel_reservation_proposal,
    verify_channel_state_transition, verify_channel_terminal_outcome_commitment,
    verify_retained_signed_channel_state, ChannelDisputePolicyV1, ChannelError,
    ChannelFundingAuthorityV1, ChannelLifecycleBatchVerifier, ChannelLifecycleProjectionV1,
    ChannelOpenTrustV1, ChannelPreparedReservationV1, ChannelReservationAuthorityV1,
    RetainedChannelStateV1, SignedChannelFundingAcknowledgementV1, SignedChannelFundingEvidenceV1,
    SignedChannelReservationV1, SignedChannelStateV1, SignedChannelTerminalOutcomeCommitmentV1,
    VerifiedAdmittedChannelReservationV1, VerifiedChannelOpenConsentV1,
    VerifiedChannelPreparedReservationV1, VerifiedChannelReservationProposalV1,
    VerifiedChannelStateV1, VerifiedChannelTerminalOutcomeCommitmentV1,
};

pub const CHANNEL_TRANSITION_REPLAY_FORMAT: &str = "chio.channel.transition-replay.v1";
pub const MAX_CHANNEL_TRANSITION_REPLAY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CHANNEL_TRANSITION_REPLAY_AUTHORITY_PINS_BYTES: usize = 256 * 1024;

const CHANNEL_TRANSITION_REPLAY_VERSION: u64 = 1;
const CHANNEL_TRANSITION_REPLAY_AUTHORITY_PINS_DOMAIN: &[u8] =
    b"chio.channel.transition-replay.authority-pins.digest.v1\0";
const CHANNEL_TRANSITION_REPLAY_DESCRIPTOR_DOMAIN: &[u8] =
    b"chio.channel.transition-replay.descriptor.digest.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChannelTransitionReplayAnchorPinsV1 {
    anchor_id: String,
    namespace: String,
    signer_key_id: String,
    signer_key_epoch: u64,
    #[serde(deserialize_with = "super::signed::deserialize_canonical_public_key")]
    signer_public_key: PublicKey,
}

impl ChannelTransitionReplayAnchorPinsV1 {
    fn from_runtime(pins: &EconomicStateAnchorPins) -> Self {
        Self {
            anchor_id: pins.anchor_id.clone(),
            namespace: pins.namespace.clone(),
            signer_key_id: pins.signer_key_id.clone(),
            signer_key_epoch: pins.signer_key_epoch,
            signer_public_key: pins.signer_public_key.clone(),
        }
    }

    fn runtime(&self) -> EconomicStateAnchorPins {
        EconomicStateAnchorPins {
            anchor_id: self.anchor_id.clone(),
            namespace: self.namespace.clone(),
            signer_key_id: self.signer_key_id.clone(),
            signer_key_epoch: self.signer_key_epoch,
            signer_public_key: self.signer_public_key.clone(),
        }
    }

    fn validate(&self) -> Result<(), ChannelError> {
        self.runtime()
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelTransitionReplayAuthorityPinsV1 {
    open_trust: ChannelOpenTrustV1,
    funding_authority: ChannelFundingAuthorityV1,
    reservation_authority: ChannelReservationAuthorityV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_canonical_public_key"
    )]
    trusted_kernel_key: Option<PublicKey>,
    anchor: ChannelTransitionReplayAnchorPinsV1,
}

impl ChannelTransitionReplayAuthorityPinsV1 {
    pub fn new(
        open_trust: ChannelOpenTrustV1,
        funding_authority: ChannelFundingAuthorityV1,
        reservation_authority: ChannelReservationAuthorityV1,
        trusted_kernel_key: Option<PublicKey>,
        anchor: &EconomicStateAnchorPins,
    ) -> Result<Self, ChannelError> {
        let pins = Self {
            open_trust,
            funding_authority,
            reservation_authority,
            trusted_kernel_key,
            anchor: ChannelTransitionReplayAnchorPinsV1::from_runtime(anchor),
        };
        pins.validate()?;
        Ok(pins)
    }

    fn validate(&self) -> Result<(), ChannelError> {
        self.open_trust.validate()?;
        self.funding_authority.validate()?;
        self.reservation_authority.validate()?;
        self.anchor.validate()
    }

    pub fn digest(&self) -> Result<String, ChannelError> {
        self.validate()?;
        digest(CHANNEL_TRANSITION_REPLAY_AUTHORITY_PINS_DOMAIN, self)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChannelError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        if bytes.len() > MAX_CHANNEL_TRANSITION_REPLAY_AUTHORITY_PINS_BYTES {
            return Err(ChannelError::InvalidField(
                "channel_transition_replay_authority_pins_size",
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ChannelError> {
        if bytes.is_empty() || bytes.len() > MAX_CHANNEL_TRANSITION_REPLAY_AUTHORITY_PINS_BYTES {
            return Err(ChannelError::InvalidField(
                "channel_transition_replay_authority_pins_size",
            ));
        }
        let pins: Self = serde_json::from_slice(bytes)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        if pins.canonical_bytes()?.as_slice() != bytes {
            return Err(ChannelError::Canonicalization(
                "channel transition replay authority pins are not canonical".to_owned(),
            ));
        }
        Ok(pins)
    }

    #[must_use]
    pub fn anchor_pins(&self) -> EconomicStateAnchorPins {
        self.anchor.runtime()
    }

    fn anchor(&self) -> EconomicStateAnchorPins {
        self.anchor_pins()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelTransitionReplayOpenArtifactsV1 {
    pub funding_evidence: SignedChannelFundingEvidenceV1,
    pub funding_acknowledgement: SignedChannelFundingAcknowledgementV1,
    pub dispute_policy: ChannelDisputePolicyV1,
}

impl ChannelTransitionReplayOpenArtifactsV1 {
    fn validate(&self) -> Result<(), ChannelError> {
        self.funding_evidence.digest()?;
        self.funding_acknowledgement.digest()?;
        self.dispute_policy.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelReservationReplayContextV1 {
    prepared: ChannelPreparedReservationV1,
    signed_reservation: SignedChannelReservationV1,
    prepared_base_view: EconomicStateAnchorViewV1,
}

impl ChannelReservationReplayContextV1 {
    pub fn from_pre_anchor(
        prepared: &VerifiedChannelPreparedReservationV1,
        proposal: &VerifiedChannelReservationProposalV1,
    ) -> Result<Self, ChannelError> {
        if prepared.prepared().reservation != proposal.artifact().body {
            return Err(ChannelError::AuthorityVerification);
        }
        let context = Self {
            prepared: prepared.prepared().clone(),
            signed_reservation: proposal.artifact().clone(),
            prepared_base_view: prepared.current().view().clone(),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn from_verified(
        prepared: &VerifiedChannelPreparedReservationV1,
        reservation: &super::VerifiedAdmittedChannelReservationV1,
    ) -> Result<Self, ChannelError> {
        Self::from_pre_anchor(prepared, reservation.proposal())
    }

    fn validate(&self) -> Result<(), ChannelError> {
        self.prepared.digest()?;
        self.signed_reservation.digest()?;
        self.prepared_base_view
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        if self.prepared.reservation != self.signed_reservation.body
            || self.prepared.anchor_id != self.prepared_base_view.anchor_id
            || self.prepared.namespace != self.prepared_base_view.namespace
            || self.prepared.checkpoint_sequence != self.prepared_base_view.checkpoint_sequence
            || self.prepared.checkpoint_digest != self.prepared_base_view.checkpoint_digest
            || self.prepared.observed_at_unix_ms != self.prepared_base_view.observed_at
        {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelTransitionReplayKindV1 {
    Reservation,
    Dispatch,
    Terminal,
    Cancellation,
}

impl ChannelTransitionReplayKindV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reservation => "reservation",
            Self::Dispatch => "dispatch",
            Self::Terminal => "terminal",
            Self::Cancellation => "cancellation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChannelTransitionReplaySourceBindingV1 {
    resource_key: EconomicResourceKeyV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    expected_head_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ChannelTransitionReplayEvidenceV1 {
    Reservation,
    Dispatch,
    Cancellation {
        reservation_view: Box<EconomicStateAnchorViewV1>,
    },
    Terminal {
        reservation_view: Box<EconomicStateAnchorViewV1>,
        signed_receipt: Box<ChioReceipt>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "super::validation::deserialize_present_option"
        )]
        obligation: Option<Box<ObligationAtomV1>>,
        signed_next_state: Box<SignedChannelStateV1>,
        terminal_outcome: Box<SignedChannelTerminalOutcomeCommitmentV1>,
    },
}

impl ChannelTransitionReplayEvidenceV1 {
    const fn kind(&self) -> ChannelTransitionReplayKindV1 {
        match self {
            Self::Reservation => ChannelTransitionReplayKindV1::Reservation,
            Self::Dispatch => ChannelTransitionReplayKindV1::Dispatch,
            Self::Cancellation { .. } => ChannelTransitionReplayKindV1::Cancellation,
            Self::Terminal { .. } => ChannelTransitionReplayKindV1::Terminal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChannelTransitionReplayBodyV1 {
    authority_pins: ChannelTransitionReplayAuthorityPinsV1,
    authority_pins_digest: String,
    open_artifacts: ChannelTransitionReplayOpenArtifactsV1,
    reservation_context: ChannelReservationReplayContextV1,
    current_view: EconomicStateAnchorViewV1,
    base_checkpoint_sequence: u64,
    base_checkpoint_digest: String,
    descriptor_key: String,
    operation_id: String,
    request: EconomicRequestBindingV1,
    source_bindings: Vec<ChannelTransitionReplaySourceBindingV1>,
    issued_at: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "super::validation::deserialize_present_option"
    )]
    not_after_unix_ms: Option<u64>,
    expected_batch_digest: String,
    evidence: ChannelTransitionReplayEvidenceV1,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelTransitionReplayDescriptorCommitmentV1<'a> {
    format: &'a str,
    version: u64,
    body: &'a ChannelTransitionReplayBodyV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelTransitionReplayDescriptorV1 {
    format: String,
    version: u64,
    body: Box<ChannelTransitionReplayBodyV1>,
    descriptor_digest: String,
}

impl ChannelTransitionReplayDescriptorV1 {
    pub fn for_reservation(
        context: &ChannelReservationReplayContextV1,
        open_artifacts: &ChannelTransitionReplayOpenArtifactsV1,
        authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        expected_batch: &EconomicStateBatchV1,
    ) -> Result<Self, ChannelError> {
        let current = verify_replay_view(&context.prepared_base_view, authority_pins)?;
        Self::new(
            context,
            open_artifacts,
            authority_pins,
            &current,
            ChannelTransitionReplayEvidenceV1::Reservation,
            expected_batch,
        )
    }

    pub fn for_dispatch(
        context: &ChannelReservationReplayContextV1,
        open_artifacts: &ChannelTransitionReplayOpenArtifactsV1,
        authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        current: &VerifiedEconomicStateView,
        expected_batch: &EconomicStateBatchV1,
    ) -> Result<Self, ChannelError> {
        Self::new(
            context,
            open_artifacts,
            authority_pins,
            current,
            ChannelTransitionReplayEvidenceV1::Dispatch,
            expected_batch,
        )
    }

    pub fn for_cancellation(
        context: &ChannelReservationReplayContextV1,
        open_artifacts: &ChannelTransitionReplayOpenArtifactsV1,
        authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        reservation_view: &VerifiedEconomicStateView,
        current: &VerifiedEconomicStateView,
        expected_batch: &EconomicStateBatchV1,
    ) -> Result<Self, ChannelError> {
        Self::new(
            context,
            open_artifacts,
            authority_pins,
            current,
            ChannelTransitionReplayEvidenceV1::Cancellation {
                reservation_view: Box::new(reservation_view.view().clone()),
            },
            expected_batch,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_terminal(
        context: &ChannelReservationReplayContextV1,
        open_artifacts: &ChannelTransitionReplayOpenArtifactsV1,
        authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        reservation_view: &VerifiedEconomicStateView,
        current: &VerifiedEconomicStateView,
        signed_receipt: &ChioReceipt,
        obligation: Option<&ObligationAtomV1>,
        signed_next_state: &SignedChannelStateV1,
        terminal_outcome: &VerifiedChannelTerminalOutcomeCommitmentV1,
        expected_batch: &EconomicStateBatchV1,
    ) -> Result<Self, ChannelError> {
        Self::new(
            context,
            open_artifacts,
            authority_pins,
            current,
            ChannelTransitionReplayEvidenceV1::Terminal {
                reservation_view: Box::new(reservation_view.view().clone()),
                signed_receipt: Box::new(signed_receipt.clone()),
                obligation: obligation.cloned().map(Box::new),
                signed_next_state: Box::new(signed_next_state.clone()),
                terminal_outcome: Box::new(terminal_outcome.artifact().clone()),
            },
            expected_batch,
        )
    }

    #[must_use]
    pub fn kind(&self) -> ChannelTransitionReplayKindV1 {
        self.body.evidence.kind()
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.body.descriptor_key
    }

    #[must_use]
    pub fn request(&self) -> &EconomicRequestBindingV1 {
        &self.body.request
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.descriptor_digest
    }

    #[must_use]
    pub fn expected_batch_digest(&self) -> &str {
        &self.body.expected_batch_digest
    }

    #[must_use]
    pub fn not_after_unix_ms(&self) -> Option<u64> {
        self.body.not_after_unix_ms
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ChannelError> {
        self.reconstruct(&self.body.authority_pins)?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        if bytes.len() > MAX_CHANNEL_TRANSITION_REPLAY_BYTES {
            return Err(ChannelError::InvalidField("channel_transition_replay_size"));
        }
        Ok(bytes)
    }

    fn new(
        context: &ChannelReservationReplayContextV1,
        open_artifacts: &ChannelTransitionReplayOpenArtifactsV1,
        authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        current: &VerifiedEconomicStateView,
        evidence: ChannelTransitionReplayEvidenceV1,
        expected_batch: &EconomicStateBatchV1,
    ) -> Result<Self, ChannelError> {
        authority_pins.validate()?;
        current
            .view()
            .verify(&authority_pins.anchor())
            .map_err(|_| ChannelError::AuthorityVerification)?;
        let expires_at = context.signed_reservation.body.expires_at_unix_ms;
        let not_after_unix_ms = match evidence.kind() {
            ChannelTransitionReplayKindV1::Cancellation
            | ChannelTransitionReplayKindV1::Terminal => None,
            ChannelTransitionReplayKindV1::Reservation
            | ChannelTransitionReplayKindV1::Dispatch => Some(expires_at),
        };
        let body = ChannelTransitionReplayBodyV1 {
            authority_pins: authority_pins.clone(),
            authority_pins_digest: authority_pins.digest()?,
            open_artifacts: open_artifacts.clone(),
            reservation_context: context.clone(),
            current_view: current.view().clone(),
            base_checkpoint_sequence: current.view().checkpoint_sequence,
            base_checkpoint_digest: current.view().checkpoint_digest.clone(),
            descriptor_key: descriptor_key(
                evidence.kind(),
                &context.signed_reservation.body.operation_id,
            ),
            operation_id: context.signed_reservation.body.operation_id.clone(),
            request: context.prepared.service.request.clone(),
            source_bindings: source_bindings(&expected_batch.transitions),
            issued_at: expected_batch.issued_at,
            not_after_unix_ms,
            expected_batch_digest: expected_batch.checkpoint_digest.clone(),
            evidence,
        };
        let mut descriptor = Self {
            format: CHANNEL_TRANSITION_REPLAY_FORMAT.to_owned(),
            version: CHANNEL_TRANSITION_REPLAY_VERSION,
            body: Box::new(body),
            descriptor_digest: String::new(),
        };
        descriptor.descriptor_digest = descriptor.recompute_digest()?;
        let reconstructed = descriptor.reconstruct(authority_pins)?;
        verify_economic_state_batch_advance(
            &reconstructed.current,
            expected_batch.clone(),
            &authority_pins.anchor(),
            &ChannelLifecycleBatchVerifier::new(reconstructed.projection),
        )
        .map_err(|_| ChannelError::AuthorityVerification)?;
        Ok(descriptor)
    }

    fn recompute_digest(&self) -> Result<String, ChannelError> {
        digest(
            CHANNEL_TRANSITION_REPLAY_DESCRIPTOR_DOMAIN,
            &ChannelTransitionReplayDescriptorCommitmentV1 {
                format: &self.format,
                version: self.version,
                body: &self.body,
            },
        )
    }

    fn reconstruct(
        &self,
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
    ) -> Result<ReconstructedChannelTransitionReplayV1, ChannelError> {
        self.validate_envelope(expected_authority_pins)?;
        let context = &self.body.reservation_context;
        let prepared_current =
            verify_replay_view(&context.prepared_base_view, expected_authority_pins)?;
        let current = verify_replay_view(&self.body.current_view, expected_authority_pins)?;
        let verified_intent = verify_channel_open_intent(
            &context.prepared.signed_open_intent,
            &self.body.open_artifacts.funding_evidence,
            &expected_authority_pins.funding_authority,
            &self.body.open_artifacts.dispute_policy,
            &expected_authority_pins.open_trust,
        )?;
        let open = verify_channel_open_consent(
            &context.prepared.signed_open,
            &verified_intent,
            &self.body.open_artifacts.funding_acknowledgement,
            &expected_authority_pins.funding_authority,
            &expected_authority_pins.open_trust,
        )?;
        let admitted_open = verify_admitted_channel_open(&open, &prepared_current)?;
        let prior = replay_prior_state(
            &context.prepared.prior_state,
            &open,
            &expected_authority_pins.open_trust,
        )?;
        let proposal = verify_channel_reservation_proposal(
            &context.signed_reservation,
            &admitted_open,
            &prior,
            &expected_authority_pins.reservation_authority,
            &expected_authority_pins.open_trust,
        )?;
        let prepared = verify_channel_prepared_reservation(
            &context.prepared,
            &admitted_open,
            &prior,
            &prepared_current,
            &context.prepared.reservation,
            &context.prepared.service,
        )?;
        let projection = self.recompose_projection(
            &open,
            &prior,
            &proposal,
            &prepared,
            &current,
            expected_authority_pins,
        )?;
        if projection.operation_id() != Some(self.body.operation_id.as_str())
            || projection.not_after_unix_ms() != self.body.not_after_unix_ms
            || source_bindings(projection.transitions()) != self.body.source_bindings
        {
            return Err(ChannelError::AuthorityVerification);
        }
        Ok(ReconstructedChannelTransitionReplayV1 {
            current,
            projection,
            prepared,
            proposal,
        })
    }

    fn recompose_projection(
        &self,
        open: &VerifiedChannelOpenConsentV1,
        prior: &VerifiedChannelStateV1,
        proposal: &VerifiedChannelReservationProposalV1,
        prepared: &VerifiedChannelPreparedReservationV1,
        current: &VerifiedEconomicStateView,
        authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
    ) -> Result<ChannelLifecycleProjectionV1, ChannelError> {
        match &self.body.evidence {
            ChannelTransitionReplayEvidenceV1::Reservation => {
                if current.view() != prepared.current().view() {
                    return Err(ChannelError::AuthorityVerification);
                }
                compose_channel_reservation_transition(prepared, proposal, self.body.issued_at)
            }
            ChannelTransitionReplayEvidenceV1::Dispatch => {
                let reservation = verify_admitted_channel_reservation(proposal, prepared, current)?;
                compose_channel_dispatch_transition(&reservation, current, self.body.issued_at)
            }
            ChannelTransitionReplayEvidenceV1::Cancellation { reservation_view } => {
                let reservation_view = verify_replay_view(reservation_view, authority_pins)?;
                let reservation =
                    verify_admitted_channel_reservation(proposal, prepared, &reservation_view)?;
                compose_channel_cancellation_transition(&reservation, current, self.body.issued_at)
            }
            ChannelTransitionReplayEvidenceV1::Terminal {
                reservation_view,
                signed_receipt,
                obligation,
                signed_next_state,
                terminal_outcome,
            } => {
                let reservation_view = verify_replay_view(reservation_view, authority_pins)?;
                let reservation =
                    verify_admitted_channel_reservation(proposal, prepared, &reservation_view)?;
                let trusted_kernel_key = authority_pins
                    .trusted_kernel_key
                    .as_ref()
                    .ok_or(ChannelError::AuthorityVerification)?;
                let receipt = verify_channel_receipt_binding(
                    signed_receipt,
                    trusted_kernel_key,
                    &reservation,
                    open,
                    obligation.as_deref(),
                )?;
                let outcome = verify_channel_terminal_outcome_commitment(
                    terminal_outcome,
                    trusted_kernel_key,
                    &reservation,
                    signed_receipt,
                )?;
                let next = verify_channel_state_transition(
                    signed_next_state,
                    prior,
                    &reservation,
                    &receipt,
                    open,
                    &authority_pins.open_trust,
                )?;
                compose_channel_terminal_transition(
                    open,
                    &reservation,
                    &next,
                    &receipt,
                    &outcome,
                    current,
                    self.body.issued_at,
                )
            }
        }
    }

    fn validate_envelope(
        &self,
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
    ) -> Result<(), ChannelError> {
        if self.format != CHANNEL_TRANSITION_REPLAY_FORMAT
            || self.version != CHANNEL_TRANSITION_REPLAY_VERSION
        {
            return Err(ChannelError::InvalidField(
                "channel_transition_replay_format",
            ));
        }
        expected_authority_pins.validate()?;
        self.body.authority_pins.validate()?;
        self.body.open_artifacts.validate()?;
        self.body.reservation_context.validate()?;
        validate_digest(
            "channel_transition_replay_authority_pins_digest",
            &self.body.authority_pins_digest,
        )?;
        validate_digest(
            "channel_transition_replay_descriptor_digest",
            &self.descriptor_digest,
        )?;
        validate_digest(
            "channel_transition_replay_base_checkpoint_digest",
            &self.body.base_checkpoint_digest,
        )?;
        validate_digest(
            "channel_transition_replay_operation_id",
            &self.body.operation_id,
        )?;
        validate_digest(
            "channel_transition_replay_expected_batch_digest",
            &self.body.expected_batch_digest,
        )?;
        validate_positive(
            "channel_transition_replay_base_checkpoint_sequence",
            self.body.base_checkpoint_sequence,
        )?;
        validate_positive("channel_transition_replay_issued_at", self.body.issued_at)?;
        self.body
            .request
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        let expected_not_after = match self.body.evidence.kind() {
            ChannelTransitionReplayKindV1::Cancellation
            | ChannelTransitionReplayKindV1::Terminal => None,
            ChannelTransitionReplayKindV1::Reservation
            | ChannelTransitionReplayKindV1::Dispatch => Some(
                self.body
                    .reservation_context
                    .signed_reservation
                    .body
                    .expires_at_unix_ms,
            ),
        };
        if &self.body.authority_pins != expected_authority_pins
            || self.body.authority_pins_digest != expected_authority_pins.digest()?
            || self.descriptor_digest != self.recompute_digest()?
            || self.body.current_view.checkpoint_sequence != self.body.base_checkpoint_sequence
            || self.body.current_view.checkpoint_digest != self.body.base_checkpoint_digest
            || self.body.descriptor_key
                != descriptor_key(self.body.evidence.kind(), &self.body.operation_id)
            || self.body.operation_id
                != self
                    .body
                    .reservation_context
                    .signed_reservation
                    .body
                    .operation_id
            || self.body.request != self.body.reservation_context.prepared.service.request
            || self.body.not_after_unix_ms != expected_not_after
        {
            return Err(ChannelError::AuthorityVerification);
        }
        if let Some(not_after) = self.body.not_after_unix_ms {
            validate_positive("channel_transition_replay_not_after", not_after)?;
            if self.body.issued_at >= not_after {
                return Err(ChannelError::AuthorityVerification);
            }
        }
        if let ChannelTransitionReplayEvidenceV1::Terminal {
            terminal_outcome, ..
        } = &self.body.evidence
        {
            if terminal_outcome.body.terminalized_at_unix_ms > self.body.issued_at {
                return Err(ChannelError::AuthorityVerification);
            }
        }
        validate_source_bindings(&self.body.current_view, &self.body.source_bindings)
    }
}

fn descriptor_key(kind: ChannelTransitionReplayKindV1, operation_id: &str) -> String {
    format!("{}:{operation_id}", kind.as_str())
}

struct ReconstructedChannelTransitionReplayV1 {
    current: VerifiedEconomicStateView,
    projection: ChannelLifecycleProjectionV1,
    prepared: VerifiedChannelPreparedReservationV1,
    proposal: VerifiedChannelReservationProposalV1,
}

pub struct ChannelTransitionReplayVerifierV1 {
    descriptor: ChannelTransitionReplayDescriptorV1,
    current: VerifiedEconomicStateView,
    projection: ChannelLifecycleProjectionV1,
    prepared: VerifiedChannelPreparedReservationV1,
    proposal: VerifiedChannelReservationProposalV1,
}

impl ChannelTransitionReplayVerifierV1 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
    ) -> Result<Self, ChannelError> {
        if bytes.is_empty() || bytes.len() > MAX_CHANNEL_TRANSITION_REPLAY_BYTES {
            return Err(ChannelError::InvalidField("channel_transition_replay_size"));
        }
        let descriptor: ChannelTransitionReplayDescriptorV1 = serde_json::from_slice(bytes)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        let canonical = canonical_json_bytes(&descriptor)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
        if canonical.as_slice() != bytes {
            return Err(ChannelError::Canonicalization(
                "channel transition replay descriptor is not canonical".to_owned(),
            ));
        }
        let reconstructed = descriptor.reconstruct(expected_authority_pins)?;
        Ok(Self {
            descriptor,
            current: reconstructed.current,
            projection: reconstructed.projection,
            prepared: reconstructed.prepared,
            proposal: reconstructed.proposal,
        })
    }

    #[must_use]
    pub const fn descriptor(&self) -> &ChannelTransitionReplayDescriptorV1 {
        &self.descriptor
    }

    #[must_use]
    pub const fn verified_reservation_proposal(&self) -> &VerifiedChannelReservationProposalV1 {
        &self.proposal
    }

    pub fn verify_committed_reservation(
        &self,
        committed: &VerifiedEconomicStateView,
    ) -> Result<VerifiedAdmittedChannelReservationV1, ChannelError> {
        let expected_sequence = self
            .current
            .view()
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        committed
            .view()
            .verify(&self.descriptor.body.authority_pins.anchor_pins())
            .map_err(|_| ChannelError::AuthorityVerification)?;
        if self.descriptor.kind() != ChannelTransitionReplayKindV1::Reservation
            || committed.view().checkpoint_sequence != expected_sequence
            || committed.view().checkpoint_digest != self.descriptor.body.expected_batch_digest
            || committed.view().observed_at < self.descriptor.body.issued_at
        {
            return Err(ChannelError::AuthorityVerification);
        }
        verify_admitted_channel_reservation(&self.proposal, &self.prepared, committed)
    }
}

impl EconomicTransitionProofVerifier for ChannelTransitionReplayVerifierV1 {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::TransitionProofRejected(
            transition.resource_key.clone(),
        ))
    }

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        let rejected_key = batch
            .transitions
            .first()
            .ok_or(EconomicStateAnchorError::InvalidView(
                "channel replay batch has no transition",
            ))?
            .resource_key
            .clone();
        let rejected = || EconomicStateAnchorError::TransitionProofRejected(rejected_key.clone());
        let pins = self.descriptor.body.authority_pins.anchor();
        current.view().verify(&pins)?;
        batch.verify_signature(&pins.signer_public_key)?;
        if current.view() != self.current.view()
            || batch.checkpoint_digest != self.descriptor.body.expected_batch_digest
            || batch.anchor_id != pins.anchor_id
            || batch.namespace != pins.namespace
            || batch.signer_key_id != pins.signer_key_id
            || batch.signer_key_epoch != pins.signer_key_epoch
        {
            return Err(rejected());
        }
        ChannelLifecycleBatchVerifier::new(self.projection.clone()).verify_batch(current, batch)
    }
}

fn verify_replay_view(
    view: &EconomicStateAnchorViewV1,
    authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    verify_economic_state_view(view.clone(), &authority_pins.anchor())
        .map_err(|_| ChannelError::AuthorityVerification)
}

fn replay_prior_state(
    retained: &RetainedChannelStateV1,
    open: &VerifiedChannelOpenConsentV1,
    trust: &ChannelOpenTrustV1,
) -> Result<VerifiedChannelStateV1, ChannelError> {
    match retained {
        RetainedChannelStateV1::Initial { body } => {
            if body.as_ref() != open.initial_state().body() {
                return Err(ChannelError::AuthorityVerification);
            }
            Ok(open.initial_state().clone())
        }
        RetainedChannelStateV1::Signed { state } => {
            verify_retained_signed_channel_state(state, open, trust)
        }
    }
}

fn source_bindings(
    transitions: &[EconomicStateTransitionV1],
) -> Vec<ChannelTransitionReplaySourceBindingV1> {
    transitions
        .iter()
        .map(|transition| ChannelTransitionReplaySourceBindingV1 {
            resource_key: transition.resource_key.clone(),
            expected_head_digest: transition.expected_head_digest.clone(),
        })
        .collect()
}

fn validate_source_bindings(
    current: &EconomicStateAnchorViewV1,
    bindings: &[ChannelTransitionReplaySourceBindingV1],
) -> Result<(), ChannelError> {
    if bindings.is_empty()
        || bindings.len() > 3
        || !bindings
            .windows(2)
            .all(|pair| pair[0].resource_key < pair[1].resource_key)
    {
        return Err(ChannelError::AuthorityVerification);
    }
    for binding in bindings {
        binding
            .resource_key
            .validate()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        match binding.expected_head_digest.as_deref() {
            Some(expected) => {
                validate_digest("channel_transition_replay_source_head", expected)?;
                let head = current
                    .head(&binding.resource_key)
                    .ok_or(ChannelError::AuthorityVerification)?;
                if head
                    .digest()
                    .map_err(|_| ChannelError::AuthorityVerification)?
                    != expected
                {
                    return Err(ChannelError::AuthorityVerification);
                }
            }
            None if current.proves_resource_absent(&binding.resource_key) => {}
            None => return Err(ChannelError::AuthorityVerification),
        }
    }
    Ok(())
}

fn deserialize_optional_canonical_public_key<'de, D>(
    deserializer: D,
) -> Result<Option<PublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let key = PublicKey::from_hex(&encoded).map_err(serde::de::Error::custom)?;
    if key.to_hex() != encoded {
        return Err(serde::de::Error::custom("noncanonical public key"));
    }
    Ok(Some(key))
}
