use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::canonical::canonical_json_bytes;
use chio_core::economic_continuity::{
    economic_effect_slot_from_head, EconomicAdmissionHandoffStateV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTerminalV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, VerifiedEconomicEffectDispatch,
};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationKind, AdmissionOperationState, AdmissionOperationV1,
    SideEffectClass,
};
use chio_settle::channel::{
    ChannelEscrowReservationStatusV1, ChannelEscrowReservationViewV1, ChannelLifecycleStatusV1,
    ChannelLifecycleViewV1, VerifiedChannelLifecycleSnapshotV1,
    VerifiedSignedChannelReleaseAuthorizationV1, CHANNEL_RELEASE_BROADCAST_EFFECT_KIND,
    CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND,
};
use chio_settle::{PreparedAuthorizedChannelMerkleReleaseV1, SettlementChainConfig};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Row, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

mod persistence;
mod qualification;

use persistence::*;
pub(crate) use persistence::{
    initialize_channel_release_publisher_schema, verify_channel_release_publisher_invariants,
};
use qualification::*;

const CHANNEL_RELEASE_PUBLISHER_SCHEMA_KEY: &str = "channel_release_publisher";
pub(crate) const CHANNEL_RELEASE_PUBLISHER_SUPPORTED_SCHEMA_VERSION: i32 = 1;
const CHANNEL_RELEASE_PUBLISHER_SCHEMA_ANCHORS: &[&str] = &[
    "chio_channel_release_publisher_meta",
    "chio_channel_release_publications",
    "channel_lifecycle_records",
];
const CHANNEL_RELEASE_PUBLISHER_SCHEMA: &str = include_str!("channel_release_publisher_store.sql");
const CHANNEL_RELEASE_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.release-authorization.signed-digest.v1\0";
const MAX_PUBLISHER_ARTIFACT_BYTES: usize = 1024 * 1024;
#[cfg(test)]
const MAX_FAILURE_DETAIL_BYTES: usize = 4 * 1024;
const CHANNEL_ROOT_PUBLICATION_RESULT_SCHEMA: &str = "chio.channel.root-publication-result.v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChannelRootPublicationResultV1 {
    schema: String,
    publication_root: String,
    call_digest: String,
    transaction_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelReleasePublisherError {
    #[error("channel release publisher store is unavailable: {0}")]
    Unavailable(String),
    #[error("channel release publisher mutation was fenced")]
    Fenced,
    #[error("channel release publisher record conflicts with retained state")]
    Conflict,
    #[error("channel release publisher invariant failed: {0}")]
    Invalid(String),
    #[error("channel release publisher durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("channel release publisher broadcast is disabled: {0}")]
    BroadcastDisabled(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelReleasePublicationStatusV1 {
    DispatchCommitted,
    Submitted,
    Unknown,
    Incident,
}

impl ChannelReleasePublicationStatusV1 {
    fn parse(value: &str) -> Result<Self, ChannelReleasePublisherError> {
        match value {
            "dispatch_committed" => Ok(Self::DispatchCommitted),
            "submitted" => Ok(Self::Submitted),
            "unknown" => Ok(Self::Unknown),
            "incident" => Ok(Self::Incident),
            _ => Err(invalid("retained channel release status is invalid")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReleasePublicationRecordV1 {
    channel_id: String,
    publication_binding_digest: String,
    authorization_digest: String,
    prepared_call_digest: String,
    publisher_fence: u64,
    status: ChannelReleasePublicationStatusV1,
    transaction_hash: Option<String>,
    failure_detail: Option<String>,
    record_version: u64,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl ChannelReleasePublicationRecordV1 {
    #[must_use]
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    #[must_use]
    pub fn publication_binding_digest(&self) -> &str {
        &self.publication_binding_digest
    }

    #[must_use]
    pub fn authorization_digest(&self) -> &str {
        &self.authorization_digest
    }

    #[must_use]
    pub fn prepared_call_digest(&self) -> &str {
        &self.prepared_call_digest
    }

    #[must_use]
    pub const fn publisher_fence(&self) -> u64 {
        self.publisher_fence
    }

    #[must_use]
    pub const fn status(&self) -> ChannelReleasePublicationStatusV1 {
        self.status
    }

    #[must_use]
    pub fn transaction_hash(&self) -> Option<&str> {
        self.transaction_hash.as_deref()
    }

    #[must_use]
    pub fn failure_detail(&self) -> Option<&str> {
        self.failure_detail.as_deref()
    }

    #[must_use]
    pub const fn record_version(&self) -> u64 {
        self.record_version
    }

    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    #[must_use]
    pub const fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelReleaseSubmissionOutcomeV1 {
    Submitted(ChannelReleasePublicationRecordV1),
    AlreadyClaimed(ChannelReleasePublicationRecordV1),
}

#[derive(Debug)]
pub struct VerifiedChannelReleasePublicationV1 {
    candidate: ChannelReleasePublisherCandidate,
}

impl VerifiedChannelReleasePublicationV1 {
    pub fn verify(
        authorization: &VerifiedSignedChannelReleaseAuthorizationV1,
        prepared: &PreparedAuthorizedChannelMerkleReleaseV1,
        closing: &VerifiedChannelLifecycleSnapshotV1,
    ) -> Result<Self, ChannelReleasePublisherError> {
        Ok(Self {
            candidate: ChannelReleasePublisherCandidate::from_verified(
                authorization,
                prepared,
                closing,
            )?,
        })
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct ChannelReleaseBroadcastPermitV1 {
    channel_id: String,
    publication_binding_digest: String,
    authorization_digest: String,
    prepared_call_digest: String,
    publisher_fence: u64,
    record_version: u64,
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum ChannelReleasePermitClaimV1 {
    Claimed {
        permit: ChannelReleaseBroadcastPermitV1,
    },
    ExactReplay(ChannelReleasePublicationRecordV1),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelReleasePublisherCandidate {
    channel_id: String,
    chain_id: String,
    escrow_contract: String,
    escrow_id: String,
    open_digest: String,
    close_digest: String,
    close_body_digest: String,
    effective_close_digest: String,
    final_state_digest: String,
    final_state_sequence: u64,
    source_channel_state_version: u64,
    source_escrow_reservation_version: u64,
    source_lifecycle_fence: u64,
    source_checkpoint_sequence: u64,
    source_checkpoint_digest: String,
    source_channel_head_digest: String,
    source_escrow_head_digest: String,
    closing_checkpoint_sequence: u64,
    closing_checkpoint_digest: String,
    closing_channel_head_digest: String,
    closing_escrow_head_digest: String,
    closing_channel_predecessor_digest: String,
    closing_escrow_predecessor_digest: String,
    closing_lifecycle: ChannelLifecycleViewV1,
    closing_escrow: ChannelEscrowReservationViewV1,
    bound_token_base_units: String,
    release_token_base_units: String,
    refund_token_base_units: String,
    original_operator: String,
    original_operator_key_hash: String,
    beneficiary_address: String,
    asset_binding_digest: String,
    original_dispatch_digest: String,
    close_submission_cutoff_unix_ms: u64,
    escrow_deadline_unix_ms: u64,
    publisher_fence: u64,
    authorized_at_unix_ms: u64,
    frost_slot_id: String,
    frost_authorization_id: String,
    frost_action_digest: String,
    frost_envelope_digest: String,
    frost_scope_id: String,
    frost_resource_id: String,
    frost_resource_version: u64,
    frost_resource_fence: u64,
    frost_roster_digest: String,
    frost_key_epoch: u64,
    frost_issued_at_unix_ms: u64,
    publication_root: String,
    root_operation_id: String,
    root_effect_slot_id: String,
    root_effect_scope_id: String,
    root_effect_kind: String,
    root_idempotency_key: String,
    root_call_digest: String,
    root_resource_head_digest: String,
    release_operation_id: String,
    release_effect_slot_id: String,
    release_effect_scope_id: String,
    release_effect_kind: String,
    release_idempotency_key: String,
    release_call_digest: String,
    release_resource_head_digest: String,
    authorization_digest: String,
    authorization_json: Vec<u8>,
    prepared_call_digest: String,
    prepared_call_json: Vec<u8>,
}

impl ChannelReleasePublisherCandidate {
    fn from_verified(
        authorization: &VerifiedSignedChannelReleaseAuthorizationV1,
        prepared: &PreparedAuthorizedChannelMerkleReleaseV1,
        closing: &VerifiedChannelLifecycleSnapshotV1,
    ) -> Result<Self, ChannelReleasePublisherError> {
        let authority = authorization.authority();
        let binding = authority.binding();
        let body = authorization.body();
        if prepared.authorization() != binding
            || prepared.authorization_digest() != authority.authorization_digest()
            || body.authority() != binding
            || body.publication_root() != prepared.publication_root()
        {
            return Err(invalid(
                "prepared channel release lost its verified authorization",
            ));
        }
        let root = body.root_publication();
        let release_binding = body.release_broadcast();
        let source = authority.close().snapshot();
        let authorization_json = encode(
            authorization.artifact(),
            "signed channel release authorization",
        )?;
        let authorization_digest = authorization_digest(&authorization_json);
        if authorization_digest != authorization.digest() {
            return Err(invalid(
                "channel release authorization digest is not canonical",
            ));
        }
        let prepared_call_json = prepared
            .canonical_call()
            .map_err(|error| invalid(error.to_string()))?;
        let prepared_call_digest = sha256_hex(&prepared_call_json);
        if release_binding.call_digest != prepared_call_digest {
            return Err(invalid(
                "signed channel release authorization changed the prepared release",
            ));
        }
        let frost = binding.frost();
        Ok(Self {
            channel_id: binding.channel_id().to_owned(),
            chain_id: binding.escrow_reference().chain_id.clone(),
            escrow_contract: binding.escrow_reference().escrow_contract.clone(),
            escrow_id: binding.escrow_reference().escrow_id.clone(),
            open_digest: binding.open_digest().to_owned(),
            close_digest: binding.close_digest().to_owned(),
            close_body_digest: binding.close_body_digest().to_owned(),
            effective_close_digest: binding.effective_close_digest().to_owned(),
            final_state_digest: binding.final_state_digest().to_owned(),
            final_state_sequence: binding.final_state_sequence(),
            source_channel_state_version: binding.channel_state_version(),
            source_escrow_reservation_version: binding.escrow_reservation_version(),
            source_lifecycle_fence: binding.lifecycle_fence(),
            source_checkpoint_sequence: source.checkpoint_sequence(),
            source_checkpoint_digest: source.checkpoint_digest().to_owned(),
            source_channel_head_digest: source.channel_head_digest().to_owned(),
            source_escrow_head_digest: source.escrow_head_digest().to_owned(),
            closing_checkpoint_sequence: closing.checkpoint_sequence(),
            closing_checkpoint_digest: closing.checkpoint_digest().to_owned(),
            closing_channel_head_digest: closing.channel_head_digest().to_owned(),
            closing_escrow_head_digest: closing.escrow_head_digest().to_owned(),
            closing_channel_predecessor_digest: closing
                .channel_predecessor_digest()
                .ok_or_else(|| invalid("closing channel head has no predecessor"))?
                .to_owned(),
            closing_escrow_predecessor_digest: closing
                .escrow_predecessor_digest()
                .ok_or_else(|| invalid("closing escrow head has no predecessor"))?
                .to_owned(),
            closing_lifecycle: closing.lifecycle().clone(),
            closing_escrow: closing.escrow().clone(),
            bound_token_base_units: binding.bound_token_base_units().to_owned(),
            release_token_base_units: binding.expected_release_token_base_units().to_owned(),
            refund_token_base_units: binding.expected_refund_token_base_units().to_owned(),
            original_operator: binding.original_operator().to_owned(),
            original_operator_key_hash: binding.original_operator_key_hash().to_owned(),
            beneficiary_address: binding.payee_beneficiary_address().to_owned(),
            asset_binding_digest: binding.asset_binding_digest().to_owned(),
            original_dispatch_digest: binding.original_web3_dispatch_digest().to_owned(),
            close_submission_cutoff_unix_ms: binding.close_submission_cutoff_unix_ms(),
            escrow_deadline_unix_ms: binding.escrow_deadline_unix_ms(),
            publisher_fence: binding.publisher_fence(),
            authorized_at_unix_ms: binding.authorized_at_unix_ms(),
            frost_slot_id: frost.authorization_slot_id.clone(),
            frost_authorization_id: frost.authorization_id.clone(),
            frost_action_digest: frost.action_digest.clone(),
            frost_envelope_digest: frost.signed_envelope_digest.clone(),
            frost_scope_id: binding.frost_scope_id().to_owned(),
            frost_resource_id: binding.frost_resource_id().to_owned(),
            frost_resource_version: binding.frost_resource_version(),
            frost_resource_fence: binding.frost_resource_fence(),
            frost_roster_digest: binding.frost_roster_digest().to_owned(),
            frost_key_epoch: binding.frost_key_epoch(),
            frost_issued_at_unix_ms: binding.frost_issued_at_unix_ms(),
            publication_root: body.publication_root().to_owned(),
            root_operation_id: root.operation_id.clone(),
            root_effect_slot_id: root.effect_slot_id.clone(),
            root_effect_scope_id: root.scope_id.clone(),
            root_effect_kind: root.effect_kind.clone(),
            root_idempotency_key: root.idempotency_key.clone(),
            root_call_digest: root.call_digest.clone(),
            root_resource_head_digest: root.resource_head_digest.clone(),
            release_operation_id: release_binding.operation_id.clone(),
            release_effect_slot_id: release_binding.effect_slot_id.clone(),
            release_effect_scope_id: release_binding.scope_id.clone(),
            release_effect_kind: release_binding.effect_kind.clone(),
            release_idempotency_key: release_binding.idempotency_key.clone(),
            release_call_digest: release_binding.call_digest.clone(),
            release_resource_head_digest: release_binding.resource_head_digest.clone(),
            authorization_digest,
            authorization_json,
            prepared_call_digest,
            prepared_call_json,
        })
    }

    fn binding_digest(&self) -> Result<String, ChannelReleasePublisherError> {
        Ok(sha256_hex(&encode(self, "channel release publication")?))
    }

    fn verify_dispatch(
        &self,
        dispatch: &VerifiedEconomicEffectDispatch,
    ) -> Result<(), ChannelReleasePublisherError> {
        self.verify_dispatch_slot(dispatch.slot())
    }

    fn verify_dispatch_slot(
        &self,
        slot: &EconomicEffectSlotV1,
    ) -> Result<(), ChannelReleasePublisherError> {
        let frost = slot.frost.as_ref();
        if slot.slot_id != self.release_effect_slot_id
            || slot.operation_id != self.release_operation_id
            || slot.resource_key.resource_family != "channel_escrow_reservation"
            || slot.resource_key.scope_id != self.release_effect_scope_id
            || slot.resource_key.scope_id != self.frost_scope_id
            || slot.resource_key.resource_id != self.channel_id
            || slot.effect_kind != self.release_effect_kind
            || slot.effect_kind != CHANNEL_RELEASE_BROADCAST_EFFECT_KIND
            || slot.idempotency_key != self.release_idempotency_key
            || slot.parameters_digest != self.release_call_digest
            || slot.parameters_digest != self.prepared_call_digest
            || slot.resource_head_digest != self.release_resource_head_digest
            || slot.action_digest != self.frost_action_digest
            || slot.admission_handoff.state != EconomicAdmissionHandoffStateV1::MutationSubmitted
            || slot.state != EconomicEffectStateV1::DispatchCommitted
            || frost.is_none_or(|binding| {
                binding.authorization_slot_id != self.frost_slot_id
                    || binding.authorization_id != self.frost_authorization_id
                    || binding.action_digest != self.frost_action_digest
                    || binding.signed_envelope_digest != self.frost_envelope_digest
            })
        {
            return Err(ChannelReleasePublisherError::Fenced);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqliteChannelReleasePublisherStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteChannelReleasePublisherStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    pub fn verify_invariants(&self) -> Result<(), ChannelReleasePublisherError> {
        let connection = self.connection()?;
        verify_channel_release_publisher_invariants(&connection).map_err(owner_error)
    }

    pub fn load(
        &self,
        channel_id: &str,
    ) -> Result<Option<ChannelReleasePublicationRecordV1>, ChannelReleasePublisherError> {
        let connection = self.connection()?;
        self.serving_owner
            .verify_authority_anchor(&connection)
            .map_err(owner_error)?;
        load_record(&connection, channel_id)
    }

    pub async fn submit_authorized_channel_release(
        &self,
        config: &SettlementChainConfig,
        publication: &VerifiedChannelReleasePublicationV1,
        dispatch: VerifiedEconomicEffectDispatch,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReleaseSubmissionOutcomeV1, ChannelReleasePublisherError> {
        let candidate = &publication.candidate;
        if let Some(record) = self.replay_candidate(candidate, fence, trusted_now_unix_ms)? {
            return Ok(ChannelReleaseSubmissionOutcomeV1::AlreadyClaimed(record));
        }
        candidate.verify_dispatch(&dispatch)?;
        if config.chain_id != candidate.chain_id
            || config.escrow_contract != candidate.escrow_contract
            || config.operator_address != candidate.original_operator
        {
            return Err(invalid(
                "settlement configuration does not match channel release authority",
            ));
        }
        config
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.qualify_new_dispatch(candidate, &dispatch, fence, trusted_now_unix_ms)?;
        Err(ChannelReleasePublisherError::BroadcastDisabled(
            "deterministic raw transaction signing, nonce leasing, recovery, and live FROST/operator key resolution are unavailable".to_owned(),
        ))
    }

    pub fn replay_authorized_channel_release(
        &self,
        publication: &VerifiedChannelReleasePublicationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<ChannelReleaseSubmissionOutcomeV1>, ChannelReleasePublisherError> {
        let candidate = &publication.candidate;
        self.replay_candidate(candidate, fence, trusted_now_unix_ms)
            .map(|record| record.map(ChannelReleaseSubmissionOutcomeV1::AlreadyClaimed))
    }

    fn replay_candidate(
        &self,
        candidate: &ChannelReleasePublisherCandidate,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<ChannelReleasePublicationRecordV1>, ChannelReleasePublisherError> {
        self.replay_candidate_inner(candidate, fence, trusted_now_unix_ms, true)
    }

    #[cfg(test)]
    fn replay_candidate_unqualified_for_test(
        &self,
        candidate: &ChannelReleasePublisherCandidate,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<ChannelReleasePublicationRecordV1>, ChannelReleasePublisherError> {
        self.replay_candidate_inner(candidate, fence, trusted_now_unix_ms, false)
    }

    fn replay_candidate_inner(
        &self,
        candidate: &ChannelReleasePublisherCandidate,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
        _require_durable_execution: bool,
    ) -> Result<Option<ChannelReleasePublicationRecordV1>, ChannelReleasePublisherError> {
        if fence != &self.serving_owner.fence {
            return Err(ChannelReleasePublisherError::Fenced);
        }
        let mut connection = self.connection()?;
        self.serving_owner
            .verify_authority_anchor(&connection)
            .map_err(owner_error)?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        validate_candidate(candidate)?;
        let binding_digest = candidate.binding_digest()?;
        match load_record(&transaction, &candidate.channel_id)? {
            Some(record) if record_matches_candidate(&record, candidate, &binding_digest) => {
                Ok(Some(record))
            }
            Some(_) => Err(ChannelReleasePublisherError::Conflict),
            None => Ok(None),
        }
    }

    #[cfg(test)]
    fn claim_candidate_unqualified_for_test(
        &self,
        candidate: &ChannelReleasePublisherCandidate,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReleasePermitClaimV1, ChannelReleasePublisherError> {
        self.claim_candidate_inner(candidate, fence, trusted_now_unix_ms, false)
    }

    #[cfg(test)]
    fn claim_candidate_inner(
        &self,
        candidate: &ChannelReleasePublisherCandidate,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        require_durable_execution: bool,
    ) -> Result<ChannelReleasePermitClaimV1, ChannelReleasePublisherError> {
        if fence != &self.serving_owner.fence {
            return Err(ChannelReleasePublisherError::Fenced);
        }
        let mut connection = self.connection()?;
        self.serving_owner
            .verify_authority_anchor(&connection)
            .map_err(owner_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        validate_candidate(candidate)?;
        let binding_digest = candidate.binding_digest()?;
        if let Some(existing) = load_record(&transaction, &candidate.channel_id)? {
            if record_matches_candidate(&existing, candidate, &binding_digest) {
                return Ok(ChannelReleasePermitClaimV1::ExactReplay(existing));
            }
            return Err(ChannelReleasePublisherError::Conflict);
        }
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        validate_candidate_freshness(candidate, trusted_now_unix_ms)?;
        let lifecycle_json = encode(&candidate.closing_lifecycle, "closing channel lifecycle")?;
        let escrow_json = encode(&candidate.closing_escrow, "closing escrow reservation")?;
        qualify_durable_closing(&transaction, candidate, &lifecycle_json, &escrow_json)?;
        if require_durable_execution {
            let _ = qualify_durable_release_execution(&transaction, candidate, fence)?;
        }
        advance_trusted_time(&transaction, trusted_now_unix_ms)?;
        insert_publication(
            &transaction,
            candidate,
            &binding_digest,
            &lifecycle_json,
            &escrow_json,
            fence,
            trusted_now_unix_ms,
        )?;
        self.serving_owner
            .append_global_commit(
                &transaction,
                "channel_release_dispatch_committed",
                "channel_release_publication",
                &candidate.channel_id,
                1,
            )
            .map_err(owner_error)?;
        transaction.commit().map_err(|error| {
            owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite channel release claim outcome is unknown: {error}"
            )))
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(owner_error)?;
        Ok(ChannelReleasePermitClaimV1::Claimed {
            permit: ChannelReleaseBroadcastPermitV1 {
                channel_id: candidate.channel_id.clone(),
                publication_binding_digest: binding_digest,
                authorization_digest: candidate.authorization_digest.clone(),
                prepared_call_digest: candidate.prepared_call_digest.clone(),
                publisher_fence: candidate.publisher_fence,
                record_version: 1,
            },
        })
    }

    fn qualify_new_dispatch(
        &self,
        candidate: &ChannelReleasePublisherCandidate,
        dispatch: &VerifiedEconomicEffectDispatch,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), ChannelReleasePublisherError> {
        if fence != &self.serving_owner.fence {
            return Err(ChannelReleasePublisherError::Fenced);
        }
        let mut connection = self.connection()?;
        self.serving_owner
            .verify_authority_anchor(&connection)
            .map_err(owner_error)?;
        let transaction = connection.transaction().map_err(sqlite_error)?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        validate_candidate(candidate)?;
        validate_candidate_freshness(candidate, trusted_now_unix_ms)?;
        let lifecycle_json = encode(&candidate.closing_lifecycle, "closing channel lifecycle")?;
        let escrow_json = encode(&candidate.closing_escrow, "closing escrow reservation")?;
        qualify_durable_closing(&transaction, candidate, &lifecycle_json, &escrow_json)?;
        let durable_slot = qualify_durable_release_execution(&transaction, candidate, fence)?;
        qualify_exact_dispatch_slot(
            candidate,
            &durable_slot,
            dispatch.slot(),
            dispatch.commit_id(),
        )
    }

    #[cfg(test)]
    fn record_submission_unknown(
        &self,
        permit: &ChannelReleaseBroadcastPermitV1,
        detail: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReleasePublicationRecordV1, ChannelReleasePublisherError> {
        self.record_submission(
            permit,
            SubmissionRecord::Unknown(detail),
            fence,
            trusted_now_unix_ms,
        )
    }

    #[cfg(test)]
    fn record_submission(
        &self,
        permit: &ChannelReleaseBroadcastPermitV1,
        submission: SubmissionRecord<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReleasePublicationRecordV1, ChannelReleasePublisherError> {
        if fence != &self.serving_owner.fence || trusted_now_unix_ms == 0 {
            return Err(ChannelReleasePublisherError::Fenced);
        }
        let mut connection = self.connection()?;
        self.serving_owner
            .verify_authority_anchor(&connection)
            .map_err(owner_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let (status, transaction_hash, failure_detail, mutation_kind) = match submission {
            SubmissionRecord::Submitted(transaction_hash)
                if is_evm_transaction_hash(transaction_hash) =>
            {
                (
                    "submitted",
                    Some(transaction_hash),
                    None,
                    "channel_release_submitted",
                )
            }
            SubmissionRecord::Unknown(detail)
                if !detail.is_empty() && detail.len() <= MAX_FAILURE_DETAIL_BYTES =>
            {
                ("unknown", None, Some(detail), "channel_release_unknown")
            }
            _ => return Err(invalid("channel release submission result is empty")),
        };
        let changed = transaction
            .execute(
                r#"
                UPDATE chio_channel_release_publications
                SET status = ?1, transaction_hash = ?2, failure_detail = ?3,
                    record_version = record_version + 1,
                    store_uuid = ?4, store_lease_id = ?5, store_owner_epoch = ?6,
                    updated_at_unix_ms = ?7
                WHERE channel_id = ?8 AND status = 'dispatch_committed'
                  AND publication_binding_digest = ?9
                  AND authorization_digest = ?10 AND prepared_call_digest = ?11
                  AND publisher_fence = ?12 AND record_version = ?13
                  AND updated_at_unix_ms <= ?7
                "#,
                params![
                    status,
                    transaction_hash,
                    failure_detail,
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                    sqlite_i64(trusted_now_unix_ms, "updated_at_unix_ms")?,
                    &permit.channel_id,
                    &permit.publication_binding_digest,
                    &permit.authorization_digest,
                    &permit.prepared_call_digest,
                    sqlite_i64(permit.publisher_fence, "publisher_fence")?,
                    sqlite_i64(permit.record_version, "record_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            let existing = load_record(&transaction, &permit.channel_id)?
                .ok_or(ChannelReleasePublisherError::Fenced)?;
            let exact = existing.publication_binding_digest == permit.publication_binding_digest
                && existing.authorization_digest == permit.authorization_digest
                && existing.prepared_call_digest == permit.prepared_call_digest
                && existing.publisher_fence == permit.publisher_fence
                && existing.status == submission.status()
                && existing.transaction_hash.as_deref() == submission.transaction_hash()
                && existing.failure_detail.as_deref() == submission.failure_detail();
            if exact {
                return Ok(existing);
            }
            return Err(ChannelReleasePublisherError::Fenced);
        }
        advance_trusted_time(&transaction, trusted_now_unix_ms)?;
        self.serving_owner
            .append_global_commit(
                &transaction,
                mutation_kind,
                "channel_release_publication",
                &permit.channel_id,
                permit
                    .record_version
                    .checked_add(1)
                    .ok_or_else(|| invalid("channel release record version overflowed"))?,
            )
            .map_err(owner_error)?;
        transaction.commit().map_err(|error| {
            owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite channel release submission record outcome is unknown: {error}"
            )))
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(owner_error)?;
        load_record(&connection, &permit.channel_id)?
            .ok_or_else(|| invalid("committed channel release record disappeared"))
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ChannelReleasePublisherError> {
        self.connection.lock().map_err(|_| {
            ChannelReleasePublisherError::Unavailable(
                "sqlite channel release publisher lock poisoned".to_owned(),
            )
        })
    }
}

pub(crate) fn quarantine_incomplete_dispatches_at_startup(
    connection: &mut Connection,
    serving_owner: &SqliteServingOwner,
) -> Result<(), SqliteServingOwnerError> {
    serving_owner.verify_authority_anchor(connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let retained = {
        let mut statement = transaction.prepare(
            r#"
            SELECT channel_id, record_version, updated_at_unix_ms
            FROM chio_channel_release_publications
            WHERE status = 'dispatch_committed'
            ORDER BY channel_id
            "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    if retained.is_empty() {
        return Ok(());
    }
    let trusted_time_high_water = transaction.query_row(
        r#"
        SELECT trusted_time_high_water_unix_ms
        FROM chio_channel_release_publisher_meta
        WHERE singleton = 1
        "#,
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let detail = "deterministic transaction recovery is unavailable for a previously committed channel release dispatch";
    for (channel_id, record_version, updated_at_unix_ms) in retained {
        let next_version = record_version.checked_add(1).ok_or_else(|| {
            SqliteServingOwnerError::Invalid(
                "channel release recovery record version overflowed".to_owned(),
            )
        })?;
        let changed = transaction.execute(
            r#"
            UPDATE chio_channel_release_publications
            SET status = 'unknown', transaction_hash = NULL, failure_detail = ?1,
                record_version = ?2, store_uuid = ?3, store_lease_id = ?4,
                store_owner_epoch = ?5, updated_at_unix_ms = ?6
            WHERE channel_id = ?7 AND status = 'dispatch_committed'
              AND record_version = ?8
            "#,
            params![
                detail,
                next_version,
                &serving_owner.fence.store_uuid,
                &serving_owner.fence.lease_id,
                i64::try_from(serving_owner.fence.owner_epoch).map_err(|_| {
                    SqliteServingOwnerError::Invalid(
                        "channel release recovery owner epoch exceeds SQLite range".to_owned(),
                    )
                })?,
                updated_at_unix_ms.max(trusted_time_high_water),
                &channel_id,
                record_version,
            ],
        )?;
        if changed != 1 {
            return Err(SqliteServingOwnerError::Invalid(
                "channel release startup quarantine lost its retained row".to_owned(),
            ));
        }
        serving_owner.append_global_commit(
            &transaction,
            "channel_release_startup_outcome_unknown",
            "channel_release_publication",
            &channel_id,
            u64::try_from(next_version).map_err(|_| {
                SqliteServingOwnerError::Invalid(
                    "channel release recovery record version is invalid".to_owned(),
                )
            })?,
        )?;
    }
    transaction.commit().map_err(|error| {
        serving_owner.outcome_unknown(format!(
            "sqlite channel release startup quarantine outcome is unknown: {error}"
        ))
    })?;
    serving_owner.sync_authority_anchor(connection)
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum SubmissionRecord<'a> {
    Submitted(&'a str),
    Unknown(&'a str),
}

#[cfg(test)]
impl<'a> SubmissionRecord<'a> {
    const fn status(self) -> ChannelReleasePublicationStatusV1 {
        match self {
            Self::Submitted(_) => ChannelReleasePublicationStatusV1::Submitted,
            Self::Unknown(_) => ChannelReleasePublicationStatusV1::Unknown,
        }
    }

    const fn transaction_hash(self) -> Option<&'a str> {
        match self {
            Self::Submitted(transaction_hash) => Some(transaction_hash),
            Self::Unknown(_) => None,
        }
    }

    fn failure_detail(&self) -> Option<&'a str> {
        match *self {
            Self::Submitted(_) => None,
            Self::Unknown(detail) => Some(detail),
        }
    }
}

#[cfg(test)]
#[path = "channel_release_publisher_store_tests.rs"]
mod tests;
