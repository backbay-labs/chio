use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{Keypair, PublicKey, Signature};
use chio_core::receipt::body::ChioReceipt;
use chio_credit::obligation::{
    ObligationAtomV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
    ObligationDispositionV1,
};
use chio_settle::channel::derive_channel_receipt_authority_digest;
use serde::{Deserialize, Serialize};

use crate::receipt_store::{AuthorizationReceiptConsumption, PendingSettlementObservation};
use crate::tool_outcome::{VerifiedPreDispatchNoEffect, VerifiedTransportNotAccepted};

use super::*;

const SIGNED_TERMINAL_PROJECTION_SCHEMA: &str = "chio.signed-admission-terminal-projection.v1";
const SIGNED_TERMINAL_PROJECTION_DOMAIN: &[u8] = b"chio.signed-admission-terminal-projection.v1\0";
pub const MAX_ADMISSION_TERMINAL_PROJECTION_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ADMISSION_TERMINAL_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_ADMISSION_TERMINAL_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_ADMISSION_TERMINAL_RECORDS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedAdmissionTerminalProjectionRecordV1 {
    pub kind: AdmissionProjectionRecordKind,
    pub record_id: AdmissionIdentifier,
    pub record_digest: AdmissionDigest,
    pub canonical_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTerminalObserverProjectionV1 {
    pub receipt_id: AdmissionIdentifier,
    pub pending: PendingSettlementObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmissionTerminalProjectionBodyV1 {
    schema: String,
    signer_key: PublicKey,
    context: AdmissionProjectionContext,
    source_operation: PersistedAdmissionOperationV1,
    terminal_operation: PersistedAdmissionOperationV1,
    projection_json: String,
    manifest_json: String,
    records: Vec<PersistedAdmissionTerminalProjectionRecordV1>,
    authorization_consumption: Option<AuthorizationReceiptConsumption>,
    observer: Option<AdmissionTerminalObserverProjectionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAdmissionTerminalProjectionV1 {
    body: SignedAdmissionTerminalProjectionBodyV1,
    signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmissionTerminalProjectionRecordV1 {
    kind: AdmissionProjectionRecordKind,
    record_id: AdmissionIdentifier,
    record_digest: AdmissionDigest,
    canonical_json: Vec<u8>,
}

impl VerifiedAdmissionTerminalProjectionRecordV1 {
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

    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAdmissionTerminalProjectionV1 {
    signer_key: PublicKey,
    context: AdmissionProjectionContext,
    source_operation: AdmissionOperationV1,
    terminal_operation: AdmissionOperationV1,
    projection_json: Vec<u8>,
    manifest_json: Vec<u8>,
    records: Vec<VerifiedAdmissionTerminalProjectionRecordV1>,
    channel_terminal: Option<VerifiedChannelTerminalProjectionV1>,
    anchored_transport_cancellation: bool,
    anchored_economic_mutation: bool,
    pre_dispatch_release_proof: Option<VerifiedPreDispatchNoEffect>,
    authorization_consumption: Option<AuthorizationReceiptConsumption>,
    observer: Option<AdmissionTerminalObserverProjectionV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrustedTerminalObligationSourceV1 {
    binding: AdmissionExactProjectionBindingV1,
    source_authority_digest: AdmissionDigest,
    source_record_id: AdmissionIdentifier,
    source_record_digest: AdmissionDigest,
    source_recorded_at_unix_ms: u64,
    consumer_receipt_id: AdmissionIdentifier,
    consumer_receipt_digest: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrustedTerminalObligationProjectionV1 {
    source: UntrustedTerminalObligationSourceV1,
    atom: ObligationAtomV1,
    disposition_record: ObligationDispositionRecordV1,
}

impl SignedAdmissionTerminalProjectionV1 {
    pub fn from_verified(
        source_operation: &AdmissionOperationV1,
        projection: &AdmissionTerminalProjection,
        capabilities: &AdmissionProjectionCapabilities,
        signer: &Keypair,
    ) -> Result<Self, AdmissionOperationError> {
        let canonical = projection.canonical_projection()?;
        let terminal_operation =
            source_operation.apply_terminal_projection(projection, capabilities)?;
        let (authorization_consumption, observer) = match projection {
            AdmissionTerminalProjection::Completed(completed) => (
                completed
                    .authorization
                    .as_ref()
                    .map(|authorization| authorization.consumption().clone()),
                completed
                    .observer_work
                    .as_ref()
                    .map(|observer| {
                        Ok(AdmissionTerminalObserverProjectionV1 {
                            receipt_id: AdmissionIdentifier::try_new(
                                "observer_receipt_id",
                                completed.receipt.receipt().id.clone(),
                            )?,
                            pending: *observer.pending(),
                        })
                    })
                    .transpose()?,
            ),
            _ => (None, None),
        };
        let records = canonical
            .records()
            .iter()
            .map(|record| PersistedAdmissionTerminalProjectionRecordV1 {
                kind: record.commitment().kind(),
                record_id: record.commitment().record_id().clone(),
                record_digest: record.commitment().record_digest().clone(),
                canonical_json: STANDARD.encode(record.canonical_bytes()),
            })
            .collect();
        let body = SignedAdmissionTerminalProjectionBodyV1 {
            schema: SIGNED_TERMINAL_PROJECTION_SCHEMA.to_owned(),
            signer_key: signer.public_key(),
            context: projection.context().clone(),
            source_operation: source_operation.to_persisted(),
            terminal_operation: terminal_operation.to_persisted(),
            projection_json: STANDARD.encode(canonical.projection_bytes()),
            manifest_json: STANDARD.encode(canonical.manifest_bytes()),
            records,
            authorization_consumption,
            observer,
        };
        let signature = signer.sign(&signing_preimage(&body)?);
        let envelope = Self { body, signature };
        envelope.verify()?;
        Ok(envelope)
    }

    pub fn verify(&self) -> Result<VerifiedAdmissionTerminalProjectionV1, AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        if self.body.schema != SIGNED_TERMINAL_PROJECTION_SCHEMA
            || !self
                .body
                .signer_key
                .verify(&signing_preimage(&self.body)?, &self.signature)
        {
            return Err(mismatch());
        }
        self.body.context.validate()?;
        let source_operation =
            AdmissionOperationV1::from_persisted(self.body.source_operation.clone())?;
        let terminal_operation =
            AdmissionOperationV1::from_persisted(self.body.terminal_operation.clone())?;
        let projection_json = decode_bounded(
            &self.body.projection_json,
            MAX_ADMISSION_TERMINAL_PROJECTION_BYTES,
        )?;
        let manifest_json = decode_bounded(
            &self.body.manifest_json,
            MAX_ADMISSION_TERMINAL_MANIFEST_BYTES,
        )?;
        let manifest = AdmissionProjectionManifestV1::from_canonical_bytes(&manifest_json)?;
        manifest.verify_projection_body(&projection_json)?;
        let projection_digest = manifest.projection_digest()?;
        validate_terminal_successor(
            &source_operation,
            &terminal_operation,
            &self.body.context,
            &projection_digest,
        )?;
        validate_projection_body(
            &projection_json,
            &self.body.context,
            terminal_operation.state(),
        )?;
        let records = validate_records(&self.body.records, &manifest)?;
        validate_record_set(&source_operation, terminal_operation.state(), &records)?;
        validate_receipt_record(
            &records,
            &source_operation,
            &terminal_operation,
            &self.body.context,
            &self.body.signer_key,
        )?;
        let channel_terminal =
            validate_channel_terminal_record(&records, &source_operation, &self.body.context)?;
        let anchored_economic_mutation = validate_economic_mutation_result_record(
            &records,
            &source_operation,
            &terminal_operation,
            &self.body.context,
        )?;
        let (pre_dispatch_release_proof, anchored_transport_cancellation) =
            validate_release_proof_record(
                &records,
                &source_operation,
                terminal_operation.state(),
                &self.body.context,
            )?;
        validate_sidecars(
            &records,
            self.body.authorization_consumption.as_ref(),
            self.body.observer.as_ref(),
        )?;
        Ok(VerifiedAdmissionTerminalProjectionV1 {
            signer_key: self.body.signer_key.clone(),
            context: self.body.context.clone(),
            source_operation,
            terminal_operation,
            projection_json,
            manifest_json,
            records,
            channel_terminal,
            anchored_transport_cancellation,
            anchored_economic_mutation,
            pre_dispatch_release_proof,
            authorization_consumption: self.body.authorization_consumption.clone(),
            observer: self.body.observer.clone(),
        })
    }
}

impl VerifiedAdmissionTerminalProjectionV1 {
    #[must_use]
    pub const fn signer_key(&self) -> &PublicKey {
        &self.signer_key
    }

    #[must_use]
    pub const fn pre_dispatch_release_proof(&self) -> Option<&VerifiedPreDispatchNoEffect> {
        self.pre_dispatch_release_proof.as_ref()
    }

    #[must_use]
    pub const fn context(&self) -> &AdmissionProjectionContext {
        &self.context
    }

    #[must_use]
    pub const fn source_operation(&self) -> &AdmissionOperationV1 {
        &self.source_operation
    }

    #[must_use]
    pub const fn terminal_operation(&self) -> &AdmissionOperationV1 {
        &self.terminal_operation
    }

    #[must_use]
    pub fn projection_json(&self) -> &[u8] {
        &self.projection_json
    }

    #[must_use]
    pub fn manifest_json(&self) -> &[u8] {
        &self.manifest_json
    }

    #[must_use]
    pub fn records(&self) -> &[VerifiedAdmissionTerminalProjectionRecordV1] {
        &self.records
    }

    #[must_use]
    pub const fn channel_terminal(&self) -> Option<&VerifiedChannelTerminalProjectionV1> {
        self.channel_terminal.as_ref()
    }

    #[must_use]
    pub const fn requires_anchored_economic_commit(&self) -> bool {
        self.channel_terminal.is_some()
            || self.anchored_transport_cancellation
            || self.anchored_economic_mutation
    }

    #[must_use]
    pub const fn authorization_consumption(&self) -> Option<&AuthorizationReceiptConsumption> {
        self.authorization_consumption.as_ref()
    }

    #[must_use]
    pub const fn observer(&self) -> Option<&AdmissionTerminalObserverProjectionV1> {
        self.observer.as_ref()
    }

    pub fn terminal(&self) -> Result<AdmissionTerminal, AdmissionOperationError> {
        Ok(AdmissionTerminal {
            operation_id: self.context.operation_id.clone(),
            state: self.terminal_operation.state(),
            replay: self
                .terminal_operation
                .terminal_replay()
                .cloned()
                .ok_or(AdmissionOperationError::TerminalReplayMismatch)?,
        })
    }
}

fn signing_preimage(
    body: &SignedAdmissionTerminalProjectionBodyV1,
) -> Result<Vec<u8>, AdmissionOperationError> {
    let canonical = canonical_json_bytes(body)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut preimage =
        Vec::with_capacity(SIGNED_TERMINAL_PROJECTION_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(SIGNED_TERMINAL_PROJECTION_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

fn decode_bounded(value: &str, maximum: usize) -> Result<Vec<u8>, AdmissionOperationError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(bytes)
}

fn validate_terminal_successor(
    source: &AdmissionOperationV1,
    terminal: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projection_digest: &AdmissionDigest,
) -> Result<(), AdmissionOperationError> {
    let source_persisted = source.to_persisted();
    let terminal_persisted = terminal.to_persisted();
    if source.state().is_terminal()
        || !terminal.state().is_terminal()
        || context.operation_id != *source.binding().operation_id()
        || context.request_id != source.replay_key().request_id
        || context.expected_operation_version != source.version()
        || context.coordinator_lease_epoch != source.coordinator_lease_epoch()
        || source_persisted.binding != terminal_persisted.binding
        || source_persisted.attachments != terminal_persisted.attachments
        || source_persisted.dispatch_commit != terminal_persisted.dispatch_commit
        || source_persisted.coordinator_lease_epoch != terminal_persisted.coordinator_lease_epoch
        || source_persisted.last_error != terminal_persisted.last_error
        || terminal.version() != next_version(source.version())?
        || !is_legal_transition(
            source.binding().kind(),
            source.binding().participant_requirements(),
            source.state(),
            terminal.state(),
        )
        || terminal
            .terminal_replay()
            .is_none_or(|replay| replay.projection_digest() != projection_digest)
        || source.dispatch_commit().is_some_and(|commit| {
            commit.store_fence.store_uuid != context.store_fence.store_uuid
                || (context.store_fence != commit.store_fence
                    && context.store_fence.owner_epoch <= commit.store_fence.owner_epoch)
        })
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn validate_projection_body(
    bytes: &[u8],
    context: &AdmissionProjectionContext,
    terminal_state: AdmissionOperationState,
) -> Result<(), AdmissionOperationError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    if canonical_json_bytes(&value)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
        != bytes
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let expected_terminal = match terminal_state {
        AdmissionOperationState::Completed => "completed",
        AdmissionOperationState::CompensatedBeforeDispatch => "compensated_before_dispatch",
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            "not_accepted_after_dispatch_commit"
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        AdmissionOperationState::EconomicMutationApplied => "economic_mutation_applied",
        AdmissionOperationState::EconomicMutationNotApplied => "economic_mutation_not_applied",
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    };
    if value.get("terminal").and_then(serde_json::Value::as_str) != Some(expected_terminal)
        || value.get("context")
            != Some(
                &serde_json::to_value(context)
                    .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
            )
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn validate_records(
    records: &[PersistedAdmissionTerminalProjectionRecordV1],
    manifest: &AdmissionProjectionManifestV1,
) -> Result<Vec<VerifiedAdmissionTerminalProjectionRecordV1>, AdmissionOperationError> {
    if records.is_empty()
        || records.len() > MAX_ADMISSION_TERMINAL_RECORDS
        || records.len() != manifest.records().len()
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    records
        .iter()
        .zip(manifest.records())
        .map(|(record, commitment)| {
            let canonical_json =
                decode_bounded(&record.canonical_json, MAX_ADMISSION_TERMINAL_RECORD_BYTES)?;
            let value: serde_json::Value = serde_json::from_slice(&canonical_json)
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
            if canonical_json_bytes(&value)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?
                != canonical_json
                || sha256_hex(&canonical_json) != record.record_digest.as_str()
                || record.kind != commitment.kind()
                || record.record_id != *commitment.record_id()
                || record.record_digest != *commitment.record_digest()
            {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
            }
            Ok(VerifiedAdmissionTerminalProjectionRecordV1 {
                kind: record.kind,
                record_id: record.record_id.clone(),
                record_digest: record.record_digest.clone(),
                canonical_json,
            })
        })
        .collect()
}

fn validate_record_set(
    source: &AdmissionOperationV1,
    terminal_state: AdmissionOperationState,
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
) -> Result<(), AdmissionOperationError> {
    validate_record_set_shape(
        source.binding().kind(),
        source.binding().participant_requirements(),
        terminal_state,
        records,
    )
}

fn validate_record_set_shape(
    operation_kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    terminal_state: AdmissionOperationState,
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
) -> Result<(), AdmissionOperationError> {
    let actual = records
        .iter()
        .map(|record| record.kind)
        .collect::<BTreeSet<_>>();
    if actual.len() != records.len() {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let mut expected = BTreeSet::new();
    match terminal_state {
        AdmissionOperationState::Completed => {
            expected.insert(AdmissionProjectionRecordKind::Receipt);
            if operation_kind == AdmissionOperationKind::ToolDispatch {
                expected.insert(AdmissionProjectionRecordKind::ToolOutcome);
            }
            for (required, kind) in [
                (
                    requirements.payment,
                    AdmissionProjectionRecordKind::PaymentTerminal,
                ),
                (
                    requirements.authorization_consumption,
                    AdmissionProjectionRecordKind::AuthorizationConsumption,
                ),
                (
                    requirements.outcome_eligibility,
                    AdmissionProjectionRecordKind::OutcomeEligibility,
                ),
                (
                    requirements.observation_attempt_zero,
                    AdmissionProjectionRecordKind::ObservationAttemptZero,
                ),
            ] {
                if required {
                    expected.insert(kind);
                }
            }
            if requirements.channel {
                expected.insert(AdmissionProjectionRecordKind::ChannelTerminal);
                if channel_terminal_charge(records)?.units > 0 {
                    expected.insert(AdmissionProjectionRecordKind::Obligation);
                }
            } else if requirements.obligation {
                expected.insert(AdmissionProjectionRecordKind::Obligation);
            }
        }
        AdmissionOperationState::CompensatedBeforeDispatch
        | AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            expected.insert(AdmissionProjectionRecordKind::ReleaseProof);
            let evidence_count =
                usize::from(actual.contains(&AdmissionProjectionRecordKind::Receipt))
                    + usize::from(actual.contains(&AdmissionProjectionRecordKind::Incident));
            if evidence_count != 1 {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
            }
            expected.insert(
                if actual.contains(&AdmissionProjectionRecordKind::Receipt) {
                    AdmissionProjectionRecordKind::Receipt
                } else {
                    AdmissionProjectionRecordKind::Incident
                },
            );
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            expected.insert(AdmissionProjectionRecordKind::Incident);
        }
        AdmissionOperationState::EconomicMutationApplied
        | AdmissionOperationState::EconomicMutationNotApplied => {
            expected.insert(AdmissionProjectionRecordKind::EconomicMutationResult);
            expected.insert(AdmissionProjectionRecordKind::MutationAudit);
        }
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
    if actual != expected {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}

fn validate_release_proof_record(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    source: &AdmissionOperationV1,
    terminal_state: AdmissionOperationState,
    context: &AdmissionProjectionContext,
) -> Result<(Option<VerifiedPreDispatchNoEffect>, bool), AdmissionOperationError> {
    let record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::ReleaseProof);
    match (terminal_state, record) {
        (AdmissionOperationState::CompensatedBeforeDispatch, Some(record)) => {
            VerifiedPreDispatchNoEffect::from_canonical_record_verified(
                record.canonical_json(),
                source,
                context,
            )
            .map(|proof| (Some(proof), false))
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)
        }
        (AdmissionOperationState::NotAcceptedAfterDispatchCommit, Some(record)) => {
            VerifiedTransportNotAccepted::from_canonical_record_verified(
                record.canonical_json(),
                source,
                context,
            )
            .map(|proof| (None, proof.uses_economic_effect_cancellation()))
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)
        }
        (
            AdmissionOperationState::Completed
            | AdmissionOperationState::OutcomeUnknownAfterDispatch
            | AdmissionOperationState::EconomicMutationApplied
            | AdmissionOperationState::EconomicMutationNotApplied,
            None,
        ) => Ok((None, false)),
        _ => Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
}

fn validate_economic_mutation_result_record(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    source: &AdmissionOperationV1,
    terminal: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> Result<bool, AdmissionOperationError> {
    if !matches!(
        terminal.state(),
        AdmissionOperationState::EconomicMutationApplied
            | AdmissionOperationState::EconomicMutationNotApplied
    ) {
        return Ok(false);
    }
    let record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::EconomicMutationResult)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let result: GovernedEconomicMutationResultBinding =
        serde_json::from_slice(record.canonical_json())
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    result
        .validate_remote_terminal(source, context, terminal, record.record_id())
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)
}

fn channel_terminal_charge(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
) -> Result<MonetaryAmount, AdmissionOperationError> {
    let record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::ChannelTerminal)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let value: serde_json::Value = serde_json::from_slice(record.canonical_json())
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let charge = value
        .get("actual_charge")
        .cloned()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)
        .and_then(|value| {
            serde_json::from_value::<MonetaryAmount>(value)
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)
        })?;
    if charge.units > ((1_u64 << 53) - 1)
        || charge.currency.len() != 3
        || !charge
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(charge)
}

fn validate_channel_terminal_record(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    source: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> Result<Option<VerifiedChannelTerminalProjectionV1>, AdmissionOperationError> {
    let Some(record) = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::ChannelTerminal)
    else {
        return Ok(None);
    };
    let channel = VerifiedChannelTerminalProjectionV1::from_canonical_record_verified(
        record.canonical_json(),
        source,
        context,
    )?;
    if channel.record_id() != record.record_id() {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let receipt_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::Receipt)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let receipt: ChioReceipt = serde_json::from_slice(receipt_record.canonical_json())
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let receipt_digest = AdmissionDigest::try_new(
        "channel_terminal_receipt_digest",
        sha256_hex(
            &canonical_json_bytes(&receipt)
                .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?,
        ),
    )?;
    let expected_authority = AdmissionDigest::try_new(
        "channel_terminal_receipt_authority_digest",
        derive_channel_receipt_authority_digest(&receipt.kernel_key)
            .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?,
    )?;
    let financial = receipt
        .financial_metadata()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let metadata = receipt
        .channel_metadata()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let tool_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::ToolOutcome)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let Some(chio_core::economic_continuity::EconomicEffectTerminalV1::Completed {
        result_id,
        result_digest,
        result,
    }) = channel.completed_effect_slot().terminal.as_ref()
    else {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    };
    let chio_core::economic_continuity::EconomicContentV1::Inline { value } = result else {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    };
    let result_bytes = canonical_json_bytes(value)
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let expected_result_digest = result
        .digest()
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    if channel.receipt_id().as_str() != receipt.id
        || channel.receipt_digest() != &receipt_digest
        || channel.receipt_authority_digest() != &expected_authority
        || channel.actual_charge().units != financial.cost_charged
        || channel.actual_charge().currency != financial.currency
        || metadata.channel_id != channel.signed_reservation().body.channel_id
        || metadata.open_digest != channel.signed_reservation().body.open_digest
        || metadata.reservation_id != channel.signed_reservation().body.reservation_id
        || metadata.reservation_digest != channel.reservation_digest().as_str()
        || metadata.sequence != channel.signed_reservation().body.next_sequence
        || result_id != tool_record.record_id().as_str()
        || result_digest != &expected_result_digest
        || result_bytes != tool_record.canonical_json()
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    validate_channel_obligation_record(records, source, context, &channel, &receipt, tool_record)?;
    Ok(Some(channel))
}

fn validate_channel_obligation_record(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    source: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    channel: &VerifiedChannelTerminalProjectionV1,
    receipt: &ChioReceipt,
    tool_record: &VerifiedAdmissionTerminalProjectionRecordV1,
) -> Result<(), AdmissionOperationError> {
    let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
    let obligation_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::Obligation);
    if channel.actual_charge().units == 0 {
        if obligation_record.is_some()
            || channel.obligation_atom_id().is_some()
            || channel.obligation_atom_digest().is_some()
        {
            return Err(mismatch());
        }
        return Ok(());
    }
    let obligation_record = obligation_record.ok_or_else(mismatch)?;
    let obligation: UntrustedTerminalObligationProjectionV1 =
        serde_json::from_slice(obligation_record.canonical_json()).map_err(|_| mismatch())?;
    obligation.source.binding.validate_against(
        source,
        context,
        AdmissionOperationState::Completed,
    )?;
    obligation.atom.validate().map_err(|_| mismatch())?;
    obligation
        .disposition_record
        .validate_against(&obligation.atom)
        .map_err(|_| mismatch())?;
    let atom_digest = obligation.atom.digest().map_err(|_| mismatch())?;
    let proposal_intent_digest = channel
        .signed_reservation()
        .body
        .proposal_digest()
        .map_err(|_| mismatch())?;
    let tool_value: serde_json::Value =
        serde_json::from_slice(tool_record.canonical_json()).map_err(|_| mismatch())?;
    let outcome_version = tool_value
        .get("outcome_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(mismatch)?;
    validate_positive_ijson("channel_terminal_outcome_version", outcome_version)?;
    let disposition_matches = matches!(
        obligation.disposition_record.disposition(),
        ObligationDispositionV1::Channelized {
            channel_id,
            reservation_id,
        } if channel_id == &channel.signed_reservation().body.channel_id
            && reservation_id == &channel.signed_reservation().body.reservation_id
    );
    let transition_matches = matches!(
        obligation.disposition_record.last_transition(),
        ObligationDispositionTransitionV1::ReserveChannel {
            channel_id,
            reservation_id,
            authority_digest,
        } if channel_id == &channel.signed_reservation().body.channel_id
            && reservation_id == &channel.signed_reservation().body.reservation_id
            && authority_digest == channel.reservation_digest().as_str()
    );
    if obligation_record.record_id().as_str() != source.binding().operation_id().as_str()
        || channel
            .obligation_atom_id()
            .map(AdmissionIdentifier::as_str)
            != Some(obligation.atom.obligation_id())
        || channel
            .obligation_atom_digest()
            .map(AdmissionDigest::as_str)
            != Some(atom_digest.as_str())
        || obligation.atom.amount() != channel.actual_charge()
        || obligation.atom.economic_intent_digest() != proposal_intent_digest.as_str()
        || obligation.atom.source_receipt_id() != receipt.id.as_str()
        || obligation.atom.source_receipt_id() != channel.receipt_id().as_str()
        || obligation.atom.source_receipt_digest() != channel.receipt_digest().as_str()
        || obligation.atom.pre_action_authority_digest() != channel.reservation_digest().as_str()
        || obligation.atom.created_at_unix_ms() > context.trusted_time_unix_ms
        || obligation.source.source_authority_digest != *channel.reservation_digest()
        || obligation.source.source_record_id.as_str() != obligation.atom.obligation_id()
        || obligation.source.source_record_digest.as_str() != atom_digest.as_str()
        || obligation.source.source_recorded_at_unix_ms != obligation.atom.created_at_unix_ms()
        || obligation.source.consumer_receipt_id != *channel.receipt_id()
        || obligation.source.consumer_receipt_digest != *channel.receipt_digest()
        || obligation.source.outcome_id.as_str() != tool_record.record_id().as_str()
        || obligation.source.outcome_version != outcome_version
        || obligation.disposition_record.version() != 2
        || obligation.disposition_record.lifecycle_fence() != 2
        || !disposition_matches
        || !transition_matches
    {
        return Err(mismatch());
    }
    Ok(())
}

fn validate_receipt_record(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    source: &AdmissionOperationV1,
    terminal: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    signer_key: &PublicKey,
) -> Result<(), AdmissionOperationError> {
    let Some(record) = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::Receipt)
    else {
        return Ok(());
    };
    let receipt: ChioReceipt = serde_json::from_slice(&record.canonical_json)
        .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    if receipt.id != record.record_id.as_str() || receipt.kernel_key != *signer_key {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(ADMISSION_RECEIPT_METADATA_KEY))
        .cloned()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)
        .and_then(|value| {
            serde_json::from_value::<AdmissionReceiptMetadataV1>(value)
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)
        })?;
    let outcome = metadata
        .tool_outcome_id
        .as_ref()
        .zip(metadata.tool_outcome_version);
    let compensation = match terminal.state() {
        AdmissionOperationState::Completed => AdmissionCompensationStatus::NotCompensated,
        AdmissionOperationState::CompensatedBeforeDispatch => {
            AdmissionCompensationStatus::CompensatedBeforeDispatch
        }
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            AdmissionCompensationStatus::NotAcceptedAfterDispatchCommit
        }
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    };
    validate_receipt_projection(
        &receipt,
        source,
        context,
        terminal.state(),
        compensation,
        outcome,
    )
}

fn validate_sidecars(
    records: &[VerifiedAdmissionTerminalProjectionRecordV1],
    authorization: Option<&AuthorizationReceiptConsumption>,
    observer: Option<&AdmissionTerminalObserverProjectionV1>,
) -> Result<(), AdmissionOperationError> {
    let authorization_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::AuthorizationConsumption);
    match (authorization_record, authorization) {
        (Some(record), Some(authorization))
            if record.record_id.as_str() == authorization.authorization_receipt_id
                && record.canonical_json
                    == canonical_json_bytes(authorization).map_err(|error| {
                        AdmissionOperationError::CanonicalJson(error.to_string())
                    })? => {}
        (None, None) => {}
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
    let observer_record = records
        .iter()
        .find(|record| record.kind == AdmissionProjectionRecordKind::ObservationAttemptZero);
    match (observer_record, observer) {
        (Some(record), Some(observer))
            if record.record_id == observer.receipt_id
                && record.canonical_json
                    == canonical_json_bytes(&observer.pending).map_err(|error| {
                        AdmissionOperationError::CanonicalJson(error.to_string())
                    })? => {}
        (None, None) => {}
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        kind: AdmissionProjectionRecordKind,
        value: serde_json::Value,
    ) -> Result<VerifiedAdmissionTerminalProjectionRecordV1, AdmissionOperationError> {
        let canonical_json = canonical_json_bytes(&value)
            .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
        Ok(VerifiedAdmissionTerminalProjectionRecordV1 {
            kind,
            record_id: AdmissionIdentifier::try_new("record_id", kind.as_str().to_owned())?,
            record_digest: AdmissionDigest::try_new("record_digest", sha256_hex(&canonical_json))?,
            canonical_json,
        })
    }

    fn channel_records(
        units: u64,
    ) -> Result<Vec<VerifiedAdmissionTerminalProjectionRecordV1>, AdmissionOperationError> {
        Ok(vec![
            record(
                AdmissionProjectionRecordKind::Receipt,
                serde_json::json!({}),
            )?,
            record(
                AdmissionProjectionRecordKind::ToolOutcome,
                serde_json::json!({}),
            )?,
            record(
                AdmissionProjectionRecordKind::ChannelTerminal,
                serde_json::json!({
                    "actual_charge": { "currency": "USD", "units": units }
                }),
            )?,
        ])
    }

    #[test]
    fn channel_record_set_requires_charge_dependent_obligation(
    ) -> Result<(), AdmissionOperationError> {
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            obligation: true,
            channel: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let validate = |records: &[VerifiedAdmissionTerminalProjectionRecordV1]| {
            validate_record_set_shape(
                AdmissionOperationKind::ToolDispatch,
                requirements,
                AdmissionOperationState::Completed,
                records,
            )
        };

        let mut positive = channel_records(7)?;
        assert_eq!(
            validate(&positive),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        );
        positive.push(record(
            AdmissionProjectionRecordKind::Obligation,
            serde_json::json!({}),
        )?);
        validate(&positive)?;

        let mut zero = channel_records(0)?;
        validate(&zero)?;
        zero.push(record(
            AdmissionProjectionRecordKind::Obligation,
            serde_json::json!({}),
        )?);
        assert_eq!(
            validate(&zero),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn channel_record_set_rejects_missing_duplicate_and_malformed_terminal_records(
    ) -> Result<(), AdmissionOperationError> {
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            obligation: true,
            channel: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let validate = |records: &[VerifiedAdmissionTerminalProjectionRecordV1]| {
            validate_record_set_shape(
                AdmissionOperationKind::ToolDispatch,
                requirements,
                AdmissionOperationState::Completed,
                records,
            )
        };

        let mut missing = channel_records(0)?;
        missing.retain(|record| record.kind != AdmissionProjectionRecordKind::ChannelTerminal);
        assert!(validate(&missing).is_err());

        let mut duplicate = channel_records(0)?;
        duplicate.push(record(
            AdmissionProjectionRecordKind::ChannelTerminal,
            serde_json::json!({
                "actual_charge": { "currency": "USD", "units": 0 }
            }),
        )?);
        assert!(validate(&duplicate).is_err());

        let mut malformed = channel_records(0)?;
        let channel_record = malformed
            .iter_mut()
            .find(|record| record.kind == AdmissionProjectionRecordKind::ChannelTerminal)
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
        channel_record.canonical_json = canonical_json_bytes(&serde_json::json!({
            "actual_charge": { "currency": "usd", "units": 0 }
        }))
        .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
        assert!(validate(&malformed).is_err());
        Ok(())
    }

    #[test]
    fn non_channel_record_set_preserves_legacy_obligation_shape(
    ) -> Result<(), AdmissionOperationError> {
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            obligation: true,
            ..AdmissionParticipantRequirements::NONE
        };
        let mut records = vec![
            record(
                AdmissionProjectionRecordKind::Receipt,
                serde_json::json!({}),
            )?,
            record(
                AdmissionProjectionRecordKind::ToolOutcome,
                serde_json::json!({}),
            )?,
            record(
                AdmissionProjectionRecordKind::Obligation,
                serde_json::json!({}),
            )?,
        ];
        let validate = |records: &[VerifiedAdmissionTerminalProjectionRecordV1]| {
            validate_record_set_shape(
                AdmissionOperationKind::ToolDispatch,
                requirements,
                AdmissionOperationState::Completed,
                records,
            )
        };
        validate(&records)?;

        records.push(record(
            AdmissionProjectionRecordKind::ChannelTerminal,
            serde_json::json!({
                "actual_charge": { "currency": "USD", "units": 0 }
            }),
        )?);
        assert_eq!(
            validate(&records),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        );
        Ok(())
    }
}
