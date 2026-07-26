use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use super::{
    contract::authenticate_outcome_eligibility_at, domain_digest, domain_digest_without_field,
    envelope_digest, load_canonical_outcome_json, validate_digest, validate_text, validate_time,
    AuthenticatedOutcomeEligibilityV1, OutcomeEligibilityAuthenticationV1, OutcomeError,
    OutcomeSignerTrustV1,
};

pub const OUTCOME_DELIVERY_CHECKPOINT_SCHEMA: &str =
    chio_core_types::CHIO_OUTCOME_DELIVERY_CHECKPOINT_V1_SCHEMA;
pub const OUTCOME_DELIVERY_ACKNOWLEDGEMENT_SCHEMA: &str =
    chio_core_types::CHIO_OUTCOME_DELIVERY_ACKNOWLEDGEMENT_V1_SCHEMA;
pub const OUTCOME_DELIVERY_NONACCEPTANCE_SCHEMA: &str =
    chio_core_types::CHIO_OUTCOME_DELIVERY_NONACCEPTANCE_V1_SCHEMA;

const ACK_ID_DOMAIN: &[u8] = b"chio.outcome.delivery-acknowledgement.id.v1\0";
const NONACCEPTANCE_ID_DOMAIN: &[u8] = b"chio.outcome.delivery-nonacceptance.id.v1\0";
const RECEIVER_BINDING_DOMAIN: &[u8] = b"chio.outcome.receiver-binding.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeDeliveryCheckpointStateV1 {
    Pending,
    Acknowledged,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeDeliveryCheckpointInputV1 {
    pub anchor_id: String,
    pub anchor_key_epoch: u64,
    pub receiver_binding_digest: String,
    pub receiver_id: String,
    pub receiver_namespace: String,
    pub receiver_key_epoch: u64,
    pub delivery_id: String,
    pub idempotency_key: String,
    pub receiver_queue_id: String,
    pub request_id: String,
    pub eligibility_digest: String,
    pub provider_acceptance_digest: String,
    pub output_digest: String,
    pub trusted_clock_high_water_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeReceiverBindingV1 {
    receiver_binding_digest: String,
    anchor_id: String,
    anchor_key: PublicKey,
    anchor_key_epoch: u64,
    receiver_id: String,
    receiver_namespace: String,
    receiver_key_id: String,
    receiver_key: PublicKey,
    receiver_key_epoch: u64,
}

impl OutcomeReceiverBindingV1 {
    pub fn new(
        receiver_id: String,
        receiver_namespace: String,
        anchor_trust: &OutcomeSignerTrustV1,
        receiver_trust: &OutcomeSignerTrustV1,
    ) -> Result<Self, OutcomeError> {
        validate_text("receiver_id", &receiver_id)?;
        validate_text("receiver_namespace", &receiver_namespace)?;
        let receiver_binding_digest = domain_digest(
            RECEIVER_BINDING_DOMAIN,
            &OutcomeReceiverBindingPreimageV1 {
                anchor_id: anchor_trust.principal_id(),
                anchor_key: anchor_trust.key(),
                anchor_key_epoch: anchor_trust.key_epoch(),
                receiver_id: &receiver_id,
                receiver_namespace: &receiver_namespace,
                receiver_key_id: receiver_trust.principal_id(),
                receiver_key: receiver_trust.key(),
                receiver_key_epoch: receiver_trust.key_epoch(),
            },
        )?;
        Ok(Self {
            receiver_binding_digest,
            anchor_id: anchor_trust.principal_id().to_owned(),
            anchor_key: anchor_trust.key().clone(),
            anchor_key_epoch: anchor_trust.key_epoch(),
            receiver_id,
            receiver_namespace,
            receiver_key_id: receiver_trust.principal_id().to_owned(),
            receiver_key: receiver_trust.key().clone(),
            receiver_key_epoch: receiver_trust.key_epoch(),
        })
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.receiver_binding_digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OutcomeReceiverBindingPreimageV1<'a> {
    anchor_id: &'a str,
    anchor_key: &'a PublicKey,
    anchor_key_epoch: u64,
    receiver_id: &'a str,
    receiver_namespace: &'a str,
    receiver_key_id: &'a str,
    receiver_key: &'a PublicKey,
    receiver_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeDeliveryCheckpointBodyV1 {
    schema: String,
    anchor_id: String,
    anchor_key_epoch: u64,
    receiver_binding_digest: String,
    receiver_id: String,
    receiver_namespace: String,
    receiver_key_epoch: u64,
    delivery_id: String,
    idempotency_key: String,
    receiver_queue_id: String,
    sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_digest: Option<String>,
    state: OutcomeDeliveryCheckpointStateV1,
    request_id: String,
    eligibility_digest: String,
    provider_acceptance_digest: String,
    output_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob_absence_proof_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cancellation_fence_digest: Option<String>,
    trusted_clock_high_water_unix_ms: u64,
}

impl OutcomeDeliveryCheckpointBodyV1 {
    pub fn pending_from_anchor_assertion(
        input: OutcomeDeliveryCheckpointInputV1,
    ) -> Result<Self, OutcomeError> {
        let body = Self {
            schema: OUTCOME_DELIVERY_CHECKPOINT_SCHEMA.to_owned(),
            anchor_id: input.anchor_id,
            anchor_key_epoch: input.anchor_key_epoch,
            receiver_binding_digest: input.receiver_binding_digest,
            receiver_id: input.receiver_id,
            receiver_namespace: input.receiver_namespace,
            receiver_key_epoch: input.receiver_key_epoch,
            delivery_id: input.delivery_id,
            idempotency_key: input.idempotency_key,
            receiver_queue_id: input.receiver_queue_id,
            sequence: 1,
            predecessor_digest: None,
            state: OutcomeDeliveryCheckpointStateV1::Pending,
            request_id: input.request_id,
            eligibility_digest: input.eligibility_digest,
            provider_acceptance_digest: input.provider_acceptance_digest,
            output_digest: input.output_digest,
            blob_reference: None,
            blob_digest: None,
            blob_absence_proof_digest: None,
            cancellation_fence_digest: None,
            trusted_clock_high_water_unix_ms: input.trusted_clock_high_water_unix_ms,
        };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_DELIVERY_CHECKPOINT_SCHEMA {
            return Err(OutcomeError::InvalidField("delivery_checkpoint_schema"));
        }
        for (field, value) in [
            ("anchor_id", &self.anchor_id),
            ("receiver_id", &self.receiver_id),
            ("receiver_namespace", &self.receiver_namespace),
            ("delivery_id", &self.delivery_id),
            ("idempotency_key", &self.idempotency_key),
            ("receiver_queue_id", &self.receiver_queue_id),
            ("request_id", &self.request_id),
        ] {
            validate_text(field, value)?;
        }
        for (field, value) in [
            ("receiver_binding_digest", &self.receiver_binding_digest),
            ("eligibility_digest", &self.eligibility_digest),
            (
                "provider_acceptance_digest",
                &self.provider_acceptance_digest,
            ),
            ("output_digest", &self.output_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("anchor_key_epoch", self.anchor_key_epoch),
            ("receiver_key_epoch", self.receiver_key_epoch),
            ("sequence", self.sequence),
            (
                "trusted_clock_high_water_unix_ms",
                self.trusted_clock_high_water_unix_ms,
            ),
        ] {
            validate_time(field, value)?;
        }
        if let Some(digest) = &self.predecessor_digest {
            validate_digest("predecessor_digest", digest)?;
        }
        if let Some(reference) = &self.blob_reference {
            validate_text("blob_reference", reference)?;
        }
        for (field, digest) in [
            ("blob_digest", self.blob_digest.as_deref()),
            (
                "blob_absence_proof_digest",
                self.blob_absence_proof_digest.as_deref(),
            ),
            (
                "cancellation_fence_digest",
                self.cancellation_fence_digest.as_deref(),
            ),
        ] {
            if let Some(digest) = digest {
                validate_digest(field, digest)?;
            }
        }
        if self.state == OutcomeDeliveryCheckpointStateV1::Acknowledged
            && self.blob_digest.as_deref() != Some(self.output_digest.as_str())
        {
            return Err(OutcomeError::BindingMismatch);
        }
        let shape_valid = match self.state {
            OutcomeDeliveryCheckpointStateV1::Pending => {
                self.sequence == 1
                    && self.predecessor_digest.is_none()
                    && self.blob_reference.is_none()
                    && self.blob_digest.is_none()
                    && self.blob_absence_proof_digest.is_none()
                    && self.cancellation_fence_digest.is_none()
            }
            OutcomeDeliveryCheckpointStateV1::Acknowledged => {
                self.sequence > 1
                    && self.predecessor_digest.is_some()
                    && self.blob_reference.is_some()
                    && self.blob_digest.is_some()
                    && self.blob_absence_proof_digest.is_none()
                    && self.cancellation_fence_digest.is_none()
            }
            OutcomeDeliveryCheckpointStateV1::Cancelled => {
                self.sequence > 1
                    && self.predecessor_digest.is_some()
                    && self.blob_reference.is_none()
                    && self.blob_digest.is_none()
                    && self.blob_absence_proof_digest.is_some()
                    && self.cancellation_fence_digest.is_some()
            }
        };
        if !shape_valid {
            return Err(OutcomeError::InvalidField("delivery_checkpoint_state"));
        }
        Ok(())
    }

    #[must_use]
    pub const fn state(&self) -> OutcomeDeliveryCheckpointStateV1 {
        self.state
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn receiver_binding_digest(&self) -> &str {
        &self.receiver_binding_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeDeliveryCheckpointV1(SignedExportEnvelope<OutcomeDeliveryCheckpointBodyV1>);

impl SignedOutcomeDeliveryCheckpointV1 {
    pub fn sign(
        body: OutcomeDeliveryCheckpointBodyV1,
        signer: &Keypair,
    ) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomeDeliveryCheckpointBodyV1 {
        &self.0.body
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOutcomeDeliveryCheckpointV1 {
    signed: SignedOutcomeDeliveryCheckpointV1,
    envelope_digest: String,
    receiver_binding: OutcomeReceiverBindingV1,
}

impl AuthenticatedOutcomeDeliveryCheckpointV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomeDeliveryCheckpointBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    pub fn acknowledgement_assertion(
        &self,
        blob_reference: String,
        blob_digest: String,
        trusted_clock_high_water_unix_ms: u64,
    ) -> Result<OutcomeDeliveryCheckpointBodyV1, OutcomeError> {
        validate_text("blob_reference", &blob_reference)?;
        validate_digest("blob_digest", &blob_digest)?;
        if blob_digest != self.body().output_digest {
            return Err(OutcomeError::BindingMismatch);
        }
        self.advance(
            OutcomeDeliveryCheckpointStateV1::Acknowledged,
            Some(blob_reference),
            Some(blob_digest),
            None,
            None,
            trusted_clock_high_water_unix_ms,
        )
    }

    pub fn cancellation_assertion(
        &self,
        blob_absence_proof_digest: String,
        cancellation_fence_digest: String,
        trusted_clock_high_water_unix_ms: u64,
    ) -> Result<OutcomeDeliveryCheckpointBodyV1, OutcomeError> {
        validate_digest("blob_absence_proof_digest", &blob_absence_proof_digest)?;
        validate_digest("cancellation_fence_digest", &cancellation_fence_digest)?;
        self.advance(
            OutcomeDeliveryCheckpointStateV1::Cancelled,
            None,
            None,
            Some(blob_absence_proof_digest),
            Some(cancellation_fence_digest),
            trusted_clock_high_water_unix_ms,
        )
    }

    fn advance(
        &self,
        state: OutcomeDeliveryCheckpointStateV1,
        blob_reference: Option<String>,
        blob_digest: Option<String>,
        blob_absence_proof_digest: Option<String>,
        cancellation_fence_digest: Option<String>,
        trusted_clock_high_water_unix_ms: u64,
    ) -> Result<OutcomeDeliveryCheckpointBodyV1, OutcomeError> {
        if self.body().state != OutcomeDeliveryCheckpointStateV1::Pending
            || trusted_clock_high_water_unix_ms < self.body().trusted_clock_high_water_unix_ms
        {
            return Err(OutcomeError::IllegalTransition);
        }
        let mut next = self.body().clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or(OutcomeError::ArithmeticOverflow)?;
        next.predecessor_digest = Some(self.envelope_digest.clone());
        next.state = state;
        next.blob_reference = blob_reference;
        next.blob_digest = blob_digest;
        next.blob_absence_proof_digest = blob_absence_proof_digest;
        next.cancellation_fence_digest = cancellation_fence_digest;
        next.trusted_clock_high_water_unix_ms = trusted_clock_high_water_unix_ms;
        next.validate()?;
        Ok(next)
    }
}

pub fn authenticate_outcome_delivery_checkpoint(
    canonical_envelope: &[u8],
    trust: &OutcomeSignerTrustV1,
    receiver_binding: &OutcomeReceiverBindingV1,
    current: Option<&AuthenticatedOutcomeDeliveryCheckpointV1>,
) -> Result<AuthenticatedOutcomeDeliveryCheckpointV1, OutcomeError> {
    let signed: SignedOutcomeDeliveryCheckpointV1 =
        load_canonical_outcome_json(canonical_envelope)?;
    signed.body().validate()?;
    if signed.body().anchor_id != trust.principal_id()
        || signed.body().anchor_key_epoch != trust.key_epoch()
        || trust.principal_id() != receiver_binding.anchor_id
        || trust.key() != &receiver_binding.anchor_key
        || trust.key_epoch() != receiver_binding.anchor_key_epoch
        || signed.body().receiver_binding_digest != receiver_binding.receiver_binding_digest
        || signed.body().receiver_id != receiver_binding.receiver_id
        || signed.body().receiver_namespace != receiver_binding.receiver_namespace
        || signed.body().receiver_key_epoch != receiver_binding.receiver_key_epoch
    {
        return Err(OutcomeError::BindingMismatch);
    }
    if signed.0.signer_key != *trust.key()
        || !signed
            .0
            .verify_signature()
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?
    {
        return Err(OutcomeError::AuthorityVerification);
    }
    match current {
        None if signed.body().state == OutcomeDeliveryCheckpointStateV1::Pending => {}
        Some(current) => validate_checkpoint_advance(current, signed.body())?,
        None => return Err(OutcomeError::IllegalTransition),
    }
    Ok(AuthenticatedOutcomeDeliveryCheckpointV1 {
        envelope_digest: envelope_digest(&signed)?,
        signed,
        receiver_binding: receiver_binding.clone(),
    })
}

pub fn authenticate_outcome_eligibility_from_checkpoint(
    canonical_envelope: &[u8],
    context: &OutcomeEligibilityAuthenticationV1<'_>,
    checkpoint: &AuthenticatedOutcomeDeliveryCheckpointV1,
) -> Result<AuthenticatedOutcomeEligibilityV1, OutcomeError> {
    let eligibility = authenticate_outcome_eligibility_at(
        canonical_envelope,
        context,
        checkpoint.body().trusted_clock_high_water_unix_ms,
    )?;
    if checkpoint.body().request_id != eligibility.body().request_id()
        || checkpoint.body().eligibility_digest != eligibility.envelope_digest()
        || checkpoint.body().receiver_binding_digest != eligibility.body().receiver_binding_digest()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    Ok(eligibility)
}

fn validate_checkpoint_advance(
    current: &AuthenticatedOutcomeDeliveryCheckpointV1,
    candidate: &OutcomeDeliveryCheckpointBodyV1,
) -> Result<(), OutcomeError> {
    let previous = current.body();
    let expected_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    let immutable = candidate.anchor_id == previous.anchor_id
        && candidate.anchor_key_epoch == previous.anchor_key_epoch
        && candidate.receiver_binding_digest == previous.receiver_binding_digest
        && candidate.receiver_id == previous.receiver_id
        && candidate.receiver_namespace == previous.receiver_namespace
        && candidate.receiver_key_epoch == previous.receiver_key_epoch
        && candidate.delivery_id == previous.delivery_id
        && candidate.idempotency_key == previous.idempotency_key
        && candidate.receiver_queue_id == previous.receiver_queue_id
        && candidate.request_id == previous.request_id
        && candidate.eligibility_digest == previous.eligibility_digest
        && candidate.provider_acceptance_digest == previous.provider_acceptance_digest
        && candidate.output_digest == previous.output_digest;
    if previous.state != OutcomeDeliveryCheckpointStateV1::Pending
        || !matches!(
            candidate.state,
            OutcomeDeliveryCheckpointStateV1::Acknowledged
                | OutcomeDeliveryCheckpointStateV1::Cancelled
        )
        || candidate.sequence != expected_sequence
        || candidate.predecessor_digest.as_deref() != Some(current.envelope_digest())
        || candidate.trusted_clock_high_water_unix_ms < previous.trusted_clock_high_water_unix_ms
        || !immutable
    {
        return Err(OutcomeError::IllegalTransition);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeDeliveryAcknowledgementInputV1 {
    pub receiver_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeDeliveryAcknowledgementBodyV1 {
    schema: String,
    acknowledgement_id: String,
    request_id: String,
    eligibility_digest: String,
    provider_acceptance_digest: String,
    final_output_digest: String,
    receiver_binding_digest: String,
    delivery_id: String,
    idempotency_key: String,
    receiver_queue_id: String,
    delivery_accepted_at_unix_ms: u64,
    receiver_key_id: String,
    receiver_key_epoch: u64,
    delivery_checkpoint_sequence: u64,
    delivery_checkpoint_digest: String,
    durable_blob_reference: String,
    durable_blob_digest: String,
}

impl OutcomeDeliveryAcknowledgementBodyV1 {
    pub fn from_receiver_assertion(
        eligibility: &AuthenticatedOutcomeEligibilityV1,
        checkpoint: &AuthenticatedOutcomeDeliveryCheckpointV1,
        input: OutcomeDeliveryAcknowledgementInputV1,
    ) -> Result<Self, OutcomeError> {
        let checkpoint_body = checkpoint.body();
        if checkpoint_body.state != OutcomeDeliveryCheckpointStateV1::Acknowledged
            || checkpoint_body.eligibility_digest != eligibility.envelope_digest()
            || checkpoint_body.request_id != eligibility.body().request_id()
            || checkpoint_body.receiver_binding_digest
                != eligibility.body().receiver_binding_digest()
        {
            return Err(OutcomeError::BindingMismatch);
        }
        let mut body = Self {
            schema: OUTCOME_DELIVERY_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
            acknowledgement_id: String::new(),
            request_id: checkpoint_body.request_id.clone(),
            eligibility_digest: checkpoint_body.eligibility_digest.clone(),
            provider_acceptance_digest: checkpoint_body.provider_acceptance_digest.clone(),
            final_output_digest: checkpoint_body.output_digest.clone(),
            receiver_binding_digest: eligibility.body().receiver_binding_digest().to_owned(),
            delivery_id: checkpoint_body.delivery_id.clone(),
            idempotency_key: checkpoint_body.idempotency_key.clone(),
            receiver_queue_id: checkpoint_body.receiver_queue_id.clone(),
            delivery_accepted_at_unix_ms: checkpoint_body.trusted_clock_high_water_unix_ms,
            receiver_key_id: input.receiver_key_id,
            receiver_key_epoch: checkpoint_body.receiver_key_epoch,
            delivery_checkpoint_sequence: checkpoint_body.sequence,
            delivery_checkpoint_digest: checkpoint.envelope_digest.clone(),
            durable_blob_reference: checkpoint_body
                .blob_reference
                .clone()
                .ok_or(OutcomeError::BindingMismatch)?,
            durable_blob_digest: checkpoint_body
                .blob_digest
                .clone()
                .ok_or(OutcomeError::BindingMismatch)?,
        };
        body.acknowledgement_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_DELIVERY_ACKNOWLEDGEMENT_SCHEMA {
            return Err(OutcomeError::InvalidField("delivery_ack_schema"));
        }
        for (field, value) in [
            ("acknowledgement_id", &self.acknowledgement_id),
            ("eligibility_digest", &self.eligibility_digest),
            (
                "provider_acceptance_digest",
                &self.provider_acceptance_digest,
            ),
            ("final_output_digest", &self.final_output_digest),
            ("receiver_binding_digest", &self.receiver_binding_digest),
            (
                "delivery_checkpoint_digest",
                &self.delivery_checkpoint_digest,
            ),
            ("durable_blob_digest", &self.durable_blob_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("request_id", &self.request_id),
            ("delivery_id", &self.delivery_id),
            ("idempotency_key", &self.idempotency_key),
            ("receiver_queue_id", &self.receiver_queue_id),
            ("receiver_key_id", &self.receiver_key_id),
            ("durable_blob_reference", &self.durable_blob_reference),
        ] {
            validate_text(field, value)?;
        }
        for (field, value) in [
            (
                "delivery_accepted_at_unix_ms",
                self.delivery_accepted_at_unix_ms,
            ),
            ("receiver_key_epoch", self.receiver_key_epoch),
            (
                "delivery_checkpoint_sequence",
                self.delivery_checkpoint_sequence,
            ),
        ] {
            validate_time(field, value)?;
        }
        if self.acknowledgement_id != self.derived_id()? {
            return Err(OutcomeError::BindingMismatch);
        }
        if self.final_output_digest != self.durable_blob_digest {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(ACK_ID_DOMAIN, self, "acknowledgementId")
    }

    #[must_use]
    pub const fn delivery_accepted_at_unix_ms(&self) -> u64 {
        self.delivery_accepted_at_unix_ms
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn eligibility_digest(&self) -> &str {
        &self.eligibility_digest
    }

    #[must_use]
    pub fn provider_acceptance_digest(&self) -> &str {
        &self.provider_acceptance_digest
    }

    #[must_use]
    pub fn final_output_digest(&self) -> &str {
        &self.final_output_digest
    }

    #[must_use]
    pub fn receiver_binding_digest(&self) -> &str {
        &self.receiver_binding_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeDeliveryAcknowledgementV1(
    SignedExportEnvelope<OutcomeDeliveryAcknowledgementBodyV1>,
);

impl SignedOutcomeDeliveryAcknowledgementV1 {
    pub fn sign(
        body: OutcomeDeliveryAcknowledgementBodyV1,
        signer: &Keypair,
    ) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOutcomeDeliveryAcknowledgementV1 {
    signed: SignedOutcomeDeliveryAcknowledgementV1,
    envelope_digest: String,
}

impl AuthenticatedOutcomeDeliveryAcknowledgementV1 {
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomeDeliveryAcknowledgementBodyV1 {
        &self.signed.0.body
    }
}

pub fn authenticate_outcome_delivery_acknowledgement(
    canonical_envelope: &[u8],
    eligibility: &AuthenticatedOutcomeEligibilityV1,
    checkpoint: &AuthenticatedOutcomeDeliveryCheckpointV1,
    trust: &OutcomeSignerTrustV1,
) -> Result<AuthenticatedOutcomeDeliveryAcknowledgementV1, OutcomeError> {
    let signed: SignedOutcomeDeliveryAcknowledgementV1 =
        load_canonical_outcome_json(canonical_envelope)?;
    signed.0.body.validate()?;
    if trust.principal_id() != checkpoint.receiver_binding.receiver_key_id
        || trust.key() != &checkpoint.receiver_binding.receiver_key
        || trust.key_epoch() != checkpoint.receiver_binding.receiver_key_epoch
    {
        return Err(OutcomeError::BindingMismatch);
    }
    let expected = OutcomeDeliveryAcknowledgementBodyV1::from_receiver_assertion(
        eligibility,
        checkpoint,
        OutcomeDeliveryAcknowledgementInputV1 {
            receiver_key_id: trust.principal_id().to_owned(),
        },
    )?;
    if signed.0.body != expected || signed.0.body.receiver_key_epoch != trust.key_epoch() {
        return Err(OutcomeError::BindingMismatch);
    }
    if signed.0.signer_key != *trust.key()
        || !signed
            .0
            .verify_signature()
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?
    {
        return Err(OutcomeError::AuthorityVerification);
    }
    if signed.0.body.delivery_accepted_at_unix_ms < eligibility.body().issued_at_unix_ms()
        || signed.0.body.delivery_accepted_at_unix_ms
            > eligibility.body().delivery_ack_deadline_unix_ms()
        || signed.0.body.delivery_accepted_at_unix_ms >= eligibility.body().expires_at_unix_ms()
        || signed.0.body.delivery_accepted_at_unix_ms
            > eligibility.body().rail_capture_deadline_unix_ms()
    {
        return Err(OutcomeError::NotCurrent);
    }
    Ok(AuthenticatedOutcomeDeliveryAcknowledgementV1 {
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeDeliveryNonacceptanceInputV1 {
    pub receiver_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeDeliveryNonacceptanceBodyV1 {
    schema: String,
    nonacceptance_id: String,
    request_id: String,
    eligibility_digest: String,
    provider_acceptance_digest: String,
    output_digest: String,
    receiver_binding_digest: String,
    delivery_id: String,
    idempotency_key: String,
    receiver_queue_id: String,
    cancelled_at_unix_ms: u64,
    receiver_key_id: String,
    receiver_key_epoch: u64,
    delivery_checkpoint_sequence: u64,
    delivery_checkpoint_digest: String,
    blob_absence_proof_digest: String,
    cancellation_fence_digest: String,
}

impl OutcomeDeliveryNonacceptanceBodyV1 {
    pub fn from_receiver_assertion(
        eligibility: &AuthenticatedOutcomeEligibilityV1,
        checkpoint: &AuthenticatedOutcomeDeliveryCheckpointV1,
        input: OutcomeDeliveryNonacceptanceInputV1,
    ) -> Result<Self, OutcomeError> {
        let checkpoint_body = checkpoint.body();
        if checkpoint_body.state != OutcomeDeliveryCheckpointStateV1::Cancelled
            || checkpoint_body.eligibility_digest != eligibility.envelope_digest()
            || checkpoint_body.request_id != eligibility.body().request_id()
            || checkpoint_body.receiver_binding_digest
                != eligibility.body().receiver_binding_digest()
        {
            return Err(OutcomeError::BindingMismatch);
        }
        let mut body = Self {
            schema: OUTCOME_DELIVERY_NONACCEPTANCE_SCHEMA.to_owned(),
            nonacceptance_id: String::new(),
            request_id: checkpoint_body.request_id.clone(),
            eligibility_digest: checkpoint_body.eligibility_digest.clone(),
            provider_acceptance_digest: checkpoint_body.provider_acceptance_digest.clone(),
            output_digest: checkpoint_body.output_digest.clone(),
            receiver_binding_digest: eligibility.body().receiver_binding_digest().to_owned(),
            delivery_id: checkpoint_body.delivery_id.clone(),
            idempotency_key: checkpoint_body.idempotency_key.clone(),
            receiver_queue_id: checkpoint_body.receiver_queue_id.clone(),
            cancelled_at_unix_ms: checkpoint_body.trusted_clock_high_water_unix_ms,
            receiver_key_id: input.receiver_key_id,
            receiver_key_epoch: checkpoint_body.receiver_key_epoch,
            delivery_checkpoint_sequence: checkpoint_body.sequence,
            delivery_checkpoint_digest: checkpoint.envelope_digest.clone(),
            blob_absence_proof_digest: checkpoint_body
                .blob_absence_proof_digest
                .clone()
                .ok_or(OutcomeError::BindingMismatch)?,
            cancellation_fence_digest: checkpoint_body
                .cancellation_fence_digest
                .clone()
                .ok_or(OutcomeError::BindingMismatch)?,
        };
        body.nonacceptance_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_DELIVERY_NONACCEPTANCE_SCHEMA {
            return Err(OutcomeError::InvalidField("delivery_nonacceptance_schema"));
        }
        for (field, value) in [
            ("nonacceptance_id", &self.nonacceptance_id),
            ("eligibility_digest", &self.eligibility_digest),
            (
                "provider_acceptance_digest",
                &self.provider_acceptance_digest,
            ),
            ("output_digest", &self.output_digest),
            ("receiver_binding_digest", &self.receiver_binding_digest),
            (
                "delivery_checkpoint_digest",
                &self.delivery_checkpoint_digest,
            ),
            ("blob_absence_proof_digest", &self.blob_absence_proof_digest),
            ("cancellation_fence_digest", &self.cancellation_fence_digest),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("request_id", &self.request_id),
            ("delivery_id", &self.delivery_id),
            ("idempotency_key", &self.idempotency_key),
            ("receiver_queue_id", &self.receiver_queue_id),
            ("receiver_key_id", &self.receiver_key_id),
        ] {
            validate_text(field, value)?;
        }
        for (field, value) in [
            ("cancelled_at_unix_ms", self.cancelled_at_unix_ms),
            ("receiver_key_epoch", self.receiver_key_epoch),
            (
                "delivery_checkpoint_sequence",
                self.delivery_checkpoint_sequence,
            ),
        ] {
            validate_time(field, value)?;
        }
        if self.nonacceptance_id != self.derived_id()? {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(NONACCEPTANCE_ID_DOMAIN, self, "nonacceptanceId")
    }

    #[must_use]
    pub const fn cancelled_at_unix_ms(&self) -> u64 {
        self.cancelled_at_unix_ms
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn eligibility_digest(&self) -> &str {
        &self.eligibility_digest
    }

    #[must_use]
    pub fn provider_acceptance_digest(&self) -> &str {
        &self.provider_acceptance_digest
    }

    #[must_use]
    pub fn output_digest(&self) -> &str {
        &self.output_digest
    }

    #[must_use]
    pub fn receiver_binding_digest(&self) -> &str {
        &self.receiver_binding_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeDeliveryNonacceptanceV1(
    SignedExportEnvelope<OutcomeDeliveryNonacceptanceBodyV1>,
);

impl SignedOutcomeDeliveryNonacceptanceV1 {
    pub fn sign(
        body: OutcomeDeliveryNonacceptanceBodyV1,
        signer: &Keypair,
    ) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOutcomeDeliveryNonacceptanceV1 {
    signed: SignedOutcomeDeliveryNonacceptanceV1,
    envelope_digest: String,
}

impl AuthenticatedOutcomeDeliveryNonacceptanceV1 {
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomeDeliveryNonacceptanceBodyV1 {
        &self.signed.0.body
    }
}

pub fn authenticate_outcome_delivery_nonacceptance(
    canonical_envelope: &[u8],
    eligibility: &AuthenticatedOutcomeEligibilityV1,
    checkpoint: &AuthenticatedOutcomeDeliveryCheckpointV1,
    trust: &OutcomeSignerTrustV1,
) -> Result<AuthenticatedOutcomeDeliveryNonacceptanceV1, OutcomeError> {
    let signed: SignedOutcomeDeliveryNonacceptanceV1 =
        load_canonical_outcome_json(canonical_envelope)?;
    signed.0.body.validate()?;
    if trust.principal_id() != checkpoint.receiver_binding.receiver_key_id
        || trust.key() != &checkpoint.receiver_binding.receiver_key
        || trust.key_epoch() != checkpoint.receiver_binding.receiver_key_epoch
    {
        return Err(OutcomeError::BindingMismatch);
    }
    let expected = OutcomeDeliveryNonacceptanceBodyV1::from_receiver_assertion(
        eligibility,
        checkpoint,
        OutcomeDeliveryNonacceptanceInputV1 {
            receiver_key_id: trust.principal_id().to_owned(),
        },
    )?;
    if signed.0.body != expected || signed.0.body.receiver_key_epoch != trust.key_epoch() {
        return Err(OutcomeError::BindingMismatch);
    }
    if signed.0.signer_key != *trust.key()
        || !signed
            .0
            .verify_signature()
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?
    {
        return Err(OutcomeError::AuthorityVerification);
    }
    if signed.0.body.cancelled_at_unix_ms < eligibility.body().issued_at_unix_ms() {
        return Err(OutcomeError::NotCurrent);
    }
    Ok(AuthenticatedOutcomeDeliveryNonacceptanceV1 {
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}
