use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use super::{
    domain_digest_without_field, envelope_digest, load_canonical_outcome_json,
    validate_current_window, validate_digest, validate_text, validate_time, validate_window,
    AuthenticatedOutcomeEligibilityV1, OutcomeError, OutcomeSignerTrustV1,
};

pub const OUTCOME_OUTPUT_PROVENANCE_SCHEMA: &str =
    chio_core_types::CHIO_OUTCOME_OUTPUT_PROVENANCE_V1_SCHEMA;
pub const OUTCOME_CONTRACTUAL_ZERO_SCHEMA: &str =
    chio_core_types::CHIO_OUTCOME_CONTRACTUAL_ZERO_V1_SCHEMA;

const OUTPUT_PROVENANCE_ID_DOMAIN: &[u8] = b"chio.outcome.output-provenance.id.v1\0";
const CONTRACTUAL_ZERO_ID_DOMAIN: &[u8] = b"chio.outcome.contractual-zero.id.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeOutputProvenanceClassV1 {
    Provider,
    CallerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeOutputProvenanceInputV1 {
    pub provider_acceptance_digest: String,
    pub provider_output_digest: String,
    pub final_output_digest: String,
    pub post_guard_evidence_digest: String,
    pub redaction_proof_digest: Option<String>,
    pub authority_id: String,
    pub authority_key_epoch: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeOutputProvenanceBodyV1 {
    schema: String,
    provenance_id: String,
    request_id: String,
    eligibility_digest: String,
    provider_acceptance_digest: String,
    provider_output_digest: String,
    final_output_digest: String,
    post_guard_policy_digest: String,
    post_guard_evidence_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    redaction_proof_digest: Option<String>,
    provenance_class: OutcomeOutputProvenanceClassV1,
    authority_id: String,
    authority_key_epoch: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl OutcomeOutputProvenanceBodyV1 {
    pub fn from_kernel_assertion(
        eligibility: &AuthenticatedOutcomeEligibilityV1,
        input: OutcomeOutputProvenanceInputV1,
    ) -> Result<Self, OutcomeError> {
        let provenance_class = classify_output_provenance(
            &input.provider_output_digest,
            &input.final_output_digest,
            input.redaction_proof_digest.as_deref(),
        )?;
        let mut body = Self {
            schema: OUTCOME_OUTPUT_PROVENANCE_SCHEMA.to_owned(),
            provenance_id: String::new(),
            request_id: eligibility.body().request_id().to_owned(),
            eligibility_digest: eligibility.envelope_digest().to_owned(),
            provider_acceptance_digest: input.provider_acceptance_digest,
            provider_output_digest: input.provider_output_digest,
            final_output_digest: input.final_output_digest,
            post_guard_policy_digest: eligibility.body().post_guard_policy_digest().to_owned(),
            post_guard_evidence_digest: input.post_guard_evidence_digest,
            redaction_proof_digest: input.redaction_proof_digest,
            provenance_class,
            authority_id: input.authority_id,
            authority_key_epoch: input.authority_key_epoch,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        body.provenance_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_OUTPUT_PROVENANCE_SCHEMA {
            return Err(OutcomeError::InvalidField("output_provenance_schema"));
        }
        validate_text("request_id", &self.request_id)?;
        validate_text("authority_id", &self.authority_id)?;
        for (field, digest) in [
            ("provenance_id", &self.provenance_id),
            ("eligibility_digest", &self.eligibility_digest),
            (
                "provider_acceptance_digest",
                &self.provider_acceptance_digest,
            ),
            ("provider_output_digest", &self.provider_output_digest),
            ("final_output_digest", &self.final_output_digest),
            ("post_guard_policy_digest", &self.post_guard_policy_digest),
            (
                "post_guard_evidence_digest",
                &self.post_guard_evidence_digest,
            ),
        ] {
            validate_digest(field, digest)?;
        }
        if let Some(digest) = &self.redaction_proof_digest {
            validate_digest("redaction_proof_digest", digest)?;
        }
        validate_time("authority_key_epoch", self.authority_key_epoch)?;
        validate_window(self.issued_at_unix_ms, self.expires_at_unix_ms)?;
        if self.provenance_class
            != classify_output_provenance(
                &self.provider_output_digest,
                &self.final_output_digest,
                self.redaction_proof_digest.as_deref(),
            )?
            || self.provenance_id != self.derived_id()?
        {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(OUTPUT_PROVENANCE_ID_DOMAIN, self, "provenanceId")
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
    pub const fn provenance_class(&self) -> OutcomeOutputProvenanceClassV1 {
        self.provenance_class
    }

    #[must_use]
    pub fn redaction_proof_digest(&self) -> Option<&str> {
        self.redaction_proof_digest.as_deref()
    }
}

fn classify_output_provenance(
    provider_output_digest: &str,
    final_output_digest: &str,
    redaction_proof_digest: Option<&str>,
) -> Result<OutcomeOutputProvenanceClassV1, OutcomeError> {
    match (
        provider_output_digest == final_output_digest,
        redaction_proof_digest,
    ) {
        (true, None) => Ok(OutcomeOutputProvenanceClassV1::Provider),
        (false, Some(_)) => Ok(OutcomeOutputProvenanceClassV1::CallerPolicy),
        _ => Err(OutcomeError::BindingMismatch),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeOutputProvenanceV1(SignedExportEnvelope<OutcomeOutputProvenanceBodyV1>);

impl SignedOutcomeOutputProvenanceV1 {
    pub fn sign(
        body: OutcomeOutputProvenanceBodyV1,
        signer: &Keypair,
    ) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOutcomeOutputProvenanceV1 {
    signed: SignedOutcomeOutputProvenanceV1,
    envelope_digest: String,
}

impl AuthenticatedOutcomeOutputProvenanceV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomeOutputProvenanceBodyV1 {
        &self.signed.0.body
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn authenticate_outcome_output_provenance(
    canonical_envelope: &[u8],
    eligibility: &AuthenticatedOutcomeEligibilityV1,
    trust: &OutcomeSignerTrustV1,
    trusted_now_unix_ms: u64,
) -> Result<AuthenticatedOutcomeOutputProvenanceV1, OutcomeError> {
    let signed: SignedOutcomeOutputProvenanceV1 = load_canonical_outcome_json(canonical_envelope)?;
    signed.0.body.validate()?;
    if signed.0.body.request_id != eligibility.body().request_id()
        || signed.0.body.eligibility_digest != eligibility.envelope_digest()
        || signed.0.body.post_guard_policy_digest != eligibility.body().post_guard_policy_digest()
        || signed.0.body.authority_id != eligibility.body().kernel_authority_id()
        || signed.0.body.authority_key_epoch != eligibility.body().kernel_key_epoch()
        || signed.0.body.authority_id != trust.principal_id()
        || signed.0.body.authority_key_epoch != trust.key_epoch()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    verify_evidence_envelope(
        &signed.0,
        trust,
        signed.0.body.issued_at_unix_ms,
        signed.0.body.expires_at_unix_ms,
        trusted_now_unix_ms,
    )?;
    Ok(AuthenticatedOutcomeOutputProvenanceV1 {
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomePreDeliveryZeroReasonV1 {
    OutputBlocked,
    OutputMutationAfterEvaluation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeContractualZeroInputV1 {
    pub provider_acceptance_digest: String,
    pub reason: OutcomePreDeliveryZeroReasonV1,
    pub terminal_tool_outcome_digest: String,
    pub no_delivery_slot_proof_digest: String,
    pub post_guard_evidence_digest: String,
    pub authority_id: String,
    pub authority_key_epoch: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeContractualZeroBodyV1 {
    schema: String,
    contractual_zero_id: String,
    request_id: String,
    eligibility_digest: String,
    provider_acceptance_digest: String,
    reason: OutcomePreDeliveryZeroReasonV1,
    terminal_tool_outcome_digest: String,
    no_delivery_slot_proof_digest: String,
    post_guard_policy_digest: String,
    post_guard_evidence_digest: String,
    authority_id: String,
    authority_key_epoch: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl OutcomeContractualZeroBodyV1 {
    pub fn from_kernel_assertion(
        eligibility: &AuthenticatedOutcomeEligibilityV1,
        input: OutcomeContractualZeroInputV1,
    ) -> Result<Self, OutcomeError> {
        let mut body = Self {
            schema: OUTCOME_CONTRACTUAL_ZERO_SCHEMA.to_owned(),
            contractual_zero_id: String::new(),
            request_id: eligibility.body().request_id().to_owned(),
            eligibility_digest: eligibility.envelope_digest().to_owned(),
            provider_acceptance_digest: input.provider_acceptance_digest,
            reason: input.reason,
            terminal_tool_outcome_digest: input.terminal_tool_outcome_digest,
            no_delivery_slot_proof_digest: input.no_delivery_slot_proof_digest,
            post_guard_policy_digest: eligibility.body().post_guard_policy_digest().to_owned(),
            post_guard_evidence_digest: input.post_guard_evidence_digest,
            authority_id: input.authority_id,
            authority_key_epoch: input.authority_key_epoch,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        body.contractual_zero_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_CONTRACTUAL_ZERO_SCHEMA {
            return Err(OutcomeError::InvalidField("contractual_zero_schema"));
        }
        validate_text("request_id", &self.request_id)?;
        validate_text("authority_id", &self.authority_id)?;
        for (field, digest) in [
            ("contractual_zero_id", &self.contractual_zero_id),
            ("eligibility_digest", &self.eligibility_digest),
            (
                "provider_acceptance_digest",
                &self.provider_acceptance_digest,
            ),
            (
                "terminal_tool_outcome_digest",
                &self.terminal_tool_outcome_digest,
            ),
            (
                "no_delivery_slot_proof_digest",
                &self.no_delivery_slot_proof_digest,
            ),
            ("post_guard_policy_digest", &self.post_guard_policy_digest),
            (
                "post_guard_evidence_digest",
                &self.post_guard_evidence_digest,
            ),
        ] {
            validate_digest(field, digest)?;
        }
        validate_time("authority_key_epoch", self.authority_key_epoch)?;
        validate_window(self.issued_at_unix_ms, self.expires_at_unix_ms)?;
        if self.contractual_zero_id != self.derived_id()? {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(CONTRACTUAL_ZERO_ID_DOMAIN, self, "contractualZeroId")
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
    pub const fn reason(&self) -> OutcomePreDeliveryZeroReasonV1 {
        self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeContractualZeroV1(SignedExportEnvelope<OutcomeContractualZeroBodyV1>);

impl SignedOutcomeContractualZeroV1 {
    pub fn sign(
        body: OutcomeContractualZeroBodyV1,
        signer: &Keypair,
    ) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOutcomeContractualZeroV1 {
    signed: SignedOutcomeContractualZeroV1,
    envelope_digest: String,
}

impl AuthenticatedOutcomeContractualZeroV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomeContractualZeroBodyV1 {
        &self.signed.0.body
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn authenticate_outcome_contractual_zero(
    canonical_envelope: &[u8],
    eligibility: &AuthenticatedOutcomeEligibilityV1,
    trust: &OutcomeSignerTrustV1,
    trusted_now_unix_ms: u64,
) -> Result<AuthenticatedOutcomeContractualZeroV1, OutcomeError> {
    let signed: SignedOutcomeContractualZeroV1 = load_canonical_outcome_json(canonical_envelope)?;
    signed.0.body.validate()?;
    if signed.0.body.request_id != eligibility.body().request_id()
        || signed.0.body.eligibility_digest != eligibility.envelope_digest()
        || signed.0.body.post_guard_policy_digest != eligibility.body().post_guard_policy_digest()
        || signed.0.body.authority_id != eligibility.body().kernel_authority_id()
        || signed.0.body.authority_key_epoch != eligibility.body().kernel_key_epoch()
        || signed.0.body.authority_id != trust.principal_id()
        || signed.0.body.authority_key_epoch != trust.key_epoch()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    verify_evidence_envelope(
        &signed.0,
        trust,
        signed.0.body.issued_at_unix_ms,
        signed.0.body.expires_at_unix_ms,
        trusted_now_unix_ms,
    )?;
    Ok(AuthenticatedOutcomeContractualZeroV1 {
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

fn verify_evidence_envelope<T>(
    envelope: &SignedExportEnvelope<T>,
    trust: &OutcomeSignerTrustV1,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    trusted_now_unix_ms: u64,
) -> Result<(), OutcomeError>
where
    T: Serialize + Clone,
{
    if envelope.signer_key != *trust.key()
        || !envelope
            .verify_signature()
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?
    {
        return Err(OutcomeError::AuthorityVerification);
    }
    validate_current_window(
        issued_at_unix_ms,
        expires_at_unix_ms,
        trust.max_lifetime_ms(),
        trusted_now_unix_ms,
    )
}
