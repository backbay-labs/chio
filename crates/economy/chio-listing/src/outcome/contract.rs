use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use super::predicate::VerifiedOutcomePredicateV1;
use super::{
    domain_digest, domain_digest_without_field, envelope_digest, load_canonical_outcome_json,
    validate_current_window, validate_digest, validate_money, validate_text, validate_time,
    validate_window, OutcomeError, OutcomeSignerTrustV1,
};

pub const OUTCOME_PRICING_SCHEMA: &str = chio_core_types::CHIO_OUTCOME_PRICING_V1_SCHEMA;
pub const OUTCOME_SLA_SCHEMA: &str = chio_core_types::CHIO_OUTCOME_SLA_V1_SCHEMA;
pub const OUTCOME_ELIGIBILITY_SCHEMA: &str = chio_core_types::CHIO_OUTCOME_ELIGIBILITY_V1_SCHEMA;

const PRICING_ID_DOMAIN: &[u8] = b"chio.outcome.pricing.id.v1\0";
const PRICING_BODY_DIGEST_DOMAIN: &[u8] = b"chio.outcome.pricing.body.v1\0";
const SLA_ID_DOMAIN: &[u8] = b"chio.outcome.sla.id.v1\0";
const SLA_BODY_DIGEST_DOMAIN: &[u8] = b"chio.outcome.sla.body.v1\0";
const ELIGIBILITY_ID_DOMAIN: &[u8] = b"chio.outcome.eligibility.id.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeFailureModeV1 {
    ZeroCharge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomePricingInputV1 {
    pub provider_id: String,
    pub predicate_id: String,
    pub predicate_digest: String,
    pub outcome_price: MonetaryAmount,
    pub sla_digest: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomePricingBodyV1 {
    schema: String,
    pricing_id: String,
    provider_id: String,
    predicate_id: String,
    predicate_digest: String,
    outcome_price: MonetaryAmount,
    failure_mode: OutcomeFailureModeV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    sla_digest: Option<String>,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl OutcomePricingBodyV1 {
    pub fn new(input: OutcomePricingInputV1) -> Result<Self, OutcomeError> {
        let mut body = Self {
            schema: OUTCOME_PRICING_SCHEMA.to_owned(),
            pricing_id: String::new(),
            provider_id: input.provider_id,
            predicate_id: input.predicate_id,
            predicate_digest: input.predicate_digest,
            outcome_price: input.outcome_price,
            failure_mode: OutcomeFailureModeV1::ZeroCharge,
            sla_digest: input.sla_digest,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        body.pricing_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_PRICING_SCHEMA {
            return Err(OutcomeError::InvalidField("pricing_schema"));
        }
        validate_digest("pricing_id", &self.pricing_id)?;
        validate_text("provider_id", &self.provider_id)?;
        validate_digest("predicate_id", &self.predicate_id)?;
        validate_digest("predicate_digest", &self.predicate_digest)?;
        validate_money(&self.outcome_price, false)?;
        if let Some(digest) = &self.sla_digest {
            validate_digest("sla_digest", digest)?;
        }
        validate_window(self.issued_at_unix_ms, self.expires_at_unix_ms)?;
        if self.failure_mode != OutcomeFailureModeV1::ZeroCharge
            || self.pricing_id != self.derived_id()?
        {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(PRICING_ID_DOMAIN, self, "pricingId")
    }

    #[must_use]
    pub fn pricing_id(&self) -> &str {
        &self.pricing_id
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn predicate_id(&self) -> &str {
        &self.predicate_id
    }

    #[must_use]
    pub fn predicate_digest(&self) -> &str {
        &self.predicate_digest
    }

    #[must_use]
    pub const fn outcome_price(&self) -> &MonetaryAmount {
        &self.outcome_price
    }

    #[must_use]
    pub fn sla_digest(&self) -> Option<&str> {
        self.sla_digest.as_deref()
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomePricingV1(SignedExportEnvelope<OutcomePricingBodyV1>);

impl SignedOutcomePricingV1 {
    pub fn sign(body: OutcomePricingBodyV1, signer: &Keypair) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomePricingBodyV1 {
        &self.0.body
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedOutcomePricingV1 {
    signed: SignedOutcomePricingV1,
    body_digest: String,
    envelope_digest: String,
}

impl VerifiedOutcomePricingV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomePricingBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub struct OutcomePricingVerificationV1<'a> {
    pub predicate: &'a VerifiedOutcomePredicateV1,
    pub sla: Option<&'a VerifiedOutcomeSlaV1>,
    pub trust: &'a OutcomeSignerTrustV1,
    pub trusted_now_unix_ms: u64,
}

pub fn verify_outcome_pricing(
    canonical_envelope: &[u8],
    context: &OutcomePricingVerificationV1<'_>,
) -> Result<VerifiedOutcomePricingV1, OutcomeError> {
    let signed: SignedOutcomePricingV1 = load_canonical_outcome_json(canonical_envelope)?;
    signed.body().validate()?;
    if signed.body().predicate_id() != context.predicate.body().predicate_id()
        || signed.body().predicate_digest() != context.predicate.envelope_digest()
        || signed.body().sla_digest() != context.sla.map(VerifiedOutcomeSlaV1::envelope_digest)
        || signed.body().provider_id() != context.predicate.body().provider_id()
        || context
            .sla
            .is_some_and(|sla| sla.body().provider_id() != signed.body().provider_id())
    {
        return Err(OutcomeError::BindingMismatch);
    }
    verify_provider_envelope(
        &signed.0,
        signed.body().provider_id(),
        signed.body().issued_at_unix_ms,
        signed.body().expires_at_unix_ms,
        context.trust,
        context.trusted_now_unix_ms,
    )?;
    Ok(VerifiedOutcomePricingV1 {
        body_digest: domain_digest(PRICING_BODY_DIGEST_DOMAIN, signed.body())?,
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeSlaInputV1 {
    pub provider_id: String,
    pub listing_digest: String,
    pub max_failure_bps: u16,
    pub minimum_sample_count: u64,
    pub window_seconds: u64,
    pub window_anchor_unix_ms: u64,
    pub effective_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeSlaBodyV1 {
    schema: String,
    sla_id: String,
    provider_id: String,
    listing_digest: String,
    max_failure_bps: u16,
    minimum_sample_count: u64,
    window_seconds: u64,
    window_anchor_unix_ms: u64,
    effective_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl OutcomeSlaBodyV1 {
    pub fn new(input: OutcomeSlaInputV1) -> Result<Self, OutcomeError> {
        let mut body = Self {
            schema: OUTCOME_SLA_SCHEMA.to_owned(),
            sla_id: String::new(),
            provider_id: input.provider_id,
            listing_digest: input.listing_digest,
            max_failure_bps: input.max_failure_bps,
            minimum_sample_count: input.minimum_sample_count,
            window_seconds: input.window_seconds,
            window_anchor_unix_ms: input.window_anchor_unix_ms,
            effective_at_unix_ms: input.effective_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
        };
        body.sla_id = body.derived_id()?;
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_SLA_SCHEMA {
            return Err(OutcomeError::InvalidField("sla_schema"));
        }
        validate_digest("sla_id", &self.sla_id)?;
        validate_text("provider_id", &self.provider_id)?;
        validate_digest("listing_digest", &self.listing_digest)?;
        validate_time("minimum_sample_count", self.minimum_sample_count)?;
        validate_time("window_seconds", self.window_seconds)?;
        validate_time("window_anchor_unix_ms", self.window_anchor_unix_ms)?;
        validate_window(self.effective_at_unix_ms, self.expires_at_unix_ms)?;
        let window_ms = self
            .window_seconds
            .checked_mul(1_000)
            .ok_or(OutcomeError::ArithmeticOverflow)?;
        if self.max_failure_bps > 10_000
            || self.window_anchor_unix_ms > self.effective_at_unix_ms
            || self.window_anchor_unix_ms.checked_add(window_ms).is_none()
            || self.sla_id != self.derived_id()?
        {
            return Err(OutcomeError::InvalidField("sla_terms"));
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(SLA_ID_DOMAIN, self, "slaId")
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub const fn max_failure_bps(&self) -> u16 {
        self.max_failure_bps
    }

    #[must_use]
    pub const fn minimum_sample_count(&self) -> u64 {
        self.minimum_sample_count
    }

    #[must_use]
    pub const fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    #[must_use]
    pub const fn window_anchor_unix_ms(&self) -> u64 {
        self.window_anchor_unix_ms
    }

    #[must_use]
    pub const fn effective_at_unix_ms(&self) -> u64 {
        self.effective_at_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeSlaV1(SignedExportEnvelope<OutcomeSlaBodyV1>);

impl SignedOutcomeSlaV1 {
    pub fn sign(body: OutcomeSlaBodyV1, signer: &Keypair) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomeSlaBodyV1 {
        &self.0.body
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedOutcomeSlaV1 {
    signed: SignedOutcomeSlaV1,
    body_digest: String,
    envelope_digest: String,
}

impl VerifiedOutcomeSlaV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomeSlaBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn verify_outcome_sla(
    canonical_envelope: &[u8],
    trust: &OutcomeSignerTrustV1,
    trusted_now_unix_ms: u64,
) -> Result<VerifiedOutcomeSlaV1, OutcomeError> {
    let signed: SignedOutcomeSlaV1 = load_canonical_outcome_json(canonical_envelope)?;
    signed.body().validate()?;
    verify_provider_envelope(
        &signed.0,
        signed.body().provider_id(),
        signed.body().effective_at_unix_ms,
        signed.body().expires_at_unix_ms,
        trust,
        trusted_now_unix_ms,
    )?;
    Ok(VerifiedOutcomeSlaV1 {
        body_digest: domain_digest(SLA_BODY_DIGEST_DOMAIN, signed.body())?,
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeSettlementModeV1 {
    HoldCapture,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeEligibilityInputV1 {
    pub request_id: String,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub provider_id: String,
    pub listing_id: String,
    pub listing_digest: String,
    pub provider_binding_digest: String,
    pub pricing_id: String,
    pub pricing_digest: String,
    pub predicate_id: String,
    pub predicate_digest: String,
    pub quote_digest: String,
    pub sla_digest: Option<String>,
    pub outcome_price: MonetaryAmount,
    pub request_extension_digest: String,
    pub pre_action_authority_digest: String,
    pub post_guard_policy_digest: String,
    pub receiver_binding_digest: String,
    pub delivery_ack_deadline_unix_ms: u64,
    pub qualified_rail_id: String,
    pub qualified_rail_capability_digest: String,
    pub rail_capture_deadline_unix_ms: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub artifact_valid_until_unix_ms: u64,
    pub kernel_authority_id: String,
    pub kernel_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeEligibilityBodyV1 {
    schema: String,
    eligibility_id: String,
    request_id: String,
    capability_id: String,
    tool_server: String,
    tool_name: String,
    provider_id: String,
    listing_id: String,
    listing_digest: String,
    provider_binding_digest: String,
    pricing_id: String,
    pricing_digest: String,
    predicate_id: String,
    predicate_digest: String,
    quote_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sla_digest: Option<String>,
    outcome_price: MonetaryAmount,
    settlement_mode: OutcomeSettlementModeV1,
    request_extension_digest: String,
    pre_action_authority_digest: String,
    post_guard_policy_digest: String,
    receiver_binding_digest: String,
    delivery_ack_deadline_unix_ms: u64,
    qualified_rail_id: String,
    qualified_rail_capability_digest: String,
    rail_capture_deadline_unix_ms: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    kernel_authority_id: String,
    kernel_key_epoch: u64,
}

impl OutcomeEligibilityBodyV1 {
    pub fn from_kernel_assertion(input: OutcomeEligibilityInputV1) -> Result<Self, OutcomeError> {
        let artifact_valid_until = input.artifact_valid_until_unix_ms;
        let mut body = Self {
            schema: OUTCOME_ELIGIBILITY_SCHEMA.to_owned(),
            eligibility_id: String::new(),
            request_id: input.request_id,
            capability_id: input.capability_id,
            tool_server: input.tool_server,
            tool_name: input.tool_name,
            provider_id: input.provider_id,
            listing_id: input.listing_id,
            listing_digest: input.listing_digest,
            provider_binding_digest: input.provider_binding_digest,
            pricing_id: input.pricing_id,
            pricing_digest: input.pricing_digest,
            predicate_id: input.predicate_id,
            predicate_digest: input.predicate_digest,
            quote_digest: input.quote_digest,
            sla_digest: input.sla_digest,
            outcome_price: input.outcome_price,
            settlement_mode: OutcomeSettlementModeV1::HoldCapture,
            request_extension_digest: input.request_extension_digest,
            pre_action_authority_digest: input.pre_action_authority_digest,
            post_guard_policy_digest: input.post_guard_policy_digest,
            receiver_binding_digest: input.receiver_binding_digest,
            delivery_ack_deadline_unix_ms: input.delivery_ack_deadline_unix_ms,
            qualified_rail_id: input.qualified_rail_id,
            qualified_rail_capability_digest: input.qualified_rail_capability_digest,
            rail_capture_deadline_unix_ms: input.rail_capture_deadline_unix_ms,
            issued_at_unix_ms: input.issued_at_unix_ms,
            expires_at_unix_ms: input.expires_at_unix_ms,
            kernel_authority_id: input.kernel_authority_id,
            kernel_key_epoch: input.kernel_key_epoch,
        };
        body.eligibility_id = body.derived_id()?;
        body.validate()?;
        if body.delivery_ack_deadline_unix_ms >= artifact_valid_until {
            return Err(OutcomeError::InvalidField("artifact_validity_deadline"));
        }
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_ELIGIBILITY_SCHEMA {
            return Err(OutcomeError::InvalidField("eligibility_schema"));
        }
        validate_digest("eligibility_id", &self.eligibility_id)?;
        for (field, value) in [
            ("listing_digest", &self.listing_digest),
            ("provider_binding_digest", &self.provider_binding_digest),
            ("pricing_id", &self.pricing_id),
            ("pricing_digest", &self.pricing_digest),
            ("predicate_id", &self.predicate_id),
            ("predicate_digest", &self.predicate_digest),
            ("quote_digest", &self.quote_digest),
            ("request_extension_digest", &self.request_extension_digest),
            (
                "pre_action_authority_digest",
                &self.pre_action_authority_digest,
            ),
            ("post_guard_policy_digest", &self.post_guard_policy_digest),
            ("receiver_binding_digest", &self.receiver_binding_digest),
            (
                "qualified_rail_capability_digest",
                &self.qualified_rail_capability_digest,
            ),
        ] {
            validate_digest(field, value)?;
        }
        for (field, value) in [
            ("request_id", &self.request_id),
            ("capability_id", &self.capability_id),
            ("tool_server", &self.tool_server),
            ("tool_name", &self.tool_name),
            ("provider_id", &self.provider_id),
            ("listing_id", &self.listing_id),
            ("qualified_rail_id", &self.qualified_rail_id),
            ("kernel_authority_id", &self.kernel_authority_id),
        ] {
            validate_text(field, value)?;
        }
        if let Some(digest) = &self.sla_digest {
            validate_digest("sla_digest", digest)?;
        }
        validate_money(&self.outcome_price, false)?;
        validate_time(
            "delivery_ack_deadline_unix_ms",
            self.delivery_ack_deadline_unix_ms,
        )?;
        validate_time(
            "rail_capture_deadline_unix_ms",
            self.rail_capture_deadline_unix_ms,
        )?;
        validate_window(self.issued_at_unix_ms, self.expires_at_unix_ms)?;
        validate_time("kernel_key_epoch", self.kernel_key_epoch)?;
        if self.settlement_mode != OutcomeSettlementModeV1::HoldCapture
            || self.delivery_ack_deadline_unix_ms < self.issued_at_unix_ms
            || self.delivery_ack_deadline_unix_ms >= self.expires_at_unix_ms
            || self.delivery_ack_deadline_unix_ms > self.rail_capture_deadline_unix_ms
            || self.eligibility_id != self.derived_id()?
        {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, OutcomeError> {
        domain_digest_without_field(ELIGIBILITY_ID_DOMAIN, self, "eligibilityId")
    }

    #[must_use]
    pub fn eligibility_id(&self) -> &str {
        &self.eligibility_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn listing_id(&self) -> &str {
        &self.listing_id
    }

    #[must_use]
    pub fn listing_digest(&self) -> &str {
        &self.listing_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn provider_binding_digest(&self) -> &str {
        &self.provider_binding_digest
    }

    #[must_use]
    pub fn quote_digest(&self) -> &str {
        &self.quote_digest
    }

    #[must_use]
    pub fn pricing_id(&self) -> &str {
        &self.pricing_id
    }

    #[must_use]
    pub fn pricing_digest(&self) -> &str {
        &self.pricing_digest
    }

    #[must_use]
    pub fn predicate_id(&self) -> &str {
        &self.predicate_id
    }

    #[must_use]
    pub fn predicate_digest(&self) -> &str {
        &self.predicate_digest
    }

    #[must_use]
    pub fn post_guard_policy_digest(&self) -> &str {
        &self.post_guard_policy_digest
    }

    #[must_use]
    pub fn sla_digest(&self) -> Option<&str> {
        self.sla_digest.as_deref()
    }

    #[must_use]
    pub fn receiver_binding_digest(&self) -> &str {
        &self.receiver_binding_digest
    }

    #[must_use]
    pub const fn delivery_ack_deadline_unix_ms(&self) -> u64 {
        self.delivery_ack_deadline_unix_ms
    }

    #[must_use]
    pub const fn rail_capture_deadline_unix_ms(&self) -> u64 {
        self.rail_capture_deadline_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    #[must_use]
    pub const fn outcome_price(&self) -> &MonetaryAmount {
        &self.outcome_price
    }

    #[must_use]
    pub fn kernel_authority_id(&self) -> &str {
        &self.kernel_authority_id
    }

    #[must_use]
    pub const fn kernel_key_epoch(&self) -> u64 {
        self.kernel_key_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedOutcomeEligibilityV1(SignedExportEnvelope<OutcomeEligibilityBodyV1>);

impl SignedOutcomeEligibilityV1 {
    pub fn sign(body: OutcomeEligibilityBodyV1, signer: &Keypair) -> Result<Self, OutcomeError> {
        body.validate()?;
        SignedExportEnvelope::sign(body, signer)
            .map(Self)
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &OutcomeEligibilityBodyV1 {
        &self.0.body
    }
}

pub struct OutcomeEligibilityAuthenticationV1<'a> {
    pub expected: &'a OutcomeEligibilityBodyV1,
    pub trust: &'a OutcomeSignerTrustV1,
    pub referenced_artifacts_valid_until_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedOutcomeEligibilityV1 {
    signed: SignedOutcomeEligibilityV1,
    envelope_digest: String,
}

impl AuthenticatedOutcomeEligibilityV1 {
    #[must_use]
    pub const fn body(&self) -> &OutcomeEligibilityBodyV1 {
        self.signed.body()
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn authenticate_outcome_eligibility(
    canonical_envelope: &[u8],
    context: &OutcomeEligibilityAuthenticationV1<'_>,
    trusted_now_unix_ms: u64,
) -> Result<AuthenticatedOutcomeEligibilityV1, OutcomeError> {
    authenticate_outcome_eligibility_at(canonical_envelope, context, trusted_now_unix_ms)
}

pub(super) fn authenticate_outcome_eligibility_at(
    canonical_envelope: &[u8],
    context: &OutcomeEligibilityAuthenticationV1<'_>,
    authenticated_at_unix_ms: u64,
) -> Result<AuthenticatedOutcomeEligibilityV1, OutcomeError> {
    let signed: SignedOutcomeEligibilityV1 = load_canonical_outcome_json(canonical_envelope)?;
    signed.body().validate()?;
    validate_time(
        "referenced_artifacts_valid_until_unix_ms",
        context.referenced_artifacts_valid_until_unix_ms,
    )?;
    if signed.body() != context.expected
        || signed.body().kernel_authority_id != context.trust.principal_id()
        || signed.body().kernel_key_epoch != context.trust.key_epoch()
        || signed.body().delivery_ack_deadline_unix_ms
            >= context.referenced_artifacts_valid_until_unix_ms
    {
        return Err(OutcomeError::BindingMismatch);
    }
    if signed.0.signer_key != *context.trust.key()
        || !signed
            .0
            .verify_signature()
            .map_err(|error| OutcomeError::Canonicalization(error.to_string()))?
    {
        return Err(OutcomeError::AuthorityVerification);
    }
    validate_current_window(
        signed.body().issued_at_unix_ms,
        signed.body().expires_at_unix_ms,
        context.trust.max_lifetime_ms(),
        authenticated_at_unix_ms,
    )?;
    Ok(AuthenticatedOutcomeEligibilityV1 {
        envelope_digest: envelope_digest(&signed)?,
        signed,
    })
}

fn verify_provider_envelope<T>(
    envelope: &SignedExportEnvelope<T>,
    provider_id: &str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    trust: &OutcomeSignerTrustV1,
    trusted_now_unix_ms: u64,
) -> Result<(), OutcomeError>
where
    T: Serialize + Clone,
{
    if provider_id != trust.principal_id() {
        return Err(OutcomeError::BindingMismatch);
    }
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
