use chio_core_types::capability::scope::MonetaryAmount;
use serde::{Deserialize, Serialize};

use super::{
    validate_digest, validate_money, validate_text, validate_time,
    AuthenticatedOutcomeContractualZeroV1, AuthenticatedOutcomeDeliveryAcknowledgementV1,
    AuthenticatedOutcomeDeliveryNonacceptanceV1, AuthenticatedOutcomeEligibilityV1,
    AuthenticatedOutcomeOutputProvenanceV1, OutcomeError, OutcomeEvaluationReasonV1,
    OutcomeEvaluationV1, OutcomeOutputProvenanceClassV1, OutcomePreDeliveryZeroReasonV1,
    OutcomeSlaBodyV1, VerifiedOutcomeEvaluationV1, VerifiedOutcomePricingV1,
};

pub const OUTCOME_VERDICT_SCHEMA: &str = "chio.outcome.verdict.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeSlaAttributionV1 {
    Provider,
    CallerPolicy,
    Platform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeDeliveryDispositionV1 {
    Acknowledged,
    Cancelled,
    NotAttempted,
}

#[derive(Debug)]
pub enum AuthenticatedOutcomeDeliveryEvidenceV1<'a> {
    Acknowledged {
        acknowledgement: &'a AuthenticatedOutcomeDeliveryAcknowledgementV1,
        evaluation: &'a VerifiedOutcomeEvaluationV1,
        provenance: &'a AuthenticatedOutcomeOutputProvenanceV1,
    },
    Cancelled {
        nonacceptance: &'a AuthenticatedOutcomeDeliveryNonacceptanceV1,
        evaluation: &'a VerifiedOutcomeEvaluationV1,
    },
    NotAttempted(&'a AuthenticatedOutcomeContractualZeroV1),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomePriceDispositionV1 {
    FullPrice,
    ZeroPrice,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomePriceAssessmentV1 {
    disposition: OutcomePriceDispositionV1,
    delivery_disposition: Option<OutcomeDeliveryDispositionV1>,
    verdict: Option<OutcomeEvaluationV1>,
    sla_attribution: Option<OutcomeSlaAttributionV1>,
    assessed_amount: MonetaryAmount,
}

impl OutcomePriceAssessmentV1 {
    #[must_use]
    pub const fn disposition(&self) -> &OutcomePriceDispositionV1 {
        &self.disposition
    }

    #[must_use]
    pub const fn delivery_disposition(&self) -> Option<OutcomeDeliveryDispositionV1> {
        self.delivery_disposition
    }

    #[must_use]
    pub const fn verdict(&self) -> Option<&OutcomeEvaluationV1> {
        self.verdict.as_ref()
    }

    #[must_use]
    pub const fn sla_attribution(&self) -> Option<OutcomeSlaAttributionV1> {
        self.sla_attribution
    }

    #[must_use]
    pub const fn assessed_amount(&self) -> &MonetaryAmount {
        &self.assessed_amount
    }
}

pub fn assess_outcome_price(
    delivery: AuthenticatedOutcomeDeliveryEvidenceV1<'_>,
    pricing: &VerifiedOutcomePricingV1,
    eligibility: &AuthenticatedOutcomeEligibilityV1,
) -> Result<OutcomePriceAssessmentV1, OutcomeError> {
    validate_eligibility_pricing(eligibility, pricing)?;
    let outcome_price = pricing.body().outcome_price();
    validate_money(outcome_price, false)?;
    let zero = MonetaryAmount {
        currency: outcome_price.currency.clone(),
        units: 0,
    };
    match delivery {
        AuthenticatedOutcomeDeliveryEvidenceV1::Acknowledged {
            acknowledgement,
            evaluation,
            provenance,
        } => {
            validate_evaluation_pricing(evaluation, pricing)?;
            if acknowledgement.body().request_id() != eligibility.body().request_id()
                || acknowledgement.body().eligibility_digest() != eligibility.envelope_digest()
                || evaluation.output_digest() != acknowledgement.body().final_output_digest()
                || provenance.body().request_id() != eligibility.body().request_id()
                || provenance.body().eligibility_digest() != eligibility.envelope_digest()
                || provenance.body().provider_acceptance_digest()
                    != acknowledgement.body().provider_acceptance_digest()
                || provenance.body().final_output_digest()
                    != acknowledgement.body().final_output_digest()
            {
                return Err(OutcomeError::BindingMismatch);
            }
            let sla_attribution = match provenance.body().provenance_class() {
                OutcomeOutputProvenanceClassV1::Provider => OutcomeSlaAttributionV1::Provider,
                OutcomeOutputProvenanceClassV1::CallerPolicy => {
                    OutcomeSlaAttributionV1::CallerPolicy
                }
            };
            let passed = evaluation.evaluation() == &OutcomeEvaluationV1::Passed;
            Ok(OutcomePriceAssessmentV1 {
                disposition: if passed {
                    OutcomePriceDispositionV1::FullPrice
                } else {
                    OutcomePriceDispositionV1::ZeroPrice
                },
                delivery_disposition: Some(OutcomeDeliveryDispositionV1::Acknowledged),
                verdict: Some(evaluation.evaluation().clone()),
                sla_attribution: Some(sla_attribution),
                assessed_amount: if passed { outcome_price.clone() } else { zero },
            })
        }
        AuthenticatedOutcomeDeliveryEvidenceV1::Cancelled {
            nonacceptance,
            evaluation,
        } => {
            validate_evaluation_pricing(evaluation, pricing)?;
            if nonacceptance.body().request_id() != eligibility.body().request_id()
                || nonacceptance.body().eligibility_digest() != eligibility.envelope_digest()
                || evaluation.output_digest() != nonacceptance.body().output_digest()
            {
                return Err(OutcomeError::BindingMismatch);
            }
            Ok(OutcomePriceAssessmentV1 {
                disposition: OutcomePriceDispositionV1::ZeroPrice,
                delivery_disposition: Some(OutcomeDeliveryDispositionV1::Cancelled),
                verdict: Some(OutcomeEvaluationV1::Unevaluable {
                    reason: OutcomeEvaluationReasonV1::DeliveryCancelled,
                }),
                sla_attribution: Some(OutcomeSlaAttributionV1::Platform),
                assessed_amount: zero,
            })
        }
        AuthenticatedOutcomeDeliveryEvidenceV1::NotAttempted(proof) => {
            if proof.body().request_id() != eligibility.body().request_id()
                || proof.body().eligibility_digest() != eligibility.envelope_digest()
            {
                return Err(OutcomeError::BindingMismatch);
            }
            let (reason, attribution) = match proof.body().reason() {
                OutcomePreDeliveryZeroReasonV1::OutputBlocked => (
                    OutcomeEvaluationReasonV1::OutputBlocked,
                    OutcomeSlaAttributionV1::CallerPolicy,
                ),
                OutcomePreDeliveryZeroReasonV1::OutputMutationAfterEvaluation => (
                    OutcomeEvaluationReasonV1::OutputMutationAfterEvaluation,
                    OutcomeSlaAttributionV1::Platform,
                ),
            };
            Ok(OutcomePriceAssessmentV1 {
                disposition: OutcomePriceDispositionV1::ZeroPrice,
                delivery_disposition: Some(OutcomeDeliveryDispositionV1::NotAttempted),
                verdict: Some(OutcomeEvaluationV1::Unevaluable { reason }),
                sla_attribution: Some(attribution),
                assessed_amount: zero,
            })
        }
        AuthenticatedOutcomeDeliveryEvidenceV1::Unknown => Ok(OutcomePriceAssessmentV1 {
            disposition: OutcomePriceDispositionV1::Indeterminate,
            delivery_disposition: None,
            verdict: None,
            sla_attribution: None,
            assessed_amount: zero,
        }),
    }
}

fn validate_evaluation_pricing(
    evaluation: &VerifiedOutcomeEvaluationV1,
    pricing: &VerifiedOutcomePricingV1,
) -> Result<(), OutcomeError> {
    if evaluation.predicate_id() != pricing.body().predicate_id()
        || evaluation.predicate_digest() != pricing.body().predicate_digest()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    Ok(())
}

fn validate_eligibility_pricing(
    eligibility: &AuthenticatedOutcomeEligibilityV1,
    pricing: &VerifiedOutcomePricingV1,
) -> Result<(), OutcomeError> {
    if eligibility.body().pricing_id() != pricing.body().pricing_id()
        || eligibility.body().pricing_digest() != pricing.envelope_digest()
        || eligibility.body().provider_id() != pricing.body().provider_id()
        || eligibility.body().predicate_id() != pricing.body().predicate_id()
        || eligibility.body().predicate_digest() != pricing.body().predicate_digest()
        || eligibility.body().sla_digest() != pricing.body().sla_digest()
        || eligibility.body().outcome_price() != pricing.body().outcome_price()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeVerdictStatusV1 {
    Passed,
    Failed,
    Unevaluable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeVerdictV1 {
    schema: String,
    request_id: String,
    listing_id: String,
    listing_digest: String,
    provider_id: String,
    provider_binding_digest: String,
    pricing_id: String,
    pricing_digest: String,
    predicate_id: String,
    predicate_digest: String,
    quote_digest: String,
    eligibility_digest: String,
    provider_acceptance_digest: String,
    delivery_disposition: OutcomeDeliveryDispositionV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_acknowledgement_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_nonacceptance_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contractual_zero_charge_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered_output_digest: Option<String>,
    verdict: OutcomeVerdictStatusV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<OutcomeEvaluationReasonV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assertion_index: Option<u32>,
    sla_attribution: OutcomeSlaAttributionV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribution_evidence_digest: Option<String>,
    charged_amount: MonetaryAmount,
    rail_authorization_ref: String,
}

impl OutcomeVerdictV1 {
    pub fn validate(&self) -> Result<(), OutcomeError> {
        if self.schema != OUTCOME_VERDICT_SCHEMA {
            return Err(OutcomeError::InvalidField("verdict_schema"));
        }
        for (field, value) in [
            ("request_id", &self.request_id),
            ("listing_id", &self.listing_id),
            ("provider_id", &self.provider_id),
            ("rail_authorization_ref", &self.rail_authorization_ref),
        ] {
            validate_text(field, value)?;
        }
        for (field, value) in [
            ("listing_digest", &self.listing_digest),
            ("provider_binding_digest", &self.provider_binding_digest),
            ("pricing_id", &self.pricing_id),
            ("pricing_digest", &self.pricing_digest),
            ("predicate_id", &self.predicate_id),
            ("predicate_digest", &self.predicate_digest),
            ("quote_digest", &self.quote_digest),
            ("eligibility_digest", &self.eligibility_digest),
            (
                "provider_acceptance_digest",
                &self.provider_acceptance_digest,
            ),
        ] {
            validate_digest(field, value)?;
        }
        for (field, digest) in [
            (
                "delivery_acknowledgement_digest",
                self.delivery_acknowledgement_digest.as_deref(),
            ),
            (
                "delivery_nonacceptance_digest",
                self.delivery_nonacceptance_digest.as_deref(),
            ),
            (
                "contractual_zero_charge_digest",
                self.contractual_zero_charge_digest.as_deref(),
            ),
            (
                "delivered_output_digest",
                self.delivered_output_digest.as_deref(),
            ),
            (
                "attribution_evidence_digest",
                self.attribution_evidence_digest.as_deref(),
            ),
        ] {
            if let Some(digest) = digest {
                validate_digest(field, digest)?;
            }
        }
        validate_money(&self.charged_amount, true)?;
        if let Some(index) = self.assertion_index {
            validate_time("assertion_index", u64::from(index).saturating_add(1))?;
        }
        if !self.evaluation_shape_valid() || !self.disposition_shape_valid() {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    fn evaluation_shape_valid(&self) -> bool {
        match self.verdict {
            OutcomeVerdictStatusV1::Passed => {
                self.reason_code.is_none() && self.assertion_index.is_none()
            }
            OutcomeVerdictStatusV1::Failed => {
                matches!(
                    self.reason_code,
                    Some(
                        OutcomeEvaluationReasonV1::AssertionMismatch
                            | OutcomeEvaluationReasonV1::MissingTarget
                    )
                ) && self.assertion_index.is_some()
            }
            OutcomeVerdictStatusV1::Unevaluable => {
                matches!(
                    self.reason_code,
                    Some(
                        OutcomeEvaluationReasonV1::TargetNotInteger
                            | OutcomeEvaluationReasonV1::InvalidOutputJson
                            | OutcomeEvaluationReasonV1::DeliveryCancelled
                            | OutcomeEvaluationReasonV1::OutputBlocked
                            | OutcomeEvaluationReasonV1::OutputMutationAfterEvaluation
                    )
                ) && self.assertion_index.is_none()
            }
        }
    }

    fn disposition_shape_valid(&self) -> bool {
        let passed = self.verdict == OutcomeVerdictStatusV1::Passed;
        match self.delivery_disposition {
            OutcomeDeliveryDispositionV1::Acknowledged => {
                let attribution_valid = match self.sla_attribution {
                    OutcomeSlaAttributionV1::Provider | OutcomeSlaAttributionV1::CallerPolicy => {
                        self.attribution_evidence_digest.is_some()
                    }
                    OutcomeSlaAttributionV1::Platform => false,
                };
                let outcome_valid = self.verdict != OutcomeVerdictStatusV1::Unevaluable
                    || matches!(
                        self.reason_code,
                        Some(
                            OutcomeEvaluationReasonV1::TargetNotInteger
                                | OutcomeEvaluationReasonV1::InvalidOutputJson
                        )
                    );
                self.delivery_acknowledgement_digest.is_some()
                    && self.delivery_nonacceptance_digest.is_none()
                    && self.contractual_zero_charge_digest.is_none()
                    && self.delivered_output_digest.is_some()
                    && (passed == (self.charged_amount.units > 0))
                    && attribution_valid
                    && outcome_valid
            }
            OutcomeDeliveryDispositionV1::Cancelled => {
                self.delivery_acknowledgement_digest.is_none()
                    && self.delivery_nonacceptance_digest.is_some()
                    && self.contractual_zero_charge_digest.is_none()
                    && self.delivered_output_digest.is_none()
                    && self.charged_amount.units == 0
                    && self.verdict == OutcomeVerdictStatusV1::Unevaluable
                    && self.reason_code == Some(OutcomeEvaluationReasonV1::DeliveryCancelled)
                    && self.sla_attribution == OutcomeSlaAttributionV1::Platform
                    && self.attribution_evidence_digest.is_none()
            }
            OutcomeDeliveryDispositionV1::NotAttempted => {
                let reason_attribution_valid = matches!(
                    (self.reason_code, self.sla_attribution),
                    (
                        Some(OutcomeEvaluationReasonV1::OutputBlocked),
                        OutcomeSlaAttributionV1::CallerPolicy
                    ) | (
                        Some(OutcomeEvaluationReasonV1::OutputMutationAfterEvaluation),
                        OutcomeSlaAttributionV1::Platform
                    )
                );
                self.delivery_acknowledgement_digest.is_none()
                    && self.delivery_nonacceptance_digest.is_none()
                    && self.contractual_zero_charge_digest.is_some()
                    && self.delivered_output_digest.is_none()
                    && self.charged_amount.units == 0
                    && self.verdict == OutcomeVerdictStatusV1::Unevaluable
                    && reason_attribution_valid
                    && self.attribution_evidence_digest.is_none()
            }
        }
    }

    pub fn validate_against_price(&self, price: &MonetaryAmount) -> Result<(), OutcomeError> {
        self.validate()?;
        validate_money(price, false)?;
        if self.charged_amount.currency != price.currency
            || (self.verdict == OutcomeVerdictStatusV1::Passed && self.charged_amount != *price)
            || (self.verdict != OutcomeVerdictStatusV1::Passed && self.charged_amount.units != 0)
        {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }

    pub fn validate_against_eligibility(
        &self,
        eligibility: &AuthenticatedOutcomeEligibilityV1,
    ) -> Result<(), OutcomeError> {
        self.validate_against_price(eligibility.body().outcome_price())?;
        if self.request_id != eligibility.body().request_id()
            || self.listing_id != eligibility.body().listing_id()
            || self.listing_digest != eligibility.body().listing_digest()
            || self.provider_id != eligibility.body().provider_id()
            || self.provider_binding_digest != eligibility.body().provider_binding_digest()
            || self.pricing_id != eligibility.body().pricing_id()
            || self.pricing_digest != eligibility.body().pricing_digest()
            || self.predicate_id != eligibility.body().predicate_id()
            || self.predicate_digest != eligibility.body().predicate_digest()
            || self.quote_digest != eligibility.body().quote_digest()
            || self.eligibility_digest != eligibility.envelope_digest()
        {
            return Err(OutcomeError::BindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeSlaArithmeticInputV1 {
    pub accepted_count: u64,
    pub provider_attributable_count: u64,
    pub caller_policy_excluded_count: u64,
    pub platform_excluded_count: u64,
    pub provider_failure_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeSlaRateV1 {
    pub failure_bps: u16,
    pub exceeds_threshold: bool,
}

pub fn calculate_outcome_sla_rate(
    sla: &OutcomeSlaBodyV1,
    counts: OutcomeSlaArithmeticInputV1,
) -> Result<OutcomeSlaRateV1, OutcomeError> {
    sla.validate()?;
    let partition_total = counts
        .provider_attributable_count
        .checked_add(counts.caller_policy_excluded_count)
        .and_then(|value| value.checked_add(counts.platform_excluded_count))
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    if partition_total != counts.accepted_count
        || counts.provider_failure_count > counts.provider_attributable_count
        || counts.provider_attributable_count < sla.minimum_sample_count()
    {
        return Err(OutcomeError::BindingMismatch);
    }
    let numerator = u128::from(counts.provider_failure_count)
        .checked_mul(10_000)
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    let denominator = u128::from(counts.provider_attributable_count);
    let failure_bps =
        u16::try_from(numerator / denominator).map_err(|_| OutcomeError::ArithmeticOverflow)?;
    let threshold = u128::from(sla.max_failure_bps())
        .checked_mul(denominator)
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    Ok(OutcomeSlaRateV1 {
        failure_bps,
        exceeds_threshold: numerator > threshold,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeSlaWindowV1 {
    pub start_unix_ms: u64,
    pub end_unix_ms: u64,
}

pub fn outcome_sla_window(
    sla: &OutcomeSlaBodyV1,
    accepted_at_unix_ms: u64,
) -> Result<OutcomeSlaWindowV1, OutcomeError> {
    sla.validate()?;
    validate_time("accepted_at_unix_ms", accepted_at_unix_ms)?;
    if accepted_at_unix_ms < sla.effective_at_unix_ms()
        || accepted_at_unix_ms >= sla.expires_at_unix_ms()
    {
        return Err(OutcomeError::NotCurrent);
    }
    let window_ms = sla
        .window_seconds()
        .checked_mul(1_000)
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    let offset = accepted_at_unix_ms
        .checked_sub(sla.window_anchor_unix_ms())
        .ok_or(OutcomeError::BindingMismatch)?;
    let window_index = offset / window_ms;
    let start = sla
        .window_anchor_unix_ms()
        .checked_add(
            window_index
                .checked_mul(window_ms)
                .ok_or(OutcomeError::ArithmeticOverflow)?,
        )
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    let end = start
        .checked_add(window_ms - 1)
        .ok_or(OutcomeError::ArithmeticOverflow)?;
    if start < sla.effective_at_unix_ms() || end >= sla.expires_at_unix_ms() {
        return Err(OutcomeError::NotCurrent);
    }
    Ok(OutcomeSlaWindowV1 {
        start_unix_ms: start,
        end_unix_ms: end,
    })
}
