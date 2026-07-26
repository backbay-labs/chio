use chio_core::capability::governance::{MeteredBillingContext, MeteredSettlementMode};

use crate::KernelError;

const BILLING_UNIT: &str = "verified_outcome";

pub(super) fn validate_verified_outcome_request(
    metered: &MeteredBillingContext,
) -> Result<(), KernelError> {
    let is_outcome = metered.quote.billing_unit == BILLING_UNIT;
    let Some(request) = metered.verified_outcome.as_ref() else {
        return if is_outcome {
            deny("verified outcome billing requires its typed request extension")
        } else {
            Ok(())
        };
    };
    if !is_outcome {
        return deny("verified outcome request extension is forbidden for another billing unit");
    }
    if metered.settlement_mode != MeteredSettlementMode::HoldCapture {
        return deny("verified outcome billing requires hold_capture settlement");
    }
    if metered.quote.quoted_units != 1 || metered.max_billed_units.is_some_and(|units| units != 1) {
        return deny("verified outcome billing requires exactly one quoted unit");
    }
    if request.validate().is_err() {
        return deny("verified outcome request is invalid");
    }
    deny("verified outcome pricing is not activated")
}

fn deny<T>(reason: &str) -> Result<T, KernelError> {
    Err(KernelError::GovernedTransactionDenied(reason.to_owned()))
}

#[cfg(test)]
mod tests {
    use chio_core::capability::governance::{
        VerifiedOutcomeRequestV1, VERIFIED_OUTCOME_REQUEST_SCHEMA,
    };
    use chio_core::capability::scope::MonetaryAmount;

    use super::*;

    fn extension() -> VerifiedOutcomeRequestV1 {
        VerifiedOutcomeRequestV1 {
            schema: VERIFIED_OUTCOME_REQUEST_SCHEMA.to_owned(),
            listing_id: "listing-1".to_owned(),
            listing_digest: "1".repeat(64),
            provider_binding_digest: "2".repeat(64),
            pricing_id: "3".repeat(64),
            pricing_digest: "4".repeat(64),
            predicate_id: "5".repeat(64),
            predicate_digest: "6".repeat(64),
            sla_digest: Some("7".repeat(64)),
            receiver_binding_digest: "8".repeat(64),
        }
    }

    fn context() -> MeteredBillingContext {
        MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::HoldCapture,
            quote: chio_core::capability::governance::MeteredBillingQuote {
                quote_id: "quote-1".to_owned(),
                provider: "provider-1".to_owned(),
                billing_unit: BILLING_UNIT.to_owned(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units: 500,
                    currency: "USD".to_owned(),
                },
                issued_at: 1,
                expires_at: Some(2),
            },
            max_billed_units: Some(1),
            verified_outcome: Some(extension()),
        }
    }

    fn reason(context: &MeteredBillingContext) -> String {
        match validate_verified_outcome_request(context) {
            Err(KernelError::GovernedTransactionDenied(reason)) => reason,
            other => panic!("unexpected validation result: {other:?}"),
        }
    }

    #[test]
    fn inactive_contract_rejects_every_outcome_request_shape() {
        let mut missing = context();
        missing.verified_outcome = None;
        assert!(reason(&missing).contains("requires its typed request extension"));

        let mut foreign = context();
        foreign.quote.billing_unit = "tokens".to_owned();
        assert!(reason(&foreign).contains("forbidden for another billing unit"));

        let mut prepaid = context();
        prepaid.settlement_mode = MeteredSettlementMode::MustPrepay;
        assert!(reason(&prepaid).contains("requires hold_capture"));

        let mut multiple = context();
        multiple.quote.quoted_units = 2;
        assert!(reason(&multiple).contains("exactly one quoted unit"));

        let mut unknown = context();
        let Some(request) = unknown.verified_outcome.as_mut() else {
            panic!("verified outcome request is missing");
        };
        request.schema = "chio.outcome.request.v9".to_owned();
        assert!(reason(&unknown).contains("request is invalid"));

        let mut empty = context();
        let Some(request) = empty.verified_outcome.as_mut() else {
            panic!("verified outcome request is missing");
        };
        request.listing_id.clear();
        assert!(reason(&empty).contains("request is invalid"));

        let mut malformed = context();
        let Some(request) = malformed.verified_outcome.as_mut() else {
            panic!("verified outcome request is missing");
        };
        request.pricing_digest = "A".repeat(64);
        assert!(reason(&malformed).contains("request is invalid"));

        assert!(reason(&context()).contains("pricing is not activated"));
    }

    #[test]
    fn unrelated_metered_billing_remains_admissible() {
        let mut unrelated = context();
        unrelated.quote.billing_unit = "tokens".to_owned();
        unrelated.verified_outcome = None;
        assert!(validate_verified_outcome_request(&unrelated).is_ok());
    }
}
