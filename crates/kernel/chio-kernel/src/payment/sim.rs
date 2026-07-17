//! Deterministic, no-broadcast payment adapter for sim-first acceptance lanes.
//!
//! Custody-neutral by construction: it performs no HTTP, holds no key, and moves
//! no funds. Authorization ids are a pure function of the request so smokes are
//! reproducible. It echoes the governed binding into `metadata` so the settled
//! tool-call receipt carries the governed intent hash and approval token id.

use crate::payment::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizeRequest, PaymentError, PaymentResult,
    RailSettlementStatus,
};

/// Deterministic no-broadcast payment adapter.
#[derive(Debug, Clone, Default)]
pub struct SimPaymentAdapter;

impl SimPaymentAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn deterministic_id(
        prefix: &str,
        reference: &str,
        amount_units: u64,
        currency: &str,
    ) -> String {
        let seed = format!("{reference}|{amount_units}|{currency}");
        let digest = chio_core::sha256_hex(seed.as_bytes());
        format!("{prefix}-{}", &digest[..32])
    }
}

impl PaymentAdapter for SimPaymentAdapter {
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let authorization_id = Self::deterministic_id(
            "sim",
            &request.reference,
            request.amount_units,
            &request.currency,
        );
        Ok(PaymentAuthorization {
            authorization_id,
            settled: false,
            metadata: serde_json::json!({
                "adapter": "sim",
                "mode": "prepaid_no_broadcast",
                "governed": request.governed,
                "commerce": request.commerce,
            }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "sim", "action": "capture" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "sim", "action": "release" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "sim", "action": "refund" }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(reference: &str, amount: u64) -> PaymentAuthorizeRequest {
        PaymentAuthorizeRequest {
            amount_units: amount,
            currency: "USD".to_string(),
            payer: "agent-1".to_string(),
            payee: "srv-1".to_string(),
            reference: reference.to_string(),
            governed: None,
            commerce: None,
        }
    }

    #[test]
    fn authorize_is_deterministic_and_unsettled() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let b = adapter.authorize(&request("req-1", 100)).unwrap();
        assert_eq!(a.authorization_id, b.authorization_id);
        assert!(a.authorization_id.starts_with("sim-"));
        assert!(!a.settled, "sim must leave capture/release to the kernel");
    }

    #[test]
    fn distinct_requests_get_distinct_ids() {
        let adapter = SimPaymentAdapter::new();
        let a = adapter.authorize(&request("req-1", 100)).unwrap();
        let c = adapter.authorize(&request("req-2", 100)).unwrap();
        assert_ne!(a.authorization_id, c.authorization_id);
    }

    #[test]
    fn capture_and_release_map_to_settled_and_released() {
        let adapter = SimPaymentAdapter::new();
        let captured = adapter.capture("sim-abc", 100, "USD", "req-1").unwrap();
        assert_eq!(captured.settlement_status, RailSettlementStatus::Settled);
        let released = adapter.release("sim-abc", "req-1").unwrap();
        assert_eq!(released.settlement_status, RailSettlementStatus::Released);
    }
}
