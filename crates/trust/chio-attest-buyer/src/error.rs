use std::fmt;

pub(crate) type RuntimeBuyerError = chio_runtime_core::ChioRuntimeError;

#[derive(Debug)]
pub struct BuyerAttestationError {
    code: String,
    source: RuntimeBuyerError,
}

impl BuyerAttestationError {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    pub(crate) fn from_runtime(source: RuntimeBuyerError) -> Self {
        let code = chio_attest_buyer_code(source.code());
        Self { code, source }
    }
}

impl fmt::Display for BuyerAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for BuyerAttestationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub(crate) fn chio_attest_buyer_code(code: &str) -> String {
    for (runtime_prefix, chio_prefix) in [
        ("chio_buyer.", "chio_attest_buyer.packet."),
        ("chio_buyer_review.", "chio_attest_buyer.review."),
        ("buyer_review.", "chio_attest_buyer.review."),
        ("chio_buyer_packet.", "chio_attest_buyer.packet."),
        ("buyer_packet.", "chio_attest_buyer.packet."),
        ("chio_buyer_review_", "chio_attest_buyer_review_"),
        ("buyer_review_", "chio_attest_buyer_review_"),
        ("chio_buyer_packet_", "chio_attest_buyer_packet_"),
        ("buyer_packet_", "chio_attest_buyer_packet_"),
    ] {
        if let Some(suffix) = code.strip_prefix(runtime_prefix) {
            return format!("{chio_prefix}{suffix}");
        }
    }
    code.to_string()
}

pub(crate) fn json_error(label: &str, error: impl fmt::Display) -> BuyerAttestationError {
    BuyerAttestationError::from_runtime(RuntimeBuyerError::Json(format!("{label}: {error}")))
}

pub(crate) fn boundary_rejection(
    code: &'static str,
    detail: impl Into<String>,
) -> BuyerAttestationError {
    BuyerAttestationError::from_runtime(RuntimeBuyerError::Rejected {
        code,
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_error_helper_keeps_chio_boundary_code_and_label() {
        let parse_error = match serde_json::from_str::<serde_json::Value>("{") {
            Ok(_) => panic!("invalid JSON must fail"),
            Err(error) => error,
        };
        let error = json_error("Chio buyer packet JSON", parse_error);

        assert_eq!(error.code(), "runtime_admission_json");
        assert!(
            error.to_string().contains("Chio buyer packet JSON"),
            "label should remain visible in public error text"
        );
    }
}
