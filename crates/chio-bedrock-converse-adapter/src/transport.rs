//! Bedrock Runtime transport scaffold.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Pinned Bedrock Converse API marker used in Chio provenance.
pub const BEDROCK_CONVERSE_API_VERSION: &str = "bedrock.converse.v1";

/// Only AWS region supported by the v1 Bedrock adapter.
pub const BEDROCK_REGION: &str = "us-east-1";

/// Bedrock Runtime operations this adapter is allowed to target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BedrockOperation {
    /// Batch Bedrock Runtime Converse call.
    Converse,
    /// Streaming Bedrock Runtime Converse call over HTTP/2.
    ConverseStream,
}

impl BedrockOperation {
    /// AWS SDK operation name.
    pub fn sdk_name(&self) -> &'static str {
        match self {
            BedrockOperation::Converse => "Converse",
            BedrockOperation::ConverseStream => "ConverseStream",
        }
    }
}

/// Wire-level transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("mock bedrock transport has no scripted response for {operation}")]
    MockExhausted { operation: &'static str },
    #[error("unsupported bedrock runtime operation: {operation}")]
    UnsupportedOperation { operation: String },
    #[error("unsupported bedrock region: {region}; expected us-east-1")]
    UnsupportedRegion { region: String },
    #[error("bedrock SDK transport path is not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Wire-level transport contract.
pub trait Transport: Send + Sync {
    /// AWS region targeted by this transport.
    fn region(&self) -> &str {
        BEDROCK_REGION
    }

    /// Whether this transport supports a Bedrock Runtime operation.
    fn supports_operation(&self, operation: BedrockOperation) -> bool {
        matches!(
            operation,
            BedrockOperation::Converse | BedrockOperation::ConverseStream
        )
    }

    /// Validate that the transport is pinned to the allowed region and that
    /// the requested operation is inside the scaffold scope.
    fn validate_operation(&self, operation: BedrockOperation) -> Result<(), TransportError> {
        if self.region() != BEDROCK_REGION {
            return Err(TransportError::UnsupportedRegion {
                region: self.region().to_string(),
            });
        }
        if !self.supports_operation(operation) {
            return Err(TransportError::UnsupportedOperation {
                operation: operation.sdk_name().to_string(),
            });
        }
        Ok(())
    }
}

/// In-memory transport that records intended Bedrock calls without contacting AWS.
#[derive(Default)]
pub struct MockTransport {
    calls: Mutex<Vec<(BedrockOperation, Vec<u8>)>>,
}

impl MockTransport {
    /// Construct an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call intent after validating the operation and region gates.
    pub fn record(&self, operation: BedrockOperation, body: &[u8]) -> Result<(), TransportError> {
        self.validate_operation(operation)?;
        if let Ok(mut guard) = self.calls.lock() {
            guard.push((operation, body.to_vec()));
        }
        Ok(())
    }

    /// Snapshot recorded calls for assertions.
    pub fn calls(&self) -> Vec<(BedrockOperation, Vec<u8>)> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl Transport for MockTransport {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(BEDROCK_CONVERSE_API_VERSION, "bedrock.converse.v1");
        assert_eq!(BEDROCK_REGION, "us-east-1");
    }

    #[test]
    fn operation_names_match_sdk_surface() {
        assert_eq!(BedrockOperation::Converse.sdk_name(), "Converse");
        assert_eq!(
            BedrockOperation::ConverseStream.sdk_name(),
            "ConverseStream"
        );
    }

    #[test]
    fn mock_transport_records_supported_operations() {
        let mock = MockTransport::new();
        mock.record(BedrockOperation::Converse, b"{\"input\":1}")
            .unwrap();
        mock.record(BedrockOperation::ConverseStream, b"{\"input\":2}")
            .unwrap();
        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, BedrockOperation::Converse);
        assert_eq!(calls[1].1, b"{\"input\":2}");
    }

    #[test]
    fn transport_error_display_is_em_dash_free() {
        let cases = vec![
            TransportError::MockExhausted {
                operation: "Converse",
            },
            TransportError::UnsupportedOperation {
                operation: "InvokeModel".to_string(),
            },
            TransportError::UnsupportedRegion {
                region: "us-west-2".to_string(),
            },
            TransportError::NotImplemented("converse"),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
