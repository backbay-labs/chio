//! Anthropic Messages transport scaffold.

use std::sync::Mutex;

use thiserror::Error;

/// Pinned Anthropic Messages API version. Bumping requires re-recording conformance fixtures.
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Beta header value used when the `computer-use` cargo feature is on.
pub const COMPUTER_USE_BETA: &str = "computer-use-2025-01-24";

/// Default Anthropic Messages endpoint.
pub const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";

/// Wire-level transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The mock transport has no scripted response for this endpoint.
    #[error("mock transport has no scripted response for `{endpoint}`")]
    MockExhausted { endpoint: String },
    /// Placeholder for the real HTTP transport path.
    #[error("anthropic transport HTTP path is not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Wire-level transport contract.
pub trait Transport: Send + Sync {
    fn anthropic_version(&self) -> &str {
        ANTHROPIC_VERSION
    }

    fn computer_use_beta(&self) -> Option<&str> {
        if cfg!(feature = "computer-use") {
            Some(COMPUTER_USE_BETA)
        } else {
            None
        }
    }

    fn endpoint(&self) -> &str {
        ANTHROPIC_MESSAGES_URL
    }
}

/// In-memory transport that records every call placed against it.
#[derive(Default)]
pub struct MockTransport {
    /// Captured `(endpoint, raw-body-bytes)` tuples in order of issue.
    calls: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MockTransport {
    /// Construct an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a placed call.
    pub fn record(&self, endpoint: &str, body: &[u8]) {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push((endpoint.to_string(), body.to_vec()));
        }
    }

    /// Snapshot the recorded calls for assertions.
    pub fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl Transport for MockTransport {
    fn endpoint(&self) -> &str {
        "mock://anthropic"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(ANTHROPIC_VERSION, "2023-06-01");
        assert_eq!(COMPUTER_USE_BETA, "computer-use-2025-01-24");
        assert_eq!(
            ANTHROPIC_MESSAGES_URL,
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.record("/v1/messages", b"{\"foo\":1}");
        mock.record("/v1/messages", b"{\"foo\":2}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "/v1/messages");
        assert_eq!(calls[1].1, b"{\"foo\":2}");
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.anthropic_version(), ANTHROPIC_VERSION);
        assert_eq!(mock.endpoint(), "mock://anthropic");
    }

    #[test]
    fn computer_use_header_tracks_feature() {
        let mock = MockTransport::new();
        assert_eq!(
            mock.computer_use_beta().is_some(),
            cfg!(feature = "computer-use")
        );
    }

    #[test]
    fn transport_error_display_is_em_dash_free() {
        let cases = vec![
            TransportError::MockExhausted {
                endpoint: "/v1/messages".to_string(),
            },
            TransportError::NotImplemented("messages.create"),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
