//! Gemini generateContent transport scaffold.

use std::sync::Mutex;

use thiserror::Error;

/// Pinned Gemini API version. Bumping requires re-recording conformance fixtures.
pub const GEMINI_API_VERSION: &str = "v1beta";

/// Default Gemini generateContent endpoint host.
pub const GEMINI_GENERATE_CONTENT_HOST: &str = "https://generativelanguage.googleapis.com";

/// Wire-level transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The mock transport has no scripted response for this endpoint.
    #[error("mock transport has no scripted response for `{endpoint}`")]
    MockExhausted { endpoint: String },
    /// Placeholder for the real HTTP transport path.
    #[error("gemini transport HTTP path is not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Wire-level transport contract.
pub trait Transport: Send + Sync {
    fn api_version(&self) -> &str {
        GEMINI_API_VERSION
    }

    fn endpoint(&self) -> &str {
        GEMINI_GENERATE_CONTENT_HOST
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
        "mock://gemini"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(GEMINI_API_VERSION, "v1beta");
        assert_eq!(
            GEMINI_GENERATE_CONTENT_HOST,
            "https://generativelanguage.googleapis.com"
        );
    }

    #[test]
    fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.record("/v1beta/models/gemini-1.5-pro:generateContent", b"{\"foo\":1}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.api_version(), GEMINI_API_VERSION);
        assert_eq!(mock.endpoint(), "mock://gemini");
    }

    #[test]
    fn transport_error_display_is_em_dash_free() {
        let cases = vec![
            TransportError::MockExhausted {
                endpoint: "/v1beta".to_string(),
            },
            TransportError::NotImplemented("generateContent"),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
