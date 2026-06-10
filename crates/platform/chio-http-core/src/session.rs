//! Session context for HTTP request evaluation.

use serde::{Deserialize, Serialize};

use crate::identity::CallerIdentity;

/// Per-session context carried through the Chio HTTP pipeline.
/// A session groups related requests from the same caller over a
/// bounded time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    /// Unique session identifier.
    pub session_id: String,

    /// The authenticated caller for this session.
    pub caller: CallerIdentity,

    /// Unix timestamp (seconds) when the session was created.
    pub created_at: u64,

    /// Unix timestamp (seconds) when the session expires.
    /// Guards may deny requests after this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Number of requests evaluated in this session so far.
    #[serde(default)]
    pub request_count: u64,

    /// Cumulative bytes read by this session (for data-flow guards).
    #[serde(default)]
    pub bytes_read: u64,

    /// Cumulative bytes written by this session (for data-flow guards).
    #[serde(default)]
    pub bytes_written: u64,

    /// Current delegation depth (0 = direct caller).
    #[serde(default)]
    pub delegation_depth: u32,

    /// Optional metadata for extensibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl SessionContext {
    /// Create a new session with the given ID and caller.
    #[must_use]
    pub fn new(session_id: String, caller: CallerIdentity) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            session_id,
            caller,
            created_at: now,
            expires_at: None,
            request_count: 0,
            bytes_read: 0,
            bytes_written: 0,
            delegation_depth: 0,
            metadata: None,
        }
    }

    /// Whether this session has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            let now = chrono::Utc::now().timestamp() as u64;
            now >= exp
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CallerIdentity;

    use chio_test_support::prelude::*;

    #[test]
    fn new_session_defaults() {
        let session = SessionContext::new("sess-001".to_string(), CallerIdentity::anonymous());
        assert_eq!(session.session_id, "sess-001");
        assert_eq!(session.request_count, 0);
        assert_eq!(session.bytes_read, 0);
        assert_eq!(session.delegation_depth, 0);
        assert!(session.expires_at.is_none());
    }

    #[test]
    fn expired_session() {
        let mut session = SessionContext::new("sess-002".to_string(), CallerIdentity::anonymous());
        session.expires_at = Some(0); // epoch = long expired
        assert!(session.is_expired());
    }

    #[test]
    fn not_expired_when_no_expiry() {
        let session = SessionContext::new("sess-003".to_string(), CallerIdentity::anonymous());
        assert!(!session.is_expired());
    }

    #[test]
    fn serde_roundtrip() {
        let session = SessionContext::new("sess-004".to_string(), CallerIdentity::anonymous());
        let json = serde_json::to_string(&session).test_unwrap();
        let back: SessionContext = serde_json::from_str(&json).test_unwrap();
        assert_eq!(back.session_id, "sess-004");
    }
}
