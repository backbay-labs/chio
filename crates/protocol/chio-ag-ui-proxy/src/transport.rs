//! Transport abstractions for SSE and WebSocket connections.

use serde::{Deserialize, Serialize};

/// Supported transport kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Server-Sent Events (unidirectional server-to-client).
    Sse,
    /// WebSocket (bidirectional).
    WebSocket,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sse => write!(f, "sse"),
            Self::WebSocket => write!(f, "websocket"),
        }
    }
}

/// Metadata about an active transport connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transport {
    /// Transport kind.
    pub kind: TransportKind,
    /// Connection identifier.
    pub connection_id: String,
    /// Agent on the upstream side.
    pub agent_id: String,
    /// Optional session binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Unix timestamp when the connection was established.
    pub connected_at: u64,
    /// Number of events forwarded on this connection.
    pub events_forwarded: u64,
    /// Number of events blocked by policy.
    pub events_blocked: u64,
}

impl Transport {
    /// Create a new transport connection record.
    pub fn new(kind: TransportKind, connection_id: String, agent_id: String) -> Self {
        Self {
            kind,
            connection_id,
            agent_id,
            session_id: None,
            connected_at: 0,
            events_forwarded: 0,
            events_blocked: 0,
        }
    }

    /// Record a forwarded event.
    pub fn record_forwarded(&mut self) {
        self.events_forwarded = self.events_forwarded.saturating_add(1);
    }

    /// Record a blocked event.
    pub fn record_blocked(&mut self) {
        self.events_blocked = self.events_blocked.saturating_add(1);
    }

    /// Total events seen (forwarded + blocked).
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.events_forwarded.saturating_add(self.events_blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_counters() {
        let mut t = Transport::new(
            TransportKind::Sse,
            "conn-1".to_string(),
            "agent-1".to_string(),
        );
        assert_eq!(t.total_events(), 0);

        t.record_forwarded();
        t.record_forwarded();
        t.record_blocked();

        assert_eq!(t.events_forwarded, 2);
        assert_eq!(t.events_blocked, 1);
        assert_eq!(t.total_events(), 3);
    }

    #[test]
    fn transport_kind_display() {
        assert_eq!(TransportKind::Sse.to_string(), "sse");
        assert_eq!(TransportKind::WebSocket.to_string(), "websocket");
    }

    #[test]
    fn transport_roundtrip() {
        let t = Transport::new(
            TransportKind::WebSocket,
            "ws-1".to_string(),
            "agent-2".to_string(),
        );
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: Transport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.kind, TransportKind::WebSocket);
        assert_eq!(deserialized.connection_id, "ws-1");
    }
}
