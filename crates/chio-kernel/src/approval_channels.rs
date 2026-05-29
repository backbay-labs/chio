//! Approval channels for HITL signaling.
//!
//! A channel is a delivery mechanism that gets an `ApprovalRequest` in
//! front of a human. The kernel treats channels as fire-and-forget
//! sinks: on failure the request stays in the approval store and can
//! still be fetched via `GET /approvals/pending`, matching the
//! fail-closed rule in the HITL protocol.
//!
//! Two channels:
//!
//! 1. `WebhookChannel` -- blocking HTTP POST to a configured URL.
//!    Production integrations wire this into their own dashboard or
//!    ticketing system.
//! 2. `RecordingChannel` -- captures every dispatch in an in-memory
//!    ring so tests (and host adapters) can assert that a dispatch
//!    fired without standing up an HTTP listener.

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;

use crate::approval::{ApprovalChannel, ApprovalRequest, ChannelError, ChannelHandle};

/// Payload shape delivered by `WebhookChannel`. Stable so receivers can
/// parse it without pulling in kernel types.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload<'a> {
    pub event: &'static str,
    pub approval: &'a ApprovalRequest,
    pub callback_url: String,
}

/// Blocking HTTP webhook channel. Uses `ureq`, which is already in the
/// kernel's dependency tree.
pub struct WebhookChannel {
    endpoint: String,
    timeout: Duration,
    header: Option<(String, String)>,
}

impl WebhookChannel {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(5),
            header: None,
        }
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attach a static header, typically an HMAC or bearer token. Only
    /// one is supported because every real caller uses a single auth
    /// secret; adding a second would invite operator confusion.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.header = Some((name.into(), value.into()));
        self
    }
}

impl ApprovalChannel for WebhookChannel {
    fn name(&self) -> &str {
        "webhook"
    }

    fn dispatch(&self, request: &ApprovalRequest) -> Result<ChannelHandle, ChannelError> {
        let payload = WebhookPayload {
            event: "approval_requested",
            approval: request,
            callback_url: format!("/approvals/{}/respond", request.approval_id),
        };
        let body = serde_json::to_string(&payload)
            .map_err(|e| ChannelError::Config(format!("cannot serialize payload: {e}")))?;

        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let mut req = agent
            .post(&self.endpoint)
            .set("content-type", "application/json");
        if let Some((name, value)) = &self.header {
            req = req.set(name, value);
        }

        let response = req.send_string(&body);
        match response {
            Ok(resp) => {
                let channel_ref = resp
                    .header("x-request-id")
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| request.approval_id.clone());
                Ok(ChannelHandle {
                    channel: "webhook".into(),
                    channel_ref,
                    action_url: Some(format!("/approvals/{}", request.approval_id)),
                })
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(ChannelError::Remote { status, body })
            }
            Err(ureq::Error::Transport(err)) => Err(ChannelError::Transport(err.to_string())),
        }
    }
}

/// In-memory channel that captures every dispatched `ApprovalRequest`
/// for later inspection. Useful in tests and for the `api-poll`
/// dispatch mode (where the "channel" is really the local store
/// itself).
#[derive(Default)]
pub struct RecordingChannel {
    captured: Mutex<Vec<ApprovalRequest>>,
}

impl RecordingChannel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every dispatched request.
    pub fn captured(&self) -> Vec<ApprovalRequest> {
        self.captured
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Number of requests dispatched so far.
    pub fn len(&self) -> usize {
        self.captured.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ApprovalChannel for RecordingChannel {
    fn name(&self) -> &str {
        "recording"
    }

    fn dispatch(&self, request: &ApprovalRequest) -> Result<ChannelHandle, ChannelError> {
        let mut guard = self
            .captured
            .lock()
            .map_err(|_| ChannelError::Transport("recording channel poisoned".into()))?;
        guard.push(request.clone());
        Ok(ChannelHandle {
            channel: "recording".into(),
            channel_ref: format!("rec-{}", request.approval_id),
            action_url: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;

    #[test]
    fn recording_channel_captures_dispatches() {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        let channel = RecordingChannel::new();
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "p-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "c-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "tool".into(),
            action: "invoke".into(),
            parameter_hash: "h".into(),
            expires_at: 10,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        };
        let handle = channel.dispatch(&req).unwrap();
        assert_eq!(handle.channel, "recording");
        assert_eq!(channel.len(), 1);
        assert_eq!(channel.captured()[0].approval_id, "a-1");
    }
}
