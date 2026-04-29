//! TrafficTap trait: a hook surface for the chio-tee shadow runner.
//!
//! Implementations observe kernel-bound traffic before evaluation and
//! kernel-emitted decisions after evaluation, allowing the TEE side to
//! capture both halves for replay attestation.
//!
//! The trait shape mirrors the [`Exporter`] trait in `chio-siem`
//! (`crates/chio-siem/src/exporter.rs:35`): methods take `&self` so taps
//! can be held as `Box<dyn TrafficTap>` and fan out, and errors are
//! returned as a boxed `Send + Sync` error so backend implementations
//! can choose their own error types without polluting the trait.
//!
//! The wire-level `AgentMessage` and `ChioReceipt` types from
//! `chio-core` are used as the request/receipt observation points -
//! these are the canonical on-the-wire types crossing the kernel
//! boundary, and the tap sees them as a passive observer.

use std::error::Error;

use chio_core::message::AgentMessage;
use chio_core::receipt::ChioReceipt;

/// Boxed error returned by `TrafficTap` hooks. `Send + Sync` so taps can
/// be invoked from any thread without losing the underlying error type.
pub type TapError = Box<dyn Error + Send + Sync>;

/// Result alias for `TrafficTap` hook outcomes.
pub type TapResult = Result<(), TapError>;

/// Trait implemented by chio-tee hook backends (capture spool,
/// in-memory ring buffer, structured logger, etc.).
///
/// Implementations observe traffic in two halves:
///
/// - [`TrafficTap::before_kernel`] is invoked before the kernel evaluates
///   a request. Implementations may inspect, log, or capture the
///   in-flight request. Returning an error MUST cause the tee to refuse
///   persistence of the receipt half (fail-closed).
/// - [`TrafficTap::after_kernel`] is invoked after the kernel emits a
///   decision. Implementations may inspect, log, or capture the receipt
///   together with the originating request.
///
/// The trait is dyn-compatible: hooks may be held as
/// `Box<dyn TrafficTap>` and fanned out across multiple sinks (capture
/// spool, telemetry, audit log) by a manager that owns the collection.
pub trait TrafficTap: Send + Sync {
    /// Called before the kernel evaluates `request`.
    ///
    /// Implementations should treat the request as read-only; the tap
    /// is an observer, not a transform. Returning `Err` signals a
    /// fail-closed condition to the caller.
    fn before_kernel(&self, request: &AgentMessage) -> TapResult;

    /// Called after the kernel emits `receipt` for `request`.
    ///
    /// Implementations receive both halves so they can correlate the
    /// request with the verdict for replay attestation. Returning `Err`
    /// signals a fail-closed condition to the caller.
    fn after_kernel(&self, request: &AgentMessage, receipt: &ChioReceipt) -> TapResult;

    /// Return the human-readable name of this tap (for logging and
    /// diagnostic attribution). Mirrors `Exporter::name`.
    fn name(&self) -> &str;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use chio_core::canonical::canonical_json_string;
    use chio_core::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};

    /// Recorded event in the order it was observed by a `RecordingTap`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TapEvent {
        Before(String),
        After(String),
    }

    /// Stub `TrafficTap` implementation that records every call into an
    /// internal log so tests can verify ordering and lifecycle.
    struct RecordingTap {
        log: Mutex<Vec<TapEvent>>,
    }

    impl RecordingTap {
        fn new() -> Self {
            Self {
                log: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<TapEvent> {
            match self.log.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }

        fn push(&self, event: TapEvent) {
            if let Ok(mut guard) = self.log.lock() {
                guard.push(event);
            }
        }
    }

    impl TrafficTap for RecordingTap {
        fn before_kernel(&self, request: &AgentMessage) -> TapResult {
            self.push(TapEvent::Before(request_id_for(request)));
            Ok(())
        }

        fn after_kernel(&self, request: &AgentMessage, receipt: &ChioReceipt) -> TapResult {
            let _ = receipt;
            self.push(TapEvent::After(request_id_for(request)));
            Ok(())
        }

        fn name(&self) -> &str {
            "recording-tap"
        }
    }

    /// Stub `TrafficTap` implementation whose hooks always fail. Used to
    /// verify error propagation through the trait.
    struct AlwaysFailingTap;

    impl TrafficTap for AlwaysFailingTap {
        fn before_kernel(&self, _request: &AgentMessage) -> TapResult {
            Err("synthetic before_kernel failure".into())
        }

        fn after_kernel(&self, _request: &AgentMessage, _receipt: &ChioReceipt) -> TapResult {
            Err("synthetic after_kernel failure".into())
        }

        fn name(&self) -> &str {
            "always-failing-tap"
        }
    }

    fn request_id_for(message: &AgentMessage) -> String {
        match message {
            AgentMessage::ToolCallRequest { id, .. } => id.clone(),
            AgentMessage::ListCapabilities => "list-capabilities".to_string(),
            AgentMessage::Heartbeat => "heartbeat".to_string(),
        }
    }

    fn fake_capability(kp: &Keypair, id: &str) -> CapabilityToken {
        let body = CapabilityTokenBody {
            id: format!("cap-{id}"),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
        };
        match CapabilityToken::sign(body, kp) {
            Ok(token) => token,
            Err(err) => panic!("test capability sign must succeed: {err}"),
        }
    }

    fn fake_request(kp: &Keypair, id: &str) -> AgentMessage {
        AgentMessage::ToolCallRequest {
            id: id.to_string(),
            capability_token: Box::new(fake_capability(kp, id)),
            server_id: "srv-1".to_string(),
            tool: "noop".to_string(),
            params: serde_json::Value::Null,
        }
    }

    fn fake_receipt(kp: &Keypair, id: &str) -> ChioReceipt {
        let params = serde_json::Value::Null;
        let canonical = match canonical_json_string(&params) {
            Ok(s) => s,
            Err(err) => panic!("canonical_json_string must succeed: {err}"),
        };
        let parameter_hash = sha256_hex(canonical.as_bytes());
        let action = ToolCallAction {
            parameters: params,
            parameter_hash: parameter_hash.clone(),
        };
        let body = ChioReceiptBody {
            id: format!("rcpt-{id}"),
            timestamp: 0,
            capability_id: format!("cap-{id}"),
            tool_server: "srv-1".to_string(),
            tool_name: "noop".to_string(),
            action,
            decision: Decision::Allow,
            content_hash: parameter_hash,
            policy_hash: "0".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        };
        match ChioReceipt::sign(body, kp) {
            Ok(receipt) => receipt,
            Err(err) => panic!("test receipt sign must succeed: {err}"),
        }
    }

    #[test]
    fn before_then_after_records_in_call_order() {
        let kp = Keypair::generate();
        let tap = RecordingTap::new();
        let req = fake_request(&kp, "req-1");
        let rcpt = fake_receipt(&kp, "req-1");

        tap.before_kernel(&req).expect("before_kernel ok");
        tap.after_kernel(&req, &rcpt).expect("after_kernel ok");

        assert_eq!(
            tap.events(),
            vec![
                TapEvent::Before("req-1".to_string()),
                TapEvent::After("req-1".to_string()),
            ],
        );
    }

    #[test]
    fn errors_propagate_to_caller() {
        let kp = Keypair::generate();
        let tap = AlwaysFailingTap;
        let req = fake_request(&kp, "req-err");
        let rcpt = fake_receipt(&kp, "req-err");

        let before = tap.before_kernel(&req);
        let after = tap.after_kernel(&req, &rcpt);

        assert!(before.is_err(), "before_kernel must propagate Err");
        assert!(after.is_err(), "after_kernel must propagate Err");
        if let Err(err) = before {
            assert!(err.to_string().contains("before_kernel"));
        }
        if let Err(err) = after {
            assert!(err.to_string().contains("after_kernel"));
        }
    }

    #[test]
    fn multi_call_accumulation_preserves_order() {
        let kp = Keypair::generate();
        let tap = RecordingTap::new();
        let req_a = fake_request(&kp, "a");
        let req_b = fake_request(&kp, "b");
        let rcpt_a = fake_receipt(&kp, "a");
        let rcpt_b = fake_receipt(&kp, "b");

        tap.before_kernel(&req_a).expect("before a");
        tap.before_kernel(&req_b).expect("before b");
        tap.after_kernel(&req_a, &rcpt_a).expect("after a");
        tap.after_kernel(&req_b, &rcpt_b).expect("after b");

        assert_eq!(
            tap.events(),
            vec![
                TapEvent::Before("a".to_string()),
                TapEvent::Before("b".to_string()),
                TapEvent::After("a".to_string()),
                TapEvent::After("b".to_string()),
            ],
        );
    }

    #[test]
    fn tap_is_dyn_compatible_and_carries_name() {
        let taps: Vec<Box<dyn TrafficTap>> =
            vec![Box::new(RecordingTap::new()), Box::new(AlwaysFailingTap)];

        let names: Vec<&str> = taps.iter().map(|t| t.name()).collect();
        assert_eq!(names, vec!["recording-tap", "always-failing-tap"]);
    }
}
