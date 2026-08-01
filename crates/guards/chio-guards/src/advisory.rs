//! Advisory signal framework -- signed, non-blocking evidence observations.
//!
//! Advisory signals are distinct from deterministic guard verdicts. They
//! record observations about a request without blocking it. This allows
//! operators to see patterns and anomalies without impacting request flow.
//!
//! Key properties:
//! - Advisory signals never deny requests on their own.
//! - They produce `AdvisorySignal` entries that are included in evidence
//!   alongside `GuardEvidence`.
//! - Operators can promote advisory signals to deterministic guards via
//!   `chio.yaml` configuration (see `PromotionPolicy`).
//! - Advisory signals carry a severity level and structured metadata.

use std::sync::Arc;

use chio_core::receipt::metadata::GuardEvidence;
#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Advisory signal types
// ---------------------------------------------------------------------------

/// Severity level for an advisory signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySeverity {
    /// Informational observation -- no action needed.
    Info,
    /// Low-severity warning -- worth monitoring.
    Low,
    /// Medium-severity warning -- may warrant investigation.
    Medium,
    /// High-severity warning -- likely needs attention.
    High,
    /// Critical observation -- strong signal of abuse or anomaly.
    Critical,
}

/// A non-blocking advisory signal emitted by an advisory guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorySignal {
    /// Name of the advisory guard that produced this signal.
    pub guard_name: String,
    /// Human-readable description of the observation.
    pub description: String,
    /// Severity level.
    pub severity: AdvisorySeverity,
    /// Structured metadata about the observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Whether this signal has been promoted to a deterministic denial.
    /// This is set by the promotion policy, not by the advisory guard itself.
    #[serde(default)]
    pub promoted: bool,
}

/// Classification of a guard's output: deterministic verdict or advisory signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuardOutput {
    /// A deterministic verdict (allow or deny).
    Deterministic {
        guard_name: String,
        verdict: bool,
        details: Option<String>,
    },
    /// A non-blocking advisory signal.
    Advisory(AdvisorySignal),
}

// ---------------------------------------------------------------------------
// Advisory guard trait
// ---------------------------------------------------------------------------

/// Trait for guards that produce advisory (non-blocking) signals.
///
/// Unlike the `Guard` trait which returns Allow/Deny verdicts, an
/// `AdvisoryGuard` always allows the request but may emit observations.
pub trait AdvisoryGuard: Send + Sync {
    /// Human-readable guard name.
    fn name(&self) -> &str;

    /// Evaluate the request and return any advisory signals.
    ///
    /// The returned signals are informational only and do not affect the
    /// request verdict unless a promotion policy is in effect.
    fn evaluate(&self, ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError>;
}

// ---------------------------------------------------------------------------
// Promotion policy
// ---------------------------------------------------------------------------

/// Policy for promoting advisory signals to deterministic denials.
///
/// Operators configure this in `chio.yaml` to convert specific advisory
/// signals into hard denials based on guard name and severity threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionRule {
    /// Guard name pattern to match (exact match).
    pub guard_name: String,
    /// Minimum severity to promote. Signals at or above this level
    /// from the named guard become deterministic denials.
    pub min_severity: AdvisorySeverity,
}

/// Collection of promotion rules loaded from configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromotionPolicy {
    /// Rules for promoting advisory signals to deterministic denials.
    pub rules: Vec<PromotionRule>,
}

impl PromotionPolicy {
    /// Create an empty policy (no promotions).
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a promotion rule.
    pub fn add_rule(&mut self, rule: PromotionRule) {
        self.rules.push(rule);
    }

    /// Check whether a signal should be promoted to a denial.
    pub fn should_promote(&self, signal: &AdvisorySignal) -> bool {
        for rule in &self.rules {
            if rule.guard_name == signal.guard_name
                && severity_ord(signal.severity) >= severity_ord(rule.min_severity)
            {
                return true;
            }
        }
        false
    }
}

/// Convert severity to ordinal for comparison.
fn severity_ord(s: AdvisorySeverity) -> u8 {
    match s {
        AdvisorySeverity::Info => 0,
        AdvisorySeverity::Low => 1,
        AdvisorySeverity::Medium => 2,
        AdvisorySeverity::High => 3,
        AdvisorySeverity::Critical => 4,
    }
}

fn severity_label(s: AdvisorySeverity) -> &'static str {
    match s {
        AdvisorySeverity::Info => "info",
        AdvisorySeverity::Low => "low",
        AdvisorySeverity::Medium => "medium",
        AdvisorySeverity::High => "high",
        AdvisorySeverity::Critical => "critical",
    }
}

fn signal_evidence(signal: &AdvisorySignal) -> GuardEvidence {
    let metadata = match &signal.metadata {
        Some(metadata) => metadata.to_string(),
        None => "null".to_string(),
    };
    GuardEvidence {
        guard_name: signal.guard_name.clone(),
        verdict: !signal.promoted,
        details: Some(format!(
            "action=advisory; description={}; severity={}; promoted={}; metadata={metadata}",
            signal.description,
            severity_label(signal.severity),
            signal.promoted
        )),
    }
}

// ---------------------------------------------------------------------------
// Advisory pipeline
// ---------------------------------------------------------------------------

/// Pipeline that evaluates advisory guards and optionally promotes signals.
///
/// This wraps multiple `AdvisoryGuard` implementations and a `PromotionPolicy`.
/// It implements the `Guard` trait so it can be plugged into the standard
/// guard pipeline. Without promotion rules, it always returns `Verdict::Allow`.
pub struct AdvisoryPipeline {
    guards: Vec<Box<dyn AdvisoryGuard>>,
    policy: PromotionPolicy,
    /// Collected signals from the last evaluation (for evidence export).
    signals: std::sync::Mutex<Vec<AdvisorySignal>>,
}

impl AdvisoryPipeline {
    /// Create a new pipeline with the given promotion policy.
    pub fn new(policy: PromotionPolicy) -> Self {
        Self {
            guards: Vec::new(),
            policy,
            signals: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Add an advisory guard to the pipeline.
    pub fn add(&mut self, guard: Box<dyn AdvisoryGuard>) {
        self.guards.push(guard);
    }

    /// Return the number of advisory guards in the pipeline.
    pub fn len(&self) -> usize {
        self.guards.len()
    }

    /// Return whether the pipeline has no guards.
    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    /// Return the signals collected during the last evaluation.
    pub fn last_signals(&self) -> Result<Vec<AdvisorySignal>, KernelError> {
        let signals = self
            .signals
            .lock()
            .map_err(|_| KernelError::Internal("advisory pipeline lock poisoned".to_string()))?;
        Ok(signals.clone())
    }

    /// Return the GuardOutput entries for the last evaluation.
    pub fn last_outputs(&self) -> Result<Vec<GuardOutput>, KernelError> {
        let signals = self.last_signals()?;
        Ok(signals.into_iter().map(GuardOutput::Advisory).collect())
    }
}

impl Guard for AdvisoryPipeline {
    fn name(&self) -> &str {
        "advisory-pipeline"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let mut collected = Vec::new();
        let mut should_deny = false;

        for guard in &self.guards {
            let signals = guard.evaluate(ctx)?;
            for mut signal in signals {
                if self.policy.should_promote(&signal) {
                    signal.promoted = true;
                    should_deny = true;
                }
                collected.push(signal);
            }
        }

        let evidence = collected.iter().map(signal_evidence).collect();

        // Store collected signals for evidence export.
        let mut stored = self
            .signals
            .lock()
            .map_err(|_| KernelError::Internal("advisory pipeline lock poisoned".to_string()))?;
        *stored = collected;

        if should_deny {
            Ok(GuardDecision::deny(evidence))
        } else {
            Ok(GuardDecision::allow_with_evidence(evidence))
        }
    }
}

// ---------------------------------------------------------------------------
// Built-in advisory guards
// ---------------------------------------------------------------------------

/// Advisory guard that flags unusual tool invocation patterns.
///
/// Emits advisory signals when:
/// - A tool is invoked more than a threshold number of times in a session
/// - Delegation depth exceeds a threshold
pub struct AnomalyAdvisoryGuard {
    journal: Arc<chio_http_session::SessionJournal>,
    /// Threshold for per-tool invocation count advisory.
    invocation_threshold: u64,
    /// Threshold for delegation depth advisory.
    depth_threshold: u32,
}

impl AnomalyAdvisoryGuard {
    /// Create a new anomaly advisory guard.
    pub fn new(
        journal: Arc<chio_http_session::SessionJournal>,
        invocation_threshold: u64,
        depth_threshold: u32,
    ) -> Self {
        Self {
            journal,
            invocation_threshold,
            depth_threshold,
        }
    }
}

impl AdvisoryGuard for AnomalyAdvisoryGuard {
    fn name(&self) -> &str {
        "anomaly-advisory"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError> {
        let mut signals = Vec::new();

        let snapshot = self
            .journal
            .snapshot()
            .map_err(|e| KernelError::Internal(format!("anomaly advisory journal error: {e}")))?;
        let tool_counts = &snapshot.tool_counts;

        // Check if current tool has been invoked excessively.
        if let Some(count) = tool_counts.get(&ctx.request.tool_name) {
            if *count >= self.invocation_threshold {
                signals.push(AdvisorySignal {
                    guard_name: "anomaly-advisory".to_string(),
                    description: format!(
                        "tool '{}' invoked {} times (threshold: {})",
                        ctx.request.tool_name, count, self.invocation_threshold
                    ),
                    severity: if *count >= self.invocation_threshold * 2 {
                        AdvisorySeverity::High
                    } else {
                        AdvisorySeverity::Medium
                    },
                    metadata: Some(serde_json::json!({
                        "tool_name": ctx.request.tool_name,
                        "count": count,
                        "threshold": self.invocation_threshold,
                    })),
                    promoted: false,
                });
            }
        }

        // Check delegation depth.
        let data_flow = &snapshot.data_flow;

        if data_flow.max_delegation_depth >= self.depth_threshold {
            signals.push(AdvisorySignal {
                guard_name: "anomaly-advisory".to_string(),
                description: format!(
                    "delegation depth {} exceeds threshold {}",
                    data_flow.max_delegation_depth, self.depth_threshold
                ),
                severity: AdvisorySeverity::High,
                metadata: Some(serde_json::json!({
                    "max_delegation_depth": data_flow.max_delegation_depth,
                    "threshold": self.depth_threshold,
                })),
                promoted: false,
            });
        }

        Ok(signals)
    }
}

/// Advisory guard that flags high data transfer volumes.
pub struct DataTransferAdvisoryGuard {
    journal: Arc<chio_http_session::SessionJournal>,
    /// Bytes threshold for advisory signal.
    bytes_threshold: u64,
}

impl DataTransferAdvisoryGuard {
    /// Create a new data transfer advisory guard.
    pub fn new(journal: Arc<chio_http_session::SessionJournal>, bytes_threshold: u64) -> Self {
        Self {
            journal,
            bytes_threshold,
        }
    }
}

impl AdvisoryGuard for DataTransferAdvisoryGuard {
    fn name(&self) -> &str {
        "data-transfer-advisory"
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError> {
        let snapshot = self.journal.snapshot().map_err(|e| {
            KernelError::Internal(format!("data-transfer advisory journal error: {e}"))
        })?;
        let flow = snapshot.data_flow;

        let total = flow
            .total_bytes_read
            .saturating_add(flow.total_bytes_written);

        if total >= self.bytes_threshold {
            let severity = if total >= self.bytes_threshold.saturating_mul(3) {
                AdvisorySeverity::Critical
            } else if total >= self.bytes_threshold.saturating_mul(2) {
                AdvisorySeverity::High
            } else {
                AdvisorySeverity::Medium
            };

            Ok(vec![AdvisorySignal {
                guard_name: "data-transfer-advisory".to_string(),
                description: format!(
                    "cumulative data transfer {} bytes exceeds threshold {} bytes",
                    total, self.bytes_threshold
                ),
                severity,
                metadata: Some(serde_json::json!({
                    "total_bytes": total,
                    "bytes_read": flow.total_bytes_read,
                    "bytes_written": flow.total_bytes_written,
                    "threshold": self.bytes_threshold,
                })),
                promoted: false,
            }])
        } else {
            Ok(vec![])
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chio_http_session::{RecordParams, SessionJournal};

    fn make_journal(session_id: &str) -> Arc<SessionJournal> {
        Arc::new(SessionJournal::new(session_id.to_string()))
    }

    fn record(journal: &SessionJournal, tool: &str, bytes_read: u64, depth: u32) {
        journal
            .record(RecordParams {
                tool_name: tool.to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read,
                bytes_written: 0,
                delegation_depth: depth,
                allowed: true,
            })
            .expect("record");
    }

    fn make_ctx() -> (
        chio_kernel::ToolCallRequest,
        chio_core::capability::scope::ChioScope,
        String,
        String,
    ) {
        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::scope::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::token::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        };
        let cap =
            chio_core::capability::token::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: "read_file".to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({"path": "/app/src/main.rs"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        (request, scope, agent_id, server_id)
    }

    fn guard_ctx<'a>(
        request: &'a chio_kernel::ToolCallRequest,
        scope: &'a chio_core::capability::scope::ChioScope,
        agent_id: &'a String,
        server_id: &'a String,
    ) -> chio_kernel::GuardContext<'a> {
        chio_kernel::GuardContext {
            request,
            scope,
            agent_id,
            server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        }
    }

    // -- AdvisorySignal tests --

    #[test]
    fn advisory_signal_serde_roundtrip() {
        let signal = AdvisorySignal {
            guard_name: "test-guard".to_string(),
            description: "test observation".to_string(),
            severity: AdvisorySeverity::Medium,
            metadata: Some(serde_json::json!({"key": "value"})),
            promoted: false,
        };

        let json = serde_json::to_string(&signal).expect("serialize");
        let restored: AdvisorySignal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.guard_name, "test-guard");
        assert_eq!(restored.severity, AdvisorySeverity::Medium);
        assert!(!restored.promoted);
    }

    #[test]
    fn guard_output_distinguishes_types() {
        let det = GuardOutput::Deterministic {
            guard_name: "forbidden-path".to_string(),
            verdict: false,
            details: Some("blocked".to_string()),
        };
        let adv = GuardOutput::Advisory(AdvisorySignal {
            guard_name: "anomaly".to_string(),
            description: "unusual pattern".to_string(),
            severity: AdvisorySeverity::Low,
            metadata: None,
            promoted: false,
        });

        let det_json = serde_json::to_string(&det).expect("serialize det");
        let adv_json = serde_json::to_string(&adv).expect("serialize adv");

        assert!(det_json.contains("\"type\":\"deterministic\""));
        assert!(adv_json.contains("\"type\":\"advisory\""));
    }

    // -- PromotionPolicy tests --

    #[test]
    fn promotion_policy_empty_never_promotes() {
        let policy = PromotionPolicy::new();
        let signal = AdvisorySignal {
            guard_name: "test".to_string(),
            description: "test".to_string(),
            severity: AdvisorySeverity::Critical,
            metadata: None,
            promoted: false,
        };
        assert!(!policy.should_promote(&signal));
    }

    #[test]
    fn promotion_policy_promotes_matching_signal() {
        let mut policy = PromotionPolicy::new();
        policy.add_rule(PromotionRule {
            guard_name: "anomaly-advisory".to_string(),
            min_severity: AdvisorySeverity::High,
        });

        let high_signal = AdvisorySignal {
            guard_name: "anomaly-advisory".to_string(),
            description: "test".to_string(),
            severity: AdvisorySeverity::High,
            metadata: None,
            promoted: false,
        };
        assert!(policy.should_promote(&high_signal));

        let critical_signal = AdvisorySignal {
            guard_name: "anomaly-advisory".to_string(),
            description: "test".to_string(),
            severity: AdvisorySeverity::Critical,
            metadata: None,
            promoted: false,
        };
        assert!(policy.should_promote(&critical_signal));
    }

    #[test]
    fn promotion_policy_does_not_promote_below_threshold() {
        let mut policy = PromotionPolicy::new();
        policy.add_rule(PromotionRule {
            guard_name: "anomaly-advisory".to_string(),
            min_severity: AdvisorySeverity::High,
        });

        let low_signal = AdvisorySignal {
            guard_name: "anomaly-advisory".to_string(),
            description: "test".to_string(),
            severity: AdvisorySeverity::Medium,
            metadata: None,
            promoted: false,
        };
        assert!(!policy.should_promote(&low_signal));
    }

    #[test]
    fn promotion_policy_does_not_promote_wrong_guard() {
        let mut policy = PromotionPolicy::new();
        policy.add_rule(PromotionRule {
            guard_name: "anomaly-advisory".to_string(),
            min_severity: AdvisorySeverity::Low,
        });

        let signal = AdvisorySignal {
            guard_name: "other-guard".to_string(),
            description: "test".to_string(),
            severity: AdvisorySeverity::Critical,
            metadata: None,
            promoted: false,
        };
        assert!(!policy.should_promote(&signal));
    }

    // -- AdvisoryPipeline tests --

    struct NoOpAdvisory;
    impl AdvisoryGuard for NoOpAdvisory {
        fn name(&self) -> &str {
            "no-op"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError> {
            Ok(vec![])
        }
    }

    struct AlwaysSignal {
        guard_name: String,
        severity: AdvisorySeverity,
    }
    impl AdvisoryGuard for AlwaysSignal {
        fn name(&self) -> &str {
            &self.guard_name
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Vec<AdvisorySignal>, KernelError> {
            Ok(vec![AdvisorySignal {
                guard_name: self.guard_name.clone(),
                description: "always signals".to_string(),
                severity: self.severity,
                metadata: Some(serde_json::json!({"source": "unit-test"})),
                promoted: false,
            }])
        }
    }

    #[test]
    fn advisory_pipeline_allows_without_promotion() {
        let mut pipeline = AdvisoryPipeline::new(PromotionPolicy::new());
        pipeline.add(Box::new(AlwaysSignal {
            guard_name: "test-signal".to_string(),
            severity: AdvisorySeverity::High,
        }));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let result = pipeline.evaluate(&ctx).expect("ok");
        assert_eq!(result, Verdict::Allow);

        let signals = pipeline.last_signals().expect("signals");
        assert_eq!(signals.len(), 1);
        assert!(!signals[0].promoted);
    }

    #[test]
    fn advisory_pipeline_returns_signal_evidence() {
        let mut pipeline = AdvisoryPipeline::new(PromotionPolicy::new());
        pipeline.add(Box::new(AlwaysSignal {
            guard_name: "test-signal".to_string(),
            severity: AdvisorySeverity::High,
        }));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let decision = pipeline.evaluate(&ctx).expect("ok");
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.evidence.len(), 1);

        let evidence = &decision.evidence[0];
        assert_eq!(evidence.guard_name, "test-signal");
        assert!(evidence.verdict);
        let details = evidence.details.as_deref().expect("details");
        assert!(details.contains("action=advisory"));
        assert!(details.contains("description=always signals"));
        assert!(details.contains("severity=high"));
        assert!(details.contains("promoted=false"));
        assert!(details.contains(r#"metadata={"source":"unit-test"}"#));
    }

    #[test]
    fn advisory_pipeline_denies_with_promotion() {
        let mut policy = PromotionPolicy::new();
        policy.add_rule(PromotionRule {
            guard_name: "test-signal".to_string(),
            min_severity: AdvisorySeverity::High,
        });

        let mut pipeline = AdvisoryPipeline::new(policy);
        pipeline.add(Box::new(AlwaysSignal {
            guard_name: "test-signal".to_string(),
            severity: AdvisorySeverity::High,
        }));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let result = pipeline.evaluate(&ctx).expect("ok");
        assert_eq!(result, Verdict::Deny);

        let signals = pipeline.last_signals().expect("signals");
        assert_eq!(signals.len(), 1);
        assert!(signals[0].promoted);
    }

    #[test]
    fn advisory_pipeline_no_guards_allows() {
        let pipeline = AdvisoryPipeline::new(PromotionPolicy::new());

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(pipeline.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn advisory_pipeline_collects_multiple_signals() {
        let mut pipeline = AdvisoryPipeline::new(PromotionPolicy::new());
        pipeline.add(Box::new(AlwaysSignal {
            guard_name: "signal-a".to_string(),
            severity: AdvisorySeverity::Low,
        }));
        pipeline.add(Box::new(AlwaysSignal {
            guard_name: "signal-b".to_string(),
            severity: AdvisorySeverity::Medium,
        }));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        pipeline.evaluate(&ctx).expect("ok");

        let signals = pipeline.last_signals().expect("signals");
        assert_eq!(signals.len(), 2);
        assert_eq!(signals[0].guard_name, "signal-a");
        assert_eq!(signals[1].guard_name, "signal-b");
    }

    #[test]
    fn advisory_pipeline_guard_output_types() {
        let mut pipeline = AdvisoryPipeline::new(PromotionPolicy::new());
        pipeline.add(Box::new(AlwaysSignal {
            guard_name: "test".to_string(),
            severity: AdvisorySeverity::Info,
        }));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        pipeline.evaluate(&ctx).expect("ok");

        let outputs = pipeline.last_outputs().expect("outputs");
        assert_eq!(outputs.len(), 1);
        assert!(matches!(outputs[0], GuardOutput::Advisory(_)));
    }

    // -- AnomalyAdvisoryGuard tests --

    #[test]
    fn anomaly_advisory_no_signal_below_threshold() {
        let journal = make_journal("sess-anomaly-1");
        for _ in 0..4 {
            record(&journal, "read_file", 100, 0);
        }

        let guard = AnomalyAdvisoryGuard::new(journal, 10, 5);
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let signals = guard.evaluate(&ctx).expect("ok");
        assert!(signals.is_empty());
    }

    #[test]
    fn anomaly_advisory_signals_excessive_invocations() {
        let journal = make_journal("sess-anomaly-2");
        for _ in 0..10 {
            record(&journal, "read_file", 100, 0);
        }

        let guard = AnomalyAdvisoryGuard::new(journal, 5, 10);
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let signals = guard.evaluate(&ctx).expect("ok");
        assert!(!signals.is_empty());
        assert!(signals.iter().any(|s| s.description.contains("read_file")));
    }

    #[test]
    fn anomaly_advisory_signals_deep_delegation() {
        let journal = make_journal("sess-anomaly-3");
        record(&journal, "read_file", 100, 8);

        let guard = AnomalyAdvisoryGuard::new(journal, 100, 5);
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let signals = guard.evaluate(&ctx).expect("ok");
        assert!(!signals.is_empty());
        assert!(signals
            .iter()
            .any(|s| s.description.contains("delegation depth")));
    }

    // -- DataTransferAdvisoryGuard tests --

    #[test]
    fn data_transfer_advisory_no_signal_below_threshold() {
        let journal = make_journal("sess-transfer-1");
        record(&journal, "read_file", 100, 0);

        let guard = DataTransferAdvisoryGuard::new(journal, 10_000);
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let signals = guard.evaluate(&ctx).expect("ok");
        assert!(signals.is_empty());
    }

    #[test]
    fn data_transfer_advisory_signals_above_threshold() {
        let journal = make_journal("sess-transfer-2");
        for _ in 0..20 {
            record(&journal, "read_file", 1000, 0);
        }

        let guard = DataTransferAdvisoryGuard::new(journal, 10_000);
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let signals = guard.evaluate(&ctx).expect("ok");
        assert_eq!(signals.len(), 1);
        assert!(signals[0].description.contains("data transfer"));
    }

    #[test]
    fn data_transfer_advisory_escalating_severity() {
        let journal = make_journal("sess-transfer-3");
        // 30x threshold => Critical
        for _ in 0..30 {
            record(&journal, "read_file", 1000, 0);
        }

        let guard = DataTransferAdvisoryGuard::new(journal, 10_000);
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let signals = guard.evaluate(&ctx).expect("ok");
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].severity, AdvisorySeverity::Critical);
    }

    // -- Integration: advisory pipeline with promotion --

    #[test]
    fn promoted_anomaly_denies_request() {
        let journal = make_journal("sess-promote");
        for _ in 0..20 {
            record(&journal, "read_file", 100, 0);
        }

        let mut policy = PromotionPolicy::new();
        policy.add_rule(PromotionRule {
            guard_name: "anomaly-advisory".to_string(),
            min_severity: AdvisorySeverity::Medium,
        });

        let mut pipeline = AdvisoryPipeline::new(policy);
        pipeline.add(Box::new(AnomalyAdvisoryGuard::new(journal, 5, 10)));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        let result = pipeline.evaluate(&ctx).expect("ok");
        assert_eq!(result, Verdict::Deny, "promoted advisory should deny");

        let signals = pipeline.last_signals().expect("signals");
        assert!(signals.iter().any(|s| s.promoted));
    }

    #[test]
    fn len_and_is_empty() {
        let mut pipeline = AdvisoryPipeline::new(PromotionPolicy::new());
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);
        pipeline.add(Box::new(NoOpAdvisory));
        assert!(!pipeline.is_empty());
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn promotion_policy_serde_roundtrip() {
        let mut policy = PromotionPolicy::new();
        policy.add_rule(PromotionRule {
            guard_name: "anomaly-advisory".to_string(),
            min_severity: AdvisorySeverity::High,
        });

        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: PromotionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.rules.len(), 1);
        assert_eq!(restored.rules[0].guard_name, "anomaly-advisory");
        assert_eq!(restored.rules[0].min_severity, AdvisorySeverity::High);
    }
}
