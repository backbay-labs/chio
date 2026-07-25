//! Guard pipeline -- runs guards in sequence, fail-closed.
//!
//! The pipeline evaluates registered guards in order. If any guard returns
//! `Verdict::Deny` or an error, the pipeline short-circuits and returns
//! `Verdict::Deny`.  Only if all guards return `Verdict::Allow` does the
//! pipeline allow the request.

use chio_core::receipt::metadata::GuardEvidence;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, Verdict};

/// A pipeline of guards evaluated in registration order.
///
/// This is the primary integration point for wiring guards into the Chio
/// kernel.  Construct a `GuardPipeline`, add guards, then register it as a
/// single `Guard` on the kernel via `kernel.add_guard(Box::new(pipeline))`.
pub struct GuardPipeline {
    guards: Vec<Box<dyn Guard>>,
}

impl GuardPipeline {
    pub fn new() -> Self {
        Self { guards: Vec::new() }
    }

    pub fn add(&mut self, guard: Box<dyn Guard>) {
        self.guards.push(guard);
    }

    pub fn len(&self) -> usize {
        self.guards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    /// Create a default pipeline with all implemented guards using their
    /// default configurations.
    pub fn default_pipeline() -> Self {
        let mut pipeline = Self::new();
        pipeline.add(Box::new(crate::ForbiddenPathGuard::new()));
        pipeline.add(Box::new(crate::ShellCommandGuard::new()));
        pipeline.add(Box::new(crate::EgressAllowlistGuard::new()));
        pipeline.add(Box::new(crate::PathAllowlistGuard::new()));
        pipeline.add(Box::new(crate::McpToolGuard::new()));
        pipeline.add(Box::new(crate::SecretLeakGuard::new()));
        pipeline.add(Box::new(crate::PatchIntegrityGuard::new()));
        pipeline
    }
}

impl Default for GuardPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for GuardPipeline {
    fn name(&self) -> &str {
        "guard-pipeline"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let mut final_verdict = Verdict::Allow;
        let mut evidence = Vec::new();
        for guard in &self.guards {
            match guard.evaluate(ctx) {
                Ok(decision) => {
                    evidence.extend(decision.evidence);
                    match decision.verdict {
                        Verdict::Allow => continue,
                        Verdict::PendingApproval => {
                            // `PendingApproval` is a sticky escalation state. Keep
                            // iterating so another guard can still short-circuit to
                            // Deny, but propagate the pending verdict up the stack if
                            // no deny occurs.
                            final_verdict = Verdict::PendingApproval;
                        }
                        Verdict::Deny => {
                            evidence.push(GuardEvidence {
                                guard_name: guard.name().to_string(),
                                verdict: false,
                                details: Some(
                                    "action=deny; reason=guard denied request".to_string(),
                                ),
                            });
                            return Ok(GuardDecision::deny(evidence));
                        }
                    }
                }
                Err(e) => {
                    // Fail closed: guard errors are treated as denials.
                    evidence.push(GuardEvidence {
                        guard_name: guard.name().to_string(),
                        verdict: false,
                        details: Some(format!("action=error; reason=fail-closed; error={e}")),
                    });
                    return Ok(GuardDecision::deny(evidence));
                }
            }
        }
        Ok(GuardDecision {
            verdict: final_verdict,
            evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AllowGuard;
    impl Guard for AllowGuard {
        fn name(&self) -> &str {
            "allow-all"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow())
        }
    }

    struct DenyGuard;
    impl Guard for DenyGuard {
        fn name(&self) -> &str {
            "deny-all"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    struct ErrorGuard;
    impl Guard for ErrorGuard {
        fn name(&self) -> &str {
            "error-guard"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Err(KernelError::Internal("boom".to_string()))
        }
    }

    fn make_ctx() -> (
        chio_kernel::ToolCallRequest,
        chio_core::capability::scope::ChioScope,
        chio_kernel::AgentId,
        chio_kernel::ServerId,
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

    #[test]
    fn all_allow_means_pipeline_allows() {
        let mut pipeline = GuardPipeline::new();
        pipeline.add(Box::new(AllowGuard));
        pipeline.add(Box::new(AllowGuard));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = pipeline.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(decision) if decision.verdict == Verdict::Allow
        ));
    }

    #[test]
    fn one_deny_means_pipeline_denies() {
        let mut pipeline = GuardPipeline::new();
        pipeline.add(Box::new(AllowGuard));
        pipeline.add(Box::new(DenyGuard));
        pipeline.add(Box::new(AllowGuard));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = pipeline.evaluate(&ctx).expect("pipeline decision");
        assert_eq!(result.verdict, Verdict::Deny);
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].guard_name, "deny-all");
    }

    #[test]
    fn error_treated_as_deny() {
        let mut pipeline = GuardPipeline::new();
        pipeline.add(Box::new(AllowGuard));
        pipeline.add(Box::new(ErrorGuard));

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = pipeline.evaluate(&ctx).expect("pipeline decision");
        assert_eq!(result.verdict, Verdict::Deny);
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(result.evidence[0].guard_name, "error-guard");
        let details = result.evidence[0].details.as_deref().unwrap_or_default();
        assert!(details.contains("fail-closed"), "got: {details}");
    }

    #[test]
    fn empty_pipeline_allows() {
        let pipeline = GuardPipeline::new();

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = GuardContext {
            request: &request,
            scope: &scope,
            agent_id: &agent_id,
            server_id: &server_id,
            session_filesystem_roots: None,
            matched_grant_index: None,
        };

        let result = pipeline.evaluate(&ctx);
        assert!(matches!(
            result,
            Ok(decision) if decision.verdict == Verdict::Allow
        ));
    }
}
