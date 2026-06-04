//! Behavioral sequence guard -- enforces tool ordering policies using the session journal.
//!
//! This guard checks the tool invocation sequence recorded in the session journal
//! against configurable ordering policies:
//!
//! - **Required predecessors**: tool X can only run after tool Y has been invoked.
//! - **Forbidden sequences**: tool X cannot be invoked immediately after tool Y.
//! - **Max consecutive**: limits on how many times the same tool can run in a row.
//! - **Required first tool**: the first tool in a session must match a specific name.
//!
//! The guard fails closed: if the session journal is unavailable, access is denied.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chio_http_session::SessionJournal;
use chio_kernel::{Guard, GuardContext, KernelError, Verdict};

// ---------------------------------------------------------------------------
// SequencePolicy
// ---------------------------------------------------------------------------

/// Policy configuration for the behavioral sequence guard.
#[derive(Clone, Debug, Default)]
pub struct SequencePolicy {
    /// Tools that must have been invoked before a given tool can run.
    /// Map from tool_name to set of required predecessor tools.
    pub required_predecessors: HashMap<String, HashSet<String>>,
    /// Forbidden immediate transitions: (from_tool, to_tool) pairs.
    /// If the last invoked tool is `from_tool`, then `to_tool` is denied.
    pub forbidden_transitions: Vec<(String, String)>,
    /// Maximum consecutive invocations of the same tool.
    /// None means unlimited.
    pub max_consecutive: Option<u32>,
    /// If set, the first tool in the session must match this name.
    pub required_first_tool: Option<String>,
}

// ---------------------------------------------------------------------------
// BehavioralSequenceGuard
// ---------------------------------------------------------------------------

/// Guard that enforces tool ordering policies using the session journal.
pub struct BehavioralSequenceGuard {
    journal: Arc<SessionJournal>,
    policy: SequencePolicy,
}

impl BehavioralSequenceGuard {
    /// Create a new guard with the given journal and policy.
    pub fn new(journal: Arc<SessionJournal>, policy: SequencePolicy) -> Self {
        Self { journal, policy }
    }
}

impl Guard for BehavioralSequenceGuard {
    fn name(&self) -> &str {
        "behavioral-sequence"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let tool_name = &ctx.request.tool_name;

        let snapshot = self.journal.snapshot().map_err(|e| {
            KernelError::Internal(format!(
                "behavioral-sequence guard journal error (fail-closed): {e}"
            ))
        })?;
        let sequence = snapshot.tool_sequence;

        // Check required first tool.
        if sequence.is_empty() {
            if let Some(ref required_first) = self.policy.required_first_tool {
                if tool_name != required_first {
                    return Ok(Verdict::Deny);
                }
            }
        }

        // Check required predecessors.
        if let Some(required) = self.policy.required_predecessors.get(tool_name) {
            let invoked: HashSet<&str> = sequence.iter().map(|s| s.as_str()).collect();
            for req in required {
                if !invoked.contains(req.as_str()) {
                    return Ok(Verdict::Deny);
                }
            }
        }

        // Check forbidden transitions.
        if let Some(last_tool) = sequence.last() {
            for (from, to) in &self.policy.forbidden_transitions {
                if last_tool == from && tool_name == to {
                    return Ok(Verdict::Deny);
                }
            }
        }

        // Check max consecutive.
        if let Some(max_consec) = self.policy.max_consecutive {
            let mut count: u32 = 0;
            for t in sequence.iter().rev() {
                if t == tool_name {
                    count = count.saturating_add(1);
                } else {
                    break;
                }
            }
            if count >= max_consec {
                return Ok(Verdict::Deny);
            }
        }

        Ok(Verdict::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_http_session::RecordParams;

    fn make_journal(session_id: &str) -> Arc<SessionJournal> {
        Arc::new(SessionJournal::new(session_id.to_string()))
    }

    fn record(journal: &SessionJournal, tool: &str) {
        journal
            .record(RecordParams {
                tool_name: tool.to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 0,
                bytes_written: 0,
                delegation_depth: 0,
                allowed: true,
            })
            .expect("record");
    }

    fn make_ctx_for_tool(
        tool_name: &str,
    ) -> (
        chio_kernel::ToolCallRequest,
        chio_core::capability::ChioScope,
        String,
        String,
    ) {
        let kp = chio_core::crypto::Keypair::generate();
        let scope = chio_core::capability::ChioScope::default();
        let agent_id = kp.public_key().to_hex();
        let server_id = "srv-test".to_string();

        let cap_body = chio_core::capability::CapabilityTokenBody {
            id: "cap-test".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: scope.clone(),
            issued_at: 0,
            expires_at: u64::MAX,
            delegation_chain: vec![],
        };
        let cap = chio_core::capability::CapabilityToken::sign(cap_body, &kp).expect("sign cap");

        let request = chio_kernel::ToolCallRequest {
            request_id: "req-test".to_string(),
            capability: cap,
            tool_name: tool_name.to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };

        (request, scope, agent_id, server_id)
    }

    fn guard_ctx<'a>(
        request: &'a chio_kernel::ToolCallRequest,
        scope: &'a chio_core::capability::ChioScope,
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

    #[test]
    fn guard_name() {
        let journal = make_journal("sess-1");
        let guard = BehavioralSequenceGuard::new(journal, SequencePolicy::default());
        assert_eq!(guard.name(), "behavioral-sequence");
    }

    #[test]
    fn empty_policy_allows_all() {
        let journal = make_journal("sess-1");
        record(&journal, "read_file");
        record(&journal, "bash");

        let guard = BehavioralSequenceGuard::new(journal, SequencePolicy::default());
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn required_predecessor_enforced() {
        let journal = make_journal("sess-pred");
        // No tools invoked yet.

        let mut required = HashMap::new();
        required.insert(
            "write_file".to_string(),
            HashSet::from(["read_file".to_string()]),
        );

        let guard = BehavioralSequenceGuard::new(
            journal.clone(),
            SequencePolicy {
                required_predecessors: required,
                ..SequencePolicy::default()
            },
        );

        // write_file without read_file predecessor should deny.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);

        // After read_file is invoked, write_file should be allowed.
        record(&journal, "read_file");
        let (request2, scope2, agent_id2, server_id2) = make_ctx_for_tool("write_file");
        let ctx2 = guard_ctx(&request2, &scope2, &agent_id2, &server_id2);
        assert_eq!(guard.evaluate(&ctx2).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn forbidden_transition_enforced() {
        let journal = make_journal("sess-trans");
        record(&journal, "bash");

        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                forbidden_transitions: vec![("bash".to_string(), "write_file".to_string())],
                ..SequencePolicy::default()
            },
        );

        // bash -> write_file is forbidden.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);

        // bash -> read_file is fine.
        let (request2, scope2, agent_id2, server_id2) = make_ctx_for_tool("read_file");
        let ctx2 = guard_ctx(&request2, &scope2, &agent_id2, &server_id2);
        assert_eq!(guard.evaluate(&ctx2).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn max_consecutive_enforced() {
        let journal = make_journal("sess-consec");
        record(&journal, "read_file");
        record(&journal, "read_file");
        record(&journal, "read_file");

        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                max_consecutive: Some(3),
                ..SequencePolicy::default()
            },
        );

        // 4th consecutive read_file should be denied.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("read_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);

        // A different tool should be fine.
        let (request2, scope2, agent_id2, server_id2) = make_ctx_for_tool("write_file");
        let ctx2 = guard_ctx(&request2, &scope2, &agent_id2, &server_id2);
        assert_eq!(guard.evaluate(&ctx2).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn max_consecutive_resets_on_different_tool() {
        let journal = make_journal("sess-reset");
        record(&journal, "read_file");
        record(&journal, "read_file");
        record(&journal, "bash"); // Breaks the streak
        record(&journal, "read_file");

        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                max_consecutive: Some(3),
                ..SequencePolicy::default()
            },
        );

        // Only 1 consecutive read_file after bash, so this should pass.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("read_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn required_first_tool_enforced() {
        let journal = make_journal("sess-first");

        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                required_first_tool: Some("init".to_string()),
                ..SequencePolicy::default()
            },
        );

        // First tool must be "init".
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("read_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);

        let (request2, scope2, agent_id2, server_id2) = make_ctx_for_tool("init");
        let ctx2 = guard_ctx(&request2, &scope2, &agent_id2, &server_id2);
        assert_eq!(guard.evaluate(&ctx2).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn required_first_tool_only_applies_to_first() {
        let journal = make_journal("sess-first-only");
        record(&journal, "init"); // First tool is correct.

        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                required_first_tool: Some("init".to_string()),
                ..SequencePolicy::default()
            },
        );

        // Subsequent tools can be anything.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("read_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }
}
