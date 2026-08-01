//! Data flow guard -- enforces cumulative bytes-read/written limits via session journal.
//!
//! This guard reads cumulative data flow statistics from the session journal
//! and denies requests that would cause the session to exceed configured
//! byte limits for reads, writes, or combined I/O.
//!
//! The guard fails closed: if the session journal is unavailable or returns
//! an error, the request is denied.

use std::sync::Arc;

use chio_http_session::SessionJournal;
#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

// ---------------------------------------------------------------------------
// DataFlowConfig
// ---------------------------------------------------------------------------

/// Configuration for cumulative data flow limits.
#[derive(Clone, Debug, Default)]
pub struct DataFlowConfig {
    /// Maximum cumulative bytes read per session. None means unlimited.
    pub max_bytes_read: Option<u64>,
    /// Maximum cumulative bytes written per session. None means unlimited.
    pub max_bytes_written: Option<u64>,
    /// Maximum cumulative bytes (read + written) per session. None means unlimited.
    pub max_bytes_total: Option<u64>,
}

// ---------------------------------------------------------------------------
// DataFlowGuard
// ---------------------------------------------------------------------------

/// Guard that enforces cumulative data flow limits using the session journal.
///
/// Reads the journal's cumulative data flow statistics and denies requests
/// if any configured limit has been reached.
pub struct DataFlowGuard {
    journal: Arc<SessionJournal>,
    config: DataFlowConfig,
}

impl DataFlowGuard {
    /// Create a new guard with the given journal and configuration.
    pub fn new(journal: Arc<SessionJournal>, config: DataFlowConfig) -> Self {
        Self { journal, config }
    }
}

impl Guard for DataFlowGuard {
    fn name(&self) -> &str {
        "data-flow"
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let snapshot = self.journal.snapshot().map_err(|e| {
            KernelError::Internal(format!("data-flow guard journal error (fail-closed): {e}"))
        })?;
        let flow = snapshot.data_flow;

        // Check bytes read limit.
        if let Some(max_read) = self.config.max_bytes_read {
            if flow.total_bytes_read >= max_read {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Check bytes written limit.
        if let Some(max_written) = self.config.max_bytes_written {
            if flow.total_bytes_written >= max_written {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        // Check total I/O limit.
        if let Some(max_total) = self.config.max_bytes_total {
            let total = flow
                .total_bytes_read
                .saturating_add(flow.total_bytes_written);
            if total >= max_total {
                return Ok(GuardDecision::deny(Vec::new()));
            }
        }

        Ok(GuardDecision::allow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_http_session::RecordParams;

    fn make_journal(session_id: &str) -> Arc<SessionJournal> {
        Arc::new(SessionJournal::new(session_id.to_string()))
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

    #[test]
    fn guard_name() {
        let journal = make_journal("sess-1");
        let guard = DataFlowGuard::new(journal, DataFlowConfig::default());
        assert_eq!(guard.name(), "data-flow");
    }

    #[test]
    fn unlimited_allows_all() {
        let journal = make_journal("sess-1");
        // Add some data flow.
        journal
            .record(RecordParams {
                tool_name: "read_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 1_000_000,
                bytes_written: 500_000,
                delegation_depth: 0,
                allowed: true,
            })
            .expect("record");

        let guard = DataFlowGuard::new(journal, DataFlowConfig::default());
        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn denies_when_bytes_read_exceeded() {
        let journal = make_journal("sess-read");
        journal
            .record(RecordParams {
                tool_name: "read_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 500,
                bytes_written: 0,
                delegation_depth: 0,
                allowed: true,
            })
            .expect("record");

        let guard = DataFlowGuard::new(
            journal,
            DataFlowConfig {
                max_bytes_read: Some(500),
                ..DataFlowConfig::default()
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn denies_when_bytes_written_exceeded() {
        let journal = make_journal("sess-write");
        journal
            .record(RecordParams {
                tool_name: "write_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 0,
                bytes_written: 1000,
                delegation_depth: 0,
                allowed: true,
            })
            .expect("record");

        let guard = DataFlowGuard::new(
            journal,
            DataFlowConfig {
                max_bytes_written: Some(999),
                ..DataFlowConfig::default()
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn denies_when_total_exceeded() {
        let journal = make_journal("sess-total");
        journal
            .record(RecordParams {
                tool_name: "read_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 300,
                bytes_written: 200,
                delegation_depth: 0,
                allowed: true,
            })
            .expect("record");

        let guard = DataFlowGuard::new(
            journal,
            DataFlowConfig {
                max_bytes_total: Some(500),
                ..DataFlowConfig::default()
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn allows_when_under_limit() {
        let journal = make_journal("sess-under");
        journal
            .record(RecordParams {
                tool_name: "read_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 100,
                bytes_written: 50,
                delegation_depth: 0,
                allowed: true,
            })
            .expect("record");

        let guard = DataFlowGuard::new(
            journal,
            DataFlowConfig {
                max_bytes_read: Some(1000),
                max_bytes_written: Some(1000),
                max_bytes_total: Some(2000),
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn cumulative_across_multiple_entries() {
        let journal = make_journal("sess-cumulative");
        for _ in 0..5 {
            journal
                .record(RecordParams {
                    tool_name: "read_file".to_string(),
                    server_id: "srv".to_string(),
                    agent_id: "agent".to_string(),
                    bytes_read: 200,
                    bytes_written: 0,
                    delegation_depth: 0,
                    allowed: true,
                })
                .expect("record");
        }
        // Total bytes_read = 1000.

        let guard = DataFlowGuard::new(
            journal,
            DataFlowConfig {
                max_bytes_read: Some(999),
                ..DataFlowConfig::default()
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx();
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }
}
