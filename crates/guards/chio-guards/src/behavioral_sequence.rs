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
#[cfg(test)]
use chio_kernel::Verdict;
use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError};

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

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let tool_name = &ctx.request.tool_name;

        let snapshot = self.journal.snapshot().map_err(|e| {
            KernelError::Internal(format!(
                "behavioral-sequence guard journal error (fail-closed): {e}"
            ))
        })?;

        // Check required first tool. "Have any tools run yet" is a cumulative
        // property, so consult the journal's cumulative O(1) last-tool field
        // (`current_streak_tool`), which is `None` only before the first record,
        // NOT the bounded `tool_sequence` ring. When `journal_entry_cap` is 0 the
        // ring stores no tool names (capacity 0 = disabled), so `tool_sequence`
        // would report EVERY call as the first and mis-fire this check; the
        // cumulative field is correct at any entry cap.
        if snapshot.current_streak_tool.is_none() {
            if let Some(ref required_first) = self.policy.required_first_tool {
                if tool_name != required_first {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
        }

        // Check required predecessors. "Has this tool ever been invoked" is a
        // cumulative property, so consult the journal's cumulative `tool_counts`
        // (which survives ring eviction) rather than the
        // bounded `tool_sequence` tail. A predecessor invoked once and then
        // pushed out of the retained window is still known to have run, so a
        // workflow that runs setup once and then more than `journal_entry_cap`
        // other calls is no longer falsely denied when a dependent tool needs
        // that evicted predecessor. `tool_counts` cannot grow without bound: the
        // journal caps its distinct-key set fail-closed
        // (`journal_tool_counts_cap`). Legitimate registry-bounded predecessors
        // stay recorded, but a predecessor that overflowed the cap is absent here
        // and therefore denies (fail-closed) rather than being falsely treated as
        // invoked.
        if let Some(required) = self.policy.required_predecessors.get(tool_name) {
            for req in required {
                if !snapshot.tool_counts.contains_key(req) {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
        }

        // Check forbidden transitions. The "last invoked tool" comes from the
        // journal's cumulative O(1) last-tool field (`current_streak_tool`), NOT
        // the bounded `tool_sequence` tail: when `journal_entry_cap` is 0 the ring
        // stores no tool names (capacity 0 = disabled), so `tool_sequence.last()`
        // is always None and a forbidden transition would silently never fire
        // (fail-OPEN), letting a memory-budget setting disable a transition-deny
        // policy. The cumulative field tracks the most recent recorded tool at any
        // entry cap, so the check holds fail-closed.
        if let Some(last_tool) = snapshot.current_streak_tool.as_deref() {
            for (from, to) in &self.policy.forbidden_transitions {
                if last_tool == from && tool_name == to {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
            }
        }

        // Check max consecutive. The count of prior consecutive same-tool
        // invocations comes from the journal's cumulative O(1) streak counter
        // (`current_streak_tool` + `current_streak_len`), NOT the bounded
        // `tool_sequence` tail. When `journal_entry_cap` is smaller than
        // `max_consecutive`, the ring evicts the older part of a same-tool streak,
        // so counting the retained tail would undercount and ALLOW a call that
        // must be DENIED. The cumulative counter survives ring eviction, so the
        // streak limit holds regardless of the entry cap. If the
        // request tool differs from the current-streak tool, no prior consecutive
        // run exists for it (it would start a fresh streak).
        if let Some(max_consec) = self.policy.max_consecutive {
            let prior_streak =
                if snapshot.current_streak_tool.as_deref() == Some(tool_name.as_str()) {
                    snapshot.current_streak_len
                } else {
                    0
                };
            if prior_streak >= u64::from(max_consec) {
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
            tool_name: tool_name.to_string(),
            server_id: server_id.clone(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({}),
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
    fn required_predecessor_survives_journal_ring_eviction() {
        // The required-predecessor check asks "has this tool ever been invoked",
        // which is cumulative. Once the
        // bounded tool_sequence ring evicts the setup call, the check must still
        // resolve it via the cumulative tool_counts, so a long workflow (setup
        // once, then more than journal_entry_cap other calls) is not falsely
        // denied when a dependent tool needs the evicted predecessor.
        let cap = 4;
        let journal = Arc::new(SessionJournal::with_entry_cap(
            "sess-evict".to_string(),
            cap,
        ));
        // Run the required predecessor once.
        record(&journal, "read_file");
        // Then run well over `cap` other calls, evicting "read_file" from the ring.
        for _ in 0..(cap * 3) {
            record(&journal, "bash");
        }

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

        // Precondition: the retained ring no longer holds the evicted
        // predecessor, but the cumulative tool_counts still records it.
        let snapshot = journal.snapshot().expect("snapshot");
        assert!(
            !snapshot.tool_sequence.iter().any(|t| t == "read_file"),
            "test precondition: read_file must have been evicted from the ring"
        );
        assert!(
            snapshot.tool_counts.contains_key("read_file"),
            "cumulative tool_counts must still record the evicted predecessor"
        );

        // write_file requires read_file, which ran once but was evicted; it must
        // still be ALLOWED because the predecessor is cumulatively known; a
        // sequence-based check would falsely DENY here.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
    }

    #[test]
    fn required_predecessor_denies_when_predecessor_overflowed_tool_counts_cap() {
        // The cumulative tool_counts map is distinct-key bounded fail-closed. A
        // predecessor whose tool name overflowed the cap is absent from
        // tool_counts, so the required-predecessor check must DENY (treat it as
        // never-invoked) rather than falsely allow. This gives the distinct-key
        // bound fail-closed teeth that the cumulative predecessor check depends on.
        let journal = Arc::new(SessionJournal::with_caps(
            "sess-overflow".to_string(),
            1024,
            1,
        ));
        // Fill the single distinct-key slot with an unrelated tool, then invoke
        // the required predecessor -- which overflows the cap and is dropped from
        // the cumulative counts even though it ran.
        record(&journal, "filler");
        record(&journal, "read_file");

        let snapshot = journal.snapshot().expect("snapshot");
        assert!(
            snapshot.tool_sequence.iter().any(|t| t == "read_file"),
            "test precondition: read_file ran and is in the sequence ring"
        );
        assert!(
            !snapshot.tool_counts.contains_key("read_file"),
            "test precondition: read_file overflowed the distinct-key cap"
        );

        let mut required = HashMap::new();
        required.insert(
            "write_file".to_string(),
            HashSet::from(["read_file".to_string()]),
        );
        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                required_predecessors: required,
                ..SequencePolicy::default()
            },
        );

        // read_file "ran" but overflowed the cap, so it is unknown to the check:
        // write_file must be DENIED fail-closed.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
    }

    #[test]
    fn required_predecessor_within_tool_counts_cap_still_allows() {
        // The bound must not regress legitimate (registry-bounded) workflows: a
        // predecessor that fits under the distinct-key cap stays recorded and the
        // dependent tool is allowed.
        let journal = Arc::new(SessionJournal::with_caps(
            "sess-within-cap".to_string(),
            1024,
            8,
        ));
        record(&journal, "read_file");
        assert!(journal
            .snapshot()
            .expect("snapshot")
            .tool_counts
            .contains_key("read_file"));

        let mut required = HashMap::new();
        required.insert(
            "write_file".to_string(),
            HashSet::from(["read_file".to_string()]),
        );
        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                required_predecessors: required,
                ..SequencePolicy::default()
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Allow);
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
    fn forbidden_transition_enforced_at_zero_entry_cap() {
        // A memory budget that sets journal_entry_cap = 0 disables the
        // entries/tool_sequence rings (capacity 0 = stores nothing), so
        // snapshot.tool_sequence.last() is always None. The forbidden-transition
        // check must NOT silently stop firing: it reads the journal's cumulative
        // O(1) last-tool field, which survives at any cap. Reading
        // sequence.last() instead would let cap 0 disable the transition deny.
        let journal = Arc::new(SessionJournal::with_entry_cap(
            "sess-zero-cap".to_string(),
            0,
        ));
        record(&journal, "bash");

        // The ring really stores nothing at cap 0 (the test only bites if the
        // tool_sequence tail is empty here)...
        let snapshot = journal.snapshot().expect("snapshot");
        assert!(
            snapshot.tool_sequence.is_empty(),
            "entry_cap 0 must leave the bounded tool_sequence empty for this test to bite"
        );
        // ...but the cumulative last-tool field still tracks `bash`.
        assert_eq!(snapshot.current_streak_tool.as_deref(), Some("bash"));

        let guard = BehavioralSequenceGuard::new(
            Arc::clone(&journal),
            SequencePolicy {
                forbidden_transitions: vec![("bash".to_string(), "write_file".to_string())],
                ..SequencePolicy::default()
            },
        );

        let (request, scope, agent_id, server_id) = make_ctx_for_tool("write_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(
            guard.evaluate(&ctx).expect("ok"),
            Verdict::Deny,
            "forbidden transition bash -> write_file must fire even at entry_cap 0"
        );

        // A non-forbidden transition from the same cumulative last-tool still allows.
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
    fn max_consecutive_survives_journal_ring_eviction() {
        // When `journal_entry_cap` is smaller than `max_consecutive`, the bounded
        // `tool_sequence` ring evicts the older part of a same-tool streak. If the
        // guard counted only the retained tail it would undercount and ALLOW a
        // call that must be DENIED. The cumulative O(1) streak counter survives
        // ring eviction, so the streak limit is enforced regardless of the cap.
        let cap = 4;
        let journal = Arc::new(SessionJournal::with_entry_cap(
            "sess-streak-evict".to_string(),
            cap,
        ));
        // 10 consecutive calls: max_consecutive allows exactly 10, the 11th must
        // deny. The ring only retains `cap` (4) of them.
        for _ in 0..10 {
            record(&journal, "read_file");
        }

        // Precondition: the retained ring holds only `cap` entries, far fewer than
        // the 10-long streak, but the cumulative streak counter records all 10.
        let snapshot = journal.snapshot().expect("snapshot");
        assert_eq!(
            snapshot.tool_sequence.len(),
            cap,
            "test precondition: the ring must have evicted the older streak prefix"
        );
        assert_eq!(snapshot.current_streak_tool.as_deref(), Some("read_file"));
        assert_eq!(snapshot.current_streak_len, 10);

        let guard = BehavioralSequenceGuard::new(
            journal,
            SequencePolicy {
                max_consecutive: Some(10),
                ..SequencePolicy::default()
            },
        );

        // The 11th consecutive read_file must be DENIED. Counting the retained
        // 4-entry tail (4 >= 10 is false) would falsely ALLOW it.
        let (request, scope, agent_id, server_id) = make_ctx_for_tool("read_file");
        let ctx = guard_ctx(&request, &scope, &agent_id, &server_id);
        assert_eq!(guard.evaluate(&ctx).expect("ok"), Verdict::Deny);
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
