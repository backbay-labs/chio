//! Human-in-the-loop (HITL) primitives.
//!
//! This module houses the approval-request data model, the persistent
//! approval-store contract, the approval guard that decides when a call
//! needs human sign-off, and the async resume entry points used by the
//! HTTP surface after a human responds. The design follows
//! `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md`.
//!
//! `crate::runtime::Verdict` is `Copy`. This module exposes a richer
//! [`HitlVerdict`] that carries the pending approval request when one is
//! needed, keeping `Verdict` itself `Copy`. The public `Verdict` enum carries a
//! `PendingApproval` marker variant so external callers can pattern-match on
//! the three-way decision; the payload is returned separately via
//! [`ApprovalGuard::evaluate`] and
//! [`ChioKernel::evaluate_tool_call_with_hitl`](crate::ChioKernel).

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use chio_core::capability::{
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedAutonomyTier,
        GovernedTransactionIntent,
    },
    scope::{Constraint, MonetaryAmount},
};
use chio_core::crypto::{sha256_hex, PublicKey};
use chio_log_redact::redacted;
use serde::{Deserialize, Serialize};

use crate::runtime::{ToolCallRequest, Verdict};
use crate::{AgentId, KernelError, ServerId};

/// Maximum lifetime (in seconds) permitted on a single approval token.
/// Mirrors the `MAX_APPROVAL_TTL_SECS` documented in the HITL protocol
/// section 15: the single-use replay registry's TTL is pinned to this
/// value so no token can outlive its replay entry.
pub const MAX_APPROVAL_TTL_SECS: u64 = 3600;

/// A request for human approval, produced when the approval guard
/// returns `Verdict::PendingApproval`. Designed to be serialized into
/// the approval store and the webhook payload without further wrapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalRequest {
    /// Unique request identifier. Caller-stable so the approval store
    /// can be keyed on this value. Callers should supply a UUIDv7.
    pub approval_id: String,

    /// The policy / grant identifier that triggered the approval.
    pub policy_id: String,

    /// The calling agent's identifier.
    pub subject_id: AgentId,

    /// Capability token ID bound to this request.
    pub capability_id: String,

    /// Public key of the capability subject this approval is bound to.
    /// A presented approval token must carry the same subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_public_key: Option<PublicKey>,

    /// Server hosting the target tool.
    pub tool_server: ServerId,

    /// Tool being invoked.
    pub tool_name: String,

    /// Short action verb for human summaries (e.g. `invoke`, `charge`).
    pub action: String,

    /// SHA-256 hex digest of the canonical JSON of the tool arguments
    /// / governed intent. Used to bind an approval token to this exact
    /// parameter set; a mutated argument payload will not satisfy the
    /// same approval.
    pub parameter_hash: String,

    /// Unix seconds after which the request auto-denies (or escalates,
    /// per `timeout_action` in the grant).
    pub expires_at: u64,

    /// Hint for channels about where the human can respond (e.g. the
    /// URL of the dashboard or a Slack permalink). `None` means
    /// "dispatcher will fill this in after sending".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_hint: Option<String>,

    /// Unix seconds when the request was created.
    pub created_at: u64,

    /// Short human-readable summary for dashboards.
    pub summary: String,

    /// Original governed intent, when one is bound. Required for
    /// threshold-based approvals so the approver sees the financial
    /// envelope they are signing off on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent: Option<GovernedTransactionIntent>,

    /// Public keys allowed to approve this request. The kernel fails
    /// closed when the set is empty or when the presented approver is
    /// not in the set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_approvers: Vec<PublicKey>,

    /// Guards that triggered the approval requirement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggered_by: Vec<String>,
}

/// Minimal approval decision recorded after a human responds.
///
/// Callers construct this from the HTTP `POST /approvals/{id}/respond`
/// payload. It is an in-process marker; the cryptographic artifact is
/// the `GovernedApprovalToken` that rides alongside it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Approved,
    Denied,
}

/// Decision packet delivered by an approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Approval request this decision answers.
    pub approval_id: String,
    /// Outcome (approved / denied).
    pub outcome: ApprovalOutcome,
    /// Optional free-form reason supplied by the approver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Public key of the approver. Used to validate the token signature
    /// and for non-repudiation in the receipt.
    pub approver: PublicKey,
    /// Signed approval token produced by the approver.
    pub token: GovernedApprovalToken,
    /// Unix seconds when the kernel received this decision.
    pub received_at: u64,
}

/// Lightweight "approval token" representation used inside the kernel.
/// For HITL v1 this wraps the existing `GovernedApprovalToken` together
/// with the approval request it satisfies, so consumers do not have to
/// re-plumb the full governance type through every surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub approval_id: String,
    pub governed_token: GovernedApprovalToken,
    pub approver: PublicKey,
}

impl ApprovalToken {
    /// Build an `ApprovalToken` from a decision packet.
    #[must_use]
    pub fn from_decision(decision: &ApprovalDecision) -> Self {
        Self {
            approval_id: decision.approval_id.clone(),
            governed_token: decision.token.clone(),
            approver: decision.approver.clone(),
        }
    }

    /// Verify the token's cryptographic signature and binding against
    /// the original approval request. Returns `Err(KernelError::ApprovalRejected)`
    /// when any check fails.
    pub fn verify_against(
        &self,
        request: &ApprovalRequest,
        now: u64,
    ) -> Result<GovernedApprovalDecision, KernelError> {
        // Binding checks: request_id, intent hash, approver identity.
        if self.governed_token.request_id != request.approval_id {
            return Err(KernelError::ApprovalRejected(
                "approval token bound to a different request".into(),
            ));
        }
        if self.governed_token.governed_intent_hash != request.parameter_hash {
            return Err(KernelError::ApprovalRejected(
                "approval token bound to a different parameter set".into(),
            ));
        }
        if self.governed_token.approver != self.approver {
            return Err(KernelError::ApprovalRejected(
                "approval token approver mismatch".into(),
            ));
        }
        if request.trusted_approvers.is_empty() {
            return Err(KernelError::ApprovalRejected(
                "approval request does not declare any trusted approvers".into(),
            ));
        }
        if !request.trusted_approvers.contains(&self.approver) {
            return Err(KernelError::ApprovalRejected(
                "approval token approver is not trusted for this request".into(),
            ));
        }
        match request.subject_public_key.as_ref() {
            Some(expected_subject) if &self.governed_token.subject != expected_subject => {
                return Err(KernelError::ApprovalRejected(
                    "approval token subject does not match the request subject".into(),
                ));
            }
            Some(_) => {}
            None if self.governed_token.subject.to_hex() != request.subject_id => {
                return Err(KernelError::ApprovalRejected(
                    "approval request is missing a subject binding".into(),
                ));
            }
            None => {}
        }

        // Time bounds.
        if now >= self.governed_token.expires_at {
            return Err(KernelError::ApprovalRejected(
                "approval token has expired".into(),
            ));
        }
        if now < self.governed_token.issued_at {
            return Err(KernelError::ApprovalRejected(
                "approval token not yet valid".into(),
            ));
        }

        // Lifetime cap: a token whose lifetime exceeds MAX_APPROVAL_TTL_SECS
        // cannot be safely tracked in the single-use replay registry.
        let lifetime = self
            .governed_token
            .expires_at
            .saturating_sub(self.governed_token.issued_at);
        if lifetime > MAX_APPROVAL_TTL_SECS {
            return Err(KernelError::ApprovalRejected(format!(
                "approval token lifetime {lifetime}s exceeds cap {MAX_APPROVAL_TTL_SECS}s"
            )));
        }

        let ok = self.governed_token.verify_signature().map_err(|e| {
            KernelError::ApprovalRejected(format!(
                "approval token signature verification failed: {e}"
            ))
        })?;
        if !ok {
            return Err(KernelError::ApprovalRejected(
                "approval token signature did not verify".into(),
            ));
        }

        Ok(self.governed_token.decision)
    }
}

/// Errors emitted by approval stores.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalStoreError {
    #[error("approval request not found: {0}")]
    NotFound(String),
    #[error("approval already resolved: {0}")]
    AlreadyResolved(String),
    #[error("approval token already consumed (replay detected): {0}")]
    Replay(String),
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Filter for `list_pending`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Only include requests whose `expires_at` is greater than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_expired_at: Option<u64>,
    /// Maximum number of rows to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Resolved-approval row retained for audit and replay protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedApproval {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    pub resolved_at: u64,
    pub approver_hex: String,
    pub token_id: String,
}

/// Persistent store for pending and resolved HITL approvals. The trait
/// is intentionally synchronous because every concrete implementation
/// in the kernel hot path today (in-memory, SQLite via `rusqlite`) is
/// synchronous, and the kernel itself does not run on an async
/// executor.
pub trait ApprovalStore: Send + Sync {
    /// Persist a new pending request. Idempotent on `approval_id`: a
    /// second call with the same id returns without error as long as
    /// the stored payload matches.
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError>;

    /// Fetch a single pending approval by id.
    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError>;

    /// List all pending approvals matching the filter.
    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError>;

    /// Mark a pending approval as resolved. Returns
    /// `ApprovalStoreError::AlreadyResolved` if the request has already
    /// been resolved (double-resolve protection) and
    /// `ApprovalStoreError::Replay` if the bound token has already been
    /// consumed on a different request.
    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError>;

    /// Count approved calls for a given subject / grant pair. Used by
    /// `Constraint::RequireApprovalAbove` threshold accounting.
    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError>;

    /// Record that a token (by `token_id` and `parameter_hash`) has
    /// been consumed. Used to reject replays of the same approval
    /// token across a restart. Implementations may also call this from
    /// [`resolve`]; exposing it on the trait lets the kernel do the
    /// replay check before persisting the resolution, which matters
    /// when the store is backed by SQLite and wants to run the check
    /// inside the transaction.
    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError>;

    /// Returns `true` if the token has already been consumed.
    fn is_consumed(&self, token_id: &str, parameter_hash: &str)
        -> Result<bool, ApprovalStoreError>;

    /// Fetch the resolution record for a previously resolved approval.
    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError>;
}

/// Batch approvals let a human pre-approve a class of calls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchApproval {
    pub batch_id: String,
    pub approver_hex: String,
    pub subject_id: AgentId,
    pub server_pattern: String,
    pub tool_pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_per_call: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,
    pub not_before: u64,
    pub not_after: u64,
    #[serde(default)]
    pub used_calls: u32,
    #[serde(default)]
    pub used_total_units: u64,
    #[serde(default)]
    pub revoked: bool,
}

/// Store for batch approvals. Counterpart to `ApprovalStore`.
pub trait BatchApprovalStore: Send + Sync {
    fn store(&self, batch: &BatchApproval) -> Result<(), ApprovalStoreError>;

    fn find_matching(
        &self,
        subject_id: &str,
        server_id: &str,
        tool_name: &str,
        amount: Option<&MonetaryAmount>,
        now: u64,
    ) -> Result<Option<BatchApproval>, ApprovalStoreError>;

    fn record_usage(
        &self,
        batch_id: &str,
        amount: Option<&MonetaryAmount>,
    ) -> Result<(), ApprovalStoreError>;

    fn revoke(&self, batch_id: &str) -> Result<(), ApprovalStoreError>;

    fn get(&self, batch_id: &str) -> Result<Option<BatchApproval>, ApprovalStoreError>;
}

/// Contract a channel must satisfy to dispatch an approval request.
///
/// The trait is sync; implementations that need async I/O should use a
/// dedicated thread or a small runtime. `WebhookChannel` uses the
/// blocking `ureq` client already in the crate's dependency tree.
pub trait ApprovalChannel: Send + Sync {
    /// Short channel name (`"webhook"`, `"slack"`, `"dashboard"`...).
    fn name(&self) -> &str;

    /// Deliver an approval request to the configured endpoint. The
    /// channel implementation is responsible for retries; on terminal
    /// failure the call returns `Err` and the kernel leaves the
    /// request in the store (fail-closed).
    fn dispatch(&self, request: &ApprovalRequest) -> Result<ChannelHandle, ChannelError>;
}

/// Handle returned by `dispatch`. Kernel records this alongside the
/// request in the store so `cancel` can be called later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelHandle {
    pub channel: String,
    pub channel_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
}

/// Errors returned by approval channels.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel transport error: {0}")]
    Transport(String),
    #[error("channel remote rejected dispatch: {status}: {body}")]
    Remote { status: u16, body: String },
    #[error("channel misconfigured: {0}")]
    Config(String),
}

/// Outcome of running an approval guard against a tool call.
///
/// The pending + approved variants box their inner payloads so the
/// enum stays cheap to pass by value; large variants trip clippy's
/// `large_enum_variant` lint.
#[derive(Debug, Clone)]
pub enum HitlVerdict {
    /// Guard passes -- no approval required.
    Allow,
    /// Guard denies without an approval path (e.g. fail-closed).
    Deny { reason: String },
    /// Approval is required. Kernel should persist the request and
    /// return a 202-style response to the caller.
    Pending {
        request: Box<ApprovalRequest>,
        verdict: Verdict,
    },
    /// Approval was supplied with the request and passed verification.
    Approved { token: Box<ApprovalToken> },
}

/// Compute the parameter hash that binds an `ApprovalRequest` to a
/// specific set of arguments. Input is canonicalized via the existing
/// `sha256_hex(chio_core::canonical::canonical_json_bytes(..))` helper
/// so independent kernels produce identical hashes.
#[must_use]
pub fn compute_parameter_hash(
    tool_server: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
    governed_intent: Option<&GovernedTransactionIntent>,
) -> String {
    let envelope = serde_json::json!({
        "server_id": tool_server,
        "tool_name": tool_name,
        "arguments": arguments,
        "governed_intent": governed_intent,
    });
    match chio_core::canonical::canonical_json_bytes(&envelope) {
        Ok(bytes) => sha256_hex(&bytes),
        // Canonicalization only fails on unserializable inputs -- the
        // tool call arguments are already `serde_json::Value` so this
        // path is unreachable in practice. Fall back to a tagged hash
        // of the display form rather than panicking: we still return
        // a stable string so callers do not have to handle the error.
        Err(_) => sha256_hex(envelope.to_string().as_bytes()),
    }
}

/// The built-in HITL guard. Runs before the generic guard pipeline and
/// decides whether a call passes straight through, requires approval,
/// or was already approved by an accompanying token.
pub struct ApprovalGuard {
    /// Persistent store of pending / resolved approvals.
    store: std::sync::Arc<dyn ApprovalStore>,
    /// Channels fired on new pending requests. Dispatch failures are
    /// logged but do NOT clear the pending record -- the fail-closed
    /// rule from the protocol table is that a webhook delivery failure
    /// keeps the request pending and queryable via the API.
    channels: Vec<std::sync::Arc<dyn ApprovalChannel>>,
    /// Default timeout for newly created requests.
    default_ttl_secs: u64,
}

impl ApprovalGuard {
    pub fn new(store: std::sync::Arc<dyn ApprovalStore>) -> Self {
        Self {
            store,
            channels: Vec::new(),
            default_ttl_secs: 3600,
        }
    }

    #[must_use]
    pub fn with_channel(mut self, channel: std::sync::Arc<dyn ApprovalChannel>) -> Self {
        self.channels.push(channel);
        self
    }

    #[must_use]
    pub fn with_default_ttl(mut self, secs: u64) -> Self {
        self.default_ttl_secs = secs;
        self
    }

    /// Evaluate the grant's constraints against the request. Returns
    /// a `HitlVerdict` describing the next step.
    pub fn evaluate(&self, ctx: ApprovalContext<'_>, now: u64) -> Result<HitlVerdict, KernelError> {
        let mut triggered = Vec::<String>::new();
        let mut threshold_hit = false;
        let mut always_hit = false;
        let mut tier_hit = false;

        for constraint in ctx.constraints {
            match constraint {
                Constraint::RequireApprovalAbove { threshold_units } => {
                    let amount = ctx
                        .request
                        .governed_intent
                        .as_ref()
                        .and_then(|intent| intent.max_amount.as_ref());
                    match amount {
                        Some(amt) if amt.units >= *threshold_units => {
                            threshold_hit = true;
                            triggered.push(format!("require_approval_above:{threshold_units}"));
                        }
                        Some(_) => {
                            // Below threshold -- no approval triggered.
                        }
                        None => {
                            // Fail-closed: constraint present but no
                            // amount to compare. Deny rather than
                            // silently skip.
                            return Ok(HitlVerdict::Deny {
                                reason: format!(
                                    "RequireApprovalAbove requires a governed intent with max_amount (threshold={threshold_units})"
                                ),
                            });
                        }
                    }
                }
                Constraint::MinimumAutonomyTier(GovernedAutonomyTier::Autonomous)
                    if ctx.request.governed_intent.is_some() =>
                {
                    // When paired with the HITL guard, Autonomous tier
                    // is treated as "requires human approval". Direct
                    // / Delegated pass through.
                    tier_hit = true;
                    triggered.push("minimum_autonomy_tier:autonomous".to_string());
                }
                _ => {}
            }
        }

        // An attribute flag on the request (`force_approval`) forces a
        // PendingApproval outcome so host integrations can enter the HITL
        // flow without teaching every constraint variant.
        // Test harnesses use this path too.
        if ctx.force_approval {
            always_hit = true;
            triggered.push("force_approval".to_string());
        }

        let needs_approval = threshold_hit || always_hit || tier_hit;
        if !needs_approval {
            return Ok(HitlVerdict::Allow);
        }
        if ctx.trusted_approvers.is_empty() {
            return Ok(HitlVerdict::Deny {
                reason: "approval required but no trusted approvers are configured".to_string(),
            });
        }

        // If the caller attached an approval token, try to satisfy the
        // request with it before creating a new pending entry.
        if let Some(token) = ctx.presented_token {
            // Reconstruct the request envelope matching the original
            // pending record so we can validate binding.
            let parameter_hash = compute_parameter_hash(
                &ctx.request.server_id,
                &ctx.request.tool_name,
                &ctx.request.arguments,
                ctx.request.governed_intent.as_ref(),
            );

            // Lookup the pending record. If the token refers to an
            // approval id, prefer the stored record; otherwise build
            // a synthetic record to verify against (binding by
            // parameter hash is the cryptographic gate).
            let stored = self
                .store
                .get_pending(&token.approval_id)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;
            let resolved = self
                .store
                .get_resolution(&token.approval_id)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;

            let approval_request = match stored.or_else(|| {
                resolved.map(|res| ApprovalRequest {
                    approval_id: res.approval_id,
                    policy_id: ctx.policy_id.to_string(),
                    subject_id: ctx.request.agent_id.clone(),
                    capability_id: ctx.request.capability.id.clone(),
                    subject_public_key: Some(ctx.request.capability.subject.clone()),
                    tool_server: ctx.request.server_id.clone(),
                    tool_name: ctx.request.tool_name.clone(),
                    action: "invoke".to_string(),
                    parameter_hash: parameter_hash.clone(),
                    expires_at: now + self.default_ttl_secs,
                    callback_hint: None,
                    created_at: now,
                    summary: String::new(),
                    governed_intent: ctx.request.governed_intent.clone(),
                    trusted_approvers: ctx.trusted_approvers.to_vec(),
                    triggered_by: triggered.clone(),
                })
            }) {
                Some(record) => record,
                None => {
                    return Err(KernelError::ApprovalRejected(
                        "approval token does not match any known request".into(),
                    ));
                }
            };

            // Replay check first: before spending cycles on signature
            // verification, fail-closed on a previously consumed token.
            let already_consumed = self
                .store
                .is_consumed(&token.governed_token.id, &approval_request.parameter_hash)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;
            if already_consumed {
                return Err(KernelError::ApprovalRejected(
                    "approval token already consumed (replay)".into(),
                ));
            }

            let decision = token.verify_against(&approval_request, now)?;
            match decision {
                GovernedApprovalDecision::Approved => Ok(HitlVerdict::Approved {
                    token: Box::new(token.clone()),
                }),
                GovernedApprovalDecision::Denied => Ok(HitlVerdict::Deny {
                    reason: "human approver denied the request".into(),
                }),
            }
        } else {
            // No token on the request -- build a new pending entry.
            let parameter_hash = compute_parameter_hash(
                &ctx.request.server_id,
                &ctx.request.tool_name,
                &ctx.request.arguments,
                ctx.request.governed_intent.as_ref(),
            );
            let expires_at = now.saturating_add(self.default_ttl_secs);
            let summary = format!(
                "agent {} requests approval for {}:{}",
                ctx.request.agent_id, ctx.request.server_id, ctx.request.tool_name
            );
            let request = ApprovalRequest {
                approval_id: ctx
                    .approval_id_override
                    .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                policy_id: ctx.policy_id.to_string(),
                subject_id: ctx.request.agent_id.clone(),
                capability_id: ctx.request.capability.id.clone(),
                subject_public_key: Some(ctx.request.capability.subject.clone()),
                tool_server: ctx.request.server_id.clone(),
                tool_name: ctx.request.tool_name.clone(),
                action: "invoke".to_string(),
                parameter_hash,
                expires_at,
                callback_hint: None,
                created_at: now,
                summary,
                governed_intent: ctx.request.governed_intent.clone(),
                trusted_approvers: ctx.trusted_approvers.to_vec(),
                triggered_by: triggered,
            };
            self.store
                .store_pending(&request)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;

            // Dispatch to channels. Delivery failures are logged but
            // the pending row stays in place: the API can still serve
            // it from `/approvals/pending`.
            for channel in &self.channels {
                if let Err(err) = channel.dispatch(&request) {
                    tracing::warn!(
                        approval_id = %request.approval_id,
                        channel = %channel.name(),
                        error = %redacted!(&err),
                        "approval channel dispatch failed; request remains pending"
                    );
                }
            }

            Ok(HitlVerdict::Pending {
                request: Box::new(request),
                verdict: Verdict::PendingApproval,
            })
        }
    }

    /// Accessor used by the resume flow in the HTTP layer.
    #[must_use]
    pub fn store(&self) -> std::sync::Arc<dyn ApprovalStore> {
        self.store.clone()
    }
}

/// Context passed into [`ApprovalGuard::evaluate`].
pub struct ApprovalContext<'a> {
    pub request: &'a ToolCallRequest,
    pub constraints: &'a [Constraint],
    pub policy_id: &'a str,
    /// Public keys trusted to sign the approval token for this request.
    pub trusted_approvers: &'a [PublicKey],
    /// Approval token presented by the caller, if any.
    pub presented_token: Option<&'a ApprovalToken>,
    /// When `true`, force the guard into the pending path regardless
    /// of constraints. Used by integration tests and by host adapters
    /// that decided out-of-band that the call needs approval.
    pub force_approval: bool,
    /// Optional deterministic id for the generated approval request.
    pub approval_id_override: Option<String>,
}

/// Apply a resolved approval decision: verify the token, mark it
/// consumed, persist the resolution, and return the final verdict that
/// the kernel should treat as the outcome.
pub fn resume_with_decision(
    store: &dyn ApprovalStore,
    decision: &ApprovalDecision,
    now: u64,
) -> Result<ApprovalOutcome, KernelError> {
    let pending = match store
        .get_pending(&decision.approval_id)
        .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?
    {
        Some(p) => p,
        None => {
            if let Some(resolution) = store
                .get_resolution(&decision.approval_id)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?
            {
                return Err(KernelError::ApprovalRejected(format!(
                    "already resolved: {} ({:?})",
                    resolution.approval_id, resolution.outcome
                )));
            }
            return Err(KernelError::ApprovalRejected(format!(
                "unknown approval id: {}",
                decision.approval_id
            )));
        }
    };

    // Single-use replay check: reject immediately if the token has
    // already been consumed by a prior resolution.
    let already = store
        .is_consumed(&decision.token.id, &pending.parameter_hash)
        .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;
    if already {
        return Err(KernelError::ApprovalRejected(
            "approval token already consumed (replay)".into(),
        ));
    }

    // Verify the token cryptographically.
    let approval_token = ApprovalToken {
        approval_id: pending.approval_id.clone(),
        governed_token: decision.token.clone(),
        approver: decision.approver.clone(),
    };
    let token_decision = approval_token.verify_against(&pending, now)?;

    // Validate that the HTTP envelope's outcome matches the signed-token
    // decision BEFORE touching the store. Otherwise a mismatched pair
    // (token says Denied, body says Approved) would already have flipped
    // the pending request to `resolved=true` and bumped any approval
    // counters before we bail out, corrupting approval-threshold state
    // and replay-protection bookkeeping while still returning an error.
    let outcome = match (token_decision, &decision.outcome) {
        (GovernedApprovalDecision::Approved, ApprovalOutcome::Approved) => {
            ApprovalOutcome::Approved
        }
        (GovernedApprovalDecision::Denied, ApprovalOutcome::Denied) => ApprovalOutcome::Denied,
        _ => {
            return Err(KernelError::ApprovalRejected(
                "HTTP outcome disagrees with signed token decision".into(),
            ));
        }
    };

    // Record consumption inside the same store call so it survives a
    // restart: `resolve` is expected to atomically mark the request
    // resolved AND record the consumed token id. We only reach this
    // point once the envelope/token consistency check has passed.
    store
        .resolve(&decision.approval_id, decision)
        .map_err(|e| match e {
            ApprovalStoreError::AlreadyResolved(m) => {
                KernelError::ApprovalRejected(format!("already resolved: {m}"))
            }
            ApprovalStoreError::Replay(m) => {
                KernelError::ApprovalRejected(format!("replay detected: {m}"))
            }
            other => KernelError::Internal(format!("approval store: {other}")),
        })?;

    Ok(outcome)
}

// ---------------------------------------------------------------------
// In-memory reference implementations.
// ---------------------------------------------------------------------

/// Thread-safe in-memory `ApprovalStore`. Useful for tests and for
/// ephemeral deployments where operators explicitly accept data loss
/// on restart (ephemeral: data is lost on restart; use the SQLite-backed
/// store for production durability).
#[derive(Default)]
pub struct InMemoryApprovalStore {
    pending: RwLock<HashMap<String, ApprovalRequest>>,
    resolved: RwLock<HashMap<String, ResolvedApproval>>,
    consumed: Mutex<HashMap<String, u64>>, // key: token_id ":" parameter_hash
    approved_counts: Mutex<HashMap<String, u64>>, // key: subject_id + ":" + policy_id
}

impl InMemoryApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn consumed_key(token_id: &str, parameter_hash: &str) -> String {
        format!("{token_id}:{parameter_hash}")
    }
}

impl ApprovalStore for InMemoryApprovalStore {
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .pending
            .write()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        match guard.get(&request.approval_id) {
            Some(existing) if existing == request => return Ok(()),
            Some(_) => {
                return Err(ApprovalStoreError::Backend(format!(
                    "approval_id {} already exists with different payload",
                    request.approval_id
                )))
            }
            None => {}
        }
        guard.insert(request.approval_id.clone(), request.clone());
        Ok(())
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        let guard = self
            .pending
            .read()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        Ok(guard.get(id).cloned())
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let guard = self
            .pending
            .read()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        let mut out: Vec<_> = guard
            .values()
            .filter(|req| {
                filter
                    .subject_id
                    .as_deref()
                    .is_none_or(|s| req.subject_id == s)
                    && filter
                        .tool_server
                        .as_deref()
                        .is_none_or(|s| req.tool_server == s)
                    && filter
                        .tool_name
                        .as_deref()
                        .is_none_or(|s| req.tool_name == s)
                    && filter.not_expired_at.is_none_or(|t| req.expires_at > t)
            })
            .cloned()
            .collect();
        out.sort_by_key(|approval| approval.created_at);
        if let Some(limit) = filter.limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        let mut pending_guard = self
            .pending
            .write()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        let Some(pending) = pending_guard.remove(id) else {
            return Err(ApprovalStoreError::NotFound(id.to_string()));
        };

        {
            let mut consumed = self
                .consumed
                .lock()
                .map_err(|_| ApprovalStoreError::Backend("consumed map poisoned".into()))?;
            let key = Self::consumed_key(&decision.token.id, &pending.parameter_hash);
            if consumed.contains_key(&key) {
                // Put the pending row back so the caller can retry the
                // lookup on subsequent requests.
                pending_guard.insert(id.to_string(), pending);
                return Err(ApprovalStoreError::Replay(id.to_string()));
            }
            consumed.insert(key, decision.received_at);
        }

        let mut resolved = self
            .resolved
            .write()
            .map_err(|_| ApprovalStoreError::Backend("resolved map poisoned".into()))?;
        if resolved.contains_key(id) {
            return Err(ApprovalStoreError::AlreadyResolved(id.to_string()));
        }
        resolved.insert(
            id.to_string(),
            ResolvedApproval {
                approval_id: id.to_string(),
                outcome: decision.outcome.clone(),
                resolved_at: decision.received_at,
                approver_hex: decision.approver.to_hex(),
                token_id: decision.token.id.clone(),
            },
        );

        if decision.outcome == ApprovalOutcome::Approved {
            let mut counts = self
                .approved_counts
                .lock()
                .map_err(|_| ApprovalStoreError::Backend("counts map poisoned".into()))?;
            let key = format!("{}:{}", pending.subject_id, pending.policy_id);
            *counts.entry(key).or_default() += 1;
        }

        Ok(())
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        let counts = self
            .approved_counts
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("counts map poisoned".into()))?;
        Ok(counts
            .get(&format!("{subject_id}:{policy_id}"))
            .copied()
            .unwrap_or(0))
    }

    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("consumed map poisoned".into()))?;
        let key = Self::consumed_key(token_id, parameter_hash);
        if consumed.contains_key(&key) {
            return Err(ApprovalStoreError::Replay(format!(
                "token {token_id} already consumed"
            )));
        }
        consumed.insert(key, now);
        Ok(())
    }

    fn is_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let consumed = self
            .consumed
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("consumed map poisoned".into()))?;
        Ok(consumed.contains_key(&Self::consumed_key(token_id, parameter_hash)))
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        let guard = self
            .resolved
            .read()
            .map_err(|_| ApprovalStoreError::Backend("resolved map poisoned".into()))?;
        Ok(guard.get(id).cloned())
    }
}

/// In-memory `BatchApprovalStore` used in tests. Production backends
/// should persist via `SqliteBatchApprovalStore`.
#[derive(Default)]
pub struct InMemoryBatchApprovalStore {
    batches: RwLock<HashMap<String, BatchApproval>>,
}

impl InMemoryBatchApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BatchApprovalStore for InMemoryBatchApprovalStore {
    fn store(&self, batch: &BatchApproval) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .batches
            .write()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        guard.insert(batch.batch_id.clone(), batch.clone());
        Ok(())
    }

    fn find_matching(
        &self,
        subject_id: &str,
        server_id: &str,
        tool_name: &str,
        amount: Option<&MonetaryAmount>,
        now: u64,
    ) -> Result<Option<BatchApproval>, ApprovalStoreError> {
        let guard = self
            .batches
            .read()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        Ok(guard
            .values()
            .find(|b| {
                !b.revoked
                    && b.subject_id == subject_id
                    && pattern_matches(&b.server_pattern, server_id)
                    && pattern_matches(&b.tool_pattern, tool_name)
                    && now >= b.not_before
                    && now < b.not_after
                    && b.max_calls.is_none_or(|c| b.used_calls < c)
                    && amount_fits(b, amount)
            })
            .cloned())
    }

    fn record_usage(
        &self,
        batch_id: &str,
        amount: Option<&MonetaryAmount>,
    ) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .batches
            .write()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        let Some(batch) = guard.get_mut(batch_id) else {
            return Err(ApprovalStoreError::NotFound(batch_id.to_string()));
        };
        batch.used_calls = batch.used_calls.saturating_add(1);
        if let Some(amt) = amount {
            batch.used_total_units = batch.used_total_units.saturating_add(amt.units);
        }
        Ok(())
    }

    fn revoke(&self, batch_id: &str) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .batches
            .write()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        let Some(batch) = guard.get_mut(batch_id) else {
            return Err(ApprovalStoreError::NotFound(batch_id.to_string()));
        };
        batch.revoked = true;
        Ok(())
    }

    fn get(&self, batch_id: &str) -> Result<Option<BatchApproval>, ApprovalStoreError> {
        let guard = self
            .batches
            .read()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        Ok(guard.get(batch_id).cloned())
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

fn amount_fits(batch: &BatchApproval, amount: Option<&MonetaryAmount>) -> bool {
    let Some(amt) = amount else {
        // Calls without a monetary intent match only batches that don't
        // constrain per-call amount.
        return batch.max_amount_per_call.is_none() && batch.max_total_amount.is_none();
    };
    if let Some(per_call) = &batch.max_amount_per_call {
        if amt.currency != per_call.currency || amt.units > per_call.units {
            return false;
        }
    }
    if let Some(total) = &batch.max_total_amount {
        if amt.currency != total.currency
            || batch.used_total_units.saturating_add(amt.units) > total.units
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalTokenBody};
    use chio_core::crypto::Keypair;

    fn make_request(approval_id: &str, parameter_hash: &str) -> ApprovalRequest {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        ApprovalRequest {
            approval_id: approval_id.to_string(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: parameter_hash.to_string(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        }
    }

    fn make_token(
        approver: &Keypair,
        subject: &Keypair,
        approval_id: &str,
        parameter_hash: &str,
        decision: GovernedApprovalDecision,
    ) -> GovernedApprovalToken {
        let body = GovernedApprovalTokenBody {
            id: format!("tok-{approval_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: parameter_hash.to_string(),
            request_id: approval_id.to_string(),
            threshold_proposal_hash: None,
            issued_at: 10,
            expires_at: 100,
            decision,
        };
        GovernedApprovalToken::sign(body, approver).unwrap()
    }

    #[test]
    fn resume_flow_approved() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-1", "h-1");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-1".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        let outcome = resume_with_decision(&store, &decision, 50).unwrap();
        assert_eq!(outcome, ApprovalOutcome::Approved);
        assert_eq!(store.count_approved("agent-1", "policy-1").unwrap(), 1);
    }

    #[test]
    fn resume_flow_replay_rejected() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-2", "h-2");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-2",
            "h-2",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-2".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        // First resolution succeeds.
        resume_with_decision(&store, &decision, 50).unwrap();
        // Second resolution must fail (replay).
        let err = resume_with_decision(&store, &decision, 51).unwrap_err();
        match err {
            KernelError::ApprovalRejected(_) => {}
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn resume_flow_duplicate_resolution_reports_already_resolved() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-2b", "h-2b");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-2b",
            "h-2b",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-2b".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        resume_with_decision(&store, &decision, 50).unwrap();
        let err = resume_with_decision(&store, &decision, 51).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("already resolved"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_wrong_request_id() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_token(
            &approver,
            &subject,
            "a-X",
            "h-X",
            GovernedApprovalDecision::Approved,
        );
        let req = make_request("a-other", "h-X");
        let approval_token = ApprovalToken {
            approval_id: "a-X".into(),
            governed_token: token,
            approver: approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(_) => {}
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_untrusted_approver() {
        let trusted_approver = Keypair::generate();
        let rogue_approver = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_token(
            &rogue_approver,
            &subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: "h-1".into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![trusted_approver.public_key()],
            triggered_by: vec![],
        };
        let approval_token = ApprovalToken {
            approval_id: "a-1".into(),
            governed_token: token,
            approver: rogue_approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("not trusted"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_subject_mismatch() {
        let approver = Keypair::generate();
        let expected_subject = Keypair::generate();
        let rogue_subject = Keypair::generate();
        let token = make_token(
            &approver,
            &rogue_subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(expected_subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: "h-1".into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        };
        let approval_token = ApprovalToken {
            approval_id: "a-1".into(),
            governed_token: token,
            approver: approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("subject"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }
}
