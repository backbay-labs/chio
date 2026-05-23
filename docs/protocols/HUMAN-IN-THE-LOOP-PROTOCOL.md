# Human-in-the-Loop Protocol: Async Approval for Governed Tool Calls

> **Status**: P0 -- proposed April 2026
> **Priority**: Critical -- review found that 6 of 10 production agent patterns
> require human-in-the-loop (customer support, CRM, infrastructure, SecOps,
> trading, data analysis). Elevating from P2 to P0.
> **Depends on**: `chio-core-types` (GovernedApprovalToken, GovernedTransactionIntent,
> RequireApprovalAbove, GovernedAutonomyTier), `chio-kernel` (Verdict, Guard trait)

---

## 1. Motivation

Chio governs tool calls with a fail-closed guard pipeline: every invocation
is evaluated against capability grants and guard policies before execution.
Today the pipeline produces a binary verdict -- Allow or Deny -- synchronously.
There is no mechanism for a guard to say "this needs a human decision before
I can render a verdict."

Production agent systems require a third outcome: **pending approval**. The
agent's tool call is not denied, but it cannot proceed until a human reviews
and signs off. This is distinct from "advisory mode" where the agent proceeds
and a human reviews later. Pending approval blocks execution.

### Existing Primitives

Chio already has the building blocks but no protocol connecting them:

| Primitive | Location | Role |
|-----------|----------|------|
| `RequireApprovalAbove { threshold_units }` | `Constraint` enum in `chio-core-types` | Grant-level policy: calls above threshold need approval |
| `GovernedAutonomyTier` (Direct, Delegated, Autonomous) | `chio-core-types` | Classifies how much autonomy the agent has |
| `GovernedTransactionIntent` | `chio-core-types` | Structured intent bound to a governed call |
| `GovernedApprovalToken` | `chio-core-types` | Signed approval artifact bound to one intent and one request |
| `GovernedApprovalDecision` (Approved, Denied) | `chio-core-types` | Decision enum on the token |
| `Verdict` (Allow, Deny) | `chio-kernel::runtime` | Kernel's internal evaluation result |
| `Decision` (Allow, Deny, Cancelled, Incomplete) | `chio-core-types::receipt` | Receipt-level decision record |

This protocol connects these primitives into a complete async approval flow.

---

## 2. State Machine

A tool call that triggers approval follows this lifecycle:

```
                              +----------+
                              |          |
               Agent calls    |  Received|
               tool           |          |
                              +----+-----+
                                   |
                          Kernel evaluates
                          grants + guards
                                   |
                     +-------------+-------------+
                     |             |              |
                     v             v              v
               +---------+  +-----------+  +-----------+
               |  Allow  |  |   Deny    |  |  Pending  |
               |         |  |           |  |  Approval |
               +---------+  +-----------+  +-----+-----+
                                                  |
                                        Approval request
                                        dispatched to channel
                                                  |
                              +-------------------+-------------------+
                              |                   |                   |
                              v                   v                   v
                        +-----------+      +-----------+       +----------+
                        |  Approved |      |  Denied   |       | Timed Out|
                        |           |      |           |       |          |
                        +-----+-----+      +-----+-----+       +----+-----+
                              |                  |                   |
                              v                  v                   v
                        +-----------+      +-----------+     (escalation
                        | Execute   |      | Deny with |      policy)
                        | tool call |      | receipt   |         |
                        +-----+-----+      +-----------+    +----+-----+
                              |                             |  Escalate |
                              v                             |  / Deny / |
                        +-----------+                       | Auto-     |
                        | Receipt   |                       | approve   |
                        | (with     |                       +----------+
                        |  approval)|
                        +-----------+
```

### States

| State | Description | Terminal? |
|-------|-------------|-----------|
| `Received` | Tool call request accepted by kernel | No |
| `Allow` | Guards pass, no approval required, tool executes | Yes |
| `Deny` | Guards deny, no approval can override | Yes |
| `PendingApproval` | Guards require human approval before proceeding | No |
| `Approved` | Human approved, kernel re-validates and executes | No |
| `Denied` | Human denied (or timeout with deny policy) | Yes |
| `TimedOut` | No human response within deadline | No |
| `Escalated` | Timeout triggered escalation to next approver | No |

### Transitions

```
Received        -> Allow           (all guards pass, no approval constraint matched)
Received        -> Deny            (guard denies, not convertible to approval)
Received        -> PendingApproval (approval guard triggers)

PendingApproval -> Approved        (human signs GovernedApprovalToken with Approved)
PendingApproval -> Denied          (human signs GovernedApprovalToken with Denied)
PendingApproval -> TimedOut        (deadline expires)

TimedOut        -> Denied          (timeout_policy = deny)
TimedOut        -> Escalated       (timeout_policy = escalate)
TimedOut        -> Approved        (timeout_policy = auto_approve_advisory)

Escalated       -> PendingApproval (next approver in chain, new deadline)
Escalated       -> Denied          (no more approvers to escalate to)

Approved        -> Allow           (kernel re-validates, token bound to intent)
Approved        -> Deny            (capability revoked during wait, fail-closed)
```

---

## 3. Kernel Changes: `Verdict::PendingApproval`

The kernel's internal `Verdict` enum gains a third variant:

```rust
/// Verdict of a guard or capability evaluation.
pub enum Verdict {
    /// The action is allowed.
    Allow,
    /// The action is denied.
    Deny,
    /// The action requires human approval before proceeding.
    /// Carries the approval request metadata needed to dispatch to a channel.
    PendingApproval(ApprovalRequest),
}
```

The `Decision` enum on receipts gains a matching variant:

```rust
pub enum Decision {
    Allow,
    Deny { reason: String, guard: String },
    Cancelled { reason: String },
    Incomplete { reason: String },
    /// The tool call is suspended pending human approval.
    PendingApproval {
        /// Unique approval request identifier.
        approval_request_id: String,
        /// Human-readable summary of what needs approval.
        summary: String,
        /// Deadline (unix seconds) after which timeout policy applies.
        deadline: u64,
    },
    /// The tool call was approved by a human and then executed.
    ApprovedAndExecuted {
        /// The signed approval token.
        approval_token_id: String,
        /// The approver's public key.
        approver: PublicKey,
    },
    /// The tool call was denied by a human.
    HumanDenied {
        /// The signed denial token.
        approval_token_id: String,
        /// The approver's public key.
        approver: PublicKey,
        /// Optional reason from the human.
        reason: Option<String>,
    },
}
```

### Why a kernel-level variant instead of HTTP-only

The approval flow must be kernel-native because:

1. **Guard pipeline integration.** A guard must be able to return
   PendingApproval as a first-class verdict, not an out-of-band signal.
2. **Receipt integrity.** The pending state must be recorded in a signed
   receipt so the audit trail shows the tool call was suspended, not silently
   dropped.
3. **Re-evaluation on resume.** When the human approves, the kernel must
   re-run capability validation (the grant may have been revoked or expired
   during the wait). This is a kernel concern, not an HTTP concern.
4. **Transport independence.** The same approval flow must work over HTTP,
   gRPC, A2A, and in-process embedding.

### Guard Trait Extension

```rust
/// Extended guard trait supporting async approval.
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;

    /// Evaluate the guard against a tool call request.
    ///
    /// Returns `Ok(Verdict::Allow)` to pass, `Ok(Verdict::Deny)` to block,
    /// `Ok(Verdict::PendingApproval(..))` to require human approval,
    /// or `Err` on internal failure (which the kernel treats as deny).
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>;
}
```

### Kernel Evaluation Loop Change

```rust
// Current: binary Allow/Deny
for guard in &self.guards {
    match guard.evaluate(&ctx) {
        Ok(Verdict::Allow) => { /* continue */ }
        Ok(Verdict::Deny) => { return Err(KernelError::GuardDenied(..)); }
        Err(e) => { return Err(KernelError::GuardDenied(..)); }  // fail-closed
    }
}

// New: ternary Allow/Deny/PendingApproval
let mut pending: Option<ApprovalRequest> = None;

for guard in &self.guards {
    match guard.evaluate(&ctx) {
        Ok(Verdict::Allow) => { /* continue */ }
        Ok(Verdict::Deny) => { return Err(KernelError::GuardDenied(..)); }
        Ok(Verdict::PendingApproval(request)) => {
            // Deny takes priority over PendingApproval.
            // If any guard denies, the call is denied regardless of
            // pending approvals from other guards.
            // If multiple guards return PendingApproval, merge requests.
            pending = Some(merge_approval_requests(pending, request));
        }
        Err(e) => { return Err(KernelError::GuardDenied(..)); }  // fail-closed
    }
}

if let Some(approval_request) = pending {
    // All non-approval guards passed but at least one requires approval.
    // Emit a PendingApproval receipt and suspend execution.
    return Ok(ToolCallResponse {
        verdict: Verdict::PendingApproval(approval_request),
        receipt: sign_pending_receipt(&ctx, &approval_request),
        ..
    });
}
```

**Priority rule:** Deny > PendingApproval > Allow. If any guard denies,
the entire request is denied. If no guard denies but one or more require
approval, the request is suspended. Only if all guards allow does the
request proceed.

---

## 4. Approval Request

The kernel produces an `ApprovalRequest` when a guard returns PendingApproval:

```rust
/// A request for human approval, produced by the kernel when a guard
/// returns Verdict::PendingApproval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique request identifier (UUIDv7).
    pub id: String,

    /// The original tool call request ID this approval is bound to.
    pub request_id: String,

    /// The governed transaction intent, if present.
    /// Required when RequireApprovalAbove triggers.
    pub governed_intent: Option<GovernedTransactionIntent>,

    /// Hash of the governed intent for token binding.
    pub intent_hash: String,

    /// Human-readable summary of what the agent wants to do.
    pub summary: String,

    /// The guard(s) that triggered the approval requirement.
    pub triggered_by: Vec<String>,

    /// Agent identity requesting the action.
    pub agent_id: AgentId,

    /// Tool and server the agent wants to invoke.
    pub tool_name: String,
    pub server_id: ServerId,

    /// Tool arguments (may be redacted by policy).
    pub arguments: Option<serde_json::Value>,

    /// The approval policy governing this request.
    pub policy: ApprovalPolicy,

    /// Deadline (unix seconds) after which timeout_action applies.
    pub deadline: u64,

    /// What happens if no human responds by the deadline.
    pub timeout_action: TimeoutAction,

    /// Ordered list of approvers to try.
    pub approvers: Vec<ApproverIdentity>,

    /// Which channels to dispatch the request through.
    pub channels: Vec<ChannelConfig>,

    /// Unix timestamp when the request was created.
    pub created_at: u64,
}
```

---

## 5. Approval Token

The human's decision is encoded in the existing `GovernedApprovalToken`:

```rust
/// Already exists in chio-core-types::capability.
pub struct GovernedApprovalToken {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,  // Approved | Denied
    pub signature: Signature,
}
```

### Binding Properties

The approval token is cryptographically bound to:

1. **The specific tool call** via `request_id` (matches `ToolCallRequest.request_id`).
2. **The specific intent** via `governed_intent_hash` (SHA-256 of canonical
   JSON of the `GovernedTransactionIntent`).
3. **The approver's identity** via `approver` (Ed25519 public key).
4. **The agent's identity** via `subject` (the agent's public key).
5. **Time bounds** via `issued_at` / `expires_at`.

The kernel validates all five bindings before accepting an approval token.
A token for a different request, different intent, different agent, or
outside its time window is rejected.

### Extended Token Body

For HITL-specific metadata, the approval token body is extended:

```rust
/// Extended fields carried in the approval token's metadata.
/// These do not change the signature (they ride in the receipt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalMetadata {
    /// Human-provided reason for the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Conditions the human attached to the approval.
    /// Example: "approved for amounts under $500 only"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<String>,

    /// Whether this approval was part of a batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_approval_id: Option<String>,

    /// The channel through which the human responded.
    pub channel: String,

    /// Time the human spent reviewing (milliseconds from dispatch to decision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_duration_ms: Option<u64>,
}
```

---

## 6. Approval Channels

Approval requests must reach humans through multiple channels. The protocol
defines a trait that channel implementations satisfy:

```rust
/// A channel through which approval requests are dispatched to humans.
#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    /// Human-readable channel name (e.g., "slack", "email", "dashboard").
    fn name(&self) -> &str;

    /// Dispatch an approval request to the human.
    ///
    /// Returns a channel-specific handle that can be used to track the request.
    /// The channel is responsible for rendering the request in a human-readable
    /// format and providing approve/deny controls.
    async fn dispatch(
        &self,
        request: &ApprovalRequest,
    ) -> Result<ChannelHandle, ChannelError>;

    /// Cancel a previously dispatched request.
    ///
    /// Called when the request is resolved through another channel or times out.
    async fn cancel(&self, handle: &ChannelHandle) -> Result<(), ChannelError>;

    /// Check whether this channel supports batch approval.
    fn supports_batch(&self) -> bool { false }
}

/// Handle returned by a channel after dispatching a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelHandle {
    /// Channel-specific identifier (Slack message ID, email thread ID, etc.).
    pub channel_ref: String,
    /// The channel name.
    pub channel: String,
    /// URL the human can visit to act on the request (if applicable).
    pub action_url: Option<String>,
}
```

### Built-in Channel Implementations

| Channel | Transport | Latency | Best For |
|---------|-----------|---------|----------|
| `WebhookChannel` | HTTP POST to configured endpoint | Low | Custom dashboards, internal tools |
| `SlackChannel` | Slack Block Kit message with approve/deny buttons | Low | Teams already on Slack |
| `EmailChannel` | Email with signed action links | Medium | Compliance-heavy environments |
| `DashboardChannel` | WebSocket push to Chio dashboard | Low | Ops teams monitoring in real time |
| `ApiPollChannel` | Stores request; human polls `/approvals/pending` | Varies | Programmatic approval workflows |

### Webhook Channel Example

```rust
pub struct WebhookChannel {
    endpoint: Url,
    signing_key: Keypair,
    http_client: reqwest::Client,
}

#[async_trait]
impl ApprovalChannel for WebhookChannel {
    fn name(&self) -> &str { "webhook" }

    async fn dispatch(&self, request: &ApprovalRequest) -> Result<ChannelHandle, ChannelError> {
        let payload = WebhookPayload {
            event: "approval_requested",
            approval_request: request.clone(),
            callback_url: format!("/approvals/{}/respond", request.id),
        };

        // Sign the payload so the receiver can verify it came from Chio.
        let signature = self.signing_key.sign_canonical(&payload)?;

        let response = self.http_client
            .post(self.endpoint.clone())
            .header("X-Chio-Signature", signature.to_hex())
            .json(&payload)
            .send()
            .await?;

        Ok(ChannelHandle {
            channel_ref: response.header("X-Request-Id").to_string(),
            channel: "webhook".to_string(),
            action_url: Some(format!("/approvals/{}", request.id)),
        })
    }

    async fn cancel(&self, handle: &ChannelHandle) -> Result<(), ChannelError> {
        self.http_client
            .delete(format!("{}/cancel/{}", self.endpoint, handle.channel_ref))
            .send()
            .await?;
        Ok(())
    }
}
```

### Channel Configuration

```toml
# chio.toml -- approval channel configuration
[approval.channels.slack]
type = "slack"
webhook_url = "https://hooks.slack.com/services/T.../B.../..."
channel = "#agent-approvals"
mention_group = "@agent-reviewers"

[approval.channels.webhook]
type = "webhook"
endpoint = "https://internal.example.com/chio/approvals"
signing_key_ref = "approval-webhook-signing"

[approval.channels.dashboard]
type = "dashboard"
enabled = true
```

---

## 7. Timeout and Escalation

### Timeout Actions

```rust
/// What happens when no human responds within the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutAction {
    /// Deny the request. Fail-closed. This is the default.
    Deny,
    /// Escalate to the next approver in the chain.
    Escalate,
    /// Auto-approve but flag the receipt as advisory-only.
    /// The receipt records that no human actually reviewed.
    AutoApproveAdvisory,
}
```

### Escalation Chain

```rust
/// An ordered chain of approvers with per-tier deadlines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationChain {
    /// Ordered tiers. Tier 0 is tried first.
    pub tiers: Vec<EscalationTier>,
    /// Final action if all tiers exhaust without response.
    pub terminal_action: TimeoutAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTier {
    /// Approvers at this tier (any one can approve/deny).
    pub approvers: Vec<ApproverIdentity>,
    /// Channels to use for this tier.
    pub channels: Vec<String>,
    /// Seconds to wait at this tier before escalating.
    pub timeout_seconds: u64,
}

/// Identity of a human approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverIdentity {
    /// Approver's public key (for token signature verification).
    pub public_key: PublicKey,
    /// Human-readable label.
    pub display_name: String,
    /// Contact info keyed by channel (e.g., {"slack": "@alice", "email": "alice@co.com"}).
    pub contact: HashMap<String, String>,
}
```

### Escalation Example

```yaml
# Grant-level escalation configuration
escalation:
  tiers:
    - approvers: ["team-lead"]
      channels: ["slack", "dashboard"]
      timeout_seconds: 900      # 15 minutes
    - approvers: ["manager", "security-oncall"]
      channels: ["slack", "email"]
      timeout_seconds: 3600     # 1 hour
  terminal_action: deny         # fail-closed if all tiers exhaust
```

### Timeout Receipt

When a timeout occurs, the kernel signs a receipt recording the timeout:

```rust
Decision::Deny {
    reason: format!(
        "approval request {} timed out after {}s (escalation tier {})",
        request.id, elapsed, tier_index,
    ),
    guard: "approval-timeout",
}
```

If the timeout policy is `AutoApproveAdvisory`, the receipt records:

```rust
Decision::ApprovedAndExecuted {
    approval_token_id: format!("auto-timeout-{}", request.id),
    approver: kernel_key,  // kernel self-signs, not a human
}
// receipt.metadata includes:
// { "auto_approved": true, "reason": "timeout_advisory", "review_required": true }
```

---

## 8. Approval Policies

Approval policies determine which tool calls require human approval. They
are configured per-grant using the existing `Constraint` mechanism plus
new policy types.

### 8.1 Threshold-Based (Existing)

Uses the existing `RequireApprovalAbove` constraint:

```rust
Constraint::RequireApprovalAbove { threshold_units: 500 }
```

Tool calls where `governed_intent.max_amount.units >= 500` require approval.
Calls below the threshold pass through. Calls without a governed intent are
denied (fail-closed -- you cannot skip the threshold check by omitting the
intent).

### 8.2 All Calls (Manual Mode)

Every invocation under this grant requires human approval:

```rust
/// New constraint variant.
Constraint::RequireApprovalAlways
```

Use case: initial deployment of a new agent, compliance environments,
high-risk tool servers.

### 8.3 First-N Trust Building

Approve the first N calls, then switch to autonomous:

```rust
/// New constraint variant.
Constraint::RequireApprovalFirstN { count: u32 }
```

The kernel tracks per-agent, per-grant invocation counts in the receipt
store. After `count` approved calls, subsequent calls skip approval.
The count resets if the grant is revoked and re-issued.

### 8.4 Guard-Triggered Approval

A guard that would normally deny can instead convert to an approval request.
This is configured per-guard:

```toml
[guards.pii-detector]
on_trigger = "require_approval"  # instead of "deny"
approval_summary_template = "Agent wants to access PII field: {field_name}"
```

The guard returns `Verdict::PendingApproval` instead of `Verdict::Deny`
when `on_trigger = "require_approval"` is set.

### 8.5 Action-Type Policies

Approval required for specific categories of tool actions:

```rust
/// New constraint variant.
Constraint::RequireApprovalForActions(Vec<ActionCategory>)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionCategory {
    /// Financial transactions (payments, transfers, trades).
    Financial,
    /// Outbound communications (email, SMS, Slack messages).
    Communication,
    /// Infrastructure changes (deploy, scale, delete).
    Infrastructure,
    /// Data mutations (write, delete, update).
    DataMutation,
    /// Access to sensitive data (PII, credentials, keys).
    SensitiveDataAccess,
    /// Custom category.
    Custom(String),
}
```

### 8.6 Autonomy-Tier Gating

Combine with `GovernedAutonomyTier` -- calls at `Autonomous` tier require
approval, while `Direct` and `Delegated` do not:

```rust
Constraint::RequireApprovalAboveTier(GovernedAutonomyTier::Autonomous)
```

### Policy Composition

Multiple approval constraints on a single grant compose with OR semantics:
if any constraint triggers approval, the call requires approval. This
matches the existing guard composition model (any deny = deny).

```rust
// This grant requires approval for:
// - Any call above $500, OR
// - Any financial action, OR
// - The first 10 calls
constraints: vec![
    Constraint::RequireApprovalAbove { threshold_units: 500 },
    Constraint::RequireApprovalForActions(vec![ActionCategory::Financial]),
    Constraint::RequireApprovalFirstN { count: 10 },
]
```

---

## 9. Batch Approval

Per-call approval creates friction for repetitive operations. Batch approval
lets a human pre-approve a class of calls for a bounded time window.

### Batch Approval Token

```rust
/// A blanket approval covering multiple future tool calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchApprovalToken {
    /// Unique batch approval identifier.
    pub id: String,

    /// The approver who issued this blanket approval.
    pub approver: PublicKey,

    /// The agent this approval applies to.
    pub subject: PublicKey,

    /// Tool server scope (exact or glob).
    pub server_pattern: String,

    /// Tool name scope (exact or glob).
    pub tool_pattern: String,

    /// Maximum amount per individual call (if applicable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_per_call: Option<MonetaryAmount>,

    /// Maximum total amount across all calls in this batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_amount: Option<MonetaryAmount>,

    /// Maximum number of calls this batch covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,

    /// Batch validity window.
    pub not_before: u64,
    pub not_after: u64,

    /// Ed25519 signature over the canonical JSON of all fields above.
    pub signature: Signature,
}
```

### Batch Approval Examples

```
"Approve all search calls for the next hour"
  -> server_pattern: "search-server"
     tool_pattern: "*"
     max_calls: None
     not_after: now + 3600

"Approve up to 20 database reads in the next 30 minutes"
  -> server_pattern: "db-server"
     tool_pattern: "read_*"
     max_calls: Some(20)
     not_after: now + 1800

"Approve payments under $100 for the next 4 hours, max $500 total"
  -> server_pattern: "payment-server"
     tool_pattern: "charge"
     max_amount_per_call: Some(MonetaryAmount { units: 100, currency: "USD" })
     max_total_amount: Some(MonetaryAmount { units: 500, currency: "USD" })
     not_after: now + 14400
```

### Kernel Batch Evaluation

When the kernel encounters a `RequireApprovalAbove` (or similar) constraint,
it checks for a valid batch approval before dispatching to channels:

```
1. Guard returns PendingApproval
2. Kernel checks batch approval store for a matching BatchApprovalToken:
   a. subject matches agent
   b. server_pattern covers server_id
   c. tool_pattern covers tool_name
   d. Current time is within [not_before, not_after)
   e. Amount is within max_amount_per_call (if set)
   f. Running total + this amount <= max_total_amount (if set)
   g. Running count + 1 <= max_calls (if set)
3. If matching batch found:
   a. Increment running count and total
   b. Proceed as Approved (receipt references batch_approval_id)
4. If no matching batch:
   a. Dispatch to approval channels as normal
```

### Batch Approval Receipt

Calls approved via batch carry the batch reference in the receipt metadata:

```json
{
  "decision": {
    "verdict": "approved_and_executed",
    "approval_token_id": "batch-ba-7f3a...",
    "approver": "ed25519:abc123..."
  },
  "metadata": {
    "batch_approval_id": "ba-7f3a...",
    "batch_call_index": 7,
    "batch_remaining_calls": 13,
    "batch_remaining_amount_units": 350
  }
}
```

---

## 10. Async Resume Flow

### HTTP API

The approval lifecycle is exposed via HTTP endpoints on the kernel sidecar:

```
GET  /approvals/pending              List pending approval requests
GET  /approvals/{id}                 Get a specific approval request
POST /approvals/{id}/respond         Submit an approval decision
POST /approvals/batch                Create a batch approval
GET  /approvals/batch/{id}           Get batch approval status
DELETE /approvals/batch/{id}         Revoke a batch approval
```

### Respond Endpoint

```
POST /approvals/{id}/respond
Content-Type: application/json

{
  "decision": "approved",           // or "denied"
  "reason": "Reviewed and approved for one-time charge",
  "conditions": ["amount must not exceed $200"],
  "approver_key": "ed25519:...",
  "signature": "..."
}
```

The kernel:

1. Validates the approval request exists and is still pending (not timed out).
2. Validates the approver is in the allowed approvers list.
3. Validates the signature over the approval token body.
4. If approved:
   a. Re-runs capability validation (grant may have expired during wait).
   b. Re-runs all non-approval guards (state may have changed).
   c. If re-validation passes, dispatches the tool call and signs a receipt.
   d. If re-validation fails, signs a denial receipt (with reason
      "capability expired during approval wait").
5. If denied: signs a denial receipt with the human's reason.
6. Cancels all outstanding channel dispatches for this request.

### SSE Stream for Real-Time Updates

```
GET /approvals/stream
Accept: text/event-stream

event: approval_requested
data: {"id": "ar-123", "summary": "Agent wants to charge $450", ...}

event: approval_resolved
data: {"id": "ar-123", "decision": "approved", "approver": "alice"}
```

---

## 11. Receipt Recording

Every step in the approval lifecycle produces a signed receipt.

### Receipt Chain for an Approved Call

```
Receipt 1: PendingApproval
  decision: { verdict: "pending_approval", approval_request_id: "ar-123", ... }
  timestamp: T0

Receipt 2: ApprovedAndExecuted
  decision: { verdict: "approved_and_executed", approval_token_id: "at-456", ... }
  timestamp: T1
  metadata: {
    "approval_latency_ms": T1 - T0,
    "approver_display_name": "Alice",
    "channel": "slack",
    "review_duration_ms": 45000,
    "previous_receipt_id": "receipt-1-id"
  }
```

### Receipt Chain for a Denied Call

```
Receipt 1: PendingApproval
  decision: { verdict: "pending_approval", approval_request_id: "ar-789", ... }
  timestamp: T0

Receipt 2: HumanDenied
  decision: { verdict: "human_denied", approval_token_id: "at-012", ... }
  timestamp: T1
  metadata: {
    "reason": "This agent should not access production database",
    "approver_display_name": "Bob",
    "channel": "dashboard"
  }
```

### Receipt Chain for a Timeout

```
Receipt 1: PendingApproval
  decision: { verdict: "pending_approval", ... }
  timestamp: T0

Receipt 2: Deny
  decision: { verdict: "deny", reason: "approval timed out after 3600s", guard: "approval-timeout" }
  timestamp: T0 + 3600
```

### Audit Queries

```bash
# Local `receipt list` requires --tenant <id> or --admin-all; the
# additional --decision / --meta / human-readable --since filters below
# are illustrative and tracked in a follow-up CLI surface item.

# All approval requests in the last 24 hours
chio receipt list --tenant <tenant-id> --decision pending_approval --since 24h

# All human-denied calls
chio receipt list --tenant <tenant-id> --decision human_denied

# Average approval latency by approver
chio receipt stats --tenant <tenant-id> --decision approved_and_executed --group-by metadata.approver_display_name

# Calls auto-approved due to timeout
chio receipt list --tenant <tenant-id> --decision approved_and_executed --meta auto_approved=true
```

---

## 12. Framework Integration

### 12.1 LangGraph

LangGraph's `interrupt()` maps directly to `Verdict::PendingApproval`:

```python
from langgraph.types import interrupt
from chio_langgraph import ChioNodeContext

async def tool_node(state, config):
    chio_ctx = ChioNodeContext.from_config(config)
    result = await chio_ctx.call_tool("charge", {"amount": 450})

    if result.verdict == "pending_approval":
        # LangGraph interrupt() suspends the graph.
        # The approval request is stored in graph state.
        approval = interrupt({
            "type": "chio_approval",
            "approval_request": result.approval_request,
            "action_url": result.approval_request.action_url,
        })

        if approval["decision"] == "denied":
            return {"error": "Human denied the charge"}

        # Graph resumes here after human approves.
        # Re-submit with the approval token.
        result = await chio_ctx.call_tool(
            "charge",
            {"amount": 450},
            approval_token=approval["token"],
        )

    return {"result": result.output}
```

The `chio_langgraph` SDK handles this automatically in `chio_approval_node`:

```python
@chio_approval_node(
    scope="tools:payment",
    approval_config={
        "approvers": ["finance-lead"],
        "timeout_seconds": 3600,
        "timeout_action": "deny",
    },
)
async def charge_customer(state, config):
    # If we reach here, approval was granted (or not required).
    return await execute_charge(state["amount"])
```

### 12.2 Temporal

Temporal's Signal mechanism delivers the approval token to a waiting workflow:

```python
@workflow.defn
class AgentWorkflow:

    def __init__(self):
        self._pending_approval: Optional[ApprovalRequest] = None
        self._approval_token: Optional[GovernedApprovalToken] = None

    @workflow.signal
    async def approval_received(self, token: GovernedApprovalToken):
        self._approval_token = token

    @workflow.run
    async def run(self, task):
        result = await workflow.execute_activity(
            call_tool_activity,
            args=[task],
            start_to_close_timeout=timedelta(hours=2),
        )

        if result.verdict == "pending_approval":
            self._pending_approval = result.approval_request

            # Wait for signal or timeout
            try:
                await workflow.wait_condition(
                    lambda: self._approval_token is not None,
                    timeout=timedelta(seconds=result.approval_request.deadline - time.time()),
                )
            except asyncio.TimeoutError:
                return {"error": "Approval timed out"}

            # Re-execute with approval token
            result = await workflow.execute_activity(
                call_tool_with_approval_activity,
                args=[task, self._approval_token],
                start_to_close_timeout=timedelta(minutes=5),
            )

        return result
```

### 12.3 Prefect

Prefect's `pause_flow_run` maps to the approval wait:

```python
from prefect import flow, task, pause_flow_run

@task
async def call_tool_with_approval(tool_name, args, chio_client):
    result = await chio_client.call_tool(tool_name, args)

    if result.verdict == "pending_approval":
        # Prefect suspends the flow run and waits for manual resume.
        # The approval request ID is stored in flow run state.
        approval = await pause_flow_run(
            wait_for_input=ApprovalInput,
            timeout=result.approval_request.deadline - time.time(),
            key=f"chio-approval-{result.approval_request.id}",
        )

        if approval.decision == "denied":
            raise ToolDeniedError("Human denied the request")

        # Resume with approval token
        result = await chio_client.call_tool(
            tool_name, args,
            approval_token=approval.token,
        )

    return result
```

### Framework Mapping Summary

| Framework | Pause Mechanism | Resume Mechanism | State Storage |
|-----------|----------------|-----------------|---------------|
| LangGraph | `interrupt()` | Graph replay with `Command(resume=...)` | LangGraph checkpoint |
| Temporal | `workflow.wait_condition()` | `workflow.signal()` | Temporal history |
| Prefect | `pause_flow_run()` | Manual resume via API/UI | Prefect state |
| Custom HTTP | Return 202 Accepted | Poll or SSE + POST `/respond` | Kernel approval store |

---

## 13. Approval Guard Implementation

### Built-in `ApprovalGuard`

The kernel ships a built-in guard that evaluates approval constraints:

```rust
pub struct ApprovalGuard {
    approval_store: Chio<dyn ApprovalStore>,
    batch_store: Chio<dyn BatchApprovalStore>,
    channels: Vec<Chio<dyn ApprovalChannel>>,
    escalation_config: Option<EscalationChain>,
}

impl Guard for ApprovalGuard {
    fn name(&self) -> &str { "approval" }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let grant = ctx.matched_grant();

        // Check each constraint on the grant.
        for constraint in &grant.constraints {
            match constraint {
                Constraint::RequireApprovalAbove { threshold_units } => {
                    if let Some(intent) = &ctx.request.governed_intent {
                        if let Some(amount) = &intent.max_amount {
                            if amount.units >= *threshold_units {
                                // Check for existing approval token on the request.
                                if let Some(token) = &ctx.request.approval_token {
                                    return self.validate_approval_token(ctx, token);
                                }
                                // Check for matching batch approval.
                                if self.check_batch_approval(ctx)? {
                                    return Ok(Verdict::Allow);
                                }
                                // No token, no batch -- require approval.
                                return Ok(Verdict::PendingApproval(
                                    self.build_approval_request(ctx, "threshold")?
                                ));
                            }
                        } else {
                            // No amount on intent but threshold constraint exists.
                            // Fail-closed: require approval.
                            return Ok(Verdict::PendingApproval(
                                self.build_approval_request(ctx, "threshold_no_amount")?
                            ));
                        }
                    } else {
                        // No governed intent but threshold constraint exists.
                        // Fail-closed: deny (not pending -- cannot approve
                        // without an intent to bind to).
                        return Err(KernelError::GuardDenied(
                            "RequireApprovalAbove requires a governed intent".to_string()
                        ));
                    }
                }
                Constraint::RequireApprovalAlways => {
                    if let Some(token) = &ctx.request.approval_token {
                        return self.validate_approval_token(ctx, token);
                    }
                    if self.check_batch_approval(ctx)? {
                        return Ok(Verdict::Allow);
                    }
                    return Ok(Verdict::PendingApproval(
                        self.build_approval_request(ctx, "always")?
                    ));
                }
                Constraint::RequireApprovalFirstN { count } => {
                    let invocation_count = self.approval_store
                        .count_approved_calls(
                            &ctx.agent_id,
                            &grant.id,
                        )?;
                    if invocation_count < *count as u64 {
                        if let Some(token) = &ctx.request.approval_token {
                            return self.validate_approval_token(ctx, token);
                        }
                        if self.check_batch_approval(ctx)? {
                            return Ok(Verdict::Allow);
                        }
                        return Ok(Verdict::PendingApproval(
                            self.build_approval_request(ctx, "first_n")?
                        ));
                    }
                    // Past the count threshold -- no approval needed.
                }
                _ => { /* not an approval constraint, skip */ }
            }
        }

        Ok(Verdict::Allow)
    }
}
```

### Approval Store Trait

```rust
/// Persistent store for pending and resolved approval requests.
#[async_trait]
pub trait ApprovalStore: Send + Sync {
    /// Store a new pending approval request.
    async fn store_pending(&self, request: &ApprovalRequest) -> Result<(), StoreError>;

    /// Retrieve a pending approval request by ID.
    async fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, StoreError>;

    /// List all pending approval requests, optionally filtered.
    async fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, StoreError>;

    /// Mark a request as resolved (approved, denied, or timed out).
    async fn resolve(
        &self,
        id: &str,
        token: &GovernedApprovalToken,
    ) -> Result<(), StoreError>;

    /// Count the number of approved calls for a given agent and grant.
    /// Used by RequireApprovalFirstN.
    async fn count_approved_calls(
        &self,
        agent_id: &AgentId,
        grant_id: &str,
    ) -> Result<u64, StoreError>;
}

/// Persistent store for batch approvals.
#[async_trait]
pub trait BatchApprovalStore: Send + Sync {
    /// Store a new batch approval.
    async fn store(&self, batch: &BatchApprovalToken) -> Result<(), StoreError>;

    /// Find a batch approval matching the given context.
    async fn find_matching(
        &self,
        agent_id: &AgentId,
        server_id: &str,
        tool_name: &str,
        amount: Option<&MonetaryAmount>,
        now: u64,
    ) -> Result<Option<BatchApprovalToken>, StoreError>;

    /// Increment usage counters for a batch approval.
    async fn record_usage(
        &self,
        batch_id: &str,
        amount: Option<&MonetaryAmount>,
    ) -> Result<(), StoreError>;

    /// Revoke a batch approval.
    async fn revoke(&self, batch_id: &str) -> Result<(), StoreError>;
}
```

---

## 14. End-to-End Example: Payment Agent

A customer support agent needs to issue a refund of $450. The grant has
`RequireApprovalAbove { threshold_units: 200 }`.

### Step 1: Agent Calls Tool

```json
{
  "request_id": "req-f7a3",
  "tool_name": "issue_refund",
  "server_id": "payment-server",
  "arguments": { "customer_id": "cust-9012", "amount": 450, "currency": "USD" },
  "governed_intent": {
    "id": "intent-b2c1",
    "server_id": "payment-server",
    "tool_name": "issue_refund",
    "purpose": "Customer requested refund for order #8834",
    "max_amount": { "units": 450, "currency": "USD" }
  }
}
```

### Step 2: Kernel Evaluates

1. Capability validation passes (agent has grant for `payment-server:issue_refund`).
2. ApprovalGuard evaluates `RequireApprovalAbove { threshold_units: 200 }`.
3. `governed_intent.max_amount.units` (450) >= 200 -- approval required.
4. No `approval_token` on the request. No matching batch.
5. Guard returns `Verdict::PendingApproval(approval_request)`.

### Step 3: Kernel Dispatches Approval Request

```json
{
  "id": "ar-d4e5",
  "request_id": "req-f7a3",
  "intent_hash": "sha256:8a7b3c...",
  "summary": "Agent wants to issue a $450 refund to customer cust-9012 for order #8834",
  "triggered_by": ["approval:threshold"],
  "agent_id": "agent-support-01",
  "tool_name": "issue_refund",
  "server_id": "payment-server",
  "deadline": 1713200400,
  "timeout_action": "deny"
}
```

Dispatched to Slack channel `#refund-approvals` with approve/deny buttons.

### Step 4: Kernel Signs PendingApproval Receipt

```json
{
  "id": "rc-001",
  "decision": {
    "verdict": "pending_approval",
    "approval_request_id": "ar-d4e5",
    "summary": "Agent wants to issue a $450 refund",
    "deadline": 1713200400
  },
  "tool_name": "issue_refund",
  "tool_server": "payment-server",
  "signature": "..."
}
```

### Step 5: Human Approves via Slack

Finance lead clicks "Approve" in Slack. The Slack channel implementation
calls `POST /approvals/ar-d4e5/respond` with a signed approval token.

### Step 6: Kernel Resumes

1. Validates the approval token signature.
2. Validates `governed_intent_hash` matches the original intent.
3. Validates `request_id` matches the original request.
4. Validates the approver is in the allowed list.
5. Validates the token has not expired.
6. Re-validates the capability (grant still active, not expired, not revoked).
7. Re-runs non-approval guards (state may have changed).
8. All checks pass -- dispatches the tool call to `payment-server`.

### Step 7: Kernel Signs Approved Receipt

```json
{
  "id": "rc-002",
  "decision": {
    "verdict": "approved_and_executed",
    "approval_token_id": "at-g6h7",
    "approver": "ed25519:finance-lead-key..."
  },
  "tool_name": "issue_refund",
  "tool_server": "payment-server",
  "metadata": {
    "approval_latency_ms": 127000,
    "approver_display_name": "Finance Lead",
    "channel": "slack",
    "previous_receipt_id": "rc-001"
  },
  "signature": "..."
}
```

---

## 15. Security Properties

### Fail-Closed at Every Step

| Failure mode | Behavior |
|-------------|----------|
| Guard evaluation error | Deny (existing behavior) |
| Approval channel dispatch fails | Request still stored; human can poll via API |
| Approval token signature invalid | Deny |
| Approval token expired | Deny |
| Approval token for wrong request | Deny |
| Capability revoked during wait | Deny on resume (re-validation) |
| Grant expired during wait | Deny on resume |
| Timeout with no response | Deny (default) |
| Kernel restart during wait | Pending requests survive in approval store |

### Replay Protection (Implemented)

Approval tokens are single-use. The kernel enforces this through four
mechanisms working together:

1. **Request binding** -- token is bound to a specific `request_id` and
   `governed_intent_hash`. Cannot replay for a different request or intent.
2. **Time window** -- `issued_at` to `expires_at`. Cannot use after expiry.
3. **Lifetime cap** -- the kernel rejects approval tokens with a lifetime
   exceeding `MAX_APPROVAL_TTL_SECS` (1 hour). This prevents long-lived
   tokens from outliving the replay store.
4. **Single-use consumption store** -- an LRU replay store
   (`approval_replay_store` on `ChioKernel`) records consumed
   `(request_id, intent_hash)` pairs. A token presented a second time is
   rejected with "replay detected". The store's TTL equals
   `MAX_APPROVAL_TTL_SECS`, which is always >= any valid token's lifetime
   (enforced by the lifetime cap). This guarantees a token expires before
   it can be evicted from the store, closing the cache-eviction replay
   window.

Implementation: `crates/chio-kernel/src/kernel/mod.rs`, steps 7-8 of
`validate_governed_approval_token()`.

### Separation of Concerns

- **Agent** never sees or touches the approval token. The kernel manages the
  entire approval lifecycle.
- **Approver** only sees the summary and intent, not raw tool arguments
  (unless policy exposes them).
- **Tool server** receives the call only after the kernel has validated the
  approval token. The tool server does not need to know about HITL.

### Non-Repudiation

Every approval decision is signed with the approver's Ed25519 key and
recorded in the receipt chain. The approver cannot deny having approved
a call. The receipt proves:
- Who approved (public key)
- What they approved (intent hash)
- When they approved (timestamp)
- Through which channel (metadata)

---

## 16. Configuration Reference

### Grant-Level Configuration

```toml
[[grants]]
server = "payment-server"
tool = "issue_refund"
operations = ["invoke"]

[grants.constraints]
require_approval_above = { threshold_units = 200 }
governed_intent_required = true

[grants.approval]
timeout_seconds = 3600
timeout_action = "deny"  # "deny" | "escalate" | "auto_approve_advisory"

[[grants.approval.approvers]]
public_key = "ed25519:abc..."
display_name = "Finance Lead"
contact = { slack = "@finance-lead", email = "finance@example.com" }

[[grants.approval.approvers]]
public_key = "ed25519:def..."
display_name = "CFO"
contact = { slack = "@cfo", email = "cfo@example.com" }

[grants.approval.escalation]
terminal_action = "deny"

[[grants.approval.escalation.tiers]]
approvers = ["Finance Lead"]
channels = ["slack", "dashboard"]
timeout_seconds = 900

[[grants.approval.escalation.tiers]]
approvers = ["CFO"]
channels = ["slack", "email"]
timeout_seconds = 3600
```

---

## 17. Migration Path

### Phase 1: Kernel Verdict Extension

1. Add `PendingApproval` variant to `Verdict` in `chio-kernel::runtime`.
2. Add `PendingApproval`, `ApprovedAndExecuted`, `HumanDenied` variants
   to `Decision` in `chio-core-types::receipt`.
3. Update kernel evaluation loop for ternary verdicts.
4. Add `ApprovalStore` and `BatchApprovalStore` traits.
5. Add SQLite implementation in `chio-store-sqlite`.

### Phase 2: Approval Guard and HTTP API

1. Implement `ApprovalGuard` with support for all constraint variants.
2. Add `/approvals/*` HTTP endpoints to the sidecar.
3. Implement `WebhookChannel` and `ApiPollChannel`.
4. Add approval-related receipt queries.

### Phase 3: Channel Ecosystem

1. Implement `SlackChannel` with Block Kit interactive messages.
2. Implement `DashboardChannel` with WebSocket push.
3. Implement `EmailChannel` with signed action links.
4. Add batch approval support.

### Phase 4: Framework Integration

1. Update `chio-langgraph` with `chio_approval_node` wrapper.
2. Update `chio-temporal` with Signal-based approval flow.
3. Update `chio-prefect` with `pause_flow_run` integration.
4. Publish SDK updates with approval-aware `call_tool` methods.

---

## 18. Open Questions

1. **Multi-approver quorum.** Should Chio support "2 of 3 must approve"
   policies? The current design is single-approver. Quorum adds complexity
   but is required for high-value operations in regulated environments.

2. **Approval delegation.** Can an approver delegate their approval
   authority to another person for a time window (vacation coverage)?
   This could reuse the existing `DelegationLink` mechanism.

3. **Partial approval.** Can a human approve a modified version of the
   request (e.g., "approved for $300 instead of $450")? This would require
   the approval token to carry amended parameters and the kernel to
   re-bind the intent.

4. **Cross-kernel approval.** In federated Chio deployments, can an approval
   from kernel A satisfy a pending request on kernel B? This requires
   cross-kernel trust roots.

5. **Approval analytics.** Should the kernel track approval SLAs (time to
   respond, approval rates by approver, most-approved tools) as first-class
   metrics? The receipt store has the data; the question is whether to
   build dedicated query surfaces.
