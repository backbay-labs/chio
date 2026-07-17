# Chio Agent Economy: Technical Design

Scope: economic substrate design; implemented economic primitives are part of the current v1 pre-release profile.
Authors: Engineering

> Historical internal milestone note. Any `v2.x` labels below are pre-release
> implementation milestones, not Chio-owned protocol, schema, SDK, or runtime
> versions. Current protocol posture is v1-only.

---

## 1. Overview

Chio's existing architecture -- capability tokens, delegation chains, invocation budgets, and signed receipts -- is a programmable spending authorization system. The protocol already enforces who can do what, how many times, with cryptographic proof of every decision. This document describes how to extend that architecture into a full economic substrate for the agent economy.

Three observations anchor the design:

1. **The capability token is a spending authorization.** A `CapabilityToken` already binds an issuer, a subject, a scope of permitted actions, and a time window. Adding a monetary dimension to `ToolGrant` turns it into a pre-authorized spending limit.

2. **The delegation chain is a cost-responsibility chain.** Each `DelegationLink` records who delegated what to whom, with `Attenuation` narrowing scope at each hop. Budget attenuation through delegation creates a tree of cost responsibility rooted at the original authorizer.

3. **The receipt log is a billing ledger.** Every `ChioReceipt` is a kernel-signed record of a decision; tamper-evidence holds for any backend that preserves the signed canonical bytes, and the bundled `SqliteReceiptStore` additionally enforces append-only semantics through `BEFORE UPDATE` / `BEFORE DELETE` triggers. The existing `metadata: Option<serde_json::Value>` field is the natural insertion point for structured financial data. Receipts are already persisted in `SqliteReceiptStore` with indexed queries by capability, tool, and timestamp.

The strategy is not to bolt a payment system onto Chio. It is to recognize that Chio is already 80% of a payment authorization system and close the remaining gaps with minimal, backward-compatible extensions.

The current pre-release v1 payment-facing overlay is explicit and bounded:
Chio can now project governed settlement into x402 requirements, prepare
EIP-3009 authorization digests, evaluate Circle-managed-custody nanopayments,
and assess ERC-4337/paymaster compatibility. Those surfaces remain
interoperability adapters over canonical Chio approval, receipt, and settlement
truth; they do not become a second ledger.

---

## 2. Current Architecture (What Exists)

### 2.1 Invocation-Count Budgets

`ToolGrant` in `crates/core/chio-core` carries an optional invocation cap:

```rust
pub struct ToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<Operation>,
    pub constraints: Vec<Constraint>,
    pub max_invocations: Option<u32>,
}
```

The kernel enforces this via `BudgetStore::try_increment` in `crates/kernel/chio-kernel/src/budget_store.rs`. Each budget record is keyed by `(capability_id, grant_index)`:

```rust
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,
}
```

### 2.2 BudgetStore Trait

The `BudgetStore` trait (`crates/kernel/chio-kernel/src/budget_store.rs`) now covers
both invocation-count and monetary accounting:

```rust
pub trait BudgetStore: Send {
    fn try_increment(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError>;

    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError>;

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;
}
```

Two implementations exist: `InMemoryBudgetStore` (HashMap-backed, for testing) and `SqliteBudgetStore` (WAL-mode SQLite with `PRAGMA synchronous = FULL`).

### 2.3 HA Replication

`SqliteBudgetStore` supports cross-node replication via a monotonic `seq` column and a `budget_replication_meta` table tracking `next_seq`. The `upsert_usage` method applies remote deltas with last-writer-wins conflict resolution:

```sql
ON CONFLICT(capability_id, grant_index) DO UPDATE SET
    invocation_count = CASE
        WHEN excluded.seq > capability_grant_budgets.seq
            THEN excluded.invocation_count
        ELSE MAX(capability_grant_budgets.invocation_count, excluded.invocation_count)
    END
```

Delta queries via `list_usages_after(limit, after_seq)` enable efficient replication polling.

### 2.4 Budget Enforcement in the Kernel

`ChioKernel::check_and_increment_budget` in `crates/kernel/chio-kernel/src/lib.rs` iterates matching grants that arrive pre-sorted by specificity from `resolve_matching_grants` upstream. If all matching grants with `max_invocations` are exhausted, the method returns `KernelError::BudgetExhausted`. The calling code then passes the error message (e.g. "invocation budget exhausted for capability ...") to `build_deny_response`, which produces a signed `Decision::Deny` receipt with guard `"kernel"` and the budget-exhaustion error as the reason string.

### 2.5 Delegation Attenuation

`Attenuation::ReduceBudget` in `crates/core/chio-core` already supports narrowing invocation counts during delegation:

```rust
pub enum Attenuation {
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    // ...
}
```

`ToolGrant::is_subset_of` enforces that a child grant's `max_invocations` never exceeds the parent's.

### 2.6 Receipt Metadata

`ChioReceipt` and `ChioReceiptBody` in `crates/core/chio-core` carry:

```rust
pub metadata: Option<serde_json::Value>,
```

This field is signed as part of the receipt body and is available for structured financial data without schema changes to the receipt envelope.

### 2.7 Analytics Substrate (Internal Milestone)

The local analytics join gap described by that internal milestone:

1. The receipt store persists a capability lineage index keyed by
   `capability_id`, so receipts can be joined to issuer, subject, grants, and
   delegation metadata without replaying issuance logs.
2. Receipts carry deterministic attribution metadata under
   `metadata.attribution`, including `subject_key`, `issuer_key`,
   `delegation_depth`, and `grant_index` when a specific grant matched.
3. The SQLite receipt store indexes `subject_key`, `issuer_key`, and
   `grant_index` for efficient agent-scoped and per-grant analytics queries.

This means billing dashboards, reputation scoring, and receipt analytics can
rely on persisted local state rather than ad hoc inference.

---

## 3. Economic Extensions (What to Build)

### 3.1 Monetary Budget Type

**Goal:** Extend `ToolGrant` so that in addition to invocation-count limits, a grant can carry a monetary spending cap.

#### 3.1.1 New Types in `chio-core`

Add to `crates/core/chio-core`:

```rust
/// A monetary amount with currency denomination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryAmount {
    /// Amount in the currency's smallest unit (e.g. cents for USD,
    /// wei for ETH). Using u64 avoids floating-point precision issues.
    pub units: u64,
    /// ISO 4217 currency code or chain-specific token identifier.
    /// Examples: "USD", "EUR", "USDC", "ETH".
    pub currency: String,
}
```

Extend `ToolGrant`:

```rust
pub struct ToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<Operation>,
    pub constraints: Vec<Constraint>,
    pub max_invocations: Option<u32>,

    // --- New fields (all optional, backward-compatible via serde defaults) ---

    /// Maximum cost per single invocation. The kernel rejects tool server
    /// responses that report a cost exceeding this cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,

    /// Maximum aggregate cost across all invocations under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
}
```

Current v1 does not define a second token negotiation path. New Chio-owned fields
must either be part of the v1 schema before public release or be rejected
fail-closed by v1 consumers until a future public evolution decision exists.

#### 3.1.2 Attenuation for Cost Budgets

Add a new `Attenuation` variant in `crates/core/chio-core`:

```rust
pub enum Attenuation {
    // ... existing variants ...

    /// The per-invocation cost cap was tightened.
    ReduceCostPerInvocation {
        server_id: String,
        tool_name: String,
        max_cost_per_invocation: MonetaryAmount,
    },

    /// The total cost budget was reduced.
    ReduceTotalCost {
        server_id: String,
        tool_name: String,
        max_total_cost: MonetaryAmount,
    },
}
```

`ToolGrant::is_subset_of` must be extended: if the parent has `max_total_cost`, the child must also have one with `units <= parent.units` in the same currency. Same logic for `max_cost_per_invocation`.

#### 3.1.3 Budget Store Extensions

Extend `BudgetUsageRecord` in `crates/kernel/chio-kernel/src/budget_store.rs`:

```rust
pub struct BudgetUsageRecord {
    pub capability_id: String,
    pub grant_index: u32,
    pub invocation_count: u32,
    pub updated_at: i64,
    pub seq: u64,

    // --- New fields ---

    /// Cumulative cost charged against this grant, in the grant's currency
    /// smallest units.
    pub cost_units_charged: u64,
}
```

Add a new method to `BudgetStore`:

```rust
pub trait BudgetStore: Send {
    fn try_increment(/* ... existing ... */) -> Result<bool, BudgetStoreError>;

    /// Attempt to charge a monetary cost against a grant's budget.
    /// Returns Ok(true) if the charge was accepted, Ok(false) if the
    /// budget would be exceeded. The invocation count is also incremented.
    fn try_charge_cost(
        &mut self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError>;

    fn list_usages(/* ... existing ... */) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError>;
}
```

SQLite schema change for `capability_grant_budgets`:

```sql
ALTER TABLE capability_grant_budgets
    ADD COLUMN cost_units_charged INTEGER NOT NULL DEFAULT 0;
```

The `SqliteBudgetStore::try_charge_cost` implementation mirrors `try_increment` but additionally checks `cost_units_charged + cost_units <= max_total_cost_units` within the same IMMEDIATE transaction.

Replication: the existing seq-based delta protocol extends naturally. `upsert_usage` conflict resolution uses the same seq-wins strategy for `cost_units_charged`:

```sql
cost_units_charged = CASE
    WHEN excluded.seq > capability_grant_budgets.seq
        THEN excluded.cost_units_charged
    ELSE MAX(capability_grant_budgets.cost_units_charged, excluded.cost_units_charged)
END
```

### 3.2 Cost Reporting

#### 3.2.1 Tool Server Cost Response

Tool servers must be able to report the actual cost of an invocation. Extend the `ToolServerConnection` trait in `crates/kernel/chio-kernel/src/lib.rs`:

```rust
/// Cost reported by a tool server after invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationCost {
    /// Cost in the currency's smallest units.
    pub units: u64,
    /// Currency code (must match the grant's currency).
    pub currency: String,
    /// Tool-server-provided cost breakdown (opaque to the kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<serde_json::Value>,
}
```

The existing `invoke` method on `ToolServerConnection` returns `Result<serde_json::Value, KernelError>`. Rather than change its signature (which would break all existing implementations), introduce a parallel method:

```rust
pub trait ToolServerConnection: Send + Sync {
    // ... existing methods ...

    /// Invoke a tool and return the result along with an optional cost report.
    /// Default implementation delegates to `invoke` with no cost.
    fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, nested_flow_bridge)?;
        Ok((value, None))
    }
}
```

#### 3.2.2 Kernel Cost Verification

The kernel must preserve a simple invariant: **receipts describe what actually
happened**. A tool call that executed successfully may not be rewritten into a
deny just because payment capture failed afterward.

After receiving a cost report, the kernel in `evaluate_tool_call_with_session_roots`:

1. Verifies currency matches the grant's `max_cost_per_invocation.currency`.
2. Rejects the response if `cost.units > grant.max_cost_per_invocation.units`.
3. Finalizes the budget charge against the actual cost.
4. If settlement uses a pre-authorized hold, captures only the actual cost.
5. If post-execution settlement cannot be completed synchronously, records
   `pending` or `failed` settlement state in receipt metadata and emits a
   reconciliation task. The tool outcome remains `Decision::Allow`.

If the tool server does not report cost (returns `None`) and the grant has a `max_total_cost`, the kernel charges `max_cost_per_invocation.units` as the assumed worst-case cost. This is fail-closed: unlabeled invocations debit the maximum.

### 3.3 Spending Delegation

#### 3.3.1 Parent-Child Budget Suballocation

When an agent delegates a capability with `max_total_cost`, the child's budget is carved out of the parent's remaining balance. This requires the kernel to:

1. Read the parent grant's `cost_units_charged` from the budget store.
2. Verify the child's `max_total_cost.units <= parent.max_total_cost.units - parent.cost_units_charged`.
3. Pre-reserve the child's budget by charging the parent's budget store immediately.

If the child underspends, the parent can reclaim unused budget only after the child capability expires or is revoked. This avoids double-spending during the child's lifetime.

#### 3.3.2 Delegation Chain Cost Attribution

The `DelegationLink` already carries `delegator` and `delegatee` public keys and a timestamp. Cost attribution follows the chain: the root budget holder (the first issuer with no inbound delegation) is the ultimate payer. Each intermediate delegator is a cost center.

For reconciliation, the receipt log (section 3.5) records the delegation depth and root budget holder, enabling per-level cost aggregation.

### 3.4 Governed Approval Controls

#### 3.4.1 New Constraint Variants

Add to `Constraint` in `crates/core/chio-core`:

```rust
pub enum Constraint {
    // ... existing variants ...

    /// The request must include a governed transaction intent artifact.
    GovernedIntentRequired,

    /// Invocations exceeding this cost threshold require out-of-band approval
    /// before the kernel forwards to the tool server.
    RequireApprovalAbove {
        /// Threshold in currency smallest units.
        threshold_units: u64,
    },
}
```

These two variants are now shipped in `chio-core`. Rolling-window spend and
velocity controls remain planned follow-ons, but the first production governed
flow is intentionally narrower: bind a canonical intent to the request, then
require a signed approval artifact when the spend threshold is met.

#### 3.4.2 Kernel Enforcement Path

`ChioKernel` now enforces governed transactions in a dedicated validation step
after provisional monetary charging and before guard or tool dispatch. The
runtime checks:

- the matched grant's governed constraints
- that `governed_intent.server_id` and `tool_name` match the request target
- that `governed_intent.max_amount`, when present, covers the provisional
  charged amount in the same currency
- that `approval_token`, when required, is valid for the request id, subject,
  time window, and canonical intent hash

If any governed check fails, the kernel unwinds the provisional budget charge
and emits a signed deny receipt. This keeps governed enforcement inside the
same trust boundary as capability validation and receipt signing.

#### 3.4.3 Human-in-the-Loop Approval

The shipped approval contract uses two first-class signed artifacts:

```rust
pub struct GovernedTransactionIntent {
    pub id: String,
    pub server_id: String,
    pub tool_name: String,
    pub purpose: String,
    pub max_amount: Option<MonetaryAmount>,
    pub context: Option<serde_json::Value>,
}

pub struct GovernedApprovalToken {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
    pub signature: Signature,
}
```

The orchestrating system can present the governed intent to a human or policy
service, obtain a signed approval token, and retry with both artifacts
attached. The kernel stays stateless with respect to workflow orchestration:
it only verifies the signed inputs already present on the request.

### 3.5 Receipt Financial Instrumentation

#### 3.5.1 Structured Financial Metadata

Define a structured schema for the receipt `metadata` field. This does not change the `ChioReceipt` type -- it specifies what goes into the existing `Option<serde_json::Value>`:

```rust
/// Financial metadata populated in ChioReceipt.metadata when a grant
/// carries monetary budget fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialReceiptMetadata {
    /// Which grant matched this invocation inside the capability scope.
    pub grant_index: u32,
    /// Cost charged for this invocation, in currency smallest units.
    pub cost_charged: u64,
    /// Currency code.
    pub currency: String,
    /// Budget remaining after this invocation.
    pub budget_remaining: u64,
    /// Total budget for this grant.
    pub budget_total: u64,
    /// Delegation depth (0 = root capability, 1 = first delegate, etc.).
    pub delegation_depth: u32,
    /// Public key (hex) of the root budget holder.
    pub root_budget_holder: String,
    /// Payment or authorization reference on the external rail, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    /// Canonical receipt-side settlement state.
    pub settlement_status: SettlementStatus,
    /// Optional cost breakdown from the tool server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
}
```

This struct is serialized into `receipt.metadata` as a nested object under the key `"financial"`:

```json
{
  "financial": {
    "grant_index": 0,
    "cost_charged": 1500,
    "currency": "USD",
    "budget_remaining": 8500,
    "budget_total": 10000,
    "delegation_depth": 1,
    "root_budget_holder": "a1b2c3...",
    "payment_reference": "pi_123",
    "settlement_status": "settled"
  }
}
```

The kernel populates this after the budget charge is accepted and the payment
rail reaches a canonical local state. The receipt contract is intentionally
smaller than any given payment rail's internal state machine:

- `not_applicable` for pre-execution denials where no settlement applies
- `pending` for initiated but not yet final settlement
- `settled` for a final recorded charge
- `failed` when execution completed but settlement became invalid

Denied invocations may still include structured financial metadata when denial
occurred before execution due to budget exhaustion or payment pre-authorization
failure.

#### 3.5.2 Governed Receipt Metadata

Governed invocations now add a separate `governed_transaction` block to receipt
metadata rather than overloading the `financial` section:

```json
{
  "governed_transaction": {
    "intent_id": "intent-123",
    "intent_hash": "3d7d...",
    "purpose": "approve vendor payout",
    "server_id": "payments",
    "tool_name": "submit_wire",
    "max_amount": {
      "units": 4200,
      "currency": "USD"
    },
    "approval": {
      "token_id": "approval-123",
      "approver_key": "ab12cd...",
      "approved": true
    }
  }
}
```

This block is present on allow receipts and on governed denials where an
intent was attached. Trust-control receipt queries return this metadata
unchanged, so operators can inspect both the spend record and the approval
evidence in one receipt document.

#### 3.5.3 Receipt Store Indexing

Add columns to `chio_tool_receipts` in `crates/kernel/chio-kernel/src/receipt_store.rs`:

```sql
ALTER TABLE chio_tool_receipts
    ADD COLUMN cost_charged INTEGER;
ALTER TABLE chio_tool_receipts
    ADD COLUMN cost_currency TEXT;

CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_cost
    ON chio_tool_receipts(cost_currency, cost_charged);
```

The `SqliteReceiptStore::append_chio_receipt` method extracts `financial.cost_charged` and `financial.currency` from the receipt metadata at insert time. This enables efficient billing queries without full-JSON scanning.

### 3.6 Payment Rail Integration

#### 3.6.1 PaymentAdapter Trait

Add a new module `crates/kernel/chio-kernel/src/payment.rs`:

```rust
/// Result of a payment authorization or settlement action.
#[derive(Debug, Clone)]
pub struct PaymentAuthorization {
    /// Payment rail's authorization or hold identifier.
    pub authorization_id: String,
    /// Whether the rail already considers the funds settled.
    pub settled: bool,
    /// Rail-specific metadata (idempotency keys, quote IDs, expiry, etc.).
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PaymentResult {
    /// Payment rail's transaction identifier, if a capture or settlement occurred.
    pub transaction_id: String,
    /// Richer payment-rail settlement state, mapped onto the receipt-side
    /// canonical enum when the kernel signs the receipt.
    pub settlement_status: RailSettlementStatus,
    /// Rail-specific metadata (idempotency keys, network confirmations, etc.).
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailSettlementStatus {
    Authorized,
    Captured,
    Settled,
    Pending,
    Failed,
    Released,
    Refunded,
}

/// Trait for executing payments against an external rail.
///
/// Chio authorizes. The payment rail executes. Separation of concerns:
/// the kernel never holds funds or manages wallets.
pub trait PaymentAdapter: Send + Sync {
    /// Authorize or prepay up to the requested amount before the tool executes.
    ///
    /// For prepaid rails (for example x402), this may fully settle the amount
    /// and return `settled = true`. For card-style rails, this creates a hold.
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError>;

    /// Finalize payment for the actual cost after tool execution.
    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Release an unused authorization hold.
    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;

    /// Refund a previously executed payment.
    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError>;
}

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("payment declined: {0}")]
    Declined(String),

    #[error("insufficient funds")]
    InsufficientFunds,

    #[error("payment rail unavailable: {0}")]
    Unavailable(String),

    #[error("payment rail error: {0}")]
    RailError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommercePaymentContext {
    pub seller: String,
    pub shared_payment_token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAuthorizeRequest {
    pub amount_units: u64,
    pub currency: String,
    pub payer: String,
    pub payee: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed: Option<GovernedPaymentContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<CommercePaymentContext>,
}
```

Implemented on 2026-03-23: `chio-kernel` now ships this payment bridge module
with the adapter trait, rail-side settlement enum, and canonical
receipt-side settlement mapping helper.

Also implemented on 2026-03-23: `chio-kernel` now ships a concrete
`X402PaymentAdapter` reference bridge. It performs a thin prepaid HTTP
authorization hop before execution, records receipt-linked payment references
on successful calls, and denies truthfully when authorization fails.

Extended on 2026-03-26: the x402 authorize payload now carries governed
transaction context when present, including the intent id/hash, target
server/tool, purpose, and optional approval-token id. This binds prepaid rail
authorization to the same governed request the kernel validates locally.

Extended on 2026-03-26: `chio-kernel` now also ships `AcpPaymentAdapter`, a
seller-scoped shared-payment-token reference bridge. Governed intents can now
carry typed commerce approval context (`seller`, `shared_payment_token_id`),
grants can require an exact seller scope, and receipts preserve the commerce
approval evidence alongside the financial payment block.

Also implemented on 2026-03-23: pre-execution monetary denials now release any
provisional internal budget debit before the kernel signs the deny receipt, so
guard-side denials do not leak budget state.

Also implemented on 2026-03-23: aborted monetary invocations now unwind
provisional budget debits before returning deny/cancel/incomplete outcomes, and
successful invocations reconcile the internal debit down to actual reported
cost when the configured payment rail is not prepaid.

#### 3.6.2 Implemented and Planned Adapters

| Adapter | Rail | Settlement | Notes |
|---------|------|-----------|-------|
| `AcpPaymentAdapter` | ACP-Commerce / Shared Payment Token | Hold + capture | Seller-scoped commerce approvals with explicit `max_amount` bounds and receipt-linked shared payment token evidence. |
| `X402PaymentAdapter` | x402 HTTP payment protocol | Prepaid per-request | HTTP 402 negotiation. The adapter settles before retry, so denial can still happen before execution. |
| `StablecoinPaymentAdapter` | USDC/USDT on EVM chains | Async (block confirmation) | On-chain transfer or hold model. Receipts may carry `pending` settlement state until confirmations land. |

#### 3.6.3 Integration Point

The `PaymentAdapter` is an optional dependency of `ChioKernel`.
`X402PaymentAdapter` uses the prepaid branch below, while `AcpPaymentAdapter`
uses the hold/capture branch for seller-scoped commerce approvals.

When configured, the kernel follows this rule set:

1. If the rail requires or supports pre-authorization, the kernel calls
   `authorize(...)` before invoking the tool. Authorization failure produces a
   truthful `Decision::Deny` receipt because the tool never executed.
2. The tool executes and reports the actual cost.
3. For prepaid rails, the receipt records the prepaid payment reference and
   preserves the prepaid amount as the charged cost. For non-prepaid rails, the
   kernel captures the actual amount and reconciles any provisional debit down
   to the actual reported cost.
4. If execution aborts before a result is produced, the kernel unwinds the
   provisional internal budget debit and releases or refunds the external rail
   authorization before returning the non-success outcome.
5. If settlement work fails after the tool already ran, the kernel still signs
   `Decision::Allow` and records the failed settlement state plus a recovery
   reference in `FinancialReceiptMetadata`. Reconciliation happens out-of-band.

For operator visibility, Chio preserves x402 and ACP-Commerce bridge details inside
`FinancialReceiptMetadata.cost_breakdown.payment`, including the prepaid
authorization or hold id plus adapter metadata. Governed receipts also preserve
seller-scoped commerce approval context under `governed_transaction.commerce`.
Trust-control receipt queries surface both blocks unchanged, so operators can
audit the rail evidence without a dedicated payment-rail reporting API.
Trust-control also exposes `GET /v1/reports/settlements` plus
`POST /v1/settlements/reconcile` for pending/failed settlement backlog
management. The mutable reconciliation state (`open`, `reconciled`, `ignored`,
or `retry_scheduled`) lives in a sidecar keyed by `receipt_id`, so signed
receipt settlement truth remains immutable. The composite
`GET /v1/reports/operator` surface now includes `settlementReconciliation` and
explicit `dimensions.invocations` plus `dimensions.money` budget profiles on
each utilization row.

```rust
pub struct ChioKernel {
    // ... existing fields ...
    payment_adapter: Option<Box<dyn PaymentAdapter>>,
}
```

The payment adapter is never called on the hot path for grants without monetary budgets. The kernel checks `grant.max_total_cost.is_some() || grant.max_cost_per_invocation.is_some()` before invoking the adapter.

---

## 4. Products

The economic extensions enable four product surfaces. All are built on the same kernel and receipt infrastructure.

### 4.1 Chio Authorize

Agent spending authorization -- analogous to Brex or Ramp for autonomous agents.

- Enterprise issues capability tokens with `max_total_cost` to agent identities.
- Delegation creates sub-budgets for task-specific agents.
- Real-time budget enforcement at the kernel level (not post-hoc).
- Receipts provide a complete, signed audit trail of every charge.
- Velocity controls (`MaxSpendPerWindow`, `RequireApprovalAbove`) provide the same controls a CFO applies to corporate cards.

### 4.2 Chio Meter

Tool provider billing infrastructure.

- Tool servers report `ToolInvocationCost` on every invocation.
- Receipts accumulate per-tool-server cost data.
- `SqliteReceiptStore` cost indexes enable per-provider billing aggregation.
- Settlement queries: `SELECT tool_server, SUM(cost_charged) FROM chio_tool_receipts WHERE cost_currency = ? GROUP BY tool_server`.

### 4.3 Chio Settle

Cross-organization delegation chain settlement.

- When Org A delegates to Org B which delegates to Org C, the receipt chain records cost at each level.
- `GET /v1/reports/cost-attribution` materializes that chain into operator-facing summary, `byRoot`, `byLeaf`, and per-receipt detail rows for a filtered receipt corpus.
- Trust-control cluster replication includes capability-lineage snapshots, so attribution chains and lineage queries converge on followers rather than only on the leader.
- Settlement is a batch process that walks delegation chains in receipts, nets out cost attribution per org, and triggers capture, transfer, refund, or reconciliation actions against the connected payment rail.
- Dispute resolution: any party can verify any receipt's signature and delegation chain independently using only the kernel's public key.

### 4.4 Chio Watch

Spending analytics and anomaly detection.

- Real-time streaming of `FinancialReceiptMetadata` from the receipt log.
- `GET /v1/reports/operator` composes receipt analytics, cost attribution,
  budget utilization, settlement reconciliation, and evidence-export readiness
  into one operator-facing workflow surface.
- `chio trust behavioral-feed export` and `GET /v1/reports/behavioral-feed`
  produce a signed insurer-facing behavioral feed from the same canonical
  receipt, settlement, governed-action, reputation, and shared-evidence data.
- `chio trust underwriting-input export` and `GET /v1/reports/underwriting-input`
  produce a signed underwriting policy-input snapshot with explicit receipt,
  reputation, certification, runtime-assurance, and shared-evidence references.
- `chio trust underwriting-decision evaluate` and
  `GET /v1/reports/underwriting-decision` evaluate that same canonical
  evidence package into one bounded outcome: `approve`, `reduce_ceiling`,
  `step_up`, or `deny`.
- `chio trust underwriting-decision simulate` and
  `POST /v1/reports/underwriting-simulation` compare Chio's default decision
  policy with an operator-supplied simulation policy over the same canonical
  evidence without persisting a new decision.
- `chio trust exposure-ledger export` and `GET /v1/reports/exposure-ledger`
  produce a signed economic-position ledger over governed receipts and
  persisted underwriting decisions, with per-currency totals and concrete
  evidence references for receipt-side reserve, settlement, and loss posture.
- `chio trust credit-scorecard export` and `GET /v1/reports/credit-scorecard`
  produce a signed, subject-scoped credit posture over that same exposure
  ledger plus local reputation inspection, with explicit dimensions,
  probation, confidence, and anomaly semantics.
- `chio trust credit-backtest export` and `GET /v1/reports/credit-backtest`
  replay the current credit and facility logic over bounded historical windows
  so drift, stale evidence, mixed-currency books, and prerequisite failures
  are qualification-visible instead of inferred.
- `chio trust provider-risk-package export` and
  `GET /v1/reports/provider-risk-package` produce one signed provider-facing
  review package containing signed exposure and scorecard artifacts, current
  facility posture, latest facility snapshot, runtime-assurance and
  certification state, and recent-loss history.
- `chio trust liability-provider issue|list|resolve` plus the matching
  trust-control routes keep carrier policy, jurisdiction, coverage-class,
  currency, and evidence-requirement truth curated and supersession-aware
  before any quote or bind step can proceed.
- `chio trust liability-market quote-request-issue|quote-response-issue|
  placement-issue|bound-coverage-issue|list` plus the matching trust-control
  routes now model one provider-neutral quote and bind workflow over that
  signed provider-risk package, preserving provider provenance and failing
  closed on stale provider records, expired quotes, coverage mismatches, or
  unsupported bound-coverage policy.
- `chio trust underwriting-decision issue` and
  `POST /v1/underwriting/decisions/issue` persist a signed underwriting
  decision artifact with explicit review state, budget action, premium quote
  state, and optional supersession linkage.
- `chio trust underwriting-decision list` and
  `GET /v1/reports/underwriting-decisions` return persisted signed decisions
  together with the current lifecycle projection and latest appeal status.
- `chio trust underwriting-appeal create|resolve` plus
  `POST /v1/underwriting/appeals` and
  `POST /v1/underwriting/appeals/resolve` keep appeal state explicit without
  editing execution receipts or re-signing prior decisions.
- `GET /v1/reports/settlements` lists pending/failed settlement backlog rows
  plus summary counts, while `POST /v1/settlements/reconcile` records
  operator-side follow-up state without mutating signed receipts.
- Budget utilization rows now expose named `dimensions.invocations` and
  `dimensions.money` profiles so non-monetary and monetary limits are queryable
  as first-class budget dimensions.
- The behavioral feed preserves truthful distinctions between execution
  decisions, governed approvals/commerce context, and settlement follow-up
  state. It signs the export for external consumers, but it does not pretend
  to be an underwriting model by itself.
- The underwriting-input snapshot stays one step narrower than a decision. It
  signs the evidence package, taxonomy, and derived risk signals that later
  underwriting logic will consume, while keeping final approve/deny/step-up
  outcomes out of phase `49`.
- The underwriting-decision report is deterministic and explainable: it carries
  the exact decision policy snapshot, explicit findings with evidence
  references back to concrete receipts or reconciliation rows, and a suggested
  ceiling factor only when the result is `reduce_ceiling`.
- Signed underwriting decisions are now a separate durable artifact from the
  runtime report. They preserve the exact evaluated evidence snapshot,
  explicitly price or withhold exposure, with mixed-currency governed exposure
  withholding the amount quote instead of comparing raw units across
  currencies, and can supersede earlier decisions without mutating receipt
  truth.
- Underwriting simulation is intentionally non-mutating. It shows how a policy
  change would alter outcomes and reason labels over the same evidence package
  before an operator chooses to issue a new signed decision.
- The exposure ledger is the canonical signed economic-position projection over
  those same receipts and persisted decisions. It partitions totals by
  currency rather than netting across currencies, and it fails closed if one
  receipt row contains contradictory currency truth that Chio cannot represent
  honestly in a single position row.
- The credit scorecard is intentionally subject-scoped and explicitly weighted.
  It reuses the existing local reputation inspection as one input rather than
  inventing a second trust score, then combines that with settlement, reserve,
  and provisional-loss posture from the signed exposure ledger.
- The facility-policy layer turns that scorecard into one bounded allocation
  recommendation. Chio can now produce explicit grant, manual-review, or deny
  posture with typed runtime-assurance and certification prerequisites, plus a
  signed facility artifact lifecycle that supports supersession and expiry
  without rewriting the previously signed body.
- Credit qualification is now explicit rather than implied. Chio can replay the
  current scorecard and facility-policy logic over historical windows, then
  surface typed drift reasons such as stale evidence, mixed-currency books,
  utilization overage, missing runtime assurance, or settlement backlog.
- The provider-facing risk package is intentionally review-oriented. It binds
  signed exposure and scorecard truth together with current facility posture,
  runtime-assurance or certification state, and recent-loss rows sourced from
  the newest matching loss evidence rather than from a truncated ledger page.
- The capital book is now explicit instead of implied. Chio can export one
  signed live capital book that ties the current facility commitment and
  reserve book to one subject-scoped source-of-funds view with explicit
  committed, held, drawn, disbursed, released, repaid, and impaired state over
  canonical receipt, facility, bond, and loss-lifecycle evidence.
- Capital attribution remains conservative and fail closed. Chio refuses to
  auto-blend multiple live facilities or reserve books, mixed-currency
  positions, missing counterparty attribution, or books with no active granted
  facility that can explain the committed source of funds honestly.
- Capital instructions are now explicit instead of inferred. Chio can issue one
  signed custody-neutral instruction artifact for reserve locks, reserve
  holds, reserve releases, fund transfers, or instruction cancellation over
  one subject-scoped live capital source.
- Capital execution remains evidence-linked and fail closed. Each instruction
  carries one explicit authority chain, execution window, rail descriptor,
  intended versus reconciled state, and bounded evidence set, and Chio rejects
  stale authority, mismatched custody steps, expired windows, mixed-currency
  amounts, or observed execution that does not match the intended movement.
- Capital allocation decisions are now explicit instead of ambient. Chio can
  issue one signed simulation-first allocation artifact for one governed
  receipt, one active facility-backed capital source, one optional reserve
  source, and one bounded execution envelope.
- Allocation remains deterministic and fail closed. Chio requires one approved
  actionable governed receipt, binds allocation against the currently active
  facility/book state when it exists, and emits typed `allocate`, `queue`,
  `manual_review`, or `deny` posture instead of blending sources or implying
  that capital already moved.
- Regulated roles are now explicit instead of ambient. Live-capital
  instructions and allocations require one named source-owner approval, one
  named custody-provider execution step, and one bounded execution window
  rather than relying on implicit operator authority.
- The regulated-role baseline remains intentionally bounded. Chio now emits
  auditable live-capital contracts, but it still does not claim Chio itself is
  the regulated custodian, settlement rail, or insurer of record.
- Bond policy is now explicit instead of implicit. Chio can evaluate reserve
  posture into one typed `lock`, `hold`, `release`, or `impair` report over
  canonical exposure plus the latest active granted facility, then persist the
  result as a separate signed bond artifact without mutating the facility or
  receipt bodies.
- Reserve accounting remains intentionally single-currency and fail closed.
  If the selected book or the latest active facility would require blended
  cross-currency collateral math, Chio rejects the bond report rather than
  inventing a netted reserve state.
- Bond artifacts now participate in bounded runtime enforcement. Chio can deny
  delegated and autonomous governed execution unless the caller supplies an
  explicit autonomy context with an active delegation bond whose lifecycle,
  reserve disposition, facility prerequisites, support boundary, runtime
  assurance, call-chain binding, and tool-server scope all still match the
  current invocation.
- Bond-loss lifecycle is now explicit instead of implicit. Chio can evaluate
  one delinquency, recovery, reserve-release, reserve-slash, or write-off step
  over a signed bond, then persist that step as a separate signed artifact
  without mutating the bond body or the original execution receipt.
- Delinquency booking uses recent failed-loss evidence rather than whichever
  receipts happen to fit inside the generic exposure page. That keeps
  loss-lifecycle accounting aligned with the newest actionable settlement
  backlog instead of silently aging it out of view.
- Recovery, write-off, reserve release, and reserve slash remain bounded by
  explicit accounting and execution rules. Recovery and write-off cannot
  exceed outstanding delinquency, reserve release cannot happen while
  delinquency remains open, reserve slash cannot exceed slashable reserve, and
  mixed-currency adjustments fail closed instead of inventing blended
  lifecycle math.
- Reserve release and reserve slash are now explicit control artifacts rather
  than inferred accounting consequences. They require one valid authority
  chain, one bounded execution window, one custody rail, optional observed
  execution that reconciles to the computed event amount, and an optional
  machine-readable appeal window.
- Liability-provider admission is now explicit rather than ad hoc. Chio can
  publish one curated signed provider artifact with bounded jurisdiction,
  coverage-class, currency, and evidence requirements, then fail closed
  during provider resolution when the requested combination is unsupported or
  no active provider policy exists.
- Bond artifacts are still not a live escrow engine. They now gate bounded
  autonomy tiers, but they still do not slash reserves or execute external
  collateral movement from phases `85` and `86` alone.
- Bonded execution is now operator-simulatable before runtime use. Chio can
  replay one requested autonomy tier, runtime-assurance tier, and call-chain
  posture against a persisted bond plus lifecycle history, then compare the
  default decision versus an explicit operator control policy without mutating
  the bond or execution receipt bodies.
- Operator controls are explicit instead of implied. Chio now supports a
  kill-switch, autonomy-tier clamp, runtime-assurance floor, reserve-lock
  requirement, and delinquency clamp-down policy over bonded execution, and
  the simulation path fails closed if loss-lifecycle history is truncated.
- The decision-list surface projects current lifecycle and latest appeal status
  separately from the immutable signed decision body. Appeals and supersession
  change operator-visible state, but they do not rewrite the previously signed
  artifact. Summary premium totals are partitioned by currency so cross-currency
  reports do not collapse into one raw unit count.
- Claim workflows are explicit instead of implied. Chio now issues immutable
  claim packages, provider responses, disputes, adjudications, payout
  instructions, payout receipts, settlement instructions, and settlement
  receipts linked back to bound coverage, exposure, bond, loss-lifecycle,
  capital-execution, and receipt evidence instead of expecting operators to
  reconstruct that state from quote, bond, or payment side effects alone.
- The liability-market posture is now locally qualified end to end across
  curated provider admission, quote/bind, claim/dispute workflow evidence, and
  one bounded payout-and-settlement lane. Chio can now prove the marketplace
  orchestration layer it claims without implying autonomous insurer rate setting,
  open-ended payment rails, cross-network clearing, or permissionless market
  trust.
- Delegated pricing authority is now explicit instead of implied. Chio issues a
  signed provider- or regulated-role-bounded authority artifact linked to one
  quote request, one facility, one underwriting decision, and one capital-book
  snapshot, and automatic binding fails closed on stale authority, stale
  provider state, or out-of-envelope coverage or premium requests.
- Bounded autonomous pricing is now explicit instead of implied. Chio issues one
  signed pricing-input, authority-envelope, pricing-decision, capital-pool,
  execution, rollback, comparison, drift, and qualification family that keeps
  automated reprice, renew, decline, and bind behavior subordinate to explicit
  evidence provenance, reserve strategy, human-interrupt contacts, and
  fail-safe rollback posture.
- Recovery and claims-network semantics remain intentionally bounded. Chio now
  records claim, payout, settlement, and dispute state, but it still does not
  claim insurer-network messaging or open-ended cross-organization recovery
  clearing in the signed export.
- Open-market economics are now explicit instead of informal. Chio issues one
  signed fee-schedule artifact over bounded namespace, actor-kind,
  publisher-operator, and admission-class scope plus one signed penalty
  artifact over matched listing, activation, governance sanction, abuse class,
  and bond class, then evaluates those artifacts fail closed on stale
  authority, scope mismatch, unsupported bond requirements, non-slashable
  bonds, and currency or amount mismatch instead of treating market discipline
  as ambient operator discretion.
- Federated trust is now explicit instead of implied. Chio issues one signed
  federation-activation exchange, one quorum report, one federated open-
  admission policy, one shared reputation-clearing artifact, and one
  qualification matrix so cross-operator visibility can be shared without
  turning mirrors, indexers, or imported trust into ambient runtime
  admission.
- Public identity and wallet interoperability are now explicit instead of
  implied. Chio issues one public identity profile, one verifier-bound wallet-
  directory entry, one replay-safe wallet-routing manifest, and one
  qualification matrix over `did:chio` plus bounded `did:web`, `did:key`, and
  `did:jwk` compatibility inputs without turning public routing or directory
  visibility into ambient trust or admission.
- Shared reputation remains locally weighted. Independent issuers, per-issuer
  caps, oracle-weight ceilings, and corroborated blocking negative events keep
  the federation lane from collapsing into a universal trust score or
  permissionless trust network.
- Adversarial multi-operator market proof is now explicit instead of assumed.
  Chio can preserve public visibility of conflicting or invalid registry
  replicas while refusing to treat them as runtime trust, can keep imported
  reputation locally weighted under hostile operator input, and can reject
  governance or market-penalty artifacts that depend on trust activations not
  issued by the governing local operator.
- Score confidence and probation are explicit instead of implied. Sparse
  history can still produce a scorecard, but Chio marks it low-confidence and
  probationary rather than letting later facility policy treat it as a mature
  credit book.
- Live capital execution remains intentionally bounded. Chio now issues
  reviewable capital-book, capital-instruction, capital-allocation,
  reserve-control, payout, and settlement artifacts, plus one official web3
  dispatch and settlement lane with anchored reconciliation, plus one bounded
  `chio-settle` runtime over explicit escrow, refund, and bond-lifecycle flows,
  plus one bounded autonomous pricing and capital-pool lane over that
  substrate, but it still does not claim permissionless external dispatch or
  open-ended insurer automation outside the documented bounded envelope.
- Anomaly detection: spending velocity exceeding historical baselines, unusual tool-server cost reports, delegation depth anomalies, or growing `pending`/`failed` settlement backlogs.
- Webhook integration: notify when budget utilization exceeds configurable thresholds (50%, 80%, 95%).
- Dashboard queries against the indexed receipt store.

### 4.5 Attested Runtime Tiers

Chio treats runtime attestation as an input to issuance and governed execution,
not as a replacement trust system.

- HushSpec policies can define `extensions.runtime_assurance.tiers`, where each
  named tier maps a minimum attestation tier to a maximum scope ceiling.
- HushSpec policies can also define
  `extensions.runtime_assurance.trusted_verifiers`, where each rule binds one
  `{schema, verifier}` pair to an effective runtime-assurance tier plus
  optional verifier-family, evidence-age, attestation-type, and
  normalized-assertion constraints.
- Capability issuance resolves the caller into the strongest configured runtime
  tier satisfied by the provided attestation evidence. Missing evidence can
  still resolve to the lowest matching configured tier, but stale, malformed,
  or untrusted evidence fails closed when supplied.
- Runtime assurance only widens rights through the existing scope-ceiling
  machinery. A stronger attestation tier can unlock a broader issuance ceiling,
  but it does not bypass least-privilege matching, delegation limits, or
  governed constraints.
- Economically sensitive grants issued above `none` gain an explicit
  `MinimumRuntimeAssurance(...)` constraint. The kernel re-checks that
  requirement at invocation time against `governed_intent.runtime_attestation`
  before approval and budget enforcement continue.
- Chio now recognizes one typed workload-identity projection inside runtime
  attestation: SPIFFE with `credentialKind` `uri`, `x509_svid`, or `jwt_svid`
  and normalized `{ uri, trustDomain, path }` fields. A legacy raw
  `runtimeIdentity` string still remains allowed, but Chio only projects it into
  typed policy/runtime surfaces when it is a valid SPIFFE URI.
- Chio's first concrete verifier adapter is Azure Attestation JWT
  normalization. It binds a configured issuer plus RSA signing material,
  enforces allowed `x-ms-attestation-type` values, preserves Azure-specific
  claims under `claims.azureMaa`, and can optionally project one SPIFFE URI
  from `x-ms-runtime.claims.*` into the same typed workload-identity surface.
- Chio's second and third concrete verifier adapters are AWS Nitro
  `COSE_Sign1` documents and Google Confidential VM JWTs. Nitro binds
  certificate-anchored `ES384` measurements, freshness, optional nonce
  matching, and debug-mode denial; Google binds metadata-resolved `JWKS`
  verification, audience pinning, hardware-model assertions, secure-boot
  posture, and vendor claims under `claims.googleAttestation`.
- The Azure MAA bridge remains intentionally conservative by default: raw
  normalized verifier output is `attested` and only rebinds to `verified` or
  another stronger/equivalent tier through explicit `trusted_verifiers`
  policy.
- When `trusted_verifiers` are configured, verifier trust becomes explicit and
  operator-controlled. A carried attestation must match one trusted verifier
  rule and satisfy its freshness and attestation-type constraints or issuance
  and governed execution deny fail closed.
- Conflicting or malformed workload-identity claims fail closed. Chio will not
  silently widen rights or runtime trust from an opaque verifier string it does
  not understand.
- Receipt metadata records the accepted attestation schema, optional verifier
  family, resolved runtime assurance tier, verifier, evidence digest, and
  normalized workload identity when present so operators can audit why a
  stronger budget or approval path was available.
- Trust-control can also emit one signed runtime-attestation appraisal report
  over the same canonical appraisal contract so operators can share verifier
  family, normalized assertions, vendor-scoped claims, and policy-visible
  accept or reject outcomes without inventing a second mutable trust record.

---

## 5. Architecture Diagram

```
                          Capability Token
                         (spending authorization)
                                |
                                v
  +-----------+         +----------------+         +----------------+
  |           |  req    |                |  invoke  |                |
  |  Agent    |-------->|  Chio Kernel   |--------->|  Tool Server   |
  | (spender) |         |  (authorizer)  |<---------|  (provider)    |
  |           |<--------|                |  result  |                |
  +-----------+  receipt|                |  + cost  +----------------+
                        +-------+--------+
                                |
                    +-----------+-----------+
                    |           |           |
                    v           v           v
              +---------+ +---------+ +-----------+
              | Budget  | | Receipt | | Payment   |
              | Store   | | Store   | | Adapter   |
              | (state) | | (audit) | | (settle)  |
              +---------+ +---------+ +-----------+
                    |           |           |
                    v           v           v
              +---------+ +---------+ +-----------+
              | HA      | | Merkle  | | Stripe /  |
              | Replica | | Log     | | x402 /    |
              |         | |         | | On-chain  |
              +---------+ +---------+ +-----------+
```

**Data flow for a monetized tool call:**

*Steps 1-12 reflect the current shipped behavior across the kernel,
receipt-store, and trust-control operator surfaces. Signed receipt truth stays
immutable; any follow-up reconciliation state is stored separately as
operator-managed sidecar data keyed by `receipt_id`.*

1. Agent presents `CapabilityToken` with `ToolGrant`. *(current)*
2. Kernel validates signature, time bounds, revocation, scope. *(current)*
3. Kernel calls `budget_store.try_increment(...)` to enforce invocation-count budgets, then evaluates guards. *(current)*
4. **[current]** Kernel evaluates `VelocityGuard` against velocity constraints.
5. **[current]** If needed, kernel obtains budget and payment pre-authorization using `max_cost_per_invocation` or a quoted amount.
6. Kernel forwards request to tool server. *(current, unchanged)*
7. **[current]** Tool server returns result + `ToolInvocationCost`.
8. **[current]** Kernel verifies reported cost against the per-invocation cap, unwinds aborted invocations, and finalizes the budget charge.
9. **[current]** If `PaymentAdapter` is configured, the kernel either records prepaid settlement metadata or captures/releases the post-execution amount depending on rail mode.
10. **[current]** Kernel signs `ChioReceipt` with `FinancialReceiptMetadata`, including settlement status and payment reference.
11. Receipt is appended to `SqliteReceiptStore` and replicated. *(current)*
12. **[current]** Failed or pending settlement follow-up is handled through
    trust-control reconciliation sidecar state and backlog reports, not by
    rewriting the signed receipt verdict.

---

## 6. Implementation Priorities

### Implementation Status

**The economic primitives are implemented in the current pre-release v1 branch.**
They are available in the current codebase. Earlier work also added governed
transaction metadata, x402 and ACP-Commerce bridge integrations, truthful settlement
linkage, settlement backlog reporting, and explicit invocation-plus-money
budget dimensions on operator reports. Broader observability, Stripe-style
adapters, and cross-org settlement automation remain planned.

Operational guides for current v1 features:

- [MONETARY_BUDGETS_GUIDE.md](MONETARY_BUDGETS_GUIDE.md): configuring `max_cost_per_invocation`, `max_total_cost`, and financial receipt metadata
- [VELOCITY_GUARDS.md](VELOCITY_GUARDS.md): token-bucket rate limiting per grant
- [DPOP_INTEGRATION_GUIDE.md](DPOP_INTEGRATION_GUIDE.md): DPoP proof-of-possession setup and verification
- [RECEIPT_QUERY_API.md](RECEIPT_QUERY_API.md): `GET /v1/receipts/query` filters, pagination, and CLI usage

### Out-of-Repo Consumption Model

External consumers that need the unified spend and exposure surface should poll
`GET /v1/reports/comptroller-surface` and validate the response against the
published schema before parsing:

```
spec/schemas/chio-comptroller/v1/surface-report.schema.json
```

The response carries `"schema": "chio.comptroller.surface-report.v1"` as the
top-level identifier. Consumers must reject any response where this field is
absent or does not match the pinned version -- this is the fail-closed contract.

**Schema-governed HTTP polling** is the primary integration pattern. The
endpoint is read-only, requires a Bearer token, and returns a snapshot as of
`generatedAt` (integer Unix seconds). Consumers should not merge or cache across
multiple snapshots without comparing `generatedAt` values to detect stale reads.

**Optional signed offline export** (`SignedComptrollerSurfaceReport`) is
available for consumers that need to verify surface state offline or carry it to
an external system. The signed export wraps the same `chio.comptroller.surface-report.v1`
body with a kernel Ed25519 signature over canonical bytes. Consumers must verify
the signature before trusting the body.

Both paths are pinned to the same `spec/schemas/chio-comptroller/v1/surface-report.schema.json`
schema. The projection is custody-neutral and implies no fund movement; it is a
read-only snapshot of canonical receipt, settlement, and budget truth.

### Economic Primitives -- Implemented In Current V1

These deliverables are implemented in the current pre-release v1 branch:

- `MonetaryAmount` type in `crates/core/chio-core`.
- `max_cost_per_invocation` and `max_total_cost` fields on `ToolGrant`; `is_subset_of` enforces cost caps through delegation chains.
- `ReduceCostPerInvocation` and `ReduceTotalCost` attenuation variants.
- `total_cost_charged` in `BudgetUsageRecord` and `capability_grant_budgets` table.
- `try_charge_cost` on `BudgetStore` trait with atomic invocation-count + cost-units check in both `InMemoryBudgetStore` and `SqliteBudgetStore`.
- Replication delta support for cost fields (seq-based LWW merge).
- `ToolInvocationCost` struct and `invoke_with_cost` default method on `ToolServerConnection`.
- Kernel cost verification in `evaluate_tool_call_with_session_roots`.
- `FinancialReceiptMetadata` populated into receipt `metadata` field, including `grant_index`, `cost_charged`, `currency`, `budget_remaining`, `budget_total`, `delegation_depth`, `root_budget_holder`, and `settlement_status`.
- Receipt store cost indexing columns (`cost_charged`, `cost_currency`).
- `VelocityGuard` token-bucket rate limiting in `crates/guards/chio-guards/src/velocity.rs`.
- Unit and integration tests for all of the above.

**Shipped files:**

| File | What shipped |
|------|-------------|
| `crates/core/chio-core` | `MonetaryAmount`, `ToolGrant` monetary fields, attenuation variants, `is_subset_of` monetary checks |
| `crates/kernel/chio-kernel/src/budget_store.rs` | `BudgetUsageRecord.total_cost_charged`, `try_charge_cost`, schema migration, replication |
| `crates/kernel/chio-kernel/src/lib.rs` | `ToolInvocationCost`, `invoke_with_cost`, kernel cost verification, receipt population |
| `crates/core/chio-core` | `FinancialReceiptMetadata` (serialized into `metadata` field) |
| `crates/kernel/chio-kernel/src/receipt_store.rs` | Cost indexing columns, `RetentionConfig`, archival rotation |
| `crates/guards/chio-guards/src/velocity.rs` | `VelocityGuard` token-bucket implementation |

### Next -- Observability (~3 months effort; maps to Q3 2026 in the Strategic Roadmap)

- Spending dashboard (query layer over receipt store).
- Budget utilization webhooks.
- Real-time cost streaming from receipt log.
- Design partner integrations (2-3 agent framework vendors).

### Later -- Payment Rail Integration (~3 months incremental work beyond the implemented bridge baseline; maps to Q4 2026 in the Strategic Roadmap)

Implemented bridge baseline:

- `PaymentAdapter` trait and truthful settlement mapping in
  `crates/kernel/chio-kernel/src/payment.rs`
- `X402PaymentAdapter` for prepaid API flows and `AcpPaymentAdapter` for
  shared-payment-token commerce approvals
- operator-visible settlement backlog reporting and sidecar reconciliation
  state in trust-control

Remaining incremental work:

- `PaymentAdapter` trait and `PaymentError` in `crates/kernel/chio-kernel/src/payment.rs`.
- `StripePaymentAdapter` implementation.
- Hold-and-capture flow (authorize before invocation, capture or release after cost report).
- Kernel integration: optional adapter on `ChioKernel`, with truthful receipt semantics and deeper reconciliation automation for post-execution settlement failures.

### Later -- Cross-Org Settlement (~6 months effort; maps to Q1-Q2 2027 in the Strategic Roadmap)

- Batch settlement engine walking delegation chains across receipt log.
- Net position calculation per organization.
- `StablecoinPaymentAdapter` for on-chain settlement.
- Tool provider registry with verified payment addresses.
- Multi-currency support and exchange rate snapshotting.

---

## 7. Estimated Effort

Core economic layer (the implemented primitives above):

| Component | Estimate |
|-----------|----------|
| `MonetaryAmount` + `ToolGrant` schema + attenuation + `is_subset_of` | 1 week |
| `BudgetStore` cost tracking (both implementations + replication) | 1.5 weeks |
| `ToolInvocationCost` + `invoke_with_cost` + kernel verification | 1 week |
| `VelocityGuard` + velocity constraints | 1 week |
| `FinancialReceiptMetadata` + receipt store indexing | 0.5 weeks |
| Integration tests + conformance harness updates | 1-2 weeks |
| **Total** | **6-7 weeks** |

This estimate assumes a single engineer working full-time. The work is
structured so that each component can be merged independently behind feature
flags, with the schema-tolerance migration landing before `MonetaryAmount` and
`ToolGrant` cost fields. Those fields are only non-breaking after the
`deny_unknown_fields` compatibility work has shipped.
