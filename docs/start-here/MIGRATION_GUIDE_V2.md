# Historical Internal Milestone Migration Draft

> Historical internal draft. Chio is pre-release and current Chio-owned
> protocol, schema, SDK, and runtime surfaces remain v1-only. Do not use this
> document as current implementation or compatibility guidance.

This archived draft described a pre-release internal milestone transition. It
does not describe a released protocol migration, and it must not be used as
current deployment or compatibility guidance.

---

## What Changed

The internal milestone added enforcement, compliance, and observability ideas
on top of earlier prototypes. Current Chio remains v1-only and may break
pre-release artifacts without compatibility shims.

### Internal Milestone Additions

| Feature | Crate | Summary |
|---------|-------|---------|
| Monetary budgets | `chio-core`, `chio-kernel` | `ToolGrant` gains `max_cost_per_invocation` and `max_total_cost` |
| DPoP proof binding | `chio-kernel` | Per-invocation Ed25519 proof-of-possession |
| Receipt Merkle checkpointing | `chio-kernel` | Count-triggered signed tree heads with inclusion proofs |
| Receipt query API | `chio-cli` | `GET /v1/receipts/query` with 9 filter dimensions and cursor pagination |
| Agent-subject receipt filter | `chio-cli` | Filter receipts by agent's Ed25519 public key |
| Nested flow receipts | `chio-core`, `chio-kernel` | `ChildRequestReceipt` for sub-operations |
| SIEM exporter pipeline | `chio-siem` | Cursor-pull loop exporting to Splunk HEC and Elasticsearch |
| Financial receipt metadata | `chio-core` | `FinancialReceiptMetadata` attached to monetary receipts |

---

## New ToolGrant Fields

Two optional fields were added to `ToolGrant`:

```rust
pub struct ToolGrant {
    // ... existing fields unchanged ...

    /// Maximum monetary cost per single invocation.
    pub max_cost_per_invocation: Option<MonetaryAmount>,

    /// Maximum aggregate monetary cost across all invocations.
    pub max_total_cost: Option<MonetaryAmount>,

    /// If Some(true), require a valid DPoP proof for every invocation.
    pub dpop_required: Option<bool>,
}

pub struct MonetaryAmount {
    pub units:    u64,    // Minor units (e.g. cents for USD)
    pub currency: String, // ISO 4217 code
}
```

These fields default to `None` (skipped in serialization). Existing grants
without these fields continue to work exactly as before.

### Forward Compatibility

Existing v1.0 capability tokens serialize and deserialize correctly with the
internal milestone `ToolGrant` type. The new fields are tagged with
`#[serde(default, skip_serializing_if = "Option::is_none")]`, so:

- A current-shape token deserialized by the internal milestone Kernel has all three new fields as
  `None` and behaves identically to v1.0.
- An internal milestone token with monetary fields is rejected by an older current-shape Kernel (unknown
  fields trigger a deserialization error depending on serde configuration).
  Do not use this archived draft as current compatibility guidance.

---

## How to Enable Monetary Budgets

**1. Issue a capability token with monetary limits.**

```rust
use chio_core::capability::{scope::{MonetaryAmount, ToolGrant}};

let grant = ToolGrant {
    server_id: "payments-server".to_string(),
    tool_name: "charge_card".to_string(),
    operations: vec![Operation::Invoke],
    constraints: vec![],
    max_invocations: Some(10),
    max_cost_per_invocation: Some(MonetaryAmount {
        units: 500,        // $5.00 USD
        currency: "USD".to_string(),
    }),
    max_total_cost: Some(MonetaryAmount {
        units: 2000,       // $20.00 USD
        currency: "USD".to_string(),
    }),
    dpop_required: None,
};
```

**2. Pass cost to the Kernel on each invocation.**

When the Kernel processes a tool call under a monetary grant, it calls
`BudgetStore::try_charge_cost` atomically. You must provide the cost in minor
units at dispatch time. The cost is determined by the tool server's reported
price; the Kernel enforces that it does not exceed `max_cost_per_invocation`
or push `total_cost_charged` beyond `max_total_cost`.

**3. Read financial metadata from receipts.**

Allowed invocations produce a `ChioReceipt` with financial metadata under the
`"financial"` key in `metadata`:

```rust
if let Some(meta) = receipt.metadata.as_ref() {
    if let Some(financial) = meta.get("financial") {
        let fin: FinancialReceiptMetadata = serde_json::from_value(financial.clone())?;
        println!("Charged: {} {}", fin.cost_charged, fin.currency);
        println!("Remaining: {}", fin.budget_remaining);
    }
}
```

Denial receipts due to budget exhaustion have `decision = Deny` and
`attempted_cost` set in the financial metadata.

---

## How to Enable DPoP

**1. Mark a grant as requiring DPoP.**

```rust
let grant = ToolGrant {
    dpop_required: Some(true),
    // ... other fields ...
};
```

**2. Build a DPoP proof in the agent before each invocation.**

```rust
use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};
use chio_core::crypto::sha256_hex;
use chio_core::canonical::canonical_json_bytes;

let action_hash = sha256_hex(&canonical_json_bytes(&arguments)?);

let body = DpopProofBody {
    schema: DPOP_SCHEMA.to_string(),
    capability_id: capability.id.clone(),
    tool_server: server_id.clone(),
    tool_name: tool_name.clone(),
    action_hash,
    nonce: generate_random_nonce(),  // unique per invocation
    issued_at: unix_now_secs(),
    agent_key: agent_keypair.public_key(),
};
let proof = DpopProof::sign(body, &agent_keypair)?;
```

**3. Pass the proof in the ToolCallRequest.**

```rust
let request = ToolCallRequest {
    dpop_proof: Some(proof),
    // ... other fields ...
};
```

The Kernel's `DpopNonceStore` has a default capacity of 8192 entries, and the
default proof validity window is 300 seconds. Nonces must be unique per
`(nonce, capability_id)` through the inclusive signed proof horizon. Expired
markers are reclaimed, but live markers are never evicted; a full store denies
new proofs fail-closed. Size it for peak proof volume over the full validity
window, including tolerated future clock skew. Use a random string of at least
16 bytes for the nonce.

---

## How to Set Up SIEM

The `chio-siem` crate provides a cursor-pull loop that reads signed receipts
from the Kernel's SQLite database and forwards them to Splunk HEC or
Elasticsearch.

**1. Add `chio-siem` to your binary.**

```toml
[dependencies]
chio-siem = { path = "../crates/observability/chio-siem" }
```

**2. Configure and run the ExporterManager.**

```rust
use chio_siem::{
    ExporterManager, RateLimitConfig, SiemConfig, SplunkConfig, SplunkHecExporter,
};

let config = SiemConfig {
    db_path: "/var/lib/chio/receipts.sqlite3".into(),
    poll_interval: Duration::from_secs(5),
    batch_size: 100,
    max_retries: 3,
    base_backoff_ms: 500,
    dlq_capacity: 1000,
    rate_limit: Some(RateLimitConfig {
        max_batches_per_window: 10,
        window: Duration::from_secs(1),
        burst_factor: 1.0,
    }),
};

let mut manager = ExporterManager::new(config)?;
manager.add_exporter(Box::new(SplunkHecExporter::new(SplunkConfig {
    endpoint: "https://splunk.example.com:8088".to_string(),
    hec_token: "your-hec-token".to_string(),
    sourcetype: "chio:receipt".to_string(),
    index: None,
    host: None,
})?));

let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
manager.run(cancel_rx).await;
```

`chio-siem` opens the receipt database read-only. The Kernel does not need to
be stopped during SIEM export. On restart, the manager re-exports from seq=0;
ensure your SIEM backend is configured for idempotent ingest.

---

## How to Access the Receipt Query API

The `GET /v1/receipts/query` endpoint is served by the `chio-cli` trust
control server.

**Basic query:**

```
GET /v1/receipts/query?limit=50
Authorization: Bearer <service-token>
```

**Filtered query:**

```
GET /v1/receipts/query?toolServer=payments-server&outcome=deny&since=1711000000&limit=20
```

**Paginated query:**

```
# First page
GET /v1/receipts/query?limit=50

# Next page (use nextCursor from previous response)
GET /v1/receipts/query?limit=50&cursor=137
```

**Filter by agent public key:**

```
GET /v1/receipts/query?agentSubject=<hex-encoded-ed25519-pubkey>&limit=50
```

All filter parameters are optional and combinable. Filters are applied with
AND semantics. See `ReceiptQueryHttpQuery` in `chio-control-plane/src/trust_control.rs`
for the full parameter list.

The response includes `totalCount` (full filtered set, not just this page),
`nextCursor` (present when more pages exist), and `receipts` (array of
`ChioReceipt` objects, ordered by `seq` ascending).

---

## HA Overrun Note

If you use monetary budgets in an HA deployment with multiple Kernel nodes,
read ADR-0006. The maximum possible budget overrun is
`max_cost_per_invocation * node_count`. Set your total budget with this
bound in mind.
