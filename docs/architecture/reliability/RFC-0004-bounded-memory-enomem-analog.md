# RFC-0004: Bounded-memory architecture and the ENOMEM analog

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: none
- Depends on: none (the soak and chaos acceptance items gate on the PLAN-load-chaos harness)
- Closes findings: F03, F06, F10, F12, F21, F25, F38, F39, F63 (with RFC-0010, which owns the systemd/restart half) (see ./README.md and the readiness review)

## Summary

Every long-lived serving process in Chio holds at least one collection that grows
with lifetime traffic and never sheds. The kernel receipt mirrors, the federation
dual-receipt and DSSE caches, the velocity token-bucket maps, the federation
admission rate-limiter, the per-tenant concurrency table, and the per-session
journal all append forever. Uptime alone (not attack) drives monotonic RSS growth
that ends in the OOM killer taking down the trusted mediator for every tenant at
once, which is the exact failure mode the Ubicloud "PostgreSQL and the OOM Killer"
lens warns against. This RFC establishes one repo-wide invariant, wires the
verified offenders to it, adds a typed load-shed error (the ENOMEM analog) that
denies early rather than growing, adds fallible allocation on the one hot path that
sizes buffers from wire input, and declares a per-process RSS ceiling backed by
cgroup limits plus OS deployment guidance. It is the keystone of the wave-3
reliability program: the reusable `Ring`/`BoundedMap` abstraction and the size-metric
convention defined here are the substrate that RFC-0009 (observability wiring)
reports on and PLAN-load-chaos (the load/soak/chaos program) exercises.

## Motivation

The reliability lens asks five things of an overloaded component: fail early, fail
local, fail graceful (not process death), know the blast radius when it dies
mid-operation, and keep internal accounting trustworthy. An unbounded in-memory
collection violates the first three by construction and, on the kernel, converts a
slow leak into a total outage.

The invariant this RFC installs:

> No long-lived collection in a serving process may exist without (1) a capacity
> policy (ring, LRU, idle-sweep, or deny-at-cap) and (2) a live size metric.

Blast radius of the confirmed offenders, by finding:

- F03 / F25 (high, CONFIRMED). Trigger: nothing but uptime; every dispatch clones
  a full `ChioReceipt` (and child receipts for nested flows) into unbounded `Vec`s
  even when a durable store is configured. Effect: monotonic kernel RSS growth plus
  O(n) linear scans of both `Vec`s on the governed call-chain path under a mutex, so
  governed-path latency grows with process age and contends with every concurrent
  receipt write. Impact: gradual whole-process degradation, then a full-service
  restart for all tenants.
- F10 (high, CONFIRMED). Trigger: normal federated traffic. Effect: each co-signed
  federated call permanently retains a `DualSignedReceipt` plus a `DsseEnvelope`
  (each embedding a full receipt clone plus signatures, order-of-KBs) in two
  never-evicted `DashMap`s. Impact: unbounded RSS on the kernel that mediates every
  tool call for all tenants.
- F39 (high, CONFIRMED) and the rate-limiter half of F21. Trigger: permissionless
  federation admission with fresh subject keypairs (the Sybil scenario the code
  exists to handle). Effect: every distinct `policy_id:subject_key` leaves a
  permanent map key on the trust-control leader; timestamps inside are pruned but
  keys never are. Impact: memory pressure and eventual OOM on the shared capability
  authority, taking down issuance, revocation distribution, and admission for every
  dependent kernel. The anti-Sybil control is itself the Sybil-driven sink.
- F38 (medium, PARTIAL). Trigger: a long-lived single-kernel process whose agent
  presents many distinct capability ids, including self-minted delegated leaves that
  pass signature verification. Effect: a permanent `TokenBucket` per
  `(capability_id, grant_index)`, even on deny. Impact: OOM of that agent's kernel
  (fail-closed, so blast radius is one session).
- F12 (medium, PARTIAL, latent). Trigger: 1024 distinct tenant ids over process
  lifetime. Effect: the per-tenant concurrency table fills and then denies every new
  tenant permanently, a partial outage that reads as ordinary load shedding. No
  in-repo binary wires this layer today, so it is latent library behavior.
- F21 journal half (medium, PARTIAL, latent). Trigger: an integrator wiring the
  session-journal guards. Effect: entries and tool-sequence grow linearly forever and
  whole-vector clone getters give quadratic cumulative cost on the hot path.
- F06 (medium, PARTIAL). Trigger: a custom out-of-tree tool-server connection emits
  an oversized stream. Effect: the kernel materializes the whole `Vec<ToolCallChunk>`
  before `apply_stream_limits` runs at finalize, so RSS balloons to attacker-chosen
  size before the limit is even consulted. In-tree connectors bound the worst case,
  so today the effect is redundant copies and latency, not exhaustion.

## Current behavior (verified 2026-07-04)

All line numbers below were re-read against the working tree on the date above.

### Kernel receipt mirrors (F03, F25)

`crates/kernel/chio-kernel/src/kernel/mod.rs:419-448` and `:451-480` define the two
mirrors as plain vectors with an unconditional `append` and no cap, prune, or evict:

```rust
// mod.rs:419
#[derive(Clone, Default)]
pub struct ReceiptLog {
    receipts: Vec<ChioReceipt>,
}
impl ReceiptLog {
    pub fn append(&mut self, receipt: ChioReceipt) {
        self.receipts.push(receipt);
    }
    // len / is_empty / receipts / get ...
}
```

`ChildReceiptLog` (mod.rs:451) is the same pattern over `Vec<ChildRequestReceipt>`.
The doc comment states the mirror "remains useful for process-local inspection even
when a durable backend is configured". They are held as
`receipt_log: Mutex<ReceiptLog>` and `child_receipt_log: Mutex<ChildReceiptLog>`
(`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:144-145`).

They are fed on every receipt: `record_chio_receipt`
(`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:164`) appends
at line 183 through `append_chio_receipt_to_local_log` (dispatch.rs:506), inside the
`receipt_store_write_lock` scope, after durable persistence already succeeded;
`record_child_receipts` (`crates/kernel/chio-kernel/src/kernel/dispatch.rs:482`)
appends at line 501 through `append_child_receipt_to_local_log` (dispatch.rs:513).

Reads are O(n) linear scans under the mutex:

```rust
// dispatch.rs:38
pub(crate) fn has_local_receipt_id(&self, receipt_id: &str) -> bool {
    let chio_receipt_match = match self.receipt_log.lock() {
        Ok(log) => log.receipts().iter().any(|receipt| receipt.id == receipt_id),
        Err(poisoned) => poisoned.into_inner().receipts().iter()
            .any(|receipt| receipt.id == receipt_id),
    };
    // ... then the same scan over child_receipt_log
}
```

`local_receipt_artifact` (dispatch.rs:67) is the clone-on-match variant. Both run on
the production governed call-chain path: `governed_validation.rs:579` calls
`local_receipt_artifact`, `governed_validation.rs:1099` calls `has_local_receipt_id`.
`KernelConfig` already carries `allow_ephemeral_receipt_log: bool`
(kernel_struct.rs:46), which today only decides whether a mirror-only deployment is
legal; there is no capacity knob.

### Federation caches (F10)

```rust
// kernel_struct.rs:225-231
/// Locally-signed dual receipts, indexed by ChioReceipt.id.
/// ... Kept in-memory; persistent storage plugs in via the federation-state APIs.
pub(super) federation_dual_receipts:
    DashMap<String, chio_federation::bilateral::DualSignedReceipt>,
/// DSSE signature-slice envelopes, indexed by ChioReceipt.id.
pub(super) federation_dsse_envelopes:
    DashMap<String, chio_federation::bilateral_dsse::DsseEnvelope>,
```

The only writer is the co-sign hook at
`crates/kernel/chio-kernel/src/kernel/construction.rs:885-888`
(`insert(receipt.id.clone(), ...)`); the only readers are clone-on-get accessors
`dual_signed_receipt` (construction.rs:707) and `federation_dsse_envelope`
(construction.rs:716). No `remove`, `retain`, `clear`, or `drain` exists on either
map. `RetentionConfig` (`crates/kernel/chio-kernel/src/receipt_store.rs:16-37`)
governs only the durable receipt store, not these maps.

### Velocity buckets (F38)

```rust
// crates/guards/chio-guards/src/velocity.rs:128-132
pub struct VelocityGuard {
    invocation_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    spend_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    config: VelocityConfig,
}
```

`evaluate` (velocity.rs:150) inserts via `entry(key).or_insert_with(...)` at 164-166
and 180-182, keyed by `(ctx.request.capability.id.clone(), grant_index)`. No
`retain`/`remove`/`clear` anywhere in the file. A full-and-idle bucket is
semantically identical to a fresh one, so eviction is lossless.

### Federation admission rate limiter (F39, F21 rate-limiter half)

```rust
// crates/platform/chio-control-plane/src/trust_control/service_types/state.rs:96-99
pub(crate) struct FederationAdmissionRateLimiter {
    attempts: HashMap<String, Vec<u64>>,
}
```

`check_and_record` (state.rs:102) builds `key = format!("{policy_id}:{subject_key}")`
(line 109), does `self.attempts.entry(key).or_default()` (111), prunes the inner
`Vec` with `retain` (112), and `push`es the new timestamp (129). The inner `Vec` is
trimmed to the window; the map key is never removed. This is the trust-control
leader's process-lifetime state.

### Per-tenant concurrency table (F12)

```rust
// crates/protocol/chio-tower/src/kernel_service.rs:24
pub const DEFAULT_MAX_TENANT_CONCURRENCY_BUCKETS: usize = 1024;
```

`service_for_tenant` (kernel_service.rs:235) holds
`tenants: Arc<Mutex<HashMap<TenantId, TenantBucketService<S>>>>` (226) and returns
`KernelServiceError::Overloaded` when `tenants.len() >= self.max_tenants` and the
tenant is absent (242-244); entries are only ever `or_insert_with` (246-253), never
removed. `KernelServiceError::Overloaded` already exists (kernel_service.rs:74).

### Session journal (F21 journal half)

```rust
// crates/platform/chio-http-session/src/lib.rs:159-168
struct JournalInner {
    entries: Vec<JournalEntry>,
    data_flow: CumulativeDataFlow,
    tool_sequence: Vec<String>,
    tool_counts: HashMap<String, u64>,
}
```

`record` pushes to `tool_sequence` and `entries` unconditionally (lib.rs:309-313).
`tool_sequence()` (335), `tool_counts()` (341), and `entries()` (358) clone whole
collections under the lock; `snapshot()` (329) and `recent_entries(n)` (364) already
exist as the bounded read path. `SessionJournalError` is the typed error.

### Stream materialization (F06)

```rust
// crates/kernel/chio-kernel/src/runtime.rs:128-130
pub struct ToolCallStream {
    pub chunks: Vec<ToolCallChunk>,
}
// runtime.rs:303
async fn invoke_stream(&self, tool_name: &str, arguments: serde_json::Value,
    nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
) -> Result<Option<ToolServerStreamResult>, KernelError> { ... }
```

`dispatch_tool_call_with_cost_after_nonce_check` (dispatch.rs:448) awaits the fully
materialized stream at 461-466 before any limit runs. `apply_stream_limits`
(`crates/kernel/chio-kernel/src/kernel/responses/finalization.rs:198`) calls
`truncate_stream_to_byte_limit` (defined in
`crates/kernel/chio-kernel/src/receipt_support/receipt_content.rs:64`, invoked at
finalization.rs:217); both run only at finalize.
`DEFAULT_MAX_STREAM_TOTAL_BYTES = 256 MiB` and
`DEFAULT_MAX_STREAM_DURATION_SECS = 300` (kernel_struct.rs:119-120); the live knobs
are `config.max_stream_total_bytes` / `config.max_stream_duration_secs`
(kernel_struct.rs:33-36).

### The in-tree bounded precedent

`McpRateLimiter` already implements the target pattern
(`crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs:9-63`):
`MCP_RATE_LIMIT_MAX_KEYS = 4_096`, and `check` (line 30) does a retain-then-cap
eviction (38-43) before inserting. This RFC generalizes that precedent into a
reusable abstraction and applies it uniformly.

## Design

### 1. The reusable abstractions: `Ring`, `BoundedMap`, and the size gauge

New crate `crates/core/chio-bounded` (roughly 400 LOC including tests). No
dependency on kernel or federation crates, so every serving crate can use it. It
exports three items.

A size gauge newtype so the metric is inseparable from the structure:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Live entry-count gauge for a bounded structure. Cloneable handle so a
/// telemetry exporter (RFC-0009) can read the count without locking the
/// structure that owns it.
#[derive(Clone, Debug, Default)]
pub struct SizeGauge(Arc<AtomicUsize>);

impl SizeGauge {
    pub fn new() -> Self {
        Self(Arc::new(AtomicUsize::new(0)))
    }
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    fn set(&self, value: usize) {
        self.0.store(value, Ordering::Relaxed);
    }
}
```

A fixed-capacity ring for append-only mirrors (`capacity == 0` means "disabled",
the correct default when a durable store is authoritative):

```rust
use std::collections::VecDeque;

pub struct Ring<T> {
    buf: VecDeque<T>,
    capacity: usize,
    gauge: SizeGauge,
}

impl<T> Ring<T> {
    pub fn with_capacity(capacity: usize, gauge: SizeGauge) -> Self {
        Self { buf: VecDeque::new(), capacity, gauge }
    }

    /// Push, evicting the oldest entry when at capacity. Returns the evicted
    /// item (if any) so callers may act before it drops. Never grows past
    /// `capacity`; a zero capacity stores nothing and hands the item straight
    /// back to the caller.
    pub fn push(&mut self, item: T) -> Option<T> {
        if self.capacity == 0 {
            return Some(item);
        }
        let evicted = if self.buf.len() >= self.capacity {
            self.buf.pop_front()
        } else {
            None
        };
        self.buf.push_back(item);
        self.gauge.set(self.buf.len());
        evicted
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.buf.iter()
    }
}
```

A capacity-bounded, optionally TTL-swept map for caches:

```rust
use std::collections::HashMap;
use std::hash::Hash;

pub struct BoundedMap<K, V> {
    inner: HashMap<K, Timestamped<V>>,
    /// `(key, epoch)` in insertion order. Re-inserting a key pushes a new
    /// `(key, epoch)` and leaves the old pair behind as a stale duplicate;
    /// eviction skips any pair whose epoch is not the key's current
    /// `order_epoch`, so a refreshed key is never evicted before older keys.
    order: VecDeque<(K, u64)>,
    capacity: usize,
    idle_ttl_secs: u64,
    sweep_interval: usize,
    inserts_since_sweep: usize,
    next_epoch: u64,
    gauge: SizeGauge,
}

struct Timestamped<V> {
    value: V,
    last_seen_secs: u64,
    /// Epoch of this key's NEWEST occurrence in `order`. Set on every insert so
    /// `evict_oldest` can tell the live (newest) pair from stale duplicates.
    order_epoch: u64,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    pub fn new(capacity: usize, idle_ttl_secs: u64, gauge: SizeGauge) -> Self {
        Self {
            inner: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            idle_ttl_secs,
            sweep_interval: 256,
            inserts_since_sweep: 0,
            next_epoch: 0,
            gauge,
        }
    }

    /// Insert. Returns any (key, value) evicted for capacity so the caller can
    /// persist-before-drop. Runs an amortized idle sweep every `sweep_interval`
    /// inserts (no background task). A zero capacity disables the cache: the
    /// pair is handed straight back, mirroring `Ring`.
    pub fn insert(&mut self, key: K, value: V, now_secs: u64) -> Option<(K, V)> {
        if self.capacity == 0 {
            return Some((key, value));
        }
        self.inserts_since_sweep = self.inserts_since_sweep.saturating_add(1);
        if self.inserts_since_sweep >= self.sweep_interval {
            self.sweep_idle(now_secs);
            self.inserts_since_sweep = 0;
        }
        let mut evicted = None;
        if !self.inner.contains_key(&key) && self.inner.len() >= self.capacity {
            evicted = self.evict_oldest();
        }
        // Stamp this insertion with a fresh epoch and record it as the key's
        // newest occurrence. Re-inserting a live key refreshes its recency: the
        // new `(key, epoch)` goes to the back and the entry's `order_epoch`
        // advances, so the key's OLD pair in `order` is now stale and eviction
        // will skip it. (`next_epoch` is a monotonic u64 counter; it cannot
        // realistically wrap.)
        let epoch = self.next_epoch;
        self.next_epoch = self.next_epoch.wrapping_add(1);
        self.inner.insert(
            key.clone(),
            Timestamped { value, last_seen_secs: now_secs, order_epoch: epoch },
        );
        self.order.push_back((key, epoch));
        // Re-inserting a live key leaves its old `(key, epoch)` in `order` as a
        // stale duplicate. Compact when duplicates dominate so `order` stays
        // O(capacity) and the bounded invariant holds for the map's own
        // bookkeeping, not just its values.
        if self.order.len() > self.capacity.saturating_mul(2) {
            self.compact_order();
        }
        self.gauge.set(self.inner.len());
        evicted
    }

    /// Rebuild `order` keeping only each live key's NEWEST occurrence (the pair
    /// whose epoch matches the entry's current `order_epoch`; every older pair
    /// for that key carries a smaller epoch and is dropped). Amortized O(1) per
    /// insert because it runs at most once per `capacity` inserts.
    fn compact_order(&mut self) {
        let mut compacted = VecDeque::with_capacity(self.inner.len());
        while let Some((key, epoch)) = self.order.pop_back() {
            if self
                .inner
                .get(&key)
                .is_some_and(|entry| entry.order_epoch == epoch)
            {
                compacted.push_front((key, epoch));
            }
        }
        self.order = compacted;
    }

    pub fn get(&mut self, key: &K, now_secs: u64) -> Option<&V> {
        match self.inner.get_mut(key) {
            Some(entry) => {
                entry.last_seen_secs = now_secs;
                Some(&entry.value)
            }
            None => None,
        }
    }

    fn sweep_idle(&mut self, now_secs: u64) {
        if self.idle_ttl_secs == 0 {
            return;
        }
        let floor = now_secs.saturating_sub(self.idle_ttl_secs);
        self.inner.retain(|_, entry| entry.last_seen_secs > floor);
        self.order.retain(|(k, _)| self.inner.contains_key(k));
        self.gauge.set(self.inner.len());
    }

    /// Evict the genuinely-oldest STILL-LIVE key. Popping from the front, skip
    /// any pair that is NOT its key's newest occurrence (its epoch differs from
    /// the entry's current `order_epoch`): those are stale duplicates left by a
    /// later re-insertion, and removing the key on such a pair would evict a
    /// recently-refreshed entry while a truly-older key survives (for a
    /// rate-limit bucket that would reset active state). Only remove a key when
    /// the front pair IS its newest occurrence, which makes it the genuine LRU
    /// victim.
    fn evict_oldest(&mut self) -> Option<(K, V)> {
        while let Some((candidate, epoch)) = self.order.pop_front() {
            match self.inner.get(&candidate) {
                // Stale duplicate: a newer occurrence of this key is still
                // queued behind us. Drop this pair and keep looking.
                Some(entry) if entry.order_epoch != epoch => continue,
                // Newest occurrence of a live key: the true oldest, evict it.
                Some(_) => {
                    if let Some(entry) = self.inner.remove(&candidate) {
                        self.gauge.set(self.inner.len());
                        return Some((candidate, entry.value));
                    }
                }
                // Key already gone (swept or previously evicted): skip.
                None => continue,
            }
        }
        None
    }
}
```

Eviction order is oldest by most-recent INSERT: re-inserting a key refreshes its
recency (a fresh epoch moves it to the back and its now-stale `order` pair is
skipped at eviction), while `get` refreshes only the idle timestamp and does not
reorder. This is approximate LRU, sufficient here because every `BoundedMap` in
this RFC fronts a durable authoritative store or is a rate-limit table whose
evicted entry is semantically fresh; strict recency ordering buys nothing for
either. The teeth test that guards this eviction fix: fill to capacity, refresh
the oldest key by re-inserting it, then insert a new key at capacity and assert
the refreshed key SURVIVES while the genuinely-oldest (un-refreshed) key is the
one evicted (a count- or first-copy-only eviction would wrongly drop the
refreshed key).

No `.unwrap()`/`.expect()`; poison is handled at each call site by the existing
`match lock() { Ok, Err(poisoned) => poisoned.into_inner() }` idiom already used
throughout the kernel.

### 2. The ENOMEM analog: a typed load-shed error

Add one variant to `KernelError`
(`crates/kernel/chio-kernel/src/kernel/error.rs:29`) plus its mandatory `report()`
arm (error.rs:216, every variant has one), and a small resource enum:

```rust
/// Which bounded resource shed. Included in the receipt and the structured
/// error report so operators can see which policy fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadResource {
    ReceiptMirror,
    FederationCache,
    VelocityBuckets,
    AdmissionKeys,
    ConcurrencyBuckets,
    SessionJournal,
    StreamBytes,
    Allocation,
}

// within enum KernelError:
#[error("kernel overloaded: {resource:?} at capacity")]
Overloaded { resource: OverloadResource },
```

`report()` arm (returns a `StructuredErrorReport`, code namespace `CHIO-KERNEL-*`):

```rust
Self::Overloaded { resource } => self.report_with_context(
    "CHIO-KERNEL-OVERLOADED",
    serde_json::json!({ "resource": format!("{resource:?}") }),
    "The kernel shed load to stay within its memory budget. Retry with backoff; \
     if sustained, raise the process memory budget or scale out.",
),
```

Fail-closed posture: `Overloaded` is a deny. It never admits a tool call, it never
grows a collection, and it maps cleanly onto the transport-layer
`KernelServiceError::Overloaded` (kernel_service.rs:74), which already surfaces as a
shed/429 at the tower edge. This is the local, early, graceful stop the lens
requires: a request is refused at the door instead of the process dying at the
allocator.

### 3. Fallible allocation on the wire-sized hot path (F06)

The stream accumulator is the only hot path that sizes a buffer from
attacker-influenced wire input. One placement fact matters for buildability: kernel
dispatch never accumulates chunks itself. `dispatch_tool_call_with_cost_after_nonce_check`
(dispatch.rs:448) awaits `ToolServerConnection::invoke_stream` (runtime.rs:303),
which hands back an already materialized `ToolServerStreamResult`; the accumulation
loops live in the connection implementations (in-tree: `process_sse_event`,
`crates/protocol/chio-a2a-adapter/src/transport.rs:187`, which already caps chunk
count via `MAX_SSE_CHUNKS` but not total bytes). The fix therefore has two halves.

First, export a fallible push helper from the kernel runtime module beside
`ToolCallStream` and require every in-tree accumulation site to use it (connection
implementations already return `KernelError` from `invoke_stream`, so the error type
composes):

```rust
fn push_chunk_bounded(
    acc: &mut Vec<ToolCallChunk>,
    running_bytes: &mut u64,
    chunk: ToolCallChunk,
    max_total_bytes: u64,
) -> Result<(), KernelError> {
    let chunk_bytes = canonical_len(&chunk)? as u64;
    let next = running_bytes.saturating_add(chunk_bytes);
    if max_total_bytes > 0 && next > max_total_bytes {
        return Err(KernelError::Overloaded { resource: OverloadResource::StreamBytes });
    }
    acc.try_reserve(1).map_err(|_| {
        KernelError::Overloaded { resource: OverloadResource::Allocation }
    })?;
    acc.push(chunk);
    *running_bytes = next;
    Ok(())
}
```

`canonical_len` is the existing per-chunk measurement, `canonical_json_bytes(&chunk.data)`,
shared with `truncate_stream_to_byte_limit` (receipt_content.rs:64), so the
at-arrival count and the finalize-time count agree by construction. `try_reserve`
returns `Result<(), TryReserveError>`, so under strict overcommit (see the
deployment section) a failed allocation becomes a typed deny rather than an abort.

Second, the kernel enforces the same limit at the seam it owns: size the returned
stream immediately after the `invoke_stream` await (dispatch.rs:461-466), before any
guard or serde copy, and deny with `Overloaded { StreamBytes }` on breach. This
shifts the byte-limit decision from finalize (finalization.rs:198) to the earliest
point the kernel can observe the stream, and the helper above keeps a conforming
connector from ever materializing more than `max_stream_total_bytes` in the first
place. The redundant second `serde_json` copy in `apply_post_invocation_pipeline`
(finalization.rs:74) is taken only when a post-invocation guard is installed; leave
that path alone (it already early-returns when the pipeline is empty). Note: the
streaming trait still returns a fully materialized `ToolServerStreamResult`; a fully
incremental per-chunk callback is the larger follow-on and is out of scope here.
This RFC bounds the accumulation loops we ship and adds the kernel-side check, which
is the part inside our TCB.

### 4. Applying the invariant to each verified structure

| Structure | Location | Policy | Config knob (default) | Gauge label |
| --- | --- | --- | --- | --- |
| `ReceiptLog` | mod.rs:419 | Ring; lookups route through the store when configured | `receipt_mirror_capacity` (4096; 0 when durable store present) | `receipt_mirror` |
| `ChildReceiptLog` | mod.rs:451 | Ring | `receipt_mirror_capacity` | `child_receipt_mirror` |
| `federation_dual_receipts` | kernel_struct.rs:225 | `BoundedMap` LRU + idle-sweep; new `FederationArtifactStore` authoritative when configured | `federation_cache_capacity` (8192), `federation_cache_idle_ttl_secs` (3600) | `federation_dual_receipts` |
| `federation_dsse_envelopes` | kernel_struct.rs:230 | same | same | `federation_dsse_envelopes` |
| `VelocityGuard` buckets | velocity.rs:129-130 | idle-sweep (drop full-and-idle) + key cap | `velocity_bucket_cap` (65536) | `velocity_buckets` |
| `FederationAdmissionRateLimiter.attempts` | state.rs:98 | drop-empty on retain + key cap (mirror `McpRateLimiter`) | `admission_key_cap` (4096) | `admission_keys` |
| `TenantConcurrencyLimitService.tenants` | kernel_service.rs:226 | idle reap + distinct "table full" error | `max_tenants` (exists, 1024) | `tenant_buckets` |
| `SessionJournal` `entries`/`tool_sequence` | lib.rs:161-165 | ring + cumulative stats; `recent_entries`/`snapshot` getters | `journal_entry_cap` (4096) | `session_journal` |
| stream `Vec<ToolCallChunk>` | runtime.rs:129 | incremental accounting + `try_reserve` + deny-at-cap | `max_stream_total_bytes` (exists, 256 MiB) | `stream_bytes` |

Specifics that are not mechanical:

- Receipt mirrors (F03, F25). Store-authoritative reads first. Change
  `has_local_receipt_id`/`local_receipt_artifact` (dispatch.rs:38, 67) to query the
  durable `receipt_store` by id when `self.receipt_store.is_some()`, falling back to
  the ring only when `allow_ephemeral_receipt_log` and no store exists. This removes
  the O(n) scan from the governed path (governed_validation.rs:579, 1099) entirely in
  durable deployments and caps the mirror otherwise. The by-id read path already
  half-exists: `ReceiptStore::load_chio_receipt(&self, receipt_id: &str) ->
  Result<Option<ChioReceipt>, ReceiptStoreError>` (receipt_store.rs:189) is a
  provided trait method defaulting to `Ok(None)`, and the SQLite store overrides it
  (`crates/platform/chio-store-sqlite/src/receipt_store/support/store_impl.rs:202`).
  Two small additions remain: a companion `load_child_receipt(&str)` (both lookup
  paths also scan the child log, and `local_receipt_artifact` returns
  `LocalReceiptArtifact::Child`), and overriding both loaders in any store used for
  a store-authoritative deployment. A store left on the `Ok(None)` default makes a
  lookup miss, which under the fail-closed posture is a deny of the dependent
  call-chain claim, never a false allow.
- Federation caches (F10). The map comment at kernel_struct.rs:223 says "persistent
  storage plugs in via the federation-state APIs already in chio-federation", but no
  such store API exists in-tree today (chio-federation defines the artifact types,
  not their persistence); this RFC adds the seam. Define a small additive trait,
  `FederationArtifactStore`, with put/get for `DualSignedReceipt` and `DsseEnvelope`
  keyed by `ChioReceipt.id`, with an SQLite implementation beside the existing
  receipt store in chio-store-sqlite. The co-sign hook (construction.rs:885-888)
  then becomes: write both artifacts to the store first, then `BoundedMap::insert`
  into the in-memory cache (the eviction return value is dropped safely because the
  durable copy exists). Accessors (construction.rs:707, 716) check the cache, then
  fall through to the store on a miss. When no store is configured, the cache keeps
  its cap and eviction is lossy for co-sign evidence older than the cache window;
  deployments that require durable bilateral evidence must configure the store
  (fail-closed deployments already require a durable receipt store, so this is the
  same posture extended to co-sign artifacts).
- Velocity (F38). Wrap both maps so `evaluate` (velocity.rs:150) sweeps buckets whose
  `last_refill` is older than `window_secs` (a full-and-idle bucket is a fresh bucket)
  every N inserts, and caps total keys with oldest-eviction. Deny remains deny; the
  only change is that stale keys age out.
- Admission limiter (F39, F21). After the `retain` (state.rs:112), remove the map key
  when the pruned `Vec` is empty (occupied-entry API), and cap total keys at
  `admission_key_cap` with oldest-eviction, mirroring `McpRateLimiter`. A fresh
  subject then costs nothing once its window empties, and a distinct-subject flood
  saturates instead of growing. Distinguish "key table full" from per-subject limit in
  the returned status for observability.
- Tenant table (F12). Track last-use per tenant and reap buckets whose
  `ConcurrencyLimit` is fully idle (or key by a bounded LRU), so an old tenant ages out
  instead of permanently blocking a new one. Return a distinct "bucket table full"
  variant separate from per-tenant `Overloaded`.
- Session journal (F21). Add `journal_entry_cap` with ring semantics: keep cumulative
  `data_flow`/`tool_counts` (already cumulative) and fold `head_hash` chaining across
  evicted prefixes so the chain stays verifiable; replace whole-vector clone getters at
  guard call sites with the existing `snapshot()` (lib.rs:329) and `recent_entries(n)`
  (lib.rs:364).

### 5. Per-process RSS ceiling wired to cgroup MemoryMax

Add a memory-budget config to `KernelConfig` (kernel_struct.rs:10). The declared
soft ceiling is the in-process analog of the cgroup hard limit: the kernel sheds
(returns `Overloaded`) before the OS OOM-kills it.

```rust
#[derive(Debug, Clone)]
pub struct MemoryBudgetConfig {
    /// Bounded-structure capacities (fields above map here).
    pub receipt_mirror_capacity: usize,
    pub federation_cache_capacity: usize,
    pub federation_cache_idle_ttl_secs: u64,
    pub velocity_bucket_cap: usize,
    pub admission_key_cap: usize,
    pub journal_entry_cap: usize,
    /// Process RSS soft ceiling. When set and exceeded, new admissions shed with
    /// `KernelError::Overloaded { resource: Allocation }`. Set to roughly 85-90%
    /// of the cgroup `memory.max` so the graceful stop fires before the kill.
    pub rss_soft_limit_bytes: Option<u64>,
    /// How often the RSS sampler reads /proc/self/statm.
    pub rss_sample_interval_secs: u64,
}
```

A lightweight sampler (one task, not per-request) reads `/proc/self/statm`
(resident pages times page size) every `rss_sample_interval_secs` and flips an
`AtomicBool` shed flag when RSS crosses the soft limit. The evaluate entry points
already load one atomic for the emergency kill switch (`emergency_stopped`,
kernel_struct.rs:183); the RSS shed flag is checked in the same place, so the hot
path adds one relaxed atomic load. On non-Linux hosts the sampler is a no-op and the
soft limit is inert (the cgroup and try_reserve backstops still apply).

`MemoryBudgetConfig` is added as one field on `KernelConfig`. Because `KernelConfig`
is built by struct literal (for example `tests/provenance_otel.rs:54` and
`benches/fixtures/dispatch_request_fixture.rs:307`), the field ships with
a documented `MemoryBudgetConfig::defaults()` and the in-repo literal constructors are
updated to `memory_budget: MemoryBudgetConfig::defaults()`. See Migration for the
staged default flip.

### 6. Size-metric convention (feeds RFC-0009)

Every bounded structure owns a `SizeGauge` handed in at construction. The convention
RFC-0009 consumes:

- Gauge name `chio_mem_entries{structure="<label>", tenant?="<id>"}` reports current
  entry count; the `<label>` values are the last column of the table above.
- A companion static `chio_mem_capacity{structure="<label>"}` reports the cap, so a
  saturation ratio is derivable without hardcoding limits in dashboards.
- `chio_process_rss_bytes` and `chio_process_rss_soft_limit_bytes` for the ceiling.
- A shed counter `chio_overload_total{resource="<OverloadResource>"}` increments on
  every `KernelError::Overloaded`, so a rising shed rate is the early warning that a
  cap is mis-sized, not a silent stall.

RFC-0009 defines the exporter; this RFC defines the shape and guarantees the gauges
exist and are accurate (the loom and property tests below prove accuracy).

## Wire, schema, and receipt impact

- No change to signed receipt bodies, capability tokens, or the DSSE envelope wire
  form. `DualSignedReceipt` and `DsseEnvelope` are unchanged; only their in-memory
  lifetime changes.
- A shed decision that denies a mediated call produces the normal signed deny
  receipt. The deny reason string carries `CHIO-KERNEL-OVERLOADED` and the
  `OverloadResource`; this is metadata inside an existing receipt kind, not a new
  receipt kind. Any receipt or structured-error payload that is signed or exported
  continues to be canonical JSON per RFC 8785.
- No schema files under `spec/schemas` change. The new metric names are telemetry,
  not protocol, and are specified by RFC-0009.

## Migration and compatibility

- New `chio-bounded` crate is additive.
- `KernelError::Overloaded` is a new non-exhaustive-safe variant; the `KernelError`
  enum is matched exhaustively inside the kernel, so the same change adds the arms
  (including `report()`). External matchers should already have a wildcard given the
  enum size.
- `MemoryBudgetConfig` ships in two stages to keep the invariant fail-closed without
  breaking existing embedders:
  1. Stage A (this RFC): default caps applied, but `rss_soft_limit_bytes` defaults to
     `None` and the receipt mirror keeps its current capacity when no durable store is
     present. Behavior for a correctly configured durable deployment is strictly
     better (bounded, faster lookups); a mirror-only deployment is unchanged.
  2. Stage B (follow-on, after one soak cycle): flip the receipt mirror to
     store-authoritative-by-default and set a conservative `rss_soft_limit_bytes` from
     the cgroup, behind a release note.
- The federation artifact store is a new, additive seam (the map comment at
  kernel_struct.rs:223 names the intent, but the API does not exist in-tree yet; see
  the F10 bullet in section 4). No data migration is needed because the maps are
  process-local caches; the store starts empty and fills from the co-sign hook.
- Tenant-table and session-journal changes are library-internal; no in-repo binary
  wires them today (F12, F21 journal half), so there is no live migration surface,
  only corrected library behavior for future integrators.

## Test and verification plan

- Unit (PR gate, seconds): `Ring::push` never exceeds capacity and returns the
  evicted item; `BoundedMap::insert` evicts oldest at cap and returns it;
  `sweep_idle` drops entries past TTL and keeps fresh ones; `SizeGauge` equals live
  `len` after each op.
- Property (PR gate, seconds; `proptest`): for an arbitrary interleaving of
  insert/get/sweep, `gauge.get() == inner.len()` and `inner.len() <= capacity` always
  hold (the size-accounting-is-trustworthy invariant from the lens). For the admission
  limiter, prove that after any sequence, `attempts.len()` is bounded by
  `admission_key_cap` and an empty-window key is absent.
- Loom (nightly, minutes): two threads racing `insert` and `get` on a
  `Mutex<BoundedMap>` observe no lost gauge update and no capacity breach; models the
  velocity-guard and admission-limiter concurrency.
- Chaos (nightly, PLAN-load-chaos harness): kill the kernel mid-`record_chio_receipt`,
  restart, assert the durable store is authoritative and the rebuilt ring starts empty
  with no lost committed receipt (ties to ADR-0013 durability semantics). Kill the
  trust-control leader under an admission flood and assert the limiter map is bounded
  after restart.
- Soak (weekly, PLAN-load-chaos harness, 24h): drive synthetic mixed traffic (governed
  calls, federated co-signs, fresh-subject admission attempts, distinct tenant ids)
  and assert RSS plateaus, every `chio_mem_entries` gauge stays under its cap, and
  `chio_overload_total` stays at zero under nominal load and rises only when a cap is
  deliberately undersized. This soak is the specific test that proves the OOM failure
  mode is closed.
- Regression: a targeted test that runs the governed call-chain lookup
  (governed_validation.rs:579, 1099) against a kernel with a large durable store and
  asserts lookup latency is flat in store size (no O(n) mirror scan).

## Acceptance criteria

- Every structure in the section-4 table has a capacity policy and a `SizeGauge`;
  a repo test enumerates them and fails if a new long-lived collection is added
  without both (a lightweight registry the soak also reads).
- Under the 24h soak, kernel and trust-control RSS reach a steady plateau; no gauge
  exceeds its configured cap; no process is OOM-killed.
- The governed call-chain lookup no longer scans an unbounded `Vec`; latency is
  independent of process age and receipt count in durable deployments.
- An oversized stream is refused with `KernelError::Overloaded { StreamBytes }` (or
  `Allocation` under strict overcommit): in-tree accumulators never materialize more
  than `max_stream_total_bytes` of chunk data, and the kernel denies at the
  `invoke_stream` await, before any guard or serde copy, for any connector that does.
- A fresh-subject admission flood saturates the limiter at `admission_key_cap`
  instead of growing without bound, and an emptied-window key leaves no residue.
- `KernelError::Overloaded` denies (never admits) and maps to the transport shed
  path; `cargo clippy --workspace -- -D warnings` passes (no `unwrap`/`expect` in the
  new code).

## Risks and alternatives

- Cap too small drops useful cache/mirror entries and raises store reads or shed
  rate. Mitigation: the `chio_overload_total` counter and per-structure gauges make
  under-sizing observable before it hurts; defaults are generous and the RSS ceiling
  is the real backstop.
- Store-authoritative lookups add a durable read on the governed path. This is a net
  latency win versus an O(n) mirror scan that grows unbounded, but it does move cost
  onto the store; the store is already indexed by receipt id, so the read is a point
  lookup.
- Amortized in-line sweep (every N inserts) adds a bounded O(n) pass occasionally
  rather than a background task. Chosen over a background reaper to avoid a new task,
  a new shutdown join, and cross-thread coordination; it matches the `McpRateLimiter`
  precedent. Rejected alternative: a background sweeper task per map (more moving
  parts, more shutdown surface).
- Rejected: pulling `lru` or `moka` as a dependency. `BoundedMap` is small, has no
  `.unwrap()`, and the eviction return value ("persist before drop") is a semantic we
  need that a generic LRU does not give directly. `chio-bounded` also has zero heavy
  deps, which matters for a TCB crate.
- Rejected: a global allocator hook that fails allocations at a byte budget. Too
  blunt (it cannot distinguish the receipt mirror from a transient serde buffer) and
  it interacts badly with fail-closed semantics. The per-structure cap plus
  `try_reserve` on the one wire-sized path plus the RSS soft limit is more precise.

## Rollout and sequencing

1. Land `crates/core/chio-bounded` with `Ring`, `BoundedMap`, `SizeGauge`, and their
   unit/property/loom tests. No behavior change anywhere else.
2. Add `KernelError::Overloaded` and `OverloadResource` with the `report()` arm.
3. Apply the caps structure by structure, each behind its config knob defaulted to
   today-or-better behavior (Stage A): receipt mirrors and store-authoritative
   lookups (F03, F25) first (highest blast radius, production path), then federation
   caches (F10), then the admission limiter (F39, F21), then velocity (F38), then the
   latent tenant table (F12) and session journal (F21).
4. Add the fallible-push accumulation helper, wire the in-tree connector to it, and
   add the kernel-side post-await size check (F06).
5. Land the RSS sampler and `MemoryBudgetConfig`; wire the size gauges to the RFC-0009
   exporter when it lands.
6. Publish the deployment guidance (below) alongside step 5.
7. Stage B default flip after one clean weekly soak cycle.

Dependencies: PLAN-load-chaos must provide the soak and chaos harness before the
soak/chaos acceptance items can gate (that program in turn lists this RFC as a
dependency for its memory assertions; the caps land first, the harness then
exercises them). RFC-0009 consumes the gauges defined here but is not a
blocker for landing the caps; the gauges are usable via `SizeGauge::get` immediately.

## Appendix: OS-level deployment guidance (closes F63)

There is no memory-deployment guidance in `docs/` today; this appendix is the
canonical source and should be linked from the release runbook. The goal, following
the Ubicloud PostgreSQL/OOM lesson, is that allocations fail early and locally
(returning to our `try_reserve` and shed paths) rather than the OOM killer picking a
victim later.

- cgroup v2 (per kernel process and per trust-control process):
  - `memory.max` is the hard ceiling (OOM-kill boundary). Size it to the host with
    headroom for the OS page cache.
  - `memory.high` is the soft throttle; set it below `memory.max` so the process is
    reclaim-throttled before it is killed. Set `MemoryBudgetConfig.rss_soft_limit_bytes`
    to roughly `memory.high`, so the in-process graceful shed fires first.
- Kernel VM overcommit (strict, mirroring the article's recommendation):
  - `vm.overcommit_memory = 2` and a tuned `vm.overcommit_ratio` (or
    `vm.overcommit_kbytes`) so `malloc`/`mmap` fail at allocation time. Strict
    overcommit is what makes `Vec::try_reserve` return `Err` instead of the kernel
    handing out memory it cannot back and OOM-killing later.
- OOM score:
  - Raise `oom_score_adj` for the untrusted agent sidecar and lower it for the
    kernel TCB and trust-control process, so if the OS backstop ever fires it takes
    the least-trusted process first, not the mediator.
- ulimits:
  - `RLIMIT_AS` as a coarse per-process address-space backstop below `memory.max`.
- systemd unit equivalents for operators not managing cgroups directly:
  - `MemoryMax=`, `MemoryHigh=`, `OOMScoreAdjust=`, and `LimitAS=`.

Set these together: strict overcommit turns allocation failure into a typed
`Overloaded` deny, the soft limit and `memory.high` make the process shed before it
is throttled to death, and the OOM score ordering guarantees the mediator is the last
thing standing if every earlier line of defense is misconfigured.
