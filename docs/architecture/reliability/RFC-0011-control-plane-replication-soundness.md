# RFC-0011: Control-plane replication soundness: budgeted pullers, cursor monotonicity, honest quorum

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0006 (monetary budget semantics)
- Depends on: none
- Closes findings: F14, F15, F16, F20 (see ./README.md and the readiness review)

## Summary

The trust control-plane runs a homegrown cluster replication protocol in
`crates/platform/chio-control-plane/src/trust_control/cluster/` that makes a
durability claim it cannot back. The budget-write quorum witness compares a
locally-allocated `usage.seq` against per-peer pull cursors drawn from a
different sequence domain, so it reports `quorum_committed = true` for writes
that never left the node (F16, silent accounting corruption on the money
authority). The pullers that feed those cursors trust peer-supplied `seq` with
no monotonicity or per-round budget, so a replaying or buggy peer spins a puller
forever and grows the local store without bound (F15). Every budget-write
request drives its own full cluster sync inline while polling for quorum, so one
slow peer collapses budget-write latency process-wide (F14). And the status
path materializes every store in memory on every tick while the puller
deserializes peer responses with no size cap (F20). This RFC makes replication
sound: per-round budgets and strict cursor monotonicity in every puller loop
(non-advancing pages mark the peer unhealthy, fail-closed), explicit per-origin
replication acks so the quorum witness reflects real replication, a decoupling
of budget-write handlers from inline syncing via a watch of background cursor
advancement, and hard caps on snapshot materialization and peer-response
deserialization. The `BudgetReplication.tla` model in the formal-methods plan is
the design proof for the witness change.

## Motivation

The article lens ("overload/crashes must fail early, local, and graceful; know
the blast radius when a component dies mid-operation; internal accounting must
be trustworthy or loudly broken; predictable budgets; durable recovery") is
inverted on the control plane: internal accounting lies (F16), overload is
neither early nor local (F14), a bad peer causes unbounded growth (F15, F20),
and the failure is silent, not loud.

Blast radius, per finding:

- F16 (high, silent accounting corruption). Trigger: any follower-local budget
  write, or any window where two nodes both believe they lead (the homegrown
  reachability election in `compute_cluster_consensus_locked` re-derives the
  leader from a sorted candidate list each tick). Effect: the witness sees an
  unrelated peer event whose `seq` is at or above the local write's `seq`,
  counts the peer as a witness, and returns `quorum_committed = true` for a
  single-node write. Impact: the HTTP response tells the kernel the budget
  mutation is durably quorum-committed; if that node then dies the charge, hold,
  or release is lost, spend under-counts, and a capability spending limit is
  exceeded with no error surfaced. This defeats even the ADR-0006 HA overrun
  bound, which assumes writes actually replicate and merge.
- F15 (high, unbounded growth / wedge). Trigger: an authenticated peer whose
  delta endpoint always returns a non-empty page (replayed signed receipt page,
  repeating `mutation_events`, or fabricated revocation rows). Effect: the puller
  loop never sees an empty page and spins inside `spawn_blocking`; the background
  round never completes so replication from all peers stalls; the revocation
  stream inserts unbounded distinct rows into local SQLite. Impact: one bad
  replica wedges the whole node (budget writes never respond, replication halts,
  disk fills), recoverable only by removing the peer and restarting.
- F14 (high, latency collapse). Trigger: one slow-but-not-partitioned peer while
  N budget-write requests are in flight. Effect: each request independently runs
  `sync_cluster_once` back-to-back inside `spawn_blocking`, each round paying up
  to the 15s `cluster_status` timeout on the dead peer; N concurrent writes
  multiply into N whole-cluster sync storms. Impact: control-plane-wide
  budget-write latency collapse and 503s from a single slow peer; sustained load
  drains the tokio blocking pool and starves the background sync loop itself.
- F20 (high, steady-state OOM). Trigger: normal append-only store growth plus
  routine status polling. Effect: `handle_internal_cluster_status` calls
  `cluster_replication_heads`, which calls `build_cluster_state_snapshot`, which
  materializes the entire receipt, lineage, revocation, and budget history in
  memory on every tick and discards all but the head seqs; the pulling side
  buffers and deserializes peer responses with no byte cap. Impact: trust-control
  memory and CPU scale with total historical store size on a steady-state path,
  degrading to OOM death of the authority for every kernel; an oversized peer
  body accelerates it.

## Current behavior (verified 2026-07-04)

All paths below are under
`crates/platform/chio-control-plane/src/trust_control/`.

The witness (`cluster/deltas.rs:625-661`, `budget_write_quorum_commit_view_locked`)
compares the local write seq against each peer's pull cursor:

```rust
let committed = peer_state
    .budget_cursor
    .as_ref()
    .map(|cursor| cursor.seq >= budget_seq)
    .unwrap_or(false);
if peer_state.health.is_reachable() && !peer_state.partitioned && committed {
    witness_urls.insert(peer_url.clone());
}
```

`budget_seq` here is the local `usage.seq` returned by `get_usage` after the
write (`budget_handlers.rs:181` for `handle_try_charge_cost`, and
`respond_after_budget_write_quorum_commit` at `budget_handlers.rs:289,369`).
`peer_state.budget_cursor.seq` is our pull position in that peer's delta stream:
it is set by `sync_peer_budgets` (`cluster/deltas.rs:394-420`) and by snapshot
application (`apply_cluster_snapshot`, `snapshots.rs:224`), in both cases from
`budget_cursor_from_event` (`event_seq`, `deltas.rs:808-815`) or
`budget_cursor_from_usage` (`usage.seq`, `deltas.rs:817-824`). Both the local
`usage.seq` and every peer `event_seq`/`usage.seq` are allocated by
`allocate_budget_replication_seq`
(`crates/platform/chio-store-sqlite/src/budget_store/replication.rs:92-101`):

```rust
pub(super) fn allocate_budget_replication_seq(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<u64, BudgetStoreError> {
    let current = current_budget_replication_seq(transaction)?
        .max(max_budget_usage_seq(transaction)?)
        .max(max_budget_mutation_event_seq(transaction)?);
    let next_seq = current.saturating_add(1);
    set_budget_replication_seq(transaction, next_seq)?;
    Ok(next_seq)
}
```

This is a per-node counter. Import raises the local floor to the origin's seq
(`raise_budget_replication_seq_floor`, `replication.rs:103-112`; called from
`upsert_usage_in_transaction` at `budget_store/store.rs:139` and the mutation
import at `store.rs:235`), and local writes allocate above that floor
(`store.rs:1227,1253`). Nothing binds a `seq` to the node that allocated it, so
`cursor.seq >= budget_seq` can hold for two unrelated events. The witness math is
therefore comparing magnitudes across independent sequence domains.

The quorum wait (`cluster/deltas.rs:672-726`) drives a full sync per request:

```rust
pub(crate) async fn wait_for_budget_write_quorum_commit(
    state: &TrustServiceState,
    budget_seq: u64,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    // ...
    let deadline = Instant::now() + timeout;
    loop {
        // check witness ...
        let sync_state = state.clone();
        match tokio::task::spawn_blocking(move || sync_cluster_once(&sync_state)).await {
            /* ... */
        }
        // check witness ...
        if Instant::now() >= deadline { /* 503 */ }   // deltas.rs:715
        tokio::time::sleep(poll_interval).await;
    }
}
```

`budget_write_quorum_commit_timeout` (`deltas.rs:663-670`) clamps the deadline to
`[5s, 30s]`, but it is evaluated only after `sync_cluster_once` returns
(`deltas.rs:715`); a sync that never returns hangs the request with no
server-side timeout. `sync_cluster_once` (`deltas.rs:200-217`) iterates peers
sequentially and `sync_peer` (`deltas.rs:219-222`) skips only peers explicitly
marked `partitioned`, not merely `Unhealthy`, so a dead peer costs the full
`CONTROL_HTTP_TIMEOUT` (`service_types/paths.rs:207` = 15s;
`service_runtime/client/factory.rs:62-63` builds the ureq agent with it) every
round.

The pullers trust peer `seq` unconditionally. `sync_peer_tool_receipts`
(`deltas.rs:332-361`) loops until an empty page and sets `last_seq = record.seq`
with no check that it advanced (`deltas.rs:355`); `sync_peer_revocations`
(`deltas.rs:293-330`) has the same shape and upserts peer-supplied
`capability_id`/`revoked_at` with no validation; `import_budget_delta_response`
returns `should_continue: !response.mutation_events.is_empty() || cursor_advanced`
(`deltas.rs:493`), so any non-empty `mutation_events` page loops forever even
without cursor progress. `BUDGET_DELTA_MAX_RECORDS` (`paths.rs:205`) caps a
single response, not a round.

The status path materializes everything. `cluster_replication_heads`
(`cluster/snapshots.rs:55-60`) calls `build_cluster_state_snapshot`
(`snapshots.rs:62-137`), which scans and accumulates every store into unbounded
`Vec`s (`collect_*` at `snapshots.rs:300-422`) and returns them, keeping only the
head seqs; `handle_internal_cluster_status` (`cluster/consensus.rs:28`) calls it
on every status request. The pulling client reads peer bodies with
`serde_json::from_reader(response.into_reader())` and no byte cap
(`service_runtime/client/transport.rs:217`, and identically at `259,290,334`).

Relevant types (`service_types/state.rs`): `PeerSyncState` (`state.rs:80-94`)
holds `health: PeerHealth`, `partitioned: bool`, `budget_cursor:
Option<BudgetCursor>`; `PeerHealth` (`state.rs:140-144`) is
`Unknown | Healthy | Unhealthy` with `is_reachable()` true only for `Healthy`
(`state.rs:192-194`); `BudgetCursor` (`state.rs:153-158`) is `{ seq, updated_at,
capability_id, grant_index }`. `BudgetWriteCommitView`
(`service_types/cluster_budget.rs:308-319`) and `ClusterStatusResponse`
(`cluster_budget.rs:5-18`) are the wire shapes.

## Design

Four coordinated changes. All new code is fail-closed and uses `?` / explicit
`match` with typed errors (no `unwrap`/`expect`).

### D1. Budgeted, monotone pullers (F15)

New module `cluster/pull_budget.rs`. A per-peer, per-round budget plus a strict
monotonicity guard, applied uniformly in every puller loop.

```rust
// cluster/pull_budget.rs
use std::time::{Duration, Instant};

pub(crate) const MAX_PULL_PAGES_PER_PEER_PER_ROUND: u32 = 64;
pub(crate) const MAX_PULL_RECORDS_PER_PEER_PER_ROUND: u64 = 200_000;
pub(crate) const PEER_ROUND_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub(crate) enum PeerProtocolError {
    NonAdvancingPage { after_seq: u64, page_max_seq: u64 },
    NonContiguousPage { expected_seq: u64, got_seq: u64 },
    PageBudgetExhausted { pages: u32 },
    RecordBudgetExhausted { records: u64 },
    RoundDeadlineExceeded,
    OversizedResponse { cap_bytes: u64 },
    UnattributedBudgetEvent { event_id: String },
}

impl std::fmt::Display for PeerProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonAdvancingPage { after_seq, page_max_seq } => write!(
                f,
                "peer returned a non-empty page whose max seq {page_max_seq} did not advance past cursor {after_seq}"
            ),
            Self::NonContiguousPage { expected_seq, got_seq } => write!(
                f,
                "peer returned an append-only page carrying seq {got_seq} where the cursor required contiguous seq {expected_seq}"
            ),
            Self::PageBudgetExhausted { pages } => {
                write!(f, "peer exceeded per-round page budget after {pages} pages")
            }
            Self::RecordBudgetExhausted { records } => {
                write!(f, "peer exceeded per-round record budget after {records} records")
            }
            Self::RoundDeadlineExceeded => write!(f, "peer exceeded per-round wall-clock budget"),
            Self::OversizedResponse { cap_bytes } => {
                write!(f, "peer response exceeded the {cap_bytes}-byte cap")
            }
            Self::UnattributedBudgetEvent { event_id } => {
                write!(f, "peer budget event {event_id} carried no origin authority")
            }
        }
    }
}

pub(crate) struct PullRoundBudget {
    pages_left: u32,
    records_left: u64,
    deadline: Instant,
}

impl PullRoundBudget {
    pub(crate) fn new() -> Self {
        Self {
            pages_left: MAX_PULL_PAGES_PER_PEER_PER_ROUND,
            records_left: MAX_PULL_RECORDS_PER_PEER_PER_ROUND,
            deadline: Instant::now() + PEER_ROUND_WALL_CLOCK_BUDGET,
        }
    }

    /// Charge one page of `records`. Fail-closed: any exhaustion is a peer
    /// protocol error, not a silent stop.
    pub(crate) fn charge_page(&mut self, records: u64) -> Result<(), PeerProtocolError> {
        if Instant::now() >= self.deadline {
            return Err(PeerProtocolError::RoundDeadlineExceeded);
        }
        self.pages_left = self
            .pages_left
            .checked_sub(1)
            .ok_or(PeerProtocolError::PageBudgetExhausted {
                pages: MAX_PULL_PAGES_PER_PEER_PER_ROUND,
            })?;
        self.records_left = self.records_left.checked_sub(records).ok_or(
            PeerProtocolError::RecordBudgetExhausted {
                records: MAX_PULL_RECORDS_PER_PEER_PER_ROUND,
            },
        )?;
        Ok(())
    }
}

/// Append-only contiguity for a `u64` cursor puller: a non-empty page MUST begin
/// at the expected next seq (`after_seq + 1`) and be gap-free, so the i-th
/// returned record carries seq `after_seq + 1 + i`. This is strictly stronger
/// than monotonic advancement: a page whose max advanced but which SKIPPED seqs
/// in between (e.g. one starting at `after_seq + 100`) would, once the cursor
/// advanced to that max, permanently strand the un-returned rows, because these
/// receipt/lineage tables are append-only streams and a skipped seq is never
/// re-offered. The ONLY sanctioned way to advance past a gap is a trusted
/// compaction/retention floor that provably covers it (RFC-0007 publishes such a
/// floor for the receipt log); absent that floor a gap is a peer protocol
/// violation and the peer is demoted (fail-closed). `seqs` are the page's record
/// seqs in returned order.
pub(crate) fn ensure_page_contiguous(
    after_seq: u64,
    seqs: impl IntoIterator<Item = u64>,
) -> Result<(), PeerProtocolError> {
    for (offset, seq) in seqs.into_iter().enumerate() {
        let expected = after_seq.saturating_add(offset as u64).saturating_add(1);
        if seq != expected {
            return Err(PeerProtocolError::NonContiguousPage { expected_seq: expected, got_seq: seq });
        }
    }
    Ok(())
}
```

Pullers must carry the protocol-violation distinction out to `sync_peer`, which
routes it differently from a transient error. A `CliError` return would erase
that distinction, so the pullers return a two-arm carrier:

```rust
// cluster/pull_budget.rs
#[derive(Debug)]
pub(crate) enum PullError {
    /// The peer violated the pull wire contract; demote it.
    Protocol(PeerProtocolError),
    /// Transport or store failure; retryable, peer keeps its standing.
    Transient(CliError),
}

impl From<PeerProtocolError> for PullError {
    fn from(error: PeerProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<CliError> for PullError {
    fn from(error: CliError) -> Self {
        Self::Transient(error)
    }
}
```

Error sites that already produce `CliError` compose with `?` unchanged; sites
that produce store or serde errors convert through `CliError` explicitly (as
`sync_peer_lineage` already does at `deltas.rs:518-520`), since `?` performs a
single `From` step.

Every puller loop changes from "loop until empty page, trust `record.seq`" to
"budget the round, require gap-free contiguity". `sync_peer_tool_receipts`
(`deltas.rs:332-361`) becomes representative:

```rust
fn sync_peer_tool_receipts(
    state: &TrustServiceState,
    client: &TrustControlClient,
    peer_url: &str,
    round: &mut PullRoundBudget,
) -> Result<u64, PullError> {
    let Some(path) = state.config.receipt_db_path.as_deref() else {
        return Ok(0);
    };
    let store = SqliteReceiptStore::open(path).map_err(CliError::from)?;
    let mut applied = 0u64;
    loop {
        let after_seq = peer_tool_seq(state, peer_url);
        let response = client.tool_receipt_deltas(&ReceiptDeltaQuery {
            after_seq: Some(after_seq),
            limit: Some(MAX_LIST_LIMIT),
        })?;
        if response.records.is_empty() {
            break;
        }
        round.charge_page(response.records.len() as u64)?;
        // Require the page to start at the expected next seq (after_seq + 1) and
        // be gap-free BEFORE accepting any of it: advancing the cursor past a gap
        // would permanently skip the unreplicated append-only rows in between.
        ensure_page_contiguous(after_seq, response.records.iter().map(|record| record.seq))?;
        let mut last_seq = after_seq;
        for record in response.records {
            let receipt: ChioReceipt = serde_json::from_value(record.receipt).map_err(CliError::from)?;
            store.append_chio_receipt(&receipt).map_err(CliError::from)?;
            last_seq = last_seq.max(record.seq);
            applied = applied.saturating_add(1);
        }
        update_peer_tool_seq(state, peer_url, last_seq);
    }
    Ok(applied)
}
```

(Contiguity makes the applied range exactly `after_seq + 1 ..= after_seq +
records.len()`, so `last_seq` ends at `after_seq + records.len()` and
`update_peer_tool_seq` advances the cursor by exactly the page, never across a
gap.)

`sync_peer_child_receipts` and `sync_peer_lineage` take the identical shape.
For the composite-cursor revocation puller (`sync_peer_revocations`,
`deltas.rs:293-330`), monotonicity is on the `(revoked_at, capability_id)` tuple:

```rust
fn ensure_revocation_advanced(
    after: Option<&RevocationCursor>,
    page_max: &RevocationCursor,
) -> Result<(), PeerProtocolError> {
    let advanced = match after {
        None => true,
        Some(prev) => (page_max.revoked_at, page_max.capability_id.as_str())
            > (prev.revoked_at, prev.capability_id.as_str()),
    };
    if advanced {
        Ok(())
    } else {
        Err(PeerProtocolError::NonAdvancingPage {
            after_seq: after.map(|c| c.revoked_at as u64).unwrap_or(0),
            page_max_seq: page_max.revoked_at as u64,
        })
    }
}
```

For the budget puller, `import_budget_delta_response`
(`deltas.rs:428-495`) drops the `!mutation_events.is_empty()` escape hatch:
`should_continue` becomes strictly `cursor_advanced` (the merged cursor `seq`
strictly exceeds `previous_cursor_seq`), and the caller charges the round budget
per page. A non-empty page that does not advance the merged cursor is a
`PeerProtocolError::NonAdvancingPage`, not a continuation.

`sync_peer` (`deltas.rs:219-278`) constructs one `PullRoundBudget` per peer,
threads it into every puller, and matches on the puller result:
`PullError::Protocol` routes to `update_peer_failure` (`partition.rs:131`,
which sets `PeerHealth::Unhealthy` and `force_snapshot = true`), while
`PullError::Transient` keeps today's `update_peer_sync_error` handling
(`partition.rs:153`, which records the error but leaves the peer `Healthy`).
This split matters: today every puller error takes the `update_peer_sync_error`
path, so no pull misbehavior can demote a peer at all. A demoted peer leaves
both the consensus candidate set (the reachability filter in
`compute_cluster_consensus_locked`, `consensus.rs:309`) and the witness set
(`is_reachable()` is `Healthy`-only). This is the fail-closed posture: a peer
that violates the wire contract is denied replication standing, not trusted
into an infinite loop.

Recovery is bounded, not permanent exile. `sync_peer` still issues the cheap
`cluster_status` probe to an `Unhealthy` peer each round (`deltas.rs:231`); a
successful probe restores it to `Healthy` via `update_peer_reachable`
(`deltas.rs:235`) and the next round retries its pulls under a fresh
`PullRoundBudget`. A persistently misbehaving peer therefore oscillates, costing
at most one round budget per `cluster_sync_interval`, and heals automatically
once fixed. Because `update_peer_failure` sets `force_snapshot`, each recovery
also refetches the peer snapshot; that response is bounded client-side by
`MAX_PEER_RESPONSE_BYTES` (D4).

### D2. Honest quorum via per-origin replication acks (F16)

The witness must stop comparing magnitudes and start requiring the specific peer
to acknowledge the specific write's origin seq.

Origin identity already exists on the wire: every budget mutation event carries
`authority: Option<BudgetMutationAuthorityView>` whose `authority_id` is the
leader URL that wrote it (`cluster_budget.rs:184-188`, and it is persisted as
`authority_id` in `budget_mutation_events`, `budget_store/store.rs:1153,1176`).
No new column is required; the origin of a durably-imported event is its
`authority_id`.

Each node computes, over its own `budget_mutation_events`, the highest
*contiguous* imported `event_seq` per origin (the largest `S` such that every
event from that origin in `(floor..S]` is present with no gap, where `floor` is a
durable trusted lower bound described below), and reports it in `cluster_status`.
Reporting `MAX(event_seq)` would be unsound: the puller hardening (D1) only
checks that pages advance, not that they are gap-free, so a peer that skips event
41 and then imports 42 must not be treated as having acked 41. Anchoring on the
minimum *present* row would be equally unsound: a peer that skipped 41 and holds
only `{42, ...}` would have `MIN(event_seq) = 42` and report a contiguous head of
42 for a write it never stored. The head is therefore computed from a trusted
floor, not from the minimum present row, and capped at the last event before the
first gap, so neither a mid-stream gap nor a missing prefix can be counted as an
ack:

```rust
// service_types/cluster_budget.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BudgetOriginAck {
    pub(crate) origin_id: String,
    /// Contiguous ack head: the highest event_seq S from `origin_id` such that
    /// every event in (floor..S] is present (no gap) and the run reaches down to
    /// the durable trusted floor. NOT MAX(event_seq), NOT anchored on MIN(present).
    pub(crate) event_seq: u64,
}

// added to ClusterStatusResponse (cluster_budget.rs:5-18), additive:
//   #[serde(default, skip_serializing_if = "Vec::is_empty")]
//   pub(crate) budget_ack_heads: Vec<BudgetOriginAck>,
```

The trusted floor is a durable per-origin lower bound, NOT the minimum present
row. It lives in a small `budget_import_floors(authority_id TEXT PRIMARY KEY,
floor_seq INTEGER NOT NULL)` table and defaults to `0` (genesis: the contiguous
prefix must reach the origin's first event). It is raised only by a trusted
operation: when this node installs a peer snapshot, `apply_cluster_snapshot`
(`cluster/snapshots.rs:139`) records, per origin the snapshot covers,
`floor_seq = (snapshot's minimum covered event_seq) - 1`. Today snapshots carry
each origin's full mutation-event log from genesis (`import_snapshot_records`,
`snapshots.rs:199-205`), so `floor_seq` is `0` for every origin and the genesis
anchor applies uniformly; the recorded floor exists so a future truncated or
compacted snapshot cannot be mistaken for a gap. A puller-introduced gap can
never raise the floor, because the puller never writes it.

New store read, mirroring the existing private `max_budget_mutation_event_seq`
helper (`budget_store/replication.rs:134-143`). It returns the contiguous head
per origin, not `MAX`, and anchors on the durable floor. The window-function form
uses the gaps-and-islands identity: within a partition ordered by `event_seq`, a
run that increments by exactly 1 has a constant `event_seq - ROW_NUMBER()`. The
run that begins at `floor + 1` has island key `(floor + 1) - 1 = floor`, so
restricting to `island = floor` selects the prefix anchored at the trusted floor
and takes its `MAX`. A per-origin event's `event_seq` values are consecutive
integers by construction (each leader numbers its own mutation events), so if the
lowest present row for an origin is above `floor + 1`, no row lands in the
`island = floor` group and the origin is absent from the result: the caller then
reports the floor itself as the head (nothing above the floor is provably
contiguous). This is the fix for anchoring on `MIN(present)`:

```rust
// SqliteBudgetStore
pub fn budget_ack_heads(&self) -> Result<Vec<BudgetOriginAck>, BudgetStoreError> {
    let connection = self.connection()?;
    let mut statement = connection.prepare(
        r#"
        WITH imported AS (
            SELECT
                bme.authority_id,
                bme.event_seq,
                bme.event_seq - ROW_NUMBER() OVER (
                    PARTITION BY bme.authority_id ORDER BY bme.event_seq
                ) AS island,
                COALESCE(bif.floor_seq, 0) AS floor
            FROM budget_mutation_events bme
            LEFT JOIN budget_import_floors bif
                ON bif.authority_id = bme.authority_id
            WHERE bme.authority_id IS NOT NULL AND bme.event_seq IS NOT NULL
        )
        SELECT authority_id, MAX(event_seq) AS ack_head
        FROM imported
        WHERE island = floor  -- the run anchored at the trusted floor (floor + 1..)
        GROUP BY authority_id
        "#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok(BudgetOriginAck {
            origin_id: row.get::<_, String>(0)?,
            event_seq: budget_u64_from_row(row, 1, "ack_head")?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(BudgetStoreError::from)
}
```

A peer that has imported events `{40, 42}` for an origin (41 skipped) reports a
contiguous head of `40`, not `42`, so a write at seq `41` is never witnessed by
that peer until the gap is filled. A peer that skipped the prefix entirely and
holds only `{42, 43}` with `floor = 0` has no row in the `island = 0` group, so
the origin is absent from the result and the caller reports the floor (`0`), not
`43`: a missing prefix is never laundered into an ack by the accidental minimum.
A late-joining peer seeded from a snapshot is handled by the recorded floor: the
snapshot install set `floor_seq`, so the contiguous head advances only across the
events above that trusted floor with no gap, and a gap above the floor caps the
head at the floor itself. Origins absent from the result (a gap at or below
`floor + 1`) are defaulted by the caller to their recorded `floor` as the head
(`0` when none is recorded) when it assembles the advertised set, so a
snapshot-vouched prefix is still witnessed while an unproven prefix is not. This
is fail-safe either way: under-reporting an ack can only withhold quorum, never
falsely grant it. An equivalent Rust-side computation (start at `floor + 1`,
walk while `seq == previous + 1`, stop at the first gap) is acceptable if the
SQLite build lacks window functions.

`PeerSyncState` (`state.rs:80-94`) gains
`budget_import_acks: BTreeMap<String, u64>` (origin_id -> highest *contiguous*
imported event_seq for that origin, as reported by that peer). `sync_peer`
(`deltas.rs:231`) already fetches `cluster_status` first; it now records the
peer's `budget_ack_heads` into `budget_import_acks` via a new
`update_peer_budget_acks` helper in `cluster/partition.rs` (same lock pattern as
`update_peer_state`).

Writes carry an explicit origin token rather than a bare seq:

```rust
#[derive(Debug, Clone)]
pub(crate) struct BudgetWriteToken {
    pub(crate) origin_id: String, // authority_id of the leader that wrote this event
    pub(crate) event_seq: u64,    // the mutation event's event_seq (not usage.seq)
    pub(crate) budget_term: u64,
}
```

The budget-store write functions return the allocated mutation `event_seq`
(today allocated at `budget_store/store.rs:1227,1253` and passed into
`append_mutation_event` but discarded). The `try_charge_cost`,
`settle_charge_cost`, `reverse_charge_cost`, and `reduce_charge_cost` families
(including their `_with_ids` and `_with_ids_and_authority` variants,
`budget_store/trait_impl.rs`) gain a companion that returns
`(allowed, event_seq)`; the handler pairs `event_seq` with the origin from the
`BudgetEventAuthority` it already stamps (`current_budget_event_authority`,
`consensus.rs:228-251`) to build the token. When `state.cluster` is `None`
(single-node), there is no token and the guarantee level stays
`single_node_atomic` (`budget_authority_guarantee_level`, `consensus.rs:272-285`),
unchanged.

The witness (`budget_write_quorum_commit_view_locked`, `deltas.rs:625-661`)
becomes:

```rust
fn budget_write_quorum_commit_view_locked(
    cluster: &mut ClusterRuntimeState,
    write: &BudgetWriteToken,
) -> BudgetWriteCommitView {
    let consensus = compute_cluster_consensus_locked(cluster);
    let mut witness_urls = BTreeSet::from([cluster.self_url.clone()]);
    for (peer_url, peer_state) in &cluster.peers {
        let acked = peer_state
            .budget_import_acks
            .get(&write.origin_id)
            .is_some_and(|imported_seq| *imported_seq >= write.event_seq);
        if peer_state.health.is_reachable() && !peer_state.partitioned && acked {
            witness_urls.insert(peer_url.clone());
        }
    }
    let committed_nodes = witness_urls.len();
    // ... unchanged commit-index / lease / term fields ...
    BudgetWriteCommitView {
        budget_seq: write.event_seq,
        commit_index: write.event_seq,
        quorum_committed: committed_nodes >= consensus.quorum_size,
        quorum_size: consensus.quorum_size,
        committed_nodes,
        witness_urls: witness_urls.into_iter().collect(),
        budget_term: write.budget_term,
        // authority_id, lease_id, lease_epoch as before
        // ...
    }
}
```

A peer counts only when its contiguous ack head for exactly this write's origin
is at least this write's seq. Because the head is the gap-free prefix rather than
`MAX`, a peer that skipped a lower event for that origin does not witness the
write until the gap is filled: a hole below the write's seq caps the reported
head beneath it. An unrelated peer event can no longer satisfy the witness,
because it is grouped under a different `origin_id`. Legacy events with a NULL
`authority_id` are excluded from `budget_ack_heads` and so never witness a new
write (fail-closed).

`self` is still counted as one witness (the leader always durably holds its own
write before responding), consistent with ADR-0006's atomic local commit.

### D3. Decouple write handlers from inline sync (F14)

Budget-write handlers must observe cursor advancement produced by the single
background sync loop, never drive syncs themselves.

Add a progress channel to `TrustServiceState`:

```rust
// service_types/state.rs, added to TrustServiceState
pub(crate) cluster_progress: Option<Arc<ClusterProgress>>,

pub(crate) struct ClusterProgress {
    tick: tokio::sync::watch::Sender<u64>,
    kick: tokio::sync::Notify, // writers nudge the loop to run now
}

impl ClusterProgress {
    pub(crate) fn new() -> Self {
        let (tick, _rx) = tokio::sync::watch::channel(0);
        Self { tick, kick: tokio::sync::Notify::new() }
    }
    pub(crate) fn notify_round_complete(&self) {
        self.tick.send_modify(|value| *value = value.wrapping_add(1));
    }
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.tick.subscribe()
    }
    pub(crate) fn request_sync(&self) {
        self.kick.notify_one();
    }
    pub(crate) async fn awaited_kick(&self) {
        self.kick.notified().await;
    }
}
```

`ClusterProgress` is constructed where the service state is assembled
(`service_runtime/init.rs`, which already spawns `run_cluster_sync_loop` only
when clustered, `init.rs:25-27`), so `cluster_progress` is `Some` exactly when
`state.cluster` is `Some` and the wait's not-clustered early return matches the
current `state.cluster.is_none()` check.

`run_cluster_sync_loop` (`deltas.rs:184-198`) calls
`progress.notify_round_complete()` after each `sync_cluster_once`, and races its
inter-round sleep against `progress.awaited_kick()` so a fresh write triggers a
round promptly instead of waiting the full `cluster_sync_interval`:

```rust
tokio::select! {
    _ = tokio::time::sleep(state.config.cluster_sync_interval) => {}
    _ = progress.awaited_kick() => {}
}
```

The wait loses all syncing and is bounded by a single outer timeout:

```rust
pub(crate) async fn wait_for_budget_write_quorum_commit(
    state: &TrustServiceState,
    write: BudgetWriteToken,
) -> Result<Option<BudgetWriteCommitView>, Response> {
    let Some(progress) = state.cluster_progress.as_ref() else {
        return Ok(None); // not clustered
    };
    let timeout = budget_write_quorum_commit_timeout(state.config.cluster_sync_interval);
    let mut rx = progress.subscribe();
    progress.request_sync();

    let waited = tokio::time::timeout(timeout, async {
        loop {
            let Some(view) = budget_write_quorum_commit_view(state, &write) else {
                return Ok::<_, Response>(None);
            };
            if view.quorum_committed {
                return Ok(Some(view));
            }
            if !cluster_consensus_view(state).is_some_and(|consensus| consensus.has_quorum) {
                return Err(plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!(
                        "budget write became leader-visible at commit index {} for authority term {} but cluster quorum disappeared before commit",
                        write.event_seq, write.budget_term
                    ),
                ));
            }
            // Park until the background loop advances acks, or the outer timeout fires.
            if rx.changed().await.is_err() {
                // The progress sender was dropped: the background sync/progress task
                // died. `progress` was `Some` at entry, so by the invariant below
                // `state.cluster` is still `Some` - this IS a clustered node whose
                // quorum machinery is gone, NOT the not-clustered path. Returning
                // `Ok(None)` here would be indistinguishable from "not clustered" and
                // callers (e.g. `handle_try_charge_cost`, which only rolls back on
                // `Err`) would render it as a successful leader-visible commit WITHOUT
                // quorum. Fail closed with a 503 while `state.cluster` is present so the
                // local budget write is rolled back instead of acked quorum-less.
                return Err(plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!(
                        "budget write became leader-visible at commit index {} for authority term {} but the cluster progress task exited before quorum",
                        write.event_seq, write.budget_term
                    ),
                ));
            }
        }
    })
    .await;

    match waited {
        Ok(inner) => inner,
        Err(_elapsed) => {
            let observed = budget_write_quorum_commit_view(state, &write);
            Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "budget write became leader-visible at commit index {} for authority term {} but quorum acks did not arrive before timeout ({}/{})",
                    write.event_seq,
                    write.budget_term,
                    observed.as_ref().map(|v| v.committed_nodes).unwrap_or(0),
                    observed.as_ref().map(|v| v.quorum_size).unwrap_or(0),
                ),
            ))
        }
    }
}
```

The request path no longer calls `spawn_blocking(sync_cluster_once)`, holds no
blocking-pool thread, and cannot hang past `timeout` even if a peer sync spins
(F15's failure is now contained by both D1 and this bound). N concurrent writes
share the one background loop instead of launching N sync storms. On
timeout or lost quorum the handler is fail-closed: `handle_try_charge_cost`
already rolls back the local exposure (`budget_handlers.rs:181-201`), and the
other budget writers return 503 without claiming commit.

Latency note: commit latency is now floored by the background round cadence
rather than per-request syncing. `request_sync` plus the `select!` kick keep p50
close to one round-trip under light load; under a stuck peer the write waits out
`timeout` and fails closed, which is strictly better than the current unbounded
hang.

### D4. Cap materialization and deserialization (F20)

Replication heads become dedicated `MAX(seq)` reads, never a full snapshot.
`cluster_replication_heads` (`snapshots.rs:55-60`) stops calling
`build_cluster_state_snapshot` and instead assembles `ClusterReplicationHeadsView`
from four head queries:

```rust
pub(crate) fn cluster_replication_heads(
    state: &TrustServiceState,
) -> Result<ClusterReplicationHeadsView, CliError> {
    let (tool_seq, child_seq, lineage_seq) =
        if let Some(path) = state.config.receipt_db_path.as_deref() {
            let store = SqliteReceiptStore::open(path)?;
            (
                store.max_tool_receipt_seq()?,
                store.max_child_receipt_seq()?,
                store.max_lineage_seq()?,
            )
        } else {
            (0, 0, 0)
        };
    let budget_seq = match state.config.budget_db_path.as_deref() {
        Some(path) => SqliteBudgetStore::open(path)?.max_mutation_event_seq()?,
        None => 0,
    };
    let revocation_cursor = match state.config.revocation_db_path.as_deref() {
        Some(path) => SqliteRevocationStore::open(path)?.latest_revocation_cursor()?,
        None => None,
    };
    Ok(ClusterReplicationHeadsView {
        tool_seq,
        child_seq,
        lineage_seq,
        budget_seq,
        revocation_cursor: revocation_cursor.map(|cursor| RevocationCursorView {
            revoked_at: cursor.revoked_at,
            capability_id: cursor.capability_id,
        }),
    })
}
```

(The inline `RevocationCursorView` construction matches how
`build_cluster_state_snapshot` builds the same field today,
`snapshots.rs:115-118`; there is no shared helper.)

The four `max_*_seq` / `latest_*_cursor` methods are single indexed
`SELECT MAX(...)` / `ORDER BY ... LIMIT 1` reads (the budget one already exists
privately as `max_budget_mutation_event_seq`, `replication.rs:134-143`; the
receipt-side seqs read the existing `seq` indexes). `handle_internal_cluster_status`
(`consensus.rs:28`) then costs O(index lookups) per tick instead of a full-store
scan, removing the steady-state OOM path.

The pulling side caps every peer body. A shared reader wrapper replaces the raw
`serde_json::from_reader` at `transport.rs:217,259,290,334`:

```rust
// service_types/paths.rs
pub(crate) const MAX_PEER_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

// transport helper
fn read_capped_json<T>(reader: impl std::io::Read, cap: u64) -> Result<T, CliError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut limited = reader.take(cap.saturating_add(1));
    let mut buffer = Vec::new();
    std::io::Read::read_to_end(&mut limited, &mut buffer)
        .map_err(|error| CliError::cli_other_error(format!("failed to read peer response: {error}")))?;
    if buffer.len() as u64 > cap {
        return Err(CliError::cli_other_error(format!(
            "peer response exceeded the {cap}-byte cap"
        )));
    }
    serde_json::from_slice(&buffer).map_err(|error| {
        CliError::cli_other_error(format!("failed to decode trust control service response body: {error}"))
    })
}
```

An oversized or streaming-forever peer body is rejected as a peer protocol error
inside the 15s HTTP window, never buffered without bound. The bootstrap snapshot
(`build_cluster_state_snapshot`) is retained but now bounded on the client by
this cap; converting bootstrap to reuse the delta pagination from seq 0 (so the
server never materializes the whole store either) is a follow-on tracked in this
RFC's sequencing, gated behind the same cap.

### Error taxonomy

`PeerProtocolError` (D1) is the one new fail-closed error, carried out of the
pullers inside `PullError::Protocol` so `sync_peer` can route it through
`update_peer_failure` and demote the peer to `Unhealthy`. Transport and store
errors continue to use `CliError` and `BudgetStoreError`, travelling as
`PullError::Transient` and keeping today's `update_peer_sync_error` handling.
No new panics, no `unwrap`/`expect`.

## Wire, schema, and receipt impact

- `ClusterStatusResponse` gains `budget_ack_heads: Vec<BudgetOriginAck>`
  (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`, camelCase),
  additive and backward-compatible: an older peer omits the field and its acks
  read as empty, so it simply never witnesses (fail-closed).
- No new SQLite column. Origin is the existing `authority_id` on
  `budget_mutation_events`; `budget_ack_heads` is a new read query only.
- No change to externally-signed receipt kinds or the append-only Merkle receipt
  log. The budget mutation-event stream, ack heads, and `BudgetWriteCommitView`
  are internal replication metadata authenticated by cluster peer auth
  (`validate_cluster_peer_auth`), not signed payloads. Where any of these were
  ever signed, canonical JSON per RFC 8785 would apply; they are not, so there is
  no canonicalization change here. The `authority_id` binding on each event stays
  byte-stable so acks compare on identical origin strings.
- New constants: `MAX_PULL_PAGES_PER_PEER_PER_ROUND`,
  `MAX_PULL_RECORDS_PER_PEER_PER_ROUND`, `PEER_ROUND_WALL_CLOCK_BUDGET`,
  `MAX_PEER_RESPONSE_BYTES`.

## Migration and compatibility

Backward-compatible, staged, no data migration:

1. Land `pull_budget.rs`, thread `PullRoundBudget` and the monotonicity guards
   through the pullers, and skip `Unhealthy` peers (D1). Pure hardening; no wire
   change.
2. Add the `read_capped_json` cap and the `MAX(seq)` head queries; repoint
   `cluster_replication_heads` (D4). No wire change; status responses shrink.
3. Add `BudgetOriginAck`, `budget_ack_heads`, `budget_import_acks`, the store
   ack query, and the `BudgetWriteToken` threading; switch the witness to acks
   (D2). Additive wire field; mixed-version clusters degrade to fewer witnesses
   (never to false witnesses), so a rolling upgrade only tightens the guarantee.
4. Add `ClusterProgress`, notify from the sync loop, and replace the inline-sync
   wait (D3). Internal only.

There is no feature flag: each step is a strict tightening of an unsound path, so
a flag would only preserve the unsound behavior. If an escape valve is required
for a specific deployment, the round budgets and `MAX_PEER_RESPONSE_BYTES` are
config-overridable constants, defaulted high enough that only pathological peers
trip them.

## Test and verification plan

- Unit (PR gate). `pull_budget`: `charge_page` exhausts pages, records, and
  deadline as typed errors; `ensure_page_contiguous` rejects a page that starts
  past the expected next seq or skips a seq mid-page (append-only pullers), and
  `ensure_revocation_advanced` rejects non-advancing and equal composite cursors.
  Names: `non_contiguous_page_is_peer_protocol_error`,
  `non_advancing_page_is_peer_protocol_error`.
- Unit (PR gate). Witness soundness: build a `ClusterRuntimeState` with a peer
  whose `budget_import_acks` holds a high seq under a *different* `origin_id`;
  assert `quorum_committed == false` for a local write; then add an ack under the
  write's own `origin_id` at `>= event_seq` and assert it flips to `true`. Name:
  `witness_requires_same_origin_ack`.
- Property (PR gate, `proptest`). Over random interleavings of local writes and
  imported peer events across two origins, the witness returns `true` only if
  some peer's ack for the write's origin is `>= event_seq`. This is the
  executable form of the `BudgetReplication.tla` safety invariant. Name:
  `prop_witness_never_overclaims_durability`.
- Loom (PR gate, small). Model the D3 watch/kick handoff between one writer and
  the background loop: the writer either observes a committed view or times out,
  and never blocks the loop. Name: `loom_writer_wait_never_wedges_sync_loop`.
- Soak / chaos (nightly, wave-3 load-chaos program per
  ./PLAN-load-soak-chaos-program.md).
  `replay_peer_does_not_wedge`: a peer that replays a fixed non-empty budget and
  receipt page; assert the puller marks it `Unhealthy` within one round, the
  round completes, other peers keep replicating, and disk growth is bounded.
  `slow_peer_no_latency_collapse`: one peer that blackholes `cluster_status`
  while N=200 concurrent `try_charge` run; assert budget-write p99 stays within a
  small multiple of a healthy round, no 30s hangs, and the blocking pool never
  saturates. Honest runtime: ~10-15 minutes per scenario.
- Chaos (nightly). `false_quorum_kill`: leader-visible-only write (peer partitioned
  after the local commit), `SIGKILL` the leader, restart, assert the charge is
  absent AND that the pre-kill response never reported `quorum_committed = true`.
  This is the F16 regression guard tied to the ADR-0006 durability claim.
- Formal (./PLAN-formal-methods-program.md). Register `BudgetReplication.tla` under
  `formal/tla/`: state is per-node event logs plus per-peer import acks; the
  safety property is `QuorumCommittedImpliesReplicated` (a write reported
  `quorum_committed` has been durably imported by at least `quorum_size` distinct
  nodes under its own origin). The `prop_witness_never_overclaims_durability`
  test is the code-level shadow of this invariant.

## Acceptance criteria

- No budget-write handler calls `sync_cluster_once`; `wait_for_budget_write_quorum_commit`
  contains no `spawn_blocking` and is wrapped in a single `tokio::time::timeout`
  that bounds it even when a peer sync spins.
- The witness counts a peer only via `budget_import_acks[write.origin_id] >=
  write.event_seq`; `witness_requires_same_origin_ack` and
  `prop_witness_never_overclaims_durability` are green.
- Every puller enforces `PullRoundBudget` and strict cursor monotonicity; a
  non-advancing or over-budget peer is marked `Unhealthy` (leaves consensus and
  witness sets) and `replay_peer_does_not_wedge` is green.
- `handle_internal_cluster_status` no longer materializes any store: it uses
  `MAX(seq)` head queries, and its memory is independent of total store size
  (asserted by a status-path allocation soak).
- Every peer-response decode is byte-capped at `MAX_PEER_RESPONSE_BYTES`; an
  oversized body is a typed error, not an allocation.
- `slow_peer_no_latency_collapse` shows budget-write p99 bounded under one slow
  peer with N concurrent writers.
- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace
  -- -D warnings && cargo fmt --all -- --check` passes; no `unwrap`/`expect`
  introduced.

## Risks and alternatives

- Risk: commit latency now tracks the background round cadence. Mitigation: the
  `request_sync` kick plus the `select!`-on-notify keep p50 near one round under
  light load; the outer timeout makes the tail predictable and fail-closed. This
  is the correct trade over per-request sync storms.
- Risk: `authority_id` as origin conflates a leader across terms. That is
  intended: the identity that allocated the `event_seq` is the durable-import
  key we need, and per-term distinctions are already carried by `budget_term` in
  the commit view for observability. Rejected alternative: a separate
  `origin_node_id` column plus a schema migration; rejected as unnecessary since
  `authority_id` already pins the writer and a NULL authority is correctly
  non-witnessing.
- Rejected alternative: keep magnitude comparison but tag events with node id and
  term and compare the *cursor's* tagged id. Rejected because the cursor is our
  pull position, not the peer's durable-import state; only an explicit ack of
  "I imported origin O up to seq S" is sound. The ack head is that statement.
- Rejected alternative: replace the homegrown protocol with an embedded Raft.
  Out of scope for wave-3; this RFC makes the existing protocol honest and
  bounded without a rewrite, and the `BudgetReplication.tla` model documents the
  exact safety obligation any future consensus swap must preserve.
- Rejected alternative: cap the puller by stopping silently on a non-advancing
  page. Rejected as a fail-open posture that hides a misbehaving peer; marking it
  `Unhealthy` is fail-closed and observable.
- Throughput note: strict monotonicity plus per-round budgets add two comparisons
  and one counter decrement per page, negligible against the SQLite writes each
  page already performs.

## Rollout and sequencing

No RFC dependencies. Internal order follows the migration steps: D1 (budgeted
monotone pullers) and D4 (head queries plus response cap) are independent
hardening and land first; D2 (per-origin acks and the witness change) lands next
as an additive wire field, safe to roll cluster-wide in any order because a
missing ack only ever *removes* a witness; D3 (decoupled wait via `ClusterProgress`)
lands last, once acks are the witness source, so the background loop is the sole
driver of cursor and ack advancement. Within the wave-3 reliability program, the
`replay_peer_does_not_wedge`, `slow_peer_no_latency_collapse`, and
`false_quorum_kill` scenarios join the load-chaos suite, and `BudgetReplication.tla`
joins the formal-methods plan as the design proof for the honest-quorum witness.
