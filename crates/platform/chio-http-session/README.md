# chio-http-session

`chio-http-session` is the per-session audit journal for Chio's guard pipeline:
an in-process, thread-safe, append-only, hash-chained record of tool
invocations, cumulative data flow, and delegation depth for a single session.
Guards hold a `SessionJournal` per session, append to it on every tool call via
`record`, and read it back through a single-lock `SessionJournalSnapshot`.

Despite the shared `chio-http-*` prefix, this crate is unrelated to
`chio-http-core`: it defines no HTTP request/response types and no wire
framing. `chio-http-core::SessionContext` is the mutable, request-scoped
context threaded through HTTP evaluation; `chio-http-session::SessionJournal`
is the durable, tamper-evident history of invocations that guards such as
`chio-guards`' advisory, data-flow, and behavioral-sequence guards consult
across the life of a session. Neither type references the other.

## Responsibilities

- Append-only, hash-chained record of tool invocations for one session
  (`JournalEntry`, with a SHA-256 `entry_hash` computed over each entry's
  fields on append).
- Cumulative counters for data flow (bytes read/written, invocation count, max
  delegation depth), tool sequence, per-tool counts, and a consecutive-run
  streak, all of which survive ring eviction.
- Capacity-bounded `entries` and `tool_sequence` rings, defaulting to caps
  sourced from `chio_kernel::MemoryBudgetConfig`, with evicted entries folded
  into a running head hash so `head_hash` and `verify_integrity` still commit
  to the dropped prefix.
- Fail-closed distinct-key cap on `tool_counts`: once `tool_counts_cap`
  distinct tool names are held, a previously-unseen name is dropped rather
  than admitted.
- A single-lock `SessionJournalSnapshot` giving guards one coherent read of
  data flow, tool sequence, tool counts, streak, and head hash.
- Rejects empty, padded, or control-character-bearing `tool_name`,
  `server_id`, or `agent_id` before they reach the hash chain.

## Public API

- `SessionJournal` - the thread-safe journal. Constructors: `new`,
  `from_memory_budget`, `with_entry_cap`, `with_caps`.
- `SessionJournal::record(RecordParams) -> Result<u64, SessionJournalError>` -
  append one entry, returning its sequence number.
- `SessionJournal::{snapshot, data_flow, tool_sequence, tool_counts,
  tool_counts_len, len, is_empty, entries, recent_entries, verify_integrity,
  head_hash, session_id}` - read APIs.
- `RecordParams` - the append input (`tool_name`, `server_id`, `agent_id`,
  `bytes_read`, `bytes_written`, `delegation_depth`, `allowed`).
- `JournalEntry` - the persisted entry shape.
- `CumulativeDataFlow` - `total_bytes_read`, `total_bytes_written`,
  `total_invocations`, `max_delegation_depth`.
- `SessionJournalSnapshot` - the guard-facing read view.
- `SessionJournalError` - `LockPoisoned`, `InvalidRecordField { field }`,
  `IntegrityViolation { index, expected, actual }`.

## Usage

```rust
use chio_http_session::{RecordParams, SessionJournal};

let journal = SessionJournal::new("session-1".to_string());

journal
    .record(RecordParams {
        tool_name: "read_file".to_string(),
        server_id: "srv-1".to_string(),
        agent_id: "agent-1".to_string(),
        bytes_read: 128,
        bytes_written: 0,
        delegation_depth: 0,
        allowed: true,
    })
    .unwrap();

let snapshot = journal.snapshot().unwrap();
assert_eq!(snapshot.entry_count, 1);
```

## Testing

`cargo test -p chio-http-session`

## See also

- `chio-http-core` - defines the HTTP-facing `SessionContext` and request
  evaluation types; unrelated to this crate despite the shared prefix.
- `chio-guards` - the primary consumer; its advisory, data-flow, and
  behavioral-sequence guards hold an `Arc<SessionJournal>` for session-aware
  decisions.
- `chio-kernel` - supplies `MemoryBudgetConfig`, the source of this journal's
  default entry and tool-count caps.
