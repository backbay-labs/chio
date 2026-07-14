# chio-http-session architecture

## Overview

`chio-http-session` is a self-contained, in-process data structure crate: a
thread-safe, append-only journal keyed by session ID, with no I/O and no
transport surface. It sits outside the kernel's trusted compute base, but its
append-only and hash-chain guarantees are a correctness dependency for the
`chio-guards` guards that read it: those guards derive live allow and deny
decisions from the journal, so its integrity affects guard verdicts. Despite the
`chio-http-*` prefix it is unrelated to `chio-http-core`, which owns the
HTTP-facing `SessionContext` and request-evaluation types; this crate is the
tamper-evident history guards consult, not the request pipeline. Its core
design idea is one `Mutex<JournalInner>`: every mutation (`record`) and
multi-field read (`snapshot`) happens under a single lock acquisition, so
hash-chain construction, ring eviction, and the cumulative counters stay
mutually consistent.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `SessionJournalError`; `JournalEntry` and `compute_entry_hash`; `CumulativeDataFlow`; `SessionJournalSnapshot`; `JournalInner` (non-thread-safe state: bounded rings, evicted-prefix hash fold, cumulative tool counts, streak counter); `SessionJournal` (thread-safe `Mutex<JournalInner>` wrapper: constructors and the append/read API); `RecordParams`. |

## Record lifecycle

1. `record` validates `tool_name`, `server_id`, and `agent_id` (non-empty,
   unpadded, control-free) before taking the lock; a violation returns
   `InvalidRecordField` and appends nothing.
2. Under one `Mutex` acquisition: assign the next monotonic `sequence`
   (independent of ring length, so sequence numbers never repeat after
   eviction), read `prev_hash` from the current last entry (or `ZERO_HASH` if
   empty), and compute `entry_hash`.
3. Update `CumulativeDataFlow` with saturating arithmetic; push the tool name
   onto the bounded `tool_sequence` ring; update the cumulative `tool_counts`
   map and the `current_streak_tool`/`current_streak_len` scalar.
4. Push the entry onto the bounded `entries` ring. If the push evicts an older
   entry, fold the evicted entry's hash into `evicted_head_hash` so
   `head_hash` and `verify_integrity` keep committing to the full history.

## Invariants and failure modes

- The journal is append-only: no method mutates or removes an existing
  `JournalEntry`.
- `entry_hash` is the SHA-256 digest of `sequence`, `prev_hash`,
  `timestamp_secs`, `tool_name`, `server_id`, `agent_id`, `bytes_read`,
  `bytes_written`, `delegation_depth`, `allowed`, in that order: integers as
  little-endian bytes, strings as a `u64`-LE byte length followed by UTF-8
  bytes, `allowed` as one byte (`0x01`/`0x00`). The entry's own `entry_hash` is
  excluded from its digest.
- `entries` and `tool_sequence` ring-evict at `entry_cap`; `data_flow`,
  `tool_counts`, and the streak counter are cumulative and survive eviction.
  `tool_counts` additionally caps its distinct-key count at `tool_counts_cap`,
  fail-closed: past the cap, a previously-unseen tool name is dropped rather
  than inserted, while already-seen names keep counting.
- Each evicted entry's hash folds into `evicted_head_hash`, so `head_hash`
  keeps committing to the full pre-eviction history, not just the retained
  tail. `verify_integrity` recomputes every retained entry's hash and
  `prev_hash` linkage, and accepts the oldest retained entry's `prev_hash` as
  the boundary into the evicted prefix rather than re-deriving it.
- Denied invocations (`allowed: false`) still count toward every cumulative
  counter and the tool sequence; the journal itself does not gate on
  `allowed`.
- Every method that touches the `Mutex` maps a poisoned lock to
  `SessionJournalError::LockPoisoned` instead of panicking.
- `#![forbid(unsafe_code)]`.

## Dependencies

Internal: `chio-bounded` supplies `Ring`, the capacity-bounded collection
backing the `entries` and `tool_sequence` fields. `chio-kernel` supplies
`MemoryBudgetConfig`: `SessionJournal::new` reads its compiled-in `defaults()`
for `journal_entry_cap` / `journal_tool_counts_cap`, while
`from_memory_budget` threads a caller-configured budget through instead.
External: `sha2` for the hash chain, `hex` for hash encoding,
`serde`/`serde_json` for entry and snapshot (de)serialization, `thiserror` for
`SessionJournalError`.
