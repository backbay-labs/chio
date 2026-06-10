# chio-http-session Architecture

## Boundary

`chio-http-session` owns the per-session journal shared by session-aware guards.
It is not an HTTP transport implementation. Its responsibility is to provide an
append-only, hash-chained record of tool invocations plus cumulative guard state
for data-flow, behavioral-sequence, and advisory checks.

The crate depends only on serialization, hashing, hex encoding, and error
types. Downstream crates such as `chio-guards` depend on it for session history
without reaching into kernel or transport internals.

## Module Boundaries

- `JournalEntry` is the persisted/auditable entry shape.
- `RecordParams` is the append input boundary used by callers.
- `CumulativeDataFlow` is the running data-flow summary used by guards.
- `SessionJournal` owns synchronization, append-only mutation, hash-chain
  construction, and read APIs.
- `SessionJournalError` is the fail-closed error surface for poisoned locks,
  invalid record fields, and integrity violations.

The crate is currently a compact single-file crate. Splitting files is not
useful until additional journal backends or persistence boundaries exist.

## Guard Boundary

- Guard-facing state is exposed through the `SessionJournalSnapshot` boundary,
  which captures the data-flow, tool-sequence, and tool-count views under one
  lock. `chio-guards` uses it for session-aware evaluations.
- Record admission rejects embedded control characters in `tool_name`,
  `server_id`, and `agent_id`. Those fields are copied into guard-facing
  sequences, counts, serialized journal entries, and hash-chain input, so
  log-breaking or header-breaking bytes are refused to keep the audit boundary
  on a printable identifier surface.

## Security And API Constraints

- The journal must remain append-only.
- Hash-chain semantics and the documented entry hash field order are fixed.
- Denied invocations must continue contributing to invocation totals and tool
  sequences.
- Cumulative byte counters must keep saturating arithmetic.
- Public compatibility must be preserved. Existing getters remain available.
- Lock poisoning must continue to fail closed.
- Record identity fields must be non-empty, unpadded, and control-free before
  they enter the hash chain.

## Affected Dependents

Direct dependents include `chio-guards` and conformance tests that seed
session journals for cumulative exfiltration and behavioral sequence coverage.
Guard call sites consume `SessionJournalSnapshot` so each evaluation observes
one coherent view of cumulative data flow, tool sequence, tool counts, entry
count, and journal head hash.
