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

## Pain Points

- Guard-facing state was previously exposed through several independent
  getters: `data_flow()`, `tool_sequence()`, and `tool_counts()`. The
  `SessionJournalSnapshot` boundary now captures those views under one lock and
  `chio-guards` uses it for session-aware evaluations.
- Record admission still accepts embedded control characters in `tool_name`,
  `server_id`, and `agent_id`. Those fields are copied into guard-facing
  sequences, counts, serialized journal entries, and hash-chain input, so
  accepting log-breaking or header-breaking bytes weakens the audit boundary.

## Security And API Constraints

- The journal must remain append-only.
- Hash-chain semantics and the documented entry hash field order must not
  change in this slice.
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
This slice keeps the existing public API and tightens `record` validation.
Dependent guard behavior does not need call-site changes because valid existing
test fixtures use printable identifiers.

## Completed Snapshot Boundary

Add `SessionJournalSnapshot`, an immutable guard-read model captured under one
journal lock. Use it in `chio-guards` session-aware guards so each evaluation
observes one coherent view of cumulative data flow, tool sequence, tool counts,
entry count, and journal head hash.

The change is architectural because it introduces a real read boundary for
session guard state. It reduces downstream coupling to individual journal
indexes while preserving the existing append and hash-chain contracts.

## Completed Record Identity Validation

Reject control characters in every `RecordParams` identity field before
appending an entry. This keeps journal serialization, guard-facing tool
sequences, per-tool count keys, and hash-chain input on a printable identifier
boundary while preserving the append-only and snapshot APIs.
