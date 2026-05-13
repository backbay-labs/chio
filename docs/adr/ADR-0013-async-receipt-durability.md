# ADR-0013: Async Receipt Durability

- Status: Accepted
- Decision owner: kernel and receipt-store maintainers
- Related plan items: PR 652 async receipt durability, voice deferral, current v1 receipt-kind semantics

## Context

Some future surfaces, especially low-latency voice or streaming paths, want to
avoid blocking on full receipt-store flush before returning to the caller.
Chio's security story depends on signed receipts being durable enough for audit,
replay, and dispute resolution. PR 652 must settle the durability semantics
before voice or fast-path tickets claim readiness.

## Decision

The default path remains durable-before-allow: a mediated `Allow` is returned
only after the receipt is signed and committed to the configured receipt store.

Async durability is allowed only behind an explicit feature gate and only with a
durable local write-ahead log:

- The kernel signs the mediated receipt.
- The kernel assigns the next monotonic sequence number.
- The kernel fsyncs the signed receipt to a local WAL before returning `Allow`.
- A background worker moves WAL entries to the receipt store.
- A receipt is never considered audit-complete until the store commit is
  acknowledged.

Bounded-loss target:

- A signed receipt that was acknowledged to the caller after WAL fsync has a
  zero-loss target under normal crash recovery.
- Entries not yet fsynced are not acknowledged as `Allow`.
- If WAL append, fsync, queue enqueue, or sequence assignment fails, the kernel
  denies or returns an incomplete pre-effect result.

Queue saturation behavior:

- Saturation of the async queue fails closed for new mediated allows.
- Trace-only and advisory-only export queues may drop or backpressure according
  to their own SLO, but must not affect mediated receipt durability wording.

Gap and replay handling:

- Sequence numbers are monotonic within the receipt store namespace.
- Store replay from WAL detects duplicate sequence numbers and receipt hashes.
- Gaps are recorded as audit faults and surfaced to SIEM.
- A recovered WAL entry that cannot be committed remains in an operator-visible
  fault state until resolved or explicitly quarantined.

Audit wording:

- `signed_but_not_durable` means signed and WAL-fsynced but not yet committed
  to the final receipt store.
- UI and SIEM must not call a receipt fully durable until final store commit.
- Async durability does not relax fail-closed mediation requirements.

## Rationale

Returning `Allow` before any durable write would create tail-loss windows where
the user sees an authorized effect but the audit log can vanish on crash. A WAL
keeps the latency-sensitive path smaller while preserving the core audit
invariant: acknowledged mediated allows are recoverable.

Failing closed on queue saturation keeps the fast path honest. If the receipt
system cannot absorb a mediated allow, the kernel must not silently trade away
auditability.

## Consequences

### Positive

- Future low-latency surfaces have a path that does not abandon receipt
  durability.
- Crash recovery can distinguish missing store commit from missing signed
  receipt.
- Sequence gaps become explicit audit faults.

### Negative

- Async durability still pays for WAL fsync before allow.
- Operators must monitor WAL backlog and stuck entries.
- Voice and streaming tickets remain blocked until this path is implemented and
  benchmarked.

## Required Follow-up

- Add WAL append, fsync failure, queue saturation, replay, duplicate, and gap
  tests.
- Add crash-recovery tests that commit WAL entries after restart.
- Add SIEM and UI copy for `signed_but_not_durable`.
- Add benchmark coverage after the kernel bench stubs are replaced.
- Keep voice implementation deferred until the SLO and tests are in place.
