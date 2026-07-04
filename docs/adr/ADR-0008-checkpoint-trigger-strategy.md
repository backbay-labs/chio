# ADR-0008: Checkpoint Trigger Strategy

- Status: Accepted
- Decision owner: receipt log and kernel lanes

## Context

Chio receipt checkpoints commit batches of receipts to a Merkle tree and
produce a signed `KernelCheckpoint` that enables inclusion proof verification.
A design decision was needed for when to trigger checkpoint creation.

Two candidate strategies were evaluated:

1. **Count-based trigger** -- issue a checkpoint after every N receipts.
2. **Time-based trigger** -- issue a checkpoint after a configurable wall-clock
   interval (e.g., every 60 seconds).

A hybrid was also considered: trigger on whichever comes first.

## Decision

Chio uses a **count-based trigger only**. A checkpoint is issued when the
number of receipts appended since the last checkpoint reaches
`checkpoint_batch_size`. There is no time-based trigger.

The default `checkpoint_batch_size` is 100, defined as
`DEFAULT_CHECKPOINT_BATCH_SIZE = 100` in `chio_kernel::lib`. The value is
configurable in `KernelConfig::checkpoint_batch_size`.

Setting `checkpoint_batch_size = 0` disables automatic checkpointing entirely.

The trigger logic in `ChioKernel::record_chio_receipt`:

```rust
if seq > 0
    && self.checkpoint_batch_size > 0
    && (seq - self.last_checkpoint_seq) >= self.checkpoint_batch_size
{
    self.maybe_trigger_checkpoint(seq)?;
}
```

`last_checkpoint_seq` advances to `batch_end_seq` after each checkpoint. The
next checkpoint window opens at `last_checkpoint_seq + 1`.

## Rationale

**Why count-based only:**

- A Merkle tree with zero leaves is invalid. A time-based trigger would fire
  on idle deployments and produce empty or near-empty batches with no
  meaningful tree structure.
- Count-based batches produce trees of predictable size. Inclusion proofs for
  a batch of N leaves have a maximum proof depth of ceil(log2(N)). With
  `batch_size = 100` the maximum depth is 7, keeping proofs small and
  fast to verify.
- For compliance and forensic use cases, knowing that every checkpoint covers
  exactly N receipts (modulo the final partial batch) simplifies auditability.

**Why not hybrid:**

- A hybrid trigger complicates the trigger logic and provides limited
  additional benefit. Low-traffic deployments that do not accumulate
  `batch_size` receipts may not need checkpointing at all; the lack of a
  checkpoint is not a gap in the audit trail (individual receipts are still
  signed and immutable). Operators who need time-based guarantees can run a
  separate checkpoint-flush tool or reduce `checkpoint_batch_size`.

## Consequences

### Positive

- Deterministic checkpoint sizes make proof verification overhead predictable.
- No timer management in the Kernel; fewer sources of non-determinism.
- Low-traffic deployments do not generate empty checkpoints.

### Negative

- A deployment that processes fewer than `batch_size` receipts in its lifetime
  will never produce a checkpoint, so inclusion proofs are unavailable for
  those receipts. Operators who need per-receipt proofs must set
  `checkpoint_batch_size = 1`.
- There is no guarantee that a checkpoint exists covering receipts up to
  "now" at any given wall-clock time. Log consumers that need recent proof
  coverage must either use a small batch size or poll the checkpoint store.

## Required Follow-up

- Provide a CLI command to force-flush a partial batch to a checkpoint on
  demand (useful before planned Kernel restarts).
- Document the `checkpoint_batch_size = 1` option for deployments requiring
  per-receipt Merkle proofs.
