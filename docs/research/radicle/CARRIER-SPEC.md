# Radicle checkpoint carrier: deferred implementation spec

- Status: Deferred. Do not build without a triggered revisit under ADR-0018.
- Date: 2026-07-25
- Decision: [../../adr/ADR-0018-radicle-carrier-not-authority.md](../../adr/ADR-0018-radicle-carrier-not-authority.md)
- Evidence: [./EVALUATION.md](./EVALUATION.md)
- Precedent for the seam: ADR-0014 and [../iroh/ADAPTER-SPEC.md](../iroh/ADAPTER-SPEC.md)

This document exists so that a future revisit starts from a design rather than
from scratch. It is written to be buildable, but it is explicitly not scheduled,
and stages 1 through 4 of the transparency program take priority over all of it.
Building this before the consistency proof is real (finding F1) would produce a
carrier faithfully distributing checkpoints whose append-only relationship
nothing verifies.

## 1. Scope

In scope: publishing signed Chio kernel checkpoints to a Radicle repository so
that third parties can retain them, and detecting equivocation from what those
third parties retained.

Out of scope, permanently: Radicle as an authority (see the invariants), as a
replacement for the iroh federation transport, as a store for capability
tokens, revocations, or receipts themselves, and as an in-process dependency.

## 2. Invariants

Normative. A carrier implementation may not relax these.

1. **Carrier, never authority.** The only thing making a published checkpoint
   authoritative is the Chio kernel signature inside the blob, verified against
   a key pinned out of band. Radicle NIDs, delegate thresholds, `refs/rad/sigrefs`
   attestations, and COB merge outcomes are never inputs to a Chio accept
   decision.
2. **Absence is never evidence.** A missing path means unknown. Never "does not
   exist", never "not revoked".
3. **Withholding degrades to denial.** A head staler than the freshness window
   denies. Unavailability is never a silent accept.
4. **Sibling adapter, no surgery.** `chio-kernel` and `chio-federation` are not
   modified.
5. **Out-of-process only.** Forced by the `links = "sqlite3"` collision, which
   is a hard resolver error and has no feature-flag workaround.

## 3. Crate shape

Two crates, mirroring the split that kept the iroh adapter clean.

`chio-transparency-carrier` (pure, no I/O, no Radicle dependency): the
publication layout, the canonical path scheme, the checkpoint body digest, the
equivocation detection algorithm over an abstract set of retrieved blobs, and
the verifier policy evaluation. A `CheckpointCarrier` trait with `publish`,
`fetch_head`, and `enumerate` methods. This crate is where the value is, and it
is substrate-agnostic: the same logic serves a C2SP witness quorum, a TUF
repository, or a static directory over HTTPS.

`chio-transparency-carrier-radicle` (the driver): implements
`CheckpointCarrier` by invoking `rad` and `git` as subprocesses against a
dedicated `RAD_HOME`, with bounded timeouts, bounded output, and no inherited
environment. Every subprocess failure maps to a typed error that denies.

## 4. Layout

Prefer the COB layout if built, because the experiment showed conflicts surface
automatically in merged state rather than requiring a deliberate
cross-namespace scan. The plain-file layout is the fallback and is the one to
use if the external-helper requirement proves too fragile to operate.

Plain-file layout, as exercised in the experiment:

```
log/<log_id>/checkpoints/<20-digit zero-padded batch_end_seq>.json
```

Each file is the canonical-JSON `KernelCheckpoint` including its kernel
signature. `batch_end_seq` is the cumulative checkpoint position, so routine
equal-sized batches retain distinct paths. Zero-padding gives lexicographic
ordering that matches numeric ordering.

COB layout: a custom type whose operations are checkpoint publications, with an
evaluator that unions concurrent operations and records conflicting
`(kernel_key, checkpoint_seq, batch_end_seq)` groups with distinct body
digests. Note that this requires the evaluator binary on `PATH` of every
interpreting node and that replication succeeds while evaluation hard-fails
without it. COB visibility through `radicle-httpd` and web gateways remains
unverified because `radicle-httpd` was absent from the tested release artifact.

## 5. Detection algorithm

Substrate-independent, and largely already present in `checkpoint.rs` as
`ordered_equivocation` and `CHECKPOINT_EQUIVOCATION_SCHEMA`. Chio has the
detection logic; what a carrier adds is a distribution substrate that gets both
inputs into a third party's hands.

1. Enumerate all peer namespaces, not just the canonical branch.
2. Extract every checkpoint blob.
3. Discard any blob whose `kernel_key` is not the pinned kernel key (or whose
   derived `log_id` is not the monitored log) BEFORE grouping. Signature
   validity alone only says a blob was signed by the key it carries, so in an
   open repository any peer could publish two self-signed conflicting bodies
   and manufacture a finding against an untrusted identity.
4. Recompute `sha256(canonical(body))` for each survivor.
5. Group by `(kernel_key, checkpoint_seq)` and by cumulative log position
   (`batch_end_seq`, what `checkpoint_log_tree_size` derives). Do not group by
   `body.tree_size`: that is one batch's leaf count, so routine equal-sized
   batches would collide and raise false forks. The same applies to any
   publication path or filename key.
6. Any group with more than one distinct body digest is an equivocation.
7. Verify both kernel signatures to make the finding transferable.

## 6. Operational requirements

These are not optional; the experiment showed the property fails without them.

- **Every monitor must use `--scope all`.** A monitor on `--scope followed`
  never receives a fork and will report no equivocation. This must be asserted
  at startup and must fail closed if misconfigured.
- **At least one non-colluding party must actively re-publish** received
  checkpoints under its own key. Passive seeding is insufficient: a passive
  mirror follows a force-push and loses the prior value. This role needs a new
  carrier-level republication record: `CHECKPOINT_WITNESS_SCHEMA` cannot serve
  it, because `CheckpointWitness` is derived deterministically from two kernel
  checkpoints and carries no peer identity, namespace ref, peer signature, or
  publication evidence, so it cannot distinguish an independent republication
  from the original publisher's ordinary successor checkpoint.
- **Cross-namespace retrieval must be explicit.** A default `git clone` takes
  only `refs/heads/*` and sees the canonicalized view; the fetch must use
  `+refs/namespaces/*:refs/namespaces/*`.
- **Node key custody** is a new secret to manage, distinct from the kernel
  signing key, and must never be conflated with it.

## 7. Open questions for a future revisit

- Does `radicle-httpd` filter namespace refs? Unverified: it is absent from the
  1.9.1 release tarball, so the read-only HTTP path could not be tested.
- Is the COB external-helper interface stable enough to depend on? It is
  currently undocumented and was discovered only via `strace`.
- Does Radicle add anything once C2SP witness cosigning (transparency program
  stage 4) is in place, given that witnessing delivers the stronger property?
  This is the question most likely to resolve as "no".
