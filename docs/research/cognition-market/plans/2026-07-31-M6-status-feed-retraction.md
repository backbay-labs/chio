# M6: Status Feed And Retraction

Status: implemented on the cumulative cognition-market stack. The qualified
profile is venue-operated, operator-bonded, portable, and fail-closed. Its
governance decision is recorded in
[ADR-0020](../../../adr/ADR-0020-finding-status-feed-governance.md).

## Goal And Boundary

M6 closes the post-purchase liveness seam without claiming that a fresh root
proves operator completeness. A buyer verifies an exact, signed sparse-map
non-inclusion proof before reveal. An appeal-final upheld challenge creates a
durable retraction outbox item, blocks purchases while publication is pending,
and clears only after a signed inclusion proof is persisted. Governed memory
reads resolve delivery lineage back to the Finding and deny on unavailable,
pending, stale, or retracted status.

The operator's obligation to insert every required retraction remains the
audited assumption `ASSUME-FINDING-STATUS-OPERATOR-COMPLETENESS`. The portable
proof establishes authenticity, path correctness, and freshness for one named
feed and time. It does not establish external insert completeness.

## Implemented Surfaces

- `chio-finding` owns the registered `chio.finding.status-epoch.v1` and
  `chio.finding.status-proof-input.v1` artifact families, strict validators,
  and exact canonical signing boundaries.
- `chio-revocation-oracle` owns the domain-separated sparse status map and
  portable inclusion and non-inclusion verification.
- `chio-store-sqlite` owns the monotonic epoch floor, rollback and equivocation
  rejection, sticky pending and retracted state, exact byte persistence,
  durable intents, and restart-safe proof retrieval.
- `chio-control-plane` owns authenticated root, proof, and intent routes, the
  bonded publisher, purchase verifier, challenge-outbox coupling, and the
  SQLite-backed retraction resolver.
- `chio-kernel` verifies the bounded
  `context.chio_finding_status_proof_b64` carrier before mutation and writes
  kernel-owned status proof metadata into the signed delivery receipt.
- `chio-guards` resolves governed-memory provenance and denies if status or
  lineage cannot be established.
- `chio-cli` independently verifies exact status bytes, signatures,
  authorization, freshness, and sparse paths through `chio finding status`.
- [CHIO_FINDING_MARKET_RUNBOOK.md](../../../release/CHIO_FINDING_MARKET_RUNBOOK.md)
  records epoch cadence, anchoring, inclusion SLA, equivocation, and stalled
  outbox response.

## Security Invariants

1. Feed id, numeric key-domain nonce, map epoch, root, operator identity and
   key epoch, Finding id, path, value, intent, and freshness all cross-bind.
2. Lower epochs and same-epoch alternate roots reject. Pending or retracted
   local state is sticky and cannot be cleared by later non-inclusion.
3. Evaluation alone cannot publish a retraction. Appeal-final enforcement
   atomically creates the pending marker and outbox item, and publication is
   dispatch-ineligible until seller impairment is confirmed final.
4. Missing, stale, malformed, unsigned, wrong-role, or unavailable status and
   provenance inputs deny before reveal or governed-memory read.
5. The default non-market memory profile remains unchanged.

## Recorded Exit Evidence

The reconciled M6 stack passed these gates under an explicit safe umask on
2026-08-01:

| Exit | Result |
|---|---|
| Voluntary `finding_status_retraction` purchase and guarded-read exit | 1 passed |
| Enforced challenge pending/outbox exit | 1 passed |
| Confirmed impairment, status publication, and settlement exit | 1 passed |
| Signed status artifact and portable proof suite | 10 passed |
| Sparse status-map inclusion and non-inclusion suite | 8 passed |
| SQLite rollback, stickiness, restart, rotation, and replay suite | 6 passed |
| Retraction guard unit and governed-memory integration suites | 5 passed |
| `chio finding status` parser and venue validation tests | 2 passed |
| Lean proof build, placeholder scan, manifest, and theorem inventory | 27 jobs passed |
| Schema registry and formal property mapping checks | passed |
| Strict all-target Clippy, four-language codegen, formatting, and Rust file hygiene | passed |

M9 owns the final cumulative workspace gate, feature promotion, proof passport,
and release-boundary claims.
