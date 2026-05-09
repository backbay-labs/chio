# Trajectory 5 Assurance and Claim Matrix

This file keeps the historical `SHIP-BAR-TRACKER.md` name because existing
scripts and review links still point here. Treat the filename and
`scripts/check-bounded-ship-bar.sh` as legacy compatibility names only. The
active contract is claim-by-claim assurance and integration evidence, not a
product-release declaration, not closure of future research, and not tag
authorization.

PR #620 is the planning-truth owner for this matrix. It does not ship
`v0.1.0-bounded-chiodome`. The bounded package status namespace is
`releases.toml` `[v0_1_0_bounded_chiodome].release_status`, but PR #620 does
not author that root package truth.

## Integration Order

The current release architecture is ordered as follows:

1. **Lane B integration first**. Merge the hot-path enforcement stack from a
   clean source branch: B0 async trait, B1 single-entry verifier, B2 receipt v2
   fail-closed, B3 anchor-batch async-only, and B4 DSSE-conformant bilateral
   signing.
2. **Lane A assurance addendum second**. Mutation, threat, Kani, TLA+, and Lean
   evidence is regenerated from the merged Lane B source state. Partial
   mutation samples remain partial until full-scope reruns exist against that
   integrated code.
3. **Lane C canary demo after Lane B**. The chiodome demo is a canary that
   proves composition after Lane B is real. It is not the vehicle for a product
   release claim.
4. **#618 packaging last**. If the canary becomes packageable, #618 must be
   regenerated from merged `main` after the above steps.

## Claim-By-Claim Matrix

| Claim | Allowed wording | Forbidden wording | Required preconditions | Machine evidence | Script checks | Current status |
|---|---|---|---|---|---|---|
| **B. Lane B hot-path enforcement** | Four hot-path primitives have production-call-path conformance evidence, with B4 still pending full DSSE PAE conformance. | "The release is ready because the planning bar is green." | B0 -> B1/B2/B3/B4 integrated from a clean source branch. | Current upstream fixture names are `b1_capability_v2_single_entry_no_bypass.rs`, `b2_receipt_v2_failclosed_pre_dispatch.rs`, `b3_anchor_batch_sync_path_rejected_under_public_witness.rs`, and interim `b4_bilateral_dsse_signature_slice.rs`. B4 remains pending until a full DSSE PAE conformance fixture exists. `scripts/check-anchor-batch-async-witness.sh` exists and exits 0. | `scripts/check-bounded-ship-bar.sh` Claim B block. | PARTIAL/PENDING until the Lane B PRs merge, B4 full conformance lands, fixtures are regenerated from merged `main`, and integrated checks are green. |
| **A. Lane A assurance addendum** | Mutation and threat evidence provide an assurance addendum with explicit partial rows. | "The mutation floor shipped" when any row is partial, subset-limited, budget-capped, or missing full-scope metadata. | Lane B source integration is not blocked by Lane A evidence; Lane A attaches after source ownership is clean. | `audits/evidence/mutants/banner.json`; per-crate JSON under `audits/evidence/mutants/<crate>/`; 20 threat JSON files under `audits/evidence/threats/` with `caught >= 1`, non-1970 `ran_at`, `needs_real_run:false`, and `triage_status`. | `scripts/check-bounded-ship-bar.sh` Claim A block. | PARTIAL. Existing per-crate numbers include full and partial samples; hosted-nightly full-scope reruns remain authoritative. |
| **C. Lane C canary demo** | The bounded chiodome canary runs after Lane B and produces inspectable fixtures. | "v0.1.0-bounded-chiodome is a release tag vehicle for Trajectory 5." | Lane B integrated first; Lane C rebased on that source state; canary fixtures regenerated from merged `main`. | `examples/chiodome-bilateral/` with recipe, at least two transcript JSON files, golden explain output, and pinned `receipt.json`, `envelope.json`, `checkpoint.json` under `fixtures/v0.1.0-bounded-chiodome/`. If root package metadata exists, `releases.toml` `[v0_1_0_bounded_chiodome]` records `release_status` and a non-pending 40-hex `integrated_merge_sha` before any assurance-complete status. | `scripts/check-bounded-ship-bar.sh` Claim C block. | BLOCKED/PARTIAL. The canary remains downstream of Lane B and #618 packaging remains last. |

## Future Work Outside Closure

C5 selective disclosure is not a current closure row. It is future work outside
Trajectory 5 closure unless a later protocol-owned branch adds the normative
implementation, feature, dependency evidence, proof fixtures, negative fixtures,
and release-claim marker. The compatibility status file
`.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml` remains
only so the legacy checker and review links can report an honest non-claim.

The following are also non-blocking future work outside this trajectory's
closure contract:

- Durable full async-kernel architecture beyond the current containment slice.
- Full hosted-nightly mutation reruns without budget caps.
- Full DSSE predicate conformance beyond the current signature-slice evidence.
- Predicate schema completion for the bilateral verifier.
- Distributed receipt store and live revocation oracle integrations.

## Assurance Checker Semantics

`scripts/check-bounded-ship-bar.sh` is strict by default: any `PARTIAL` row fails
the legacy checker. `--diagnostic` reports partial rows as warnings for operator
snapshots. Real `FAIL` rows fail in both modes. Because Worker A owns the
checker, #620 prose does not change script behavior here; this file defines that
Trajectory 5 may close only as an accepted planning/integration map or assurance
matrix, not as release readiness.

The gate must never depend on lane ticket inventories, issue trackers, or
`tickets.md`. Planning files can describe work; executable release or assurance
gates can only depend on evidence artifacts, scripts, source files, and
machine-readable release-status keys.

`.planning/trajectory-5/tools/planning-preflight.sh` is a planning consistency
preflight. It is not a root release close gate.

## Release-Key Contract

Do not add `[trajectory_5]`, tag state, release state, or planning inventory to
root `releases.toml` in this PR.

The only bounded chiodome status namespace, when the package owner records root
truth, is:

```toml
[v0_1_0_bounded_chiodome]
release_status = "blocked_pending_lane_b_integration"
integrated_merge_sha = "pending"
```

Allowed progression is:

```text
blocked_pending_lane_b_integration
lane_b_integrated_assurance_pending
canary_evidence_pending
canary_assurance_complete
```

The final state still does not imply a public product release. It only means
the bounded canary evidence is complete enough for a human release owner to
decide whether to package or tag from merged `main`.

## R6 Closure Matrix

| Issue | Closure in this file and scripts |
|---|---|
| R6-P0-001 | Trajectory 5 is no longer framed as a product release or tag vehicle. |
| R6-P0-003 | Integration order is Lane B first, Lane A assurance addendum second, Lane C canary after Lane B. |
| R6-P0-004 | Executable gates are artifact-based and do not depend on `tickets.md`. |
| R6-P1-005 | The aggregate ship-bar wording is replaced by this claim-by-claim assurance matrix. |
| R6-P2-001 | Release status is normalized to `[v0_1_0_bounded_chiodome].release_status`. |
| R6-P2-002 | Stale singular mutation paths are replaced by `audits/evidence/mutants/**` in the load-bearing contract. |
| R6-P2-003 | The current checker name is `scripts/check-bounded-ship-bar.sh`; stale checker-name wording is removed from the load-bearing contract. |
| R6-P2-007 | Lane C is documented as a canary whose evidence is downstream of Lane B. |
| R6-P2-009 | #618 packaging is explicitly last and must be regenerated from merged `main`. |
| RW4-REL-P2-001 | C5 selective-disclosure status remains machine-readable for legacy checker compatibility only; it is not a release or closure row. |

## RW5 Closure Contract

| Issue | Closure in this file |
|---|---|
| RW5-BI-P0-001 | Trajectory 5 can close only as an accepted planning/integration map or assurance matrix. Future work is outside the closure contract. |
| RW5-BI-P0-002 | The plan is security-reviewable sequencing: Lane B integration, regenerated Lane A evidence, Lane C canary, then #618 packaging. |
| RW5-BI-P1-003 | C5 is removed from the active closure matrix and kept as future work plus checker-compatibility metadata only. |
| RW5-BI-P1-004 | Async work is scoped as containment/integration; durable async architecture is future work. |
| RW5-BI-P2-003 | `ship-bar` survives only in legacy filenames and script names. The active term is assurance and claim matrix. |
