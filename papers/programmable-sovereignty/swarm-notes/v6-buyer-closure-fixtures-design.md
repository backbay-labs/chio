# V6 — Chiodos buyer-closure replay corpus (design)

Action-plan item: "V6: Chiodos buyer-closure replay corpus (30+ fixtures wired into tests/replay/)".

Status: design only. Manifest authoring + `--bless` golden generation
deferred to a focused engineering session because `--bless` is gated by
trajectory policy (allowed branch, audit log entry, environment guard
per `.planning/trajectory/04-deterministic-replay.md` and the gate-
operator runbook). The autonomous-execution cron should not bless
goldens.

## Context

The current replay corpus has 50 fixtures across 10 capability-side
families (see `tests/replay/fixtures/`). Paper §6 explicitly names the
buyer-closure / ratchet / cross-lane families as v2 follow-up gaps
("the corpus does NOT cover Chiodos buyer-closure / ratchet / cross-
lane"). V6 closes that gap with 30+ new fixtures.

## Family layout

Add eight new family directories under `tests/replay/fixtures/` and
matching goldens. Names use the existing `<verdict>_<scenario>` convention.

| Family directory                          | Verdict | Fixtures | Coverage                                                    |
| ----------------------------------------- | ------- | -------- | ----------------------------------------------------------- |
| `allow_buyer_closure`                     | allow   | 5        | Happy paths: 3-party buyer-vendor closure, distinct vendor selections, distinct treaty scope intersections |
| `allow_cross_lane_quorum`                 | allow   | 4        | Quorum-of-N anchor witnesses (k=2-of-3, k=3-of-5, all lanes contributed, single redundant contribution) |
| `allow_ladder_floor_preserved`            | allow   | 3        | Ladder-floor stable across closure: maintenance, quorum-required (Lean's `maintenance` label), policy-only |
| `deny_buyer_closure_scope_mismatch`       | deny    | 4        | Vendor offers scope outside treaty intersection; buyer treaty omits required ladder; cross-treaty leak attempt; expired buyer-side capability |
| `deny_ratchet_amendment`                  | deny    | 4        | Amendment fails essential-predicate preservation (V5); amendment drops trust-store predicate (V4); amendment narrows admission below adversary-only floor; amendment chains 3-step ratchet |
| `deny_cross_lane_below_quorum`            | deny    | 4        | Witness contributes 1-of-3 declared lanes; witness contributes 2-of-5 with k=3; witness lists out-of-policy lanes only; empty witness against positive-quorum policy (V3) |
| `tampered_bilateral_dsse_signature`       | deny    | 3        | Issuer-side signature tampered; kernel-side cosignature tampered; both sides intact but rebound to different scope digest |
| `replay_buyer_closure_nonce_reuse`        | deny    | 3        | Nonce reused across distinct closure sessions; nonce reused within a single closure; nonce reused across distinct buyers under same vendor |

Total: **30 fixtures** (5+4+3+4+4+4+3+3).

## Manifest schema

Each fixture is a JSON file under
`tests/replay/fixtures/<family>/<NN>_<slug>.json` with the existing
schema (see `tests/replay/fixtures/allow_simple/01_basic_capability.json`):

```json
{
  "clock": "2026-01-01T00:00:00Z",
  "expected_failure_class": null,
  "expected_verdict": "allow",
  "family": "allow_buyer_closure",
  "fixed_nonce_seed_index": 0,
  "intent": "Three-party buyer-vendor closure with non-trivial treaty intersection.",
  "name": "allow_buyer_closure/01_three_party_closure",
  "schema_version": "v1",
  "tags": ["buyer-closure", "treaty-intersection", "v2-corpus"]
}
```

Conventions for the new families:

- All `clock` values use 2026-01-01T00:00:00Z to align with the existing corpus.
- `fixed_nonce_seed_index` is the file ordinal (01 → 0, 02 → 1, ...) per family.
- `schema_version` = "v1" (unchanged).
- `tags` always include "v2-corpus" so the new fixtures can be filtered.
- Buyer-closure fixtures additionally tag with one of {"treaty-intersection", "anchor-quorum", "ladder-floor", "ratchet", "bilateral-dsse"}.

## Execution steps (deferred to focused engineering)

1. Create the eight family directories under `tests/replay/fixtures/`.
2. Write the 30 manifest JSON files per the inventory above.
3. Run `cargo run -p chio-replay-gate -- --bless` on the allowed branch
   with the gate audit log entry, per the trajectory-04 runbook. This
   produces NDJSON receipts + JSON checkpoint + hex root under
   `tests/replay/goldens/<family>/<NN>_<slug>/`.
4. Add the audit entry to `docs/replay-compat.md`.
5. Verify `cargo test -p chio-replay-gate` is green, including
   `corpus_smoke`.
6. Update paper §6 to report 80 fixtures total (50 existing + 30 new)
   and remove the v2-follow-up disclaimer for the now-covered families.

## Why this is not the autonomous cron's job

The `--bless` step is policy-gated (allowed branch, audit-log entry,
environment guard). The cron should not bless goldens. It can author
the manifests, but committing manifests without matching goldens would
turn the replay gate red. So either:

- author all 30 manifests AND bless in one commit (requires policy
  gating + human sign-off), OR
- author the design (this document) and defer the manifest + bless
  flow to a focused engineering session.

This document takes the second path.

## Connection to the formal theorems

- `deny_ratchet_amendment` fixtures exercise V5 (`essential_preserved_chain`).
- The 3-step ratchet sub-fixture exercises the induction step of V5.
- `deny_ratchet_amendment` fixtures also exercise V4 (`containsPredicate_preserved_chain`).
- `deny_cross_lane_below_quorum` fixtures exercise V3 (`anchor_admission_iff_lane_quorum_satisfied`).
- Empty-witness deny exercises the `quorum > 0` branch the V3 supplementary lemma named.
- `allow_buyer_closure` fixtures exercise the existing `treatyPredicateIntersection` theorem.

So the corpus closes the empirical side of the formal theorems V3-V5
provide, completing the spec-implementation-empirical triangle for v2.
