# Chio Link Operator Runbook

## Purpose

This runbook covers the supported operator actions for the shipped `chio-link`
runtime originally tracked under internal milestone `v2.35`.

> Version posture: this is a pre-release operator runbook. Internal `v2.x`
> milestone labels are historical planning labels, not Chio-owned protocol,
> schema, SDK, or runtime versions. Current protocol posture is v1-only.

`chio-link` is the bounded cross-currency budget-enforcement oracle surface. It
does not anchor proofs, dispatch settlement, or automate cross-chain transport.

## Routine Checks

Before enabling cross-currency enforcement for an operator deployment:

1. Review the pinned chain and pair inventory in
   `docs/standards/CHIO_LINK_BASE_MAINNET_CONFIG.json`.
2. Confirm the runtime report surface returns healthy or intentionally disabled
   chain state for Base and Arbitrum.
3. Confirm every pair you expect to charge across currencies is pinned and has
   the intended fallback policy.
4. Run the local qualification commands:
   - `CARGO_TARGET_DIR=target/chio-link-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-link -- --test-threads=1`
   - `CARGO_TARGET_DIR=target/chio-kernel-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-kernel cross_currency -- --test-threads=1`

## Failure Drills

### Global Pause

Use this when market data is clearly untrustworthy or when an operator needs to
stop all cross-currency conversions immediately.

Expected runtime state:

- runtime report `globalPause: true`
- affected pairs report `paused`
- kernel-side cross-currency reconciliation keeps the provisional charge and
  marks settlement failed

Recovery:

1. Clear the root incident.
2. Remove the global pause.
3. Re-run the routine qualification commands.
4. Confirm the runtime report no longer emits `global_pause` or `pair_paused`.

### Pair or Chain Disable

Use this when only one asset pair or one trusted chain is suspect.

Expected runtime state:

- disabled chain reports `disabled`
- pairs pinned to that chain fail closed with explicit operator error
- unrelated same-currency execution continues unaffected

Recovery:

1. Re-enable the chain or pair only after feed correctness is understood.
2. Re-run the runtime report.
3. Confirm pair status returns to `healthy`, `fallback_active`, or another
   intentional state.

### Divergence / Manipulation Suspicion

Use this when primary and fallback prices disagree beyond the configured
threshold.

Expected runtime state:

- affected pair reports `tripped`
- runtime report emits `pair_tripped`
- kernel-side cross-currency reconciliation fails closed

Recovery:

1. Inspect both feed sources and confirm whether the event is market structure,
   provider outage, or bad configuration.
2. If one backend is known good, use a forced backend override temporarily.
3. Remove the override once both sources converge again.

### Sequencer Down or Recovering

Use this when the Chainlink L2 sequencer uptime feed reports downtime or
post-recovery grace.

Expected runtime state:

- chain reports `down` or `recovering`
- affected pairs report `tripped`
- degraded mode is not used for sequencer incidents

Recovery:

1. Wait until the uptime feed returns `up` and the configured grace window has
   elapsed.
2. Re-run the runtime report.
3. Re-enable pair or chain controls only after the chain reports `healthy`.

### Stale Cache / Degraded Grace

Use this only if the operator explicitly wants bounded continuity during a short
oracle outage.

Expected runtime state:

- affected pair reports `degraded_grace`
- the conversion source is suffixed as degraded
- conversion margin is increased

Recovery:

1. Restore a fresh healthy feed path.
2. Disable degraded mode if it was enabled only for incident handling.
3. Confirm the pair returns to `healthy` or `fallback_active`.

## Supported Recovery Boundary

`chio-link` recovery is complete when:

- the runtime report has no unresolved `critical` alerts for the affected pair
  or chain
- operator overrides match the intended steady-state policy
- the local qualification commands are green

If those conditions are not met, Chio should continue failing closed for
cross-currency conversions.
