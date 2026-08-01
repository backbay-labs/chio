# Pool Purchasing and SDK (M8) Qualification

Status: implemented behind `cognition-market-experimental`. The buyer ceiling
is buyer-local policy. The hard pool ceiling applies only to the qualifying
durable SQLite ledger. A final integrated branch must still pass the workspace
gate listed below.

## Authority boundaries

M8 does not ship a re-derivation quote producer. `MeteredBillingQuote` remains
unsigned caller-carried context, and neither the venue nor kernel may claim
that the bid basis is true. `SignedBidRequest` exposes only the chosen ceiling.

`finding_bid_ceiling` is defined over canonical decimal-string integers. The
Rust reference implementation uses checked `u128` intermediates and floors
once after the combined basis-point product:

```text
min(budget_remaining,
    estimate * would_have_run_bps
             * (10000 - sibling_redundancy_bps)
             * guarantee_class_bps
             / 10000^3)
```

Every amount and timestamp is bounded to `u64`; every basis-point input is in
`0..=10000`. Exact currency, source, context, replay-recipe, provenance, and
validity bindings reject substitution or staleness. TypeScript accepts decimal
strings through `u64` but rejects an unsafe JavaScript `Number`; Python and
Rust accept the same decimal-string domain.

`SwarmBudgetPool` remains an unsigned planning object. The registered
`chio.finding.pool-allocation.v1` companion authenticates the exact canonical
pool digest, graph and pool ids, purchaser id and key, currency, amount, nonce,
authority, and validity window. The kernel resolves it against an externally
pinned authority and charges only facts returned by the installed strict
purchase verifier: payer key, purchase intent, reservation and payment
operation, finding, listing, accepted price, accepted-bid digest, and venue
admission digest.

The `QualifiedFindingPoolLedger` marker is restricted to audited atomic or
linearizable durable backends. The shipped SQLite implementation refuses
in-memory paths, serializes debits with `BEGIN IMMEDIATE`, stores full-domain
`u64` values as canonical decimal text, binds one signed purchaser allocation
per pool id, and persists exact replay. Advisory remote budget views do not
qualify.

## Fully admitted finding hint

The finding pheromone uses the generic signed deposit and substrate admission,
not indicator JSON alone. Its convention fixes:

- subject `finding_listing_hint` and namespace `dev.chio.cognition-market`;
- one configured treaty, one non-empty nonce, severity `medium`, confidence
  `0.75`, 3,600 second half-life, and evaporation floor `0.01`;
- exact Finding id, listing id, signed listing digest, signed M2 admission
  digest, and `finding:<finding_id>` capability scope;
- the exact non-destructive `SubjectClassPolicy`, a live signer passport,
  receiver-owned scarcity and replay admission, and a cryptographically
  verified observation-cost commitment below the receiver cap.

After deposit admission, the buyer still verifies the current namespace-owned
listing, its pricing signature, and the complete M2 admission bundle. The hint
grants no purchase authority.

## Named exit evidence

The M8 worktree recorded these results on 2026-07-31:

| Exit | Command | Result |
|---|---|---|
| Rust ceiling, real marketplace, and pheromone convention | `cargo test -p chio-open-market --features cognition-market-experimental --test finding_bid_policy --test cognition_market_flow --test finding_admission -j1` | 38 passed on the final cumulative base |
| Authenticated pool concurrency and restart | `cargo test -p chio-store-sqlite --features cognition-market-experimental --test finding_pool_ledger -j1` | 4 passed |
| TypeScript SDK suite and parity vectors | `node --experimental-strip-types --test ./test/*.test.ts` in `sdks/typescript/chio-ts` | 88 passed |
| TypeScript strict type check | `tsc --noEmit -p chio-ts/tsconfig.json` | passed |
| Python SDK suite and parity vectors | `uv run --project . --extra dev pytest -q` in `sdks/python/chio-sdk-python` | 145 passed |
| Schema registry | `bash scripts/check-chio-schema-registry.sh` | passed |
| Formatting | `cargo fmt --all -- --check` | passed |

The final cumulative branch, after reconciling its M5 base and the other
cognition-market milestones, must additionally pass without exclusions:

```bash
cargo build --workspace -j1
cargo test --workspace -j1
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

Targeted exits demonstrate M8 behavior; they do not substitute for that final
workspace qualification.
