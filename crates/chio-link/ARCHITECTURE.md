# chio-link Architecture

## Boundary

`chio-link` owns Chio's cross-currency oracle runtime. It reads Chainlink and Pyth feeds, enforces typed HTTP egress contracts, checks sequencer uptime, applies circuit-breaker divergence policy, caches fresh rates, converts budget units, and emits `OracleConversionEvidence` under the `chio-link` oracle authority.

## Internal Surfaces

The crate is split into oracle configuration, Chainlink and Pyth backends, cache and TWAP logic, conversion math, circuit-breaker checks, runtime monitoring, and operator control-state traces. `ChioLinkOracle` is the main trust boundary: every backend response must be fresh, pair-exact, and policy-checked before cache insertion or evidence construction can use it.

## Trust Invariants

The security constraint is auditable rate exactness. Pair symbols, feed references, source labels, update timestamps, denominators, cache age, conversion margins, and converted units must remain unambiguous across backend reads, cache reuse, degraded mode, and receipt evidence.

## Verification Focus

Tests should cover backend pair mismatch, stale feed timestamps, sequencer downtime, cache age limits, circuit-breaker divergence, degraded mode, and evidence serialization.

## Improvement Target

Planned improvement: reject backend rates whose `base` or `quote` differs from the configured pair before circuit-breaker comparison or cache insertion, so injected or fallback backends cannot poison evidence with a mismatched currency label.
