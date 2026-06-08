# chio-link Architecture

## Boundary

`chio-link` owns Chio's cross-currency oracle runtime. It reads Chainlink and Pyth feeds, enforces typed HTTP egress contracts, checks sequencer uptime, applies circuit-breaker divergence policy, caches fresh rates, converts budget units, and emits `OracleConversionEvidence` under the `chio-link` oracle authority.

## Internal Surfaces

The crate is split into oracle configuration, Chainlink and Pyth backends, cache and TWAP logic, conversion math, circuit-breaker checks, runtime monitoring, report classification, and operator control-state traces. `ChioLinkOracle` is the main trust boundary: every backend response must be fresh, pair-exact, and policy-checked before cache insertion or evidence construction can use it.

Unit tests live in `src/tests.rs` and cover the root oracle runtime without making `src/lib.rs` the catch-all test file.

## Trust Invariants

The security constraint is auditable rate exactness. Pair symbols, feed references, source labels, update timestamps, denominators, cache age, conversion margins, and converted units must remain unambiguous across backend reads, cache reuse, degraded mode, and receipt evidence.

## Verification Focus

Tests should cover backend pair mismatch, stale feed timestamps, sequencer downtime, cache age limits, circuit-breaker divergence, degraded mode, health report alert classification, and evidence serialization.
