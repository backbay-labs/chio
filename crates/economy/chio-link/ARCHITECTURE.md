# chio-link architecture

## Overview

`chio-link` turns Chainlink and Pyth price feeds into `ExchangeRate`s the rest
of Chio can use for cross-currency budget enforcement. It sits at an
untrusted edge: every backend response is pair-matched and freshness-checked
before it can enter the cache, and every outbound RPC/HTTP call is gated by a
typed `HttpEgressContract` before it leaves the process. `chio-kernel` embeds
`ChioLinkOracle` behind the `PriceOracle` trait during request evaluation;
`chio-metering` enforces budgets against the units this crate converts.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `ExchangeRate`, `PriceOracleError`, the `PriceOracle`/`OracleBackend` traits, and `ChioLinkOracle` (backend selection, cache, operator controls, health reports). |
| `src/config.rs` | `PriceOracleConfig`, `PairConfig`, `PairPolicy`, `OperatorConfig`, `PairRuntimeOverride`, `ChainlinkNetworkConfig`; config validation and `build_default_egress_contract`. |
| `src/cache.rs` | `PriceCache`: latest-rate storage per pair, rolling observation window, TWAP averaging. |
| `src/chainlink.rs` / `src/chainlink_disabled.rs` | `ChainlinkFeedReader` (`OracleBackend` for Chainlink). Feature-gated: `chainlink.rs` reads `AggregatorV3Interface.latestRoundData`/`decimals` over a contract-pinned `alloy` transport; `chainlink_disabled.rs` is the `web3`-off stub that always errors. |
| `src/pyth.rs` | `PythHermesClient` (`OracleBackend` for Pyth): fetches Hermes `latest_price_feeds`, validates the returned feed id, normalizes decimal price/confidence into a rate ratio. |
| `src/sequencer.rs` / `src/sequencer_disabled.rs` | L2 sequencer-uptime reads (`read_sequencer_status`) against a second `AggregatorV3Interface` binding (no `decimals`). Feature-gated like the Chainlink backend. |
| `src/circuit_breaker.rs` | `divergence_bps` and `ensure_within_threshold`: basis-point divergence between two rates for the same pair. |
| `src/convert.rs` | `minor_units_for_currency`, `convert_units`, `convert_supported_units`: fixed-point cross-currency conversion with basis-point margin and ceiling rounding. |
| `src/monitor.rs` | `OracleRuntimeReport`, `ChainHealthReport`, `PairHealthReport`, `OracleAlert` and their status/severity enums. |
| `src/reports.rs` | Private classification helpers that turn a resolved rate or error into a `PairHealthStatus`/`OracleAlert`, and a chain status into an `OracleAlert`. |
| `src/control.rs` | `ChioLinkControlState`: an append-only audit trail (before/after JSON) for operator actions, under the `chio.link.control-state.v1`/`control-trace.v1` schemas. |

## Rate resolution

1. `pair_config` looks up the requested base/quote in `PriceOracleConfig`,
   re-validating the whole config on every call.
2. `enforce_operator_controls` fails closed if the global pause is active,
   the pair's runtime override is disabled, its chain is disabled, or (when
   the chain has a `sequencer_uptime_feed`) the L2 sequencer is down or still
   inside its recovery grace period.
3. `resolve_cached_rate` returns a cached rate if fresh, folding recent
   observations into a TWAP when `PairPolicy::twap_enabled`. On a stale entry
   it tries `degraded_rate_if_allowed`, which extends `max_age_seconds` and
   adds margin instead of failing, but only when `DegradedModePolicy::enabled`
   and the entry is no older than `max_age_seconds + max_stale_age_seconds`.
4. On a cache miss, `fetch_authoritative_rate` reads the primary backend (or
   the pair override's forced backend). If a fallback is configured, allowed,
   and supported by the pair, it is also read and cross-checked against the
   primary with `circuit_breaker::ensure_within_threshold`; divergence beyond
   the threshold fails closed with `CircuitBreakerTripped` even though a
   valid primary rate exists. If the primary read fails, the fallback is used
   unchecked.
5. Every backend response passes through `read_validated_backend_rate`:
   `ensure_matches_pair` (exact base/quote match) and `ensure_fresh`
   (non-zero denominator, `updated_at` not in the future, age within
   `max_age_seconds`) before it can enter the cache.
6. `ExchangeRate::to_conversion_evidence` re-checks freshness and builds an
   `OracleConversionEvidence` stamped with `schema =
   chio.oracle-conversion-evidence.v1` and `authority = chio_link_runtime_v1`,
   unsigned, for a downstream signer and
   `chio-web3::anchors::validate_oracle_conversion_evidence` on the
   receiving end.

## Invariants and failure modes

- Fail closed by default: operator pause, disabled chain, sequencer
  down/recovering, stale price, pair mismatch, and circuit-breaker
  divergence all reject the call instead of returning a best-effort rate.
  Degraded mode is the one explicit, policy-gated exception, and it is off by
  default (`DegradedModePolicy::disabled`).
- `ChioLinkOracle::new`/`new_with_backends` reject a config whose declared
  `primary`/`fallback` backend kind does not match the constructed backend's
  `OracleBackend::kind()`.
- The `web3` feature gates all live Chainlink and sequencer reads. With it
  off, `chainlink_disabled`/`sequencer_disabled` return
  `PriceOracleError::UnsupportedBackend` (or, for a configured sequencer
  feed, always error), and `build_backend` refuses to construct a
  Chainlink-primary/fallback oracle at all.
- Every RPC and HTTP dispatch (Chainlink JSON-RPC, Pyth Hermes, sequencer
  uptime) routes through a typed `HttpEgressContract`: scheme/authority
  allow-listing, loopback/link-local/IPv6-ULA denial, a pinned DNS resolver
  enforced at connect, a bounded redirect chain, and a maximum response size.
  `PriceOracleConfig::validate` also enforces the contract against the
  configured Pyth and chain RPC URLs at config-load time.
- Config types derive `#[serde(deny_unknown_fields)]`, so an unrecognized
  field in operator or pair config fails deserialization instead of being
  silently dropped.
- `control::ChioLinkControlState` is a data structure only; nothing in
  `ChioLinkOracle` writes to it automatically. An integrator that needs an
  audit trail must call `record_global_pause`/`record_chain_enabled`/
  `record_pair_override` itself alongside the matching `ChioLinkOracle`
  mutator.

## Dependencies

- `chio-core` - via `web3::anchors` (a `chio-web3` re-export) supplies
  `OracleConversionEvidence`, `CHIO_LINK_ORACLE_AUTHORITY`, and
  `CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA`; via `web3::settlement` supplies
  `CHIO_LINK_CONTROL_STATE_SCHEMA`/`CHIO_LINK_CONTROL_TRACE_SCHEMA` for
  `control.rs`.
- `chio-egress-contract` (`reqwest-egress` feature) - `HttpEgressContract`
  plus `client_builder_with_contract`/`send_with_contract`, enforced on every
  outbound dispatch.
- `alloy-*` (`web3` feature) - JSON-RPC client, contract bindings (`sol!`),
  and primitives for the on-chain Chainlink and sequencer-uptime reads,
  wrapped in a custom `tower::Service` (`ContractJsonRpcTransport`) so every
  request routes through the egress contract instead of `alloy`'s default
  transport.
- `reqwest` - the Pyth Hermes HTTP client and the transport `alloy` is built
  on.
- `tokio` - `RwLock` around the cache and operator config for concurrent
  reads with exclusive writes.

## Extension points

- `OracleBackend` - implement to add a price source beyond Chainlink/Pyth;
  `ChioLinkOracle` only requires `kind()` and `read_rate()`.
- `PriceOracle` - the trait consumers (`chio-kernel`) program against instead
  of depending on `ChioLinkOracle` directly.
