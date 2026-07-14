# chio-link

Oracle runtime for Chio cross-currency budget enforcement. It resolves
exchange rates from Chainlink and Pyth behind a pluggable backend, cross-checks
and caches them, checks L2 sequencer uptime, and converts amounts between
currencies for budget decisions. `chio-kernel` embeds it via the `PriceOracle`
trait; `chio-metering` enforces budgets against the units it converts.

## Responsibilities

- Read prices from Chainlink (`AggregatorV3Interface.latestRoundData`,
  on-chain via `alloy`, feature `web3`) and Pyth (Hermes REST
  `latest_price_feeds`) behind a common `OracleBackend` trait.
- Enforce a typed `HttpEgressContract` on every RPC/HTTP dispatch (Chainlink
  JSON-RPC, Pyth Hermes, sequencer uptime reads) so oracle calls cannot reach
  arbitrary hosts.
- Cache the latest rate per pair and, when `PairPolicy::twap_enabled`,
  average a rolling observation window into a TWAP.
- Cross-check primary against fallback backend reads with a basis-point
  circuit breaker and fail closed on divergence beyond
  `divergence_threshold_bps`.
- Check L2 sequencer uptime before trusting a chain's feed; fail closed while
  the sequencer is down or inside its post-recovery grace period.
- Apply operator runtime controls: global pause, per-chain enable/disable,
  and per-pair overrides (forced backend, fallback allowance, divergence
  threshold, degraded mode).
- Convert amounts between currencies at fixed minor-unit scales with
  basis-point margin and ceiling rounding (`convert::convert_units`).
- Build a runtime health report (`OracleRuntimeReport`) with per-chain and
  per-pair status and alerts.
- Produce `OracleConversionEvidence` under the `chio_link_runtime_v1`
  authority for auditable conversions. The evidence is unsigned when it
  leaves this crate (`oracle_public_key`/`signature` are `None`); signing
  happens downstream.

## Public API

- `ChioLinkOracle` - the oracle runtime; implements `PriceOracle`. Construct
  with `new` (builds backends from `PriceOracleConfig`) or
  `new_with_backends` (inject backends directly). Exposes `cached_rate`,
  `refresh_pair`, `runtime_report`, `operator_config`, `set_global_pause`,
  `set_chain_enabled`, `set_pair_override`.
- `PriceOracle` - `get_rate`, `supported_pairs`; the trait consumers program
  against.
- `OracleBackend` - `kind`, `read_rate`; implemented by
  `chainlink::ChainlinkFeedReader` (feature `web3`) and
  `pyth::PythHermesClient`.
- `ExchangeRate` - a resolved rate plus `ensure_fresh`, `ensure_matches_pair`,
  `age_seconds`, `with_degraded_mode`, `to_conversion_evidence`.
- `PriceOracleError` - the fail-closed error surface (`Stale`,
  `CircuitBreakerTripped`, `OperatorPaused`, `ChainDisabled`,
  `SequencerDown`/`SequencerRecovering`, `InvalidFeed`,
  `ArithmeticOverflow`, ...).
- `config` - `PriceOracleConfig`, `OperatorConfig`, `PairConfig`,
  `PairPolicy`, `PairRuntimeOverride`, `ChainlinkNetworkConfig`,
  `build_default_egress_contract`.
- `convert` - `convert_units`, `convert_supported_units`,
  `minor_units_for_currency`.
- `monitor` - `OracleRuntimeReport`, `ChainHealthReport`, `PairHealthReport`,
  `OracleAlert`.
- `control::ChioLinkControlState` - operator-action audit trail (global
  pause, chain enable, pair override) with before/after snapshots. Nothing in
  this crate writes to it automatically; callers record changes through it.

## Feature flags

| Flag | Effect |
|------|--------|
| `web3` (default) | Enables the on-chain `ChainlinkFeedReader` and L2 sequencer-uptime reads via `alloy-*`. Disabling it swaps in `chainlink_disabled`/`sequencer_disabled` stubs that return `PriceOracleError::UnsupportedBackend`; `ChioLinkOracle::new` fails if `primary`/`fallback` selects `Chainlink` without the feature. |

## Testing

`cargo test -p chio-link` covers the default (`web3`-enabled) build.
`cargo test -p chio-link --no-default-features` exercises the disabled-stub
paths.

## See also

- `chio-kernel` - embeds `ChioLinkOracle` and calls `convert_supported_units` during request evaluation.
- `chio-metering` - enforces budgets against the units this crate converts.
- `chio-control-plane` - drives `ChioLinkOracle` and records operator actions through `control::ChioLinkControlState`.
- `chio-egress-contract` - supplies the `HttpEgressContract` this crate enforces on every dispatch.
