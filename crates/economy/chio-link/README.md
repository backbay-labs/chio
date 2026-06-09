# chio-link

`chio-link` is the oracle runtime for Chio cross-currency budget enforcement.
It resolves exchange rates from oracle sources (Chainlink and Pyth, gated
behind the `web3` feature), with caching, a circuit breaker, a sequencer
uptime check, and conversion helpers. It emits the
`OracleConversionEvidence` artifact under the `chio-link` oracle authority so
currency conversions used in budget decisions remain auditable.

Use this crate when budgets are denominated in one currency but enforced
against costs in another. Metering consumes its conversions via
`chio-metering`.
