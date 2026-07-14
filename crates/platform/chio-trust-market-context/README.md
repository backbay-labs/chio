# chio-trust-market-context

Verifies the trust-market section of a Chio transaction proof bundle:
provider discovery, provider selection, trust scorecards, portable
reputation imports, SLA commitments and performance, collateral,
guarantees, and adjudication jurisdiction, plus the risk-comptroller report
that binds them to reserves. The crate's one function,
`verify_trust_market_context`, turns a bundle of signed JSON artifacts and
an evidence graph into a `TrustMarketVerifierReport` or a fail-closed
`TransactionPassportError`.

It is one claim-family verifier among several that `chio-proof-room`
composes over a proof bundle; `chio-control-plane` re-exports it as
`trust_market`. It verifies a bundle after the fact and does not select
providers, update reputation, enforce SLAs live, or authorize settlement.

## Responsibilities

- Delegate passport-signature and minimal-artifact checks to
  `chio-transaction-passport` before trusting anything else in the bundle.
- Parse the trust-market evidence graph and verifier policy, then resolve
  all ten evidence artifacts by content digest and a `sig-ed25519:`
  signature check against market authority keys the verifier policy pins
  (not just supplied by the caller).
- Cross-bind the artifacts to each other (ids, order ids, freshness
  windows, ranks and scores) in dependency order: discovery, reputation
  import, scorecard, selection, risk report, SLA, jurisdiction, then
  collateral and guarantee.
- Delegate risk-comptroller report validation to `chio-risk-comptroller`
  and bind its result to the selected provider and order.
- Enforce that the verifier policy discloses a fixed set of market
  capabilities Chio does not implement (permissionless marketplace,
  published global trust score, liquidity pool, risk syndication,
  underwriter market, autonomous guarantee sales, slashing court), and
  reject any policy that requires one of them.

## Public API

- `TrustMarketBundle` - input: a `TransactionPassport`, the trust-market-
  scoped evidence graph bytes, an optional `root_evidence_graph_bytes` for
  when that graph is a scoped subset of the one the passport signs, the
  verifier policy bytes, artifact bytes keyed by bundle-relative path, and
  the trusted passport-signer and market-authority key sets.
- `TrustMarketVerifierReport` / `TrustMarketVerifierSections` - output:
  verdict, verified and unsupported claim ids, and the artifact id bound to
  each trust-market section. Both derive `Serialize`/`Deserialize`.
- `verify_trust_market_context(bundle: &TrustMarketBundle) -> Result<TrustMarketVerifierReport, TransactionPassportError>` -
  the sole entry point.

## Testing

`tests/trust_market_context.rs` builds one signed fixture bundle and
exercises each failure mode by mutating a single field at a time; the lib
target itself carries no unit tests (`test = false` in `Cargo.toml`).

```bash
cargo test -p chio-trust-market-context
```

## See also

- `chio-transaction-passport` - passport and evidence-graph signature
  verification, and the schema id constants this crate validates against.
- `chio-risk-comptroller` - validates the `RiskComptrollerReport` this
  crate binds to the selected provider.
- `chio-proof-room` - composes this verifier with other claim-family
  verifiers over one proof bundle.
- `chio-control-plane` - re-exports this crate as `trust_market`.
