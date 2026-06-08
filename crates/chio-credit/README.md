# chio-credit

`chio-credit` defines Chio's credit, capital, and bonded-execution contracts.
It provides the credit-evaluator hook and IOU envelope types, a local credit
account, an exposure ledger, and an IOU envelope store binding. It composes the
appraisal and underwriting surfaces so credit decisions reference prior signed
Chio truth rather than restating it.

Use this crate to model credit limits, IOUs, and bonded execution for metered
tool access.

## Source Layout

- `src/lib.rs` defines exposure, scorecard, facility, and bond contracts plus
  the intentionally exposed crate API.
- `src/risk_reports.rs` owns loss-lifecycle, backtest, and provider-risk
  report contracts.
- `src/credit/capital_and_execution.rs` owns capital-book, allocation,
  instruction, and bonded-execution simulation contracts.
- `src/hook.rs`, `src/local_account.rs`, and `src/store_binding.rs` own IOU
  hook, local signing, and durable-store surfaces.
