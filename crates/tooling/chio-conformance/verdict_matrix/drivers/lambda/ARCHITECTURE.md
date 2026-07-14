# chio-verdict-matrix-driver-lambda architecture

## Overview

`chio-verdict-matrix-driver-lambda` is a conformance tool, not a production
Chio component. `chio-conformance` owns the verdict-matrix scenario corpus
and manifest under `crates/tooling/chio-conformance/verdict_matrix/`, and
registers this crate there as the `lambda-deployment-shape` driver,
representing the `sdks/lambda/chio-lambda-extension` package in the registry.
The crate holds no kernel, guard, or policy logic of its own: it loads the
shared scenario corpus, hand-builds a `chio-http-core::ChioHttpRequest`-shaped
JSON body per scenario, and POSTs it to an operator-supplied Chio sidecar's
`/chio/evaluate` endpoint, then diffs the parsed verdict tuple against the
scenario's expected tuple. Its trust position is that of an external caller
exercising the sidecar's public wire contract: it has no path dependency on
any `chio-*` crate and cannot produce a verdict on its own.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Scenario loading and validation, HTTP relay to the sidecar, verdict-tuple parsing, and the `DriverReport`/`ScenarioOutcome` data model. |
| `src/main.rs` | CLI entry point: resolves the scenario root, reads the sidecar env vars, runs the driver, prints the JSON report, and sets the process exit code. |

## Evaluation flow

1. `resolve_scenario_root` walks upward from the working directory for a
   directory containing both `Cargo.toml` and
   `crates/tooling/chio-conformance/verdict_matrix`, and returns
   `<that>/scenarios`.
2. `load_scenarios` walks the scenario tree, rejecting a symlinked root or
   any symlinked file under it, sorts paths for determinism, and parses each
   `.json` file into a `Scenario`, rejecting any `schema` other than
   `chio.verdict-matrix.scenario.v1`.
3. `run_driver` branches on whether a sidecar URL is configured. Unset or
   empty: every scenario is reported `unsupported` with a diagnostic naming
   `CHIO_VERDICT_MATRIX_SIDECAR_URL`. Set: `capability` and `revocation`
   scenarios gate to `unsupported` up front (`sidecar_unsupported_reason`);
   every other scenario goes through `evaluate_scenario`.
4. `evaluate_scenario` builds a `chio-http-core::ChioHttpRequest`-shaped JSON
   body (`scenario_to_http_request`) with a synthetic `x-chio-capability`
   header, POSTs it to `<sidecar_url>/chio/evaluate`, and on a successful
   response derives the verdict tuple (`tuple_from_evaluate_response`) from
   `verdict.verdict` and the `receipt.metadata.verdict_matrix` block, falling
   back to the deny reason when matrix metadata is absent.
5. The derived tuple and the scenario's expected tuple are both normalized
   (`VerdictTuple::normalized` sorts `scope_set`) and compared; any transport
   error, non-success status, unparseable body, or tuple mismatch yields
   `fail`.
6. `run_driver` aggregates the per-scenario `ScenarioOutcome`s into a
   `DriverReport`; `main.rs` prints it as pretty JSON on stdout and exits 2 on
   a setup error, 1 if any scenario failed, 0 otherwise.

## Invariants and failure modes

- Fails closed on any symlinked scenario root or symlinked file within the
  scenario tree, before parsing.
- Every scenario must declare `schema = "chio.verdict-matrix.scenario.v1"`;
  any other value is a hard load error, not a skipped scenario.
- "No sidecar configured" (`unsupported`) and "sidecar configured but
  unreachable" (`fail`) are kept distinct outcomes; a misconfigured sidecar
  can never read as a pass.
- `capability` and `revocation` scenarios always gate to `unsupported`, even
  against a reachable sidecar, because this relay has no signed
  `CapabilityToken` builder and cannot produce a faithful verdict for
  issuer/signature/time-validity checks.
- `VerdictTuple` equality depends on `scope_set` order; both the actual and
  expected tuples must go through `normalized()` before comparison.
- `#![forbid(clippy::unwrap_used)]` and `#![forbid(clippy::expect_used)]`
  apply to both `lib.rs` and `main.rs`; every fallible path returns a
  `Result` or degrades to a reported outcome.

## Dependencies

No internal `chio-*` crate dependencies: the driver cannot link kernel or
guard code and can only reach a Chio evaluator over HTTP. External:
`reqwest` (`blocking`, `json`, `rustls`) for the sidecar relay,
`serde`/`serde_json` for the scenario and report models, `url` for
percent-encoding tool-name path segments in the request path. Both `reqwest`
call sites carry a `CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST` marker, the house
convention for exempting an operator-supplied test URL from the
`chio-egress-contract` production egress policy.
