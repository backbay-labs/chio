# chio-verdict-matrix-driver-lambda

Lambda deployment-shape driver for the Chio verdict matrix. The crate loads
the shared verdict-matrix scenario corpus, relays each scenario to an
operator-supplied Chio sidecar over `POST /chio/evaluate`, and reports a
pass/fail/unsupported verdict tuple per scenario. `chio-conformance` owns the
scenario corpus and registers this crate in its manifest as the
`lambda-deployment-shape` driver, representing the
`sdks/lambda/chio-lambda-extension` package in the deployment-shape registry.

## Responsibilities

- Resolve and load the canonical verdict-matrix scenario corpus, rejecting
  symlinked roots/files and scenarios with an unrecognized `schema`
  (`resolve_scenario_root`, `load_scenarios`).
- Translate each scenario into a `chio-http-core::ChioHttpRequest`-shaped
  wire body, mirroring the `typescript-node-http` driver's contract
  (`scenario_to_http_request`).
- Relay each request to the sidecar over blocking HTTP and derive the
  verdict tuple from the response's `verdict` and
  `receipt.metadata.verdict_matrix` fields (`run_driver`,
  `tuple_from_evaluate_response`).
- Gate `capability` and `revocation` scenarios to `unsupported` before any
  network call: this relay has no signed `CapabilityToken` builder, so it
  cannot produce a faithful verdict for those categories
  (`sidecar_unsupported_reason`).
- Fail closed on ambiguous states: no sidecar configured reports every
  scenario `unsupported` with a diagnostic; a set-but-unreachable sidecar
  reports `fail`, never a silent skip or pass.

## Public API

- `resolve_scenario_root() -> Result<PathBuf, String>` - locate the scenario
  corpus by walking upward for a `Cargo.toml` + verdict-matrix directory pair.
- `load_scenarios(root: &Path) -> Result<Vec<Scenario>, String>` - parse and
  validate the scenario corpus.
- `run_driver(scenario_root: &Path, sidecar_url: Option<&str>) -> Result<DriverReport, String>`
  - run the full scenario set and build a report.
- `scenario_to_http_request`, `tuple_from_evaluate_response`,
  `expected_tuple_map` - wire-shape and verdict-tuple helpers.
- `Scenario`, `ScenarioScript`, `VerdictTuple`, `ScenarioOutcome`,
  `DriverReport` - the scenario and report data model.
- `DRIVER_NAME`, `MATRIX_ROLE`, `UNDERLYING_DRIVER`, `SIDECAR_ENV`,
  `SIDECAR_FALLBACK_ENV`, `SCENARIO_SCHEMA` - driver identity and wiring
  constants.
- Binary `chio-verdict-matrix-driver-lambda` - resolves the scenario root,
  runs the driver against `CHIO_VERDICT_MATRIX_SIDECAR_URL` (or
  `CHIO_SIDECAR_URL`), and prints the `DriverReport` as JSON to stdout.

## Usage

```rust
use chio_verdict_matrix_driver_lambda::{resolve_scenario_root, run_driver};

fn main() -> Result<(), String> {
    let root = resolve_scenario_root()?;
    let sidecar = std::env::var("CHIO_VERDICT_MATRIX_SIDECAR_URL").ok();
    let report = run_driver(&root, sidecar.as_deref())?;
    println!("{}/{} scenarios passed", report.passed, report.total);
    Ok(())
}
```

## Testing

```bash
cargo test -p chio-verdict-matrix-driver-lambda --quiet
cargo run -p chio-verdict-matrix-driver-lambda --quiet
```

Set `CHIO_VERDICT_MATRIX_SIDECAR_URL` (or the `CHIO_SIDECAR_URL` fallback) to
a live Chio sidecar to exercise the HTTP relay path; without it, every
scenario reports `unsupported`.

## See also

- `chio-conformance` - owns the verdict-matrix scenario corpus and manifest
  (`verdict_matrix/manifest.toml`) and the `deployment_shape_smoke`
  integration test that asserts this driver is registered and wire-compatible
  with the Rust kernel reference.
- `sdks/lambda/chio-lambda-extension` - the deployment-shape package this
  driver's registry entry represents.
- `drivers/jvm`, `drivers/dotnet`, `drivers/k8s` - sibling deployment-shape
  drivers on the same scenario corpus and sidecar contract.
