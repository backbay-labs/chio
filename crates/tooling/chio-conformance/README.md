# chio-conformance

Cross-language and cross-SDK conformance harness for the Chio protocol. The
crate is a small library (scenario loading, live-run orchestration, report
rendering) fronting a large integration and negative-conformance test suite
that drives the kernel, the reference peer SDKs, and other Chio crates
against the wire shape defined in `spec/schemas/chio-wire/v1/` and
`spec/PROTOCOL.md`.

The crate is source-installable from the Chio repository so external
implementers can run the same scenarios without a full monorepo checkout. It
is not published to crates.io: its non-dev dependency graph still includes
private Chio workspace crates.

## Responsibilities

- Load and validate JSON scenario descriptors and recorded results, failing
  closed on missing directories, empty scenario sets, symlinked fixture
  escapes, and malformed JSON (`load.rs`).
- Orchestrate a live cross-language run: locate or build the `chio` binary,
  spawn `chio mcp serve-http` against a policy fixture and a mock upstream
  MCP server, drive peer client processes over remote HTTP, and collect their
  JSON results (`runner.rs`). Python and Node.js reference peers ship in the
  crate; Go and C++ peers build from `sdks/go/chio-go` and
  `sdks/cpp/chio-cpp` when run in-repo.
- Drive native (non-MCP-wrapped) capability, delegation, receipt, DPoP, and
  governed-transaction fixtures directly against kernel types over an
  `artifact`, `stdio`, or `http` executor, with no MCP framing involved
  (`native_suite.rs`).
- Parse and validate `peers.lock.toml`, the pinned peer-binary release
  manifest `chio conformance fetch-peers` downloads from (`peers.rs`).
- Render the cross-language compatibility matrix and the native conformance
  report as Markdown (`report.rs`).
- Host `verdict_matrix/`, a 48-scenario corpus and diff oracle that asserts
  `(verdict, reason_code, scope_set)` equality between the in-process Rust
  kernel and external SDK/deployment-shape drivers.
- Carry the negative-conformance and threat-model regression suite under
  `tests/`, exercising production crates (`chio-siem`, `chio-link`,
  `chio-anchor`, `chio-federation-transport-iroh`, ...) directly as evidence
  that their fail-closed guarantees hold.

## Public API

Library (`src/lib.rs`):

- `load_scenarios_from_dir`, `load_results_from_dir`, `LoadError` - scenario
  and result loading.
- `ScenarioDescriptor`, `ScenarioResult`, `CompatibilityReport`, and their
  enums (`ScenarioCategory`, `Transport`, `PeerRole`, `DeploymentMode`,
  `ResultStatus`, `RequiredCapabilities`) - the scenario/result data model.
- `default_run_options`, `run_conformance_harness`, `ConformanceRunOptions`,
  `ConformanceRunSummary`, `PeerTarget`, `ConformanceAuthMode`, `RunnerError`
  - the live cross-language runner.
- `default_native_run_options`, `run_native_conformance_suite`,
  `NativeConformanceRunOptions`, `NativeConformanceRunSummary`,
  `NativeDriver`, `NativeScenarioDescriptor`, `NativeScenarioResult`,
  `fixture_messages_for_request` - the native suite.
- `generate_markdown_report` - cross-language report rendering.
- `peers::{PeersLock, PeerEntry, PeersLockError, default_peers_lock_path,
  sha256_hex, SUPPORTED_LANGUAGES}` - `peers.lock.toml` handling.

Binaries (`src/bin/`):

| Binary | Purpose |
|---|---|
| `chio-conformance-runner` | Runs the live cross-language harness end to end. |
| `chio-conformance-report` | Renders a report from existing scenario/result directories. |
| `chio-native-conformance-runner` | Runs the native suite. |
| `chio-native-conformance-fixture` | Native fixture tool server (stdio or HTTP) that the native suite's `stdio`/`http` drivers talk to. |

## Usage

```rust
use chio_conformance::{default_run_options, run_conformance_harness, PeerTarget};

let mut options = default_run_options();
options.peers = vec![PeerTarget::Python];
let summary = run_conformance_harness(&options)?;
println!("report: {}", summary.report_output.display());
```

## Feature flags

| Flag | Effect |
|------|--------|
| `in-repo-fixtures` (default) | Resolves scenario and fixture paths against the Chio repository layout via `default_repo_root()`; falls back to the bundled crate-local `tests/conformance/` tree when no monorepo root is found. |
| `chio-bbs` | Pulls in `chio-selective-disclosure` and `chio-workflow` to enable the BBS selective-disclosure conformance test. |

## Testing

`cargo test -p chio-conformance`

Most `tests/*_live.rs` cases self-skip when their peer toolchain (`node`,
`python3` >= 3.11 with `chio-sdk-python`, `go`, `cmake`) is not on `PATH`. The
verdict-matrix cross-language and deployment-shape drivers report every
scenario as `unsupported` without an operator-supplied
`CHIO_VERDICT_MATRIX_SIDECAR_URL`.

## See also

- `chio-kernel` - the request evaluator this suite verifies.
- `chio-cli` - `chio conformance run` / `chio conformance fetch-peers` wrap this crate's runner and peer-lock API.
- `chio-control-plane` - its `certify` module builds signed certification artifacts from this crate's scenario/result loaders.
- `docs/conformance.md` - the standalone external-consumer flow.
- `spec/PROTOCOL.md` - the normative protocol this suite conforms to.
