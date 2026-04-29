# chio-conformance

Cross-language conformance harness for the Chio (formerly ARC) agent
protocol. The crate exposes a Rust library plus a small bin set that loads
JSON scenario descriptors, drives peer implementations against the Chio
HTTP edge, and renders a Markdown compatibility report.

It is the same harness Chio uses internally to keep the kernel, the
TypeScript reference peer, the Python reference peer, the C++ peer (via
`chio-cpp-kernel-ffi`) and Go peer in agreement on the wire shape defined
by `spec/schemas/chio-wire/v1/`. The crate is now packaged so that external
implementers can run the same scenarios without checking out the Chio
monorepo.

## Quickstart

```bash
cargo install chio-conformance
chio-conformance-runner \
    --peer python \
    --scenarios-dir <path/to/scenarios> \
    --results-dir <path/to/results> \
    --report-output <path/to/report.md>
```

A higher-level workflow (peer binary fetch, JSON report shape, scenario
selectors) is exposed through the `chio` CLI in milestone P4 follow-up
tickets:

```bash
chio conformance fetch-peers
chio conformance run --peer python --report json /tmp/report.json
```

See `docs/conformance.md` in this repository for the standalone
external-consumer flow.

## Bundled fixtures

The crate ships with the same fixture tree it exercises in CI. The Cargo
`include` directive bundles the following paths into the published crate:

- `tests/conformance/scenarios/**` - JSON scenario descriptors covering
  `mcp_core`, `auth`, `tasks`, `nested_callbacks`, `notifications`, and
  `chio-extensions`.
- `tests/conformance/peers/python/**` - reference Python peer (server and
  client) used by the `--peer python` mode.
- `tests/conformance/peers/js/**` - reference Node.js peer used by the
  `--peer js` mode.

The C++ and Go peers are built from sources outside the crate (the C++
peer lives under `packages/sdk/chio-cpp/`, the Go peer under
`packages/sdk/chio-go/`) and are only available when the crate is consumed
in-repo. External consumers should drive their own peer binaries via the
`ConformanceRunOptions` API or the upcoming `chio conformance fetch-peers`
subcommand.

## Peer language coverage

| Peer    | Status        | Notes                                                            |
| ------- | ------------- | ---------------------------------------------------------------- |
| Python  | bundled       | Reference peer at `tests/conformance/peers/python/`              |
| Node.js | bundled       | Reference peer at `tests/conformance/peers/js/`                  |
| C++     | in-repo only  | Built from `packages/sdk/chio-cpp/` via `chio-cpp-kernel-ffi`    |
| Go      | in-repo only  | Built from `packages/sdk/chio-go/`                               |

C++ P0 scenario coverage (`mcp_core` and `auth`) is gated by the
`cpp_peer_p0` integration test in `crates/chio-conformance/tests/`.

## Feature flags

- `in-repo-fixtures` (default): keep the historical Chio repository layout
  for resolving fixture and scenario paths through `default_repo_root()`
  and `default_run_options()`. Disable via `--no-default-features` when
  driving the runner with explicit absolute paths through
  `ConformanceRunOptions`.

## Library entry points

The library re-exports the runner, scenario loader, native suite, and
report generator:

```rust
use chio_conformance::{
    default_run_options,
    run_conformance_harness,
    PeerTarget,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut options = default_run_options();
    options.peers = vec![PeerTarget::Python];
    let summary = run_conformance_harness(&options)?;
    println!("results: {}", summary.results_dir.display());
    Ok(())
}
```

## License

Licensed under Apache-2.0. See `LICENSE` in the repository root.

## Further reading

- `docs/conformance.md` - standalone consumer flow.
- `spec/PROTOCOL.md` - normative wire-level protocol specification.
- `.planning/trajectory/01-spec-codegen-conformance.md` - milestone scope
  and phase breakdown that drives this packaging work.
