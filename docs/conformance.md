# Chio Conformance Suite (Standalone Consumer Guide)

This document is the canonical entry point for an external implementer
who wants to run the Chio (formerly ARC) cross-language conformance
suite against their own peer implementation, without checking out the
Chio monorepo.

It pairs with two other surfaces:

- `crates/chio-conformance/README.md` - quickstart for the published
  crate and its bundled fixture tree.
- `.planning/trajectory/01-spec-codegen-conformance.md` - source-of-truth
  trajectory document. Phase 4 (M01 P4) is the milestone that ships the
  external-consumer flow described below.

## Audience and prerequisites

This guide is for protocol implementers in any of the four reference
peer languages (Python, Node.js, Go, C++) plus anyone who is wiring the
Chio kernel into their own runtime and wants to verify wire compatibility.

You will need:

- A Rust toolchain at the workspace MSRV (stable, see `rust-toolchain.toml`
  for the exact pin) so that `cargo install` can build the harness.
- Network access to crates.io and to `github.com/bb-connor/arc/releases`
  (the default `peers.lock.toml` URLs point at GitHub release assets).
- One of the following, depending on which peer you intend to verify:
  - Python 3.10+ if you plan to run the bundled Python peer from source.
  - Node.js 20+ if you plan to run the bundled Node.js peer from source.
  - A Go 1.22+ toolchain or a C++23 compiler for the in-repo Go and C++
    peers (these are not bundled in the published crate; see "Peer
    coverage" below).
  - Or, no peer toolchain at all if you fetch the pre-built peer
    binaries via `chio conformance fetch-peers`.

## Quickstart

The full external-consumer flow is three commands.

```bash
# 1. Install the chio CLI (which provides the `chio conformance` subcommand)
#    plus the conformance harness library / runner binaries.
cargo install --git https://github.com/bb-connor/arc chio-cli
cargo install chio-conformance

# 2. Fetch sha256-pinned peer binaries for the languages you care about.
chio conformance fetch-peers --language python

# 3. Run the harness against the chosen peer and emit a JSON report.
chio conformance run --peer python --report json --output /tmp/report.json
```

Each step is described in detail below.

## 1. Install the conformance crate and the `chio` binary

The `chio` binary lives in the `chio-cli` crate, not `chio-conformance`.
The chio-conformance crate ships its own
`chio-conformance-runner` and `chio-conformance-report` binaries plus
the harness library, but the higher-level `chio conformance ...`
subcommands belong to `chio-cli`. Cleanup C5 issue G corrected an
earlier draft that conflated the two.

```bash
# `chio` binary (the surface this guide demonstrates).
cargo install --git https://github.com/bb-connor/arc chio-cli

# Bundled harness + scenarios + reference peers (published on crates.io).
cargo install chio-conformance
```

`chio-cli` is `publish = false` while it stabilises; install it
directly from the git source until it lands on crates.io. After both
crates are installed, every `chio conformance ...` invocation in this
guide works as written.

The published `chio-conformance` crate bundles:

- The Rust harness library (`chio_conformance`).
- The `chio-conformance-runner`, `chio-conformance-report`, and the
  native runner binaries for direct use without the higher-level CLI.
- The full scenario tree under `tests/conformance/scenarios/**`
  (vendored into the published crate via a symlinked subtree at
  `crates/chio-conformance/tests/conformance/`).
- The reference Python peer (`tests/conformance/peers/python/**`) and
  Node.js peer (`tests/conformance/peers/js/**`).

If you are building from a source checkout instead of crates.io, the
in-repo equivalent is:

```bash
cargo install --path crates/chio-cli
cargo install --path crates/chio-conformance
```

The in-repo build keeps the `in-repo-fixtures` feature (default on) so
that `default_run_options()` resolves scenario and fixture paths against
the workspace root via `chio_conformance::default_repo_root()`.
External consumers building from crates.io can either keep the feature
on (the included fixture tree rides along) or disable it via
`--no-default-features` and supply their own paths through
`ConformanceRunOptions`.

## 2. Fetch pinned peer binaries

`chio conformance fetch-peers` downloads pre-built peer-language adapter
binaries pinned by `crates/chio-conformance/peers.lock.toml`. The
lockfile has a stable schema (`chio.conformance.peers/v1`) and
sha256-pins each entry so that an evil mirror cannot silently swap a
peer binary.

### Validate the lockfile without downloading anything

```bash
chio conformance fetch-peers --check
```

This parses and validates the lockfile shape, prints the resolved path,
and lists each entry without making any network calls. Use it in CI
preflight checks where the actual fetch belongs to a later step, or to
debug a corrupted lockfile.

### Download binaries for a single language

```bash
chio conformance fetch-peers --language python
```

Supported `--language` values are `python`, `js`, `go`, and `cpp`. When
the flag is omitted, `chio conformance fetch-peers` downloads every
entry in the lockfile.

### Choose the output directory

The default output directory is `./.chio-peers`. Override it with
`--out`:

```bash
chio conformance fetch-peers --language js --out ./vendor/chio-peers
```

Each binary is written under `<out>/<language>/<target>/<filename>` so
that multiple targets for the same language coexist. The `<target>`
component is a Rust target triple (for example `x86_64-unknown-linux-gnu`
or `aarch64-apple-darwin`).

### sha256 verification

Every download is sha256-verified against the lockfile entry before
being written to disk. A mismatch aborts the run with a non-zero exit
status; no partial artifact is left behind.

## 3. Run scenarios against a peer

`chio conformance run` executes the cross-language harness against a
chosen peer-language adapter and emits a report.

### Minimum viable invocation

```bash
chio conformance run --peer python
```

This runs all scenarios against the Python peer and prints a
human-readable summary to stdout (`listen` address, results directory,
report path, and a per-scenario pass/fail table).

### Emit a machine-readable JSON report

```bash
chio conformance run --peer python --report json --output /tmp/report.json
```

The JSON envelope has the shape:

```jsonc
{
  "schemaVersion": "chio-conformance-run/v1",
  "listen": "127.0.0.1:<port>",
  "resultsDir": "<absolute path>",
  "reportOutput": "<absolute path>",
  "peerResultFiles": ["<absolute path>", "..."],
  "scenarioFilter": null,
  "scenarioCount": 6,
  "results": [
    {
      "scenario_id": "...",
      "category": "...",
      "peer": "...",
      "status": "...",
      "duration_ms": 0
    }
  ]
}
```

The schema version is stable across patch releases. Any breaking change
to this shape is gated by the M01 Phase 5 conformance-matrix workflow
(`.github/workflows/conformance-matrix.yml`, job
`external-consumer-smoke`).

### Run a single scenario

```bash
chio conformance run --peer python --scenario tasks_long_running --report json --output /tmp/report.json
```

The underlying harness still drives every scenario (so peer-side state
remains consistent), but only matching `scenario_id` rows are surfaced
in the report.

### Run every peer at once

```bash
chio conformance run --peer all
```

Supported `--peer` values are `js`, `python`, `go`, `cpp`, and `all`.
The `all` selector includes every peer the harness knows about; peers
without binaries on disk fail loudly rather than being silently skipped.

### Choose a report format explicitly

```bash
chio conformance run --peer python --report human
chio conformance run --peer python --report json
```

`--report json` emits the JSON envelope described above. `--report human`
(or omitting `--report` entirely) emits the multi-line text summary.
Any other value is rejected.

## Scenarios

The scenario tree under `tests/conformance/scenarios/` covers the
following categories. Each is a directory of JSON descriptors plus the
fixtures the harness serves to the peer:

- `mcp_core` - Model Context Protocol core flows (handshake, tool list,
  tool invocation).
- `auth` - bearer and OAuth-local authentication paths.
- `tasks` - long-running task lifecycle (start, progress, complete,
  cancel).
- `nested_callbacks` - host-side callback fan-out across nested tool
  invocations.
- `notifications` - server-initiated notifications.
- `chio-extensions` - Chio-specific protocol extensions on top of MCP.

The scenarios travel inside the published crate via the `Cargo.toml`
`include` directive, so `cargo install chio-conformance` downloads the
full corpus in one step.

## Peer coverage

| Peer    | Status            | Notes                                                            |
| ------- | ----------------- | ---------------------------------------------------------------- |
| Python  | bundled           | Reference peer at `tests/conformance/peers/python/`              |
| Node.js | bundled           | Reference peer at `tests/conformance/peers/js/`                  |
| Go      | in-repo + lockfile| Source build is in-repo only; pre-built binaries via fetch-peers |
| C++     | in-repo + lockfile| Source build is in-repo only; pre-built binaries via fetch-peers |

C++ Phase-0 scenario coverage (`mcp_core` and `auth`) is gated by the
`cpp_peer_p0` integration test under `crates/chio-conformance/tests/`.
Other categories (`chio-extensions`, `tasks`, `nested_callbacks`,
`notifications`) are deferred to a follow-on milestone for the C++
peer per the Wave 1 roadmap decision.

## Output schema and stability

The JSON report shape (`schemaVersion = "chio-conformance-run/v1"`) is
stable across versions of `chio-conformance` that share a major
version. A breaking change requires:

- A new `schemaVersion` value (`/v2`, etc.).
- A note in the changelog with a migration cue.
- A green run of `external-consumer-smoke` on both shapes during the
  deprecation window.

The Markdown compatibility report under `tests/conformance/reports/` is
considered a CI artifact rather than a stable public surface; consumers
should depend on the JSON envelope for downstream tooling.

## Lockfile resolution

The `chio conformance fetch-peers` subcommand looks for
`peers.lock.toml` in the following order (cleanup C5 issue B):

1. `--lockfile <path>` (explicit override).
2. `$CHIO_PEERS_LOCK` env var.
3. `$XDG_CONFIG_HOME/chio/peers.lock.toml` (or
   `$HOME/.config/chio/peers.lock.toml`).
4. `<repo-root>/crates/chio-conformance/peers.lock.toml` (in-repo
   default).
5. `./peers.lock.toml` (cwd-relative).

The runtime resolver mirrors the M04.P3.T3 cache-dir strategy so
`cargo install`-installed binaries do not depend on the compile-time
`CARGO_MANIFEST_DIR` of the crate that is no longer on disk.

## Unpublished peer entries

The lockfile carries `published = false` placeholders for peers whose
release artifacts have not been cut yet (cleanup C5 issue D). The
`fetch-peers` subcommand SKIPS those entries with a clear message
rather than failing the run with a sha256 mismatch:

```
$ chio conformance fetch-peers --language python
skipping unpublished peer `python / x86_64-unknown-linux-gnu`: lockfile entry has `published = false` (no real binary uploaded yet)
skipping unpublished peer `python / aarch64-apple-darwin`: lockfile entry has `published = false` (no real binary uploaded yet)
```

Once the M01 release pipeline cuts a real artifact, the lockfile
updater replaces the placeholder sha256 and flips `published = true`;
no consumer-facing change is required.

## Troubleshooting

### `cargo install chio-conformance` fails on a build dependency

The crate pulls in `reqwest` with `rustls`, `tiny_http`, and `sha2`.
On bare CI images you may need to install OpenSSL development headers
or the equivalent system package even though `rustls` is the chosen TLS
backend (transitive build-script needs vary by host). On Debian/Ubuntu
runners, `apt-get install -y pkg-config libssl-dev` resolves the most
common failure mode.

### `chio conformance fetch-peers` reports a sha256 mismatch

This means the binary at the lockfile URL has changed since the
lockfile was cut. Re-run with `--check` first to confirm the lockfile
itself is intact, then either:

- Pin to an older release of `chio-conformance` whose lockfile entries
  still match the live release assets, or
- File an issue on `github.com/bb-connor/arc` with the mismatched url
  and observed sha256; the M01 release pipeline regenerates the
  lockfile on every release tag.

### `chio conformance run --peer cpp` cannot find the C++ peer

The C++ peer is not bundled in the published crate. Either:

- Run `chio conformance fetch-peers --language cpp` first to download
  the pre-built peer binary into `./.chio-peers/cpp/`, or
- Build from source in the Chio monorepo (the C++ peer lives under
  `packages/sdk/chio-cpp/`) and point at the resulting binary via
  `ConformanceRunOptions`.

### A scenario is green locally but red in `external-consumer-smoke`

The nightly smoke job runs against the published crate (not the in-repo
path). A divergence usually means a fixture file is missing from the
crate's `include` list. Check the `include = [...]` array in
`crates/chio-conformance/Cargo.toml` and add the missing path; the
fixture is always wrong if the in-repo runner is happy and the
published runner is not.

## Continuous-integration story

For the Chio project itself, the `external-consumer-smoke` job in
`.github/workflows/conformance-matrix.yml` runs nightly on a fresh
GitHub-hosted runner against the published crate, so any drift between
the source tree and crates.io is caught within 24 hours.

External consumers can copy the same pattern into their own CI:

```yaml
- name: Install Chio CLI (provides the `chio conformance` subcommand)
  run: cargo install --git https://github.com/bb-connor/arc chio-cli

- name: Install Chio conformance harness
  run: cargo install chio-conformance --version 0.1.0

- name: Fetch pinned peer binaries
  run: chio conformance fetch-peers --language python

- name: Run conformance scenarios
  run: chio conformance run --peer python --report json --output report.json

- name: Upload conformance report
  uses: actions/upload-artifact@v4
  with:
    name: chio-conformance-report
    path: report.json
```

## See also

- `crates/chio-conformance/README.md` - crate-level quickstart.
- `crates/chio-cli/README.md` - general `chio` CLI surface and global
  flags.
- `spec/PROTOCOL.md` - normative wire-level protocol specification.
- `.planning/trajectory/01-spec-codegen-conformance.md` - milestone
  scope, phase breakdown, and exit-test definitions.
- `tests/conformance/reports/` - canonical location for generated
  compatibility matrices in Chio's own CI.

## Related milestone work

- M01.P4.T1 - flip the crate to publishable shape and seed the stub
  version of this document.
- M01.P4.T2 - ship `chio conformance run` subcommand.
- M01.P4.T3 - insta snapshot-test the JSON report shape.
- M01.P4.T4 - ship `chio conformance fetch-peers` plus
  `peers.lock.toml`.
- M01.P4.T5 (this ticket) - expand this document to the final
  consumer-facing form.
- M01.P4.T6 - C++ peer P0 (`mcp_core`, `auth`) coverage gate.
- M01.P5.T4 - nightly `external-consumer-smoke` workflow.
