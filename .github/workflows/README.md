# GitHub Actions workflows

## The PR build/lint/test gate lives in `ci.yml` (BAC-609)

The required gate that catches workspace-wide compile breakage is the
`check` job ("Build, lint, test") in [`ci.yml`](./ci.yml). It runs on
`pull_request` and `push` to `main`, on the toolchain pinned by the
repo-root `rust-toolchain.toml` (1.93.0), with `Swatinem/rust-cache` for the
cargo registry/target cache. The four gate steps are:

| Gate | Step in `ci.yml` | Command |
| ---- | ---------------- | ------- |
| Format | "Workspace format" | `cargo fmt --all -- --check` |
| Lint | "Workspace clippy" | `cargo clippy --workspace --lib --bins --examples -- -D warnings` |
| **Workspace build** | "Workspace build" | `cargo build --workspace` |
| Tests | "Workspace tests" + "Wasm guards library tests" | `cargo test --workspace --exclude chio-wasm-guards`, then `cargo test -p chio-wasm-guards --lib` |

The full set of required check contexts (the `name:` values GitHub branch
rulesets match on) is four jobs, not one:

- "Build, lint, test" (the `check` job, containing the four steps above)
- "MSRV build and test" (the `msrv` job; see below for its coverage caveats)
- "cargo-vet (locked supply-chain audit)" (the `cargo-vet` job)
- "cargo-deny (supply-chain bans/advisories/licenses)" (the `cargo-deny` job)

All four are required; cargo-vet and cargo-deny are not optional. The "Tokio
console smoke" check is *not* a separate required context: it is a step inside
the "Build, lint, test" job (see the test-lane section below), so it surfaces
under that job's context rather than as its own check.

### Why the build step MUST stay `--workspace`, not per-crate (`-p`)

BAC-539 was a class of break a per-crate scoped gate misses: a new enum
variant compiles fine in its own crate but breaks an exhaustive `match` in a
*downstream* crate. A `-p <crate>` build only compiles that crate's tree, so
cross-crate breakage slips through; `cargo build --workspace` compiles every
member's `src/`, so the downstream non-exhaustive `match` fails the build.

Note this step does not pass `--all-features`, so it only compiles
default-feature source. Modules behind non-default features are not compiled
(for example provider-adapter-gated modules in
`crates/protocol/chio-openai-adapter/src/lib.rs`), so a BAC-539-style break that
lives behind an optional feature can still slip through this lane. Full
coverage of feature-gated source would require a separate all-feature build
lane.

Do not narrow the "Workspace build" step to `-p`/path-scoped invocations, and
do not delete it in favor of relying on clippy alone (clippy here is scoped to
`--lib --bins --examples` and likewise does not compile test/bench targets).
Keeping the unscoped `cargo build --workspace` step is the invariant that
closes the BAC-539 gap.

### The test lane: workspace-wide except a separate wasm-guards lib lane

The tests run in two steps, not one, and they do *not* uniformly cover
integration-test targets:

- "Workspace tests" runs `cargo test --workspace --exclude chio-wasm-guards`.
  Across every other workspace member this compiles and runs `#[cfg(test)]`
  unit tests *and* the `tests/` integration targets, extending the
  build-breakage guarantee above to test code. Note this lane does not pass
  `--all-features`/`--features`, so it only exercises default-feature code:
  Cargo skips any `[[test]]` target whose `required-features` are not selected.
  For example `crates/kernel/chio-kernel` gates the `hybrid_receipt_sign`,
  `compliance_certificate_hybrid`, and `canonical_bytes_hybrid` integration
  targets behind the `pq` feature, and no PR lane selects `pq`, so those targets
  are not compiled or run by any gate. (The one feature-gated integration target
  that *is* covered is `tokio_console_smoke`: the separate "Tokio console smoke"
  step in `ci.yml` runs `cargo test -p chio-kernel --features tokio-console-smoke
  --test tokio_console_smoke`.) `chio-wasm-guards` is excluded here because its
  `tests/` integration suite needs a wasm-capable harness and cannot run in this
  plain `cargo test` lane.
- "Wasm guards library tests" then runs `cargo test -p chio-wasm-guards --lib`.
  `--lib` is "test only this package's library", so this lane compiles and runs
  only `chio-wasm-guards`'s in-crate unit tests. The many integration targets
  under `crates/guards/chio-wasm-guards/tests/` are **not** compiled or run by
  this gate.

So the wasm-guards carveout is deliberate but partial: the crate's library code
is gated by the PR lane, while its `tests/` integration targets are **not
exercised by any PR gate**. No PR gate compiles or runs
`crates/guards/chio-wasm-guards/tests/*` (the other PR-triggered wasm/conformance
workflows build browser SDK artifacts, run conformance peers, or run benches
via `cargo bench`, none of which invoke these integration targets). They are
covered outside the PR gates instead: the push-to-`main` and manual
`release-qualification.yml` workflow runs `cargo +1.93.0 test --workspace` with
no `--exclude`, which does compile and run those `wasmtime-runtime` integration
targets. So editing or adding a test under `crates/guards/chio-wasm-guards/tests/`
will not be caught by any PR gate (only later, by Release Qualification on
push/main or a manual run). Do not "fix" the PR-gate carveout by folding
`chio-wasm-guards` back into the PR `--workspace` test step (it is excluded there
on purpose), and do not assume a green PR `ci.yml` run covered the wasm-guards
integration tests.

### The MSRV job does not fully test the workspace

The "MSRV build and test" job (`msrv` in `ci.yml`) runs `cargo build
--workspace` on the pinned MSRV toolchain, but its test command does **not**
cover the whole workspace. It runs:

```
cargo test --workspace --exclude chio-conformance --exclude chio-wasm-guards --exclude chio-formal-diff-tests
cargo test -p chio-formal-diff-tests --no-run
cargo test -p chio-wasm-guards --lib
```

So MSRV test coverage is uneven:

- `chio-conformance` is **not tested on MSRV** at all (excluded from the
  workspace test run and never re-added).
- `chio-formal-diff-tests` gets only `--no-run`: its tests are compiled on MSRV
  but not executed.
- `chio-wasm-guards` gets only `--lib`: its in-crate unit tests run on MSRV, but
  its `tests/` integration targets do not.

Do not describe the MSRV job as testing the full workspace; it builds the full
workspace and tests it with the carveouts above.

> Note (firmware/console): the arc workspace is Rust-only; the firmware and
> console build pipelines referenced by BAC-609 live in their own repos and
> are out of scope for this workflow.

## The `chio-pheromone-*` gate family is kept as separate files

The 15 `chio-pheromone-*.yml` workflows look like near-duplicates but must not be
consolidated into a single matrix workflow. Two constraints rule out the obvious
collapses.

### The 15 files

Relay subsystem gates (each runs one `scripts/check-<name>.sh`):

- `chio-pheromone-relay.yml`
- `chio-pheromone-relay-ops.yml`
- `chio-pheromone-relay-observability.yml`
- `chio-pheromone-relay-alert-routing.yml`
- `chio-pheromone-relay-alert-delivery.yml`
- `chio-pheromone-relay-alert-handoff.yml`
- `chio-pheromone-relay-alert-assurance.yml`
- `chio-pheromone-relay-alert-assurance-archive.yml`
- `chio-pheromone-relay-alert-assurance-archive-package.yml`
- `chio-pheromone-relay-alert-assurance-archive-hardening.yml`
- `chio-pheromone-relay-alert-assurance-export.yml`
- `chio-pheromone-relay-alert-assurance-external-retention.yml`
- `chio-pheromone-directory-lifecycle.yml`
- `chio-pheromone-runtime.yml`
- `chio-pheromone-transit.yml`

### A single matrix workflow cannot path-scope per gate

Each file carries its own `on.paths` trigger (a different set of crate, spec,
script, and doc globs). A single matrix workflow has one `on:` block and cannot
express per-matrix-entry path filters, so collapsing them forces every gate to
run on every pheromone-related change, defeating the path-scoping these files
provide.

### The reusable-workflow (`workflow_call`) pattern does not fit either

Extracting the shared job body into one `workflow_call` reusable workflow with
thin path-triggered callers fails because the job bodies are not uniform. They
fall into four distinct shapes:

| Shape | Files | `permissions:` block | `Swatinem/rust-cache` | `setup-node` | node version |
| ----- | ----- | -------------------- | --------------------- | ------------ | ------------ |
| A | relay, relay-ops, directory-lifecycle, runtime, transit | none | no | no | - |
| B | relay-observability | none | no | yes | 22 |
| C | alert-routing, alert-delivery, alert-handoff, alert-assurance | `contents: read` | yes | yes | 24 |
| D | the five `...-assurance-archive` / `-export` / `-external-retention` | `contents: read` | yes | no | - |

`workflow_call` inputs could express these differences (booleans gating the
cache / node steps via `if:`, a string for the node version, strings for the
gate name and script path), but four constraints block the conversion, each on
its own sufficient:

1. The four shapes require conditional (`if: inputs.*`) steps. The resulting
   single file is harder to reason about than the 15 flat files it replaces.
2. Permissions posture differs. Shapes A and B set no `permissions:` block (they
   inherit the repository / org default token scope); shapes C and D pin
   `contents: read`. Under `workflow_call`, the effective token scope is governed
   by the called workflow plus the caller job's `permissions:`. Folding files
   with different permission postures into one reusable workflow risks silently
   changing the token scope for some gates, over-granting a fail-closed CI
   surface.
3. The node-version split (22 in shape B vs 24 in shape C) is not reconcilable
   from the YAML alone; collapsing to one version would change at least one
   gate's node runtime.
4. Required status-check matching. Branch-protection / ruleset config lives in
   GitHub settings outside this repo. Converting these to callers changes how
   each check surfaces (it appears as `caller / reusable-job` instead of the
   current top-level job name), which can silently break a required-check rule.

Any consolidation must be validated on a branch where GitHub Actions runs, with
Actions executing, against four invariants: the per-file `on.paths` triggers
still gate correctly on both `pull_request` and `push`; the effective token
permissions per gate are unchanged; the node version choice is deliberate; and
the surfaced check names still satisfy the required-status-check rules
configured in GitHub settings.
