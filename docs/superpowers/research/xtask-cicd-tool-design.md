# Unified CI/CD CLI Tool System (cargo xtask) - Design Report

Scope: redesign Chio's CI/CD tooling around a single, type-safe, cross-platform
Rust tool (`cargo xtask`) to replace the pile of ad-hoc shell scripts. This
report covers the current tooling state, the tool-choice recommendation, a
proposed subcommand tree, the CI integration pattern, and a migration path.

No source, scripts, workflows, or configs were modified to produce this report.

## 1. Current tooling state

### 1.1 xtask (the seed of the unified tool)

Location: `xtask/` (a workspace member, `publish = false`).

Files:
- `xtask/Cargo.toml` - depends only on `serde`, `serde_json`, `serde_yml`,
  `sha2`, `jsonschema`, and three internal crates (`chio-spec-validate`,
  `chio-spec-codegen`, `chio-eval-receipt`). Notably it does NOT use `clap`.
- `xtask/src/main.rs` - 1,981 lines. Hand-rolled argument parsing.
- `xtask/src/eval_receipt_regen.rs` - eval-report golden vector generator.
- `xtask/src/snippets_subcommand.rs` - editor snippet regen (vscode-chio,
  zed-chio).
- `xtask/src/tests.rs` - unit tests (`#[cfg(test)] mod tests;` at the bottom of
  main.rs); covers path resolution, PascalCase, TS namespace naming, headers.
- `xtask/codegen-tools.lock.toml` - pins the external codegen toolchain
  (`json-schema-to-typescript@15.0.4`, `oapi-codegen v2.4.1`,
  `datamodel-code-generator`, etc.).

Dispatch model (`main.rs` lines 119-142): a single `match cmd.as_str()` over the
first arg. Each subcommand takes `Vec<String>` and parses its own flags by hand
(`for arg in args { match arg.as_str() { "--check" => ..., "--lang" => ... } }`).
There is no derive-based parser, no shared flag handling, no generated help (the
help text in `print_help`, lines 144-159, is a hand-maintained `println!` list
that must be kept in sync by hand).

Current subcommands (six):
| Subcommand | Purpose |
| --- | --- |
| `validate-scenarios` | Walk `tests/conformance/scenarios/**/*.json`, resolve `$schema`, validate via `chio-spec-validate`. |
| `freeze-vectors [--check]` | Hash `tests/bindings/vectors/**/*.json` into `MANIFEST.sha256` (shasum-256 format). `--check` = drift gate. |
| `eval-receipt-regen [--check]` | Regenerate `tests/bindings/vectors/eval/v1.json` golden. |
| `codegen --lang {rust,ts,go,python} [--check]` | Schema-derived bindings for four languages. `--check` = byte-drift gate used by spec-drift CI. |
| `errors regen [--check]` | Regenerate the error registry Rust output from `spec/errors/registry.yaml`. |
| `snippets regen [--check]` | Regenerate editor snippet files from `editors/snippets/*.snippet.yaml`. |

Root location: `workspace_root()` (line 1168) derives the root from
`env!("CARGO_MANIFEST_DIR")` (the xtask crate dir) and walks up. All
subcommands compute paths relative to that, so the tool is invariant to the
caller's CWD.

The pattern is already correct in spirit: logic lives in Rust, drift gates use
`--check`, and codegen is hermetic (Python via `uv tool run`, no Cargo entry).
The problem is that xtask covers only artifact generation, not the verification
gates, which still live in shell.

### 1.2 The shell-script pile

`scripts/` contains 131 executable scripts totaling 22,087 lines:
- 121 `.sh` (122 use `#!/usr/bin/env bash`)
- 10 `.py`
- plus `scripts/smoke/chio-cli-smoke.sh` and `scripts/tests/` (25 `*.test.sh` /
  `*.bats` self-tests for the scripts themselves).

By prefix family:
| Prefix | Count | Role |
| --- | --- | --- |
| `check-*` | 90 | Verification gates (hygiene, surface, formal, threat coverage, release inputs, egress, redaction, etc.). |
| `qualify-*` | 17 | Release/profile qualification gates (release, web3, comptroller, mobile-kernel, portable-browser, trust-control, bounded-chio, cross-protocol). |
| `mutants-*` | 4 | Mutation-testing gate + banner/co-coverage/issue automation. |
| `run-*` | 2 | `run-coverage.sh`, `run-kani-manifest.sh`. |
| `build-*` | 2 | `build-android-aar.sh`, `build-ios-framework.sh`. |
| misc | 16 | `bless-replay-goldens`, `seal-bless-audit`, `tuf-rebake`, `stage-web3-release-artifacts`, `generate-proof-report`, `promote_fuzz_seed`, `criterion-compare`, `ci-workspace`, `setup-git-merge-drivers`, `cargo-lock-merge`, etc. |

Shell-portability idioms that make these Linux/macOS-only (Windows-hostile) and
brittle: `set -euo pipefail` (113), `trap` (57), `jq` (57), `mktemp` (52),
`mapfile` (1). 47 of the 131 scripts shell out to `cargo test/build/clippy`.

External-tool wrappers (the legitimately-thin scripts that should stay shell or
become thin shims): kani (112 references across scripts), cargo-mutants (44),
aeneas (34), creusot (27), apalache (17), dudect (16), cargo-vet (6),
cargo-deny (3), criterion (5), oapi-codegen, cargo-fuzz, tuf.

### 1.3 How the tooling is invoked

CI workflows: 72 YAML files under `.github/workflows/`.
- 47 workflows invoke `scripts/...` directly.
- Only 3 workflows invoke `cargo xtask` (codegen, freeze-vectors, snippets).
- 1 workflow invokes `make`.

xtask call sites in workflows (the entire current footprint):
- `cargo xtask codegen --lang ...` x6
- `cargo xtask freeze-vectors --check` x4, `cargo xtask freeze-vectors` x3
- `cargo xtask codegen rust` x2
- `cargo xtask snippets regen` x1

The flagship `ci.yml` `check` job is the clearest symptom: its steps inline
~20 separate script invocations into a handful of multi-line `run: |` blocks,
for example:
```
run: |
  ./scripts/check-release-inputs.sh
  ./scripts/check-workspace-layering.sh
  python3 scripts/check-review-slices.py
  python3 scripts/check-rust-public-surface.py
  bash scripts/tests/check-rust-public-surface.test.sh
  python3 scripts/check-architecture-docs.py
  bash ./scripts/check-sre-metrics-registry.sh
  bash ./scripts/check-log-redaction.sh
  bash ./scripts/check-http-egress-contract.sh
  bash ./scripts/tests/check-http-egress-contract.test.sh
```
This is exactly the "logic in YAML/bash" anti-pattern the owner wants gone: the
gate composition lives in YAML, the gate logic lives in 90 separate bash files,
and the only way to run "the check gate" locally is to copy-paste the YAML.

The `Makefile` (92 lines) is already a thin orchestrator and self-documents this
philosophy: its header states "every target shells out to the canonical tool
(`cargo xtask codegen`, the per-language regen scripts) and does not duplicate
logic." It only carries `codegen-check*` targets (delegating to `cargo xtask
codegen --lang <lang> --check`) plus a block of `kb-*` Docker/knowledge-base
convenience targets. It is not a real build system - it is a convenience facade.

### 1.4 Version/tool management

Three overlapping mechanisms exist, none unified:
- `xtask/codegen-tools.lock.toml` - codegen toolchain pins (jco/json2ts/
  oapi-codegen/datamodel-code-generator).
- `tools/versions.toml` - WIT world + WASM toolchain pins (jco, componentize-py,
  tinygo, wit-bindgen, wit-bindgen-go).
- `.tooling/*.version` - one-line pins for `cargo-ndk`, `wasm-bindgen`,
  `wasm-pack`.
- `tools/install-apalache.sh` - imperative installer for one external tool.

There is no single "tool doctor" that reports installed-vs-pinned versions, and
the pins are read ad hoc by whichever script needs them.

### 1.5 Dependency availability for the redesign

`clap` is already a first-class workspace dependency, used by 6 crates
(`chio-cli`, `chio-control-plane`, `chio-kernel-core`, `chio-mercury`,
`chio-wall`, `chio-provider-conformance`). Adopting derive-based clap in xtask
introduces no new third-party surface to the workspace - it reuses an
already-vetted dependency (relevant given cargo-vet/cargo-deny gates).

The workspace has 149 members / 107 crates, so the tooling supports a large,
serious codebase - all the more reason the gate surface should be a typed,
testable Rust binary rather than 22k lines of bash.

## 2. Tool-choice recommendation

Recommendation: consolidate on `cargo xtask`, upgraded to a derive-based clap
CLI, as the single entry point for all verification gates, artifact generation,
qualification, and release steps. Keep a thin set of external-tool wrapper
scripts that xtask shells out to.

### Why cargo xtask fits a Rust monorepo

- Single binary, single source of truth. One `cargo xtask <noun> <verb>`
  surface replaces 90 `check-*` and 17 `qualify-*` scripts. Composition
  ("run the whole hygiene gate") lives in Rust, not in copy-pasted YAML blocks.
- Type-safe and testable. Gate logic becomes ordinary Rust with `#[cfg(test)]`
  coverage (xtask already does this in `tests.rs`). Bash gates can only be
  tested by the parallel pile of 25 `scripts/tests/*.test.sh` files, which is
  itself a maintenance tax that disappears when the logic moves to Rust.
- No bash portability tax. The current scripts depend on bash, `jq`, `mktemp`,
  `trap`, `mapfile` - fine on Linux/macOS, broken on native Windows and fragile
  across shells. A Rust binary runs identically everywhere `cargo` runs.
- Discoverable. `cargo xtask --help` and `cargo xtask check --help` are
  generated by clap and always correct, versus the hand-maintained `println!`
  help block that already exists and can drift.
- Reuses the workspace toolchain. No extra runtime to install in CI; the build
  cache (`Swatinem/rust-cache`, already in ci.yml) covers it. The `xtask` crate
  compiles once and every gate is a fast subcommand dispatch.
- Fail-closed by construction. House rule is errors deny. Rust's `Result` +
  process exit codes make "unknown gate name" / "missing artifact" a hard
  non-zero exit, instead of a bash typo silently passing (the
  `validate-scenarios` design note already calls out that an unresolved
  `$schema` is a hard FAIL, not a SKIP - that discipline generalizes).

### Alternatives considered

- Keep bash scripts. Rejected: 22,087 lines, no type safety, no Windows
  support, requires a second 25-file test harness to verify the gates, and
  forces gate composition into YAML. This is the status quo being replaced.
- `just`. A nicer task runner than make, but it is still a thin command
  dispatcher: the gate logic would remain in bash recipes. It adds a new
  binary to install in every CI job and on every contributor machine, and it
  does not give type safety or unit-testable gates. It solves discoverability,
  not the logic-in-bash problem.
- Makefile. Already present and already (correctly) a thin facade. Make is poor
  at conditional logic, argument passing, and cross-platform behavior; pushing
  90 gates into make would recreate the bash problem with worse ergonomics.
  Keep make only as an optional alias layer (or drop it in favor of xtask).
- Dedicated standalone CLI crate (e.g. a published `chio-ci` binary). This is
  effectively what xtask becomes, minus the cargo-native invocation. The xtask
  convention (`cargo xtask <cmd>`) is the idiomatic form of exactly this: a
  non-published workspace binary run via a `.cargo/config.toml` alias. No reason
  to invent a separate distribution; keep it as `cargo xtask`.

Net: xtask is already the chosen pattern (the Makefile header even declares it
the canonical tool). The work is to grow it from 6 codegen/freeze subcommands to
the full gate surface, and to give it a real clap parser.

## 3. Proposed subcommand tree

Noun-verb structure, derive-based clap, every leaf maps to one CI job step.
Gates that wrap a true external tool (kani, apalache, creusot, aeneas, dudect,
cargo-vet, cargo-deny, cargo-mutants, cargo-fuzz, tuf) are invoked by xtask via
`std::process::Command` and keep a tiny optional shim only where the external
installer is genuinely imperative.

```
cargo xtask
  gen                          # artifact generation (existing + absorbed)
    codegen --lang {rust,ts,go,python} [--check]
    errors            [--check]    # was: errors regen
    snippets          [--check]    # was: snippets regen
    eval-receipt      [--check]    # was: eval-receipt-regen
    freeze-vectors    [--check]
    proof-report                   # was: scripts/generate-proof-report.sh
    bless-goldens                  # was: scripts/bless-replay-goldens.sh
    sbom                           # if an artifact, else under release

  check <gate> [--check]       # the verification gates (the 90 check-* scripts)
    hygiene            # check-rust-file-hygiene, check-rust-public-surface,
                       #   check-stub-surfaces, check-architecture-docs,
                       #   check-review-slices, check-corpus-metadata
    layering           # check-workspace-layering, check-transitive-surface,
                       #   check-portable-kernel, check-mapping
    egress             # check-http-egress-contract, check-adapter-no-bypass,
                       #   check-tool-server-async, check-anchor-batch-async-witness
    redaction          # check-log-redaction, check-audit-log-schema (lint)
    surface            # check-transitive-surface, check-external-wildcard-deps,
                       #   check-bindings-parity, check-sdk-parity, check-web3-contract-parity
    threat             # check-threat-coverage, check-threat-coverage-mutants,
                       #   check-adversarial-threat-link, triage-threat-rows
    release-inputs     # check-release-inputs, check-release (inputs gate)
    schema-registry    # check-chio-schema-registry, check-corpus-metadata
    metrics            # check-sre-metrics-registry
    all                # composite: run every check gate (replaces the inlined
                       #   ci.yml `run: |` block); short-circuits fail-closed

  qualify <profile>           # the 17 qualify-* release/profile gates
    release                    # qualify-release.sh (orchestrator)
    bounded                    # qualify-bounded-chio.sh
    trust-control              # qualify-trust-control.sh
    mobile-kernel              # qualify-mobile-kernel.sh
    portable-browser           # qualify-portable-browser.sh
    cross-protocol             # qualify-cross-protocol-runtime.sh
    universal-control-plane    # qualify-universal-control-plane.sh
    comptroller <facet>        # federation|market-position|operator-surfaces|partner-contracts
    web3 <stage>               # e2e|examples|local|ops-controls|promotion|runtime

  verify <method>             # formal / proof / coverage gates (thin external wrappers)
    formal                     # check-formal-proofs.sh aggregator
    kani [--scope core|public-core|smoke|changed]  # wraps cargo kani
    apalache [--mode safety|temporal]               # wraps apalache (installer stays)
    creusot [--scope core|smoke]                    # wraps creusot
    aeneas [--mode pilot|production|equivalence]    # wraps aeneas
    dudect                     # wraps dudect, check-dudect-threshold
    coverage                   # run-coverage.sh -> wraps cargo llvm-cov
    proptest                   # check-proptest-coverage.sh
    proof-report               # check-proof-report, check-chio-proof-package

  fuzz <action>
    run [--target T] [--budget ...]   # wraps cargo fuzz
    budget                            # check-fuzz-budget.sh, fuzz-budget-hard-halt
    promote-seed                      # promote_fuzz_seed.sh
    cocoverage                        # mutants-fuzz-cocoverage.sh

  mutants <action>
    gate                       # mutants-gate.sh -> wraps cargo mutants
    rationale                  # check-mutants-rationale.sh
    banner                     # update-mutants-banner.sh / mutants-banner
    comment                    # mutants-comment.sh

  release <step>
    inputs                     # = check release-inputs (alias)
    qualify                    # = qualify release (alias / full gate)
    stage-web3                 # stage-web3-release-artifacts.sh
    tuf-rebake                 # tuf-rebake.sh (wraps tuf)
    seal-audit                 # seal-bless-audit.sh
    sbom                       # SBOM emission
    binaries                   # release-binaries support
    rebuild-from-source        # rebuild-from-source.sh (reproducible build)

  supply-chain <gate>         # thin wrappers around vetting tools
    vet                        # check-cargo-vet-exemptions (wraps cargo vet)
    deny                       # cargo deny + check-cargo-deny-duplicate-baseline
    wildcard-deps              # check-external-wildcard-deps.py
    upstream-skips             # check-upstream-skips.sh

  tools <action>              # the version-management consolidation
    doctor                     # report installed vs pinned (versions.toml,
                               #   codegen-tools.lock.toml, .tooling/*.version)
    install <tool>             # apalache, kani, ... (wraps tools/install-*.sh)
    versions                   # print the unified pin set
```

Design notes:
- Every leaf is one job step. `cargo xtask check all`, `cargo xtask verify
  kani --scope core`, `cargo xtask qualify release` each replace one CI `run:`
  line.
- `--check` semantics are preserved exactly as today for all `gen` leaves
  (render-to-memory, exit non-zero on drift). This is the load-bearing contract
  spec-drift CI depends on.
- Composite gates (`check all`, `qualify release`) own the ordering and
  short-circuit logic in Rust, fail-closed: first failing gate sets a non-zero
  exit; unknown gate name is a hard error (clap rejects it before any work).
- External-tool gates do not reimplement the tool; they shell out and translate
  the tool's exit code, while keeping the "is the tool installed?" preflight (the
  thing every thin script currently does by hand) in one shared helper.

## 4. CI integration pattern

Goal: workflow YAML carries setup (checkout, toolchain, cache) and exactly one
`cargo xtask ...` line per logical step. All gate composition, ordering, and
fail-closed logic moves into Rust.

Before (today's ci.yml `check` job, abbreviated):
```yaml
- run: |
    ./scripts/check-release-inputs.sh
    ./scripts/check-workspace-layering.sh
    python3 scripts/check-review-slices.py
    python3 scripts/check-rust-public-surface.py
    ...8 more lines...
```

After:
```yaml
- run: cargo xtask check all
```

Pattern rules:
1. One xtask leaf per job step. A workflow step is `name: <gate>` +
   `run: cargo xtask <noun> <verb>`. The YAML no longer contains gate logic.
2. Composites for fan-in jobs, leaves for matrix jobs. The monolithic `check`
   job runs `cargo xtask check all`. Matrix jobs (per-language codegen, per-kani
   scope) run a single leaf parameterized from the matrix axis
   (`cargo xtask gen codegen --lang ${{ matrix.lang }} --check`).
3. External-tool jobs keep their `uses:`/install step, then call the xtask
   wrapper. Example: `apalache-safety.yml` keeps its apalache install
   (`tools/install-apalache.sh` or `cargo xtask tools install apalache`), then
   `run: cargo xtask verify apalache --mode safety`.
4. Local == CI parity. Because the gate is a real command, a contributor runs
   the identical `cargo xtask check all` locally that CI runs. The "copy the
   YAML to reproduce" failure mode disappears.
5. Make/just become aliases, not logic. The Makefile's `codegen-check*` targets
   stay as one-line delegations (`cargo xtask gen codegen --lang rust --check`);
   no new logic ever lands in make. Optionally drop make entirely once xtask
   covers its surface.
6. Exit-code contract. xtask returns `ExitCode::FAILURE` on any gate failure
   (already its model). CI relies solely on the exit code; no log-scraping.

This collapses the 47 script-invoking workflows toward a uniform shape and lets
the 72 workflows share one well-tested gate implementation instead of 90+
independently-evolving bash files.

## 5. Migration path (keep CI green throughout)

Principle: move logic into xtask behind unchanged external behavior, flip the
caller, then delete the script. Never delete a script before its xtask
equivalent is green in CI. Migrate in waves, smallest-blast-radius first.

Wave 0 - foundation (no behavior change).
- Add `clap` (already a workspace dep) to `xtask/Cargo.toml`; convert the
  hand-rolled `match` dispatcher to a derive parser. Keep the existing six
  subcommand names as aliases so the 3 current workflow call sites and the
  Makefile keep working byte-for-byte.
- Introduce the noun groups (`gen`, `check`, `qualify`, `verify`, `fuzz`,
  `mutants`, `release`, `supply-chain`, `tools`) as empty/parent commands.
- Land a shared `external_tool(name, args)` helper (preflight "is it installed?"
  + exit-code translation) and a `workspace_root()` reuse.

Wave 1 - absorb the existing gen scripts (lowest risk; pure regen).
- Move `generate-proof-report.sh` and `bless-replay-goldens.sh` logic under
  `gen proof-report` / `gen bless-goldens`. Rename existing `errors regen`,
  `snippets regen`, `eval-receipt-regen` to `gen errors|snippets|eval-receipt`
  with back-compat aliases.
- Flip CI and Makefile to the new names; delete nothing yet.

Wave 2 - the `check` family (90 scripts, highest payoff).
- Port pure-logic gates first (the ones that do not shell out to cargo): file
  hygiene, public-surface, stub-surfaces, architecture-docs, review-slices,
  workspace-layering, log-redaction, http-egress, threat-coverage,
  sre-metrics-registry. Port each `scripts/tests/*.test.sh` self-test into a
  Rust `#[cfg(test)]` test in the same module - this is where the parallel
  25-file test harness collapses.
- Build `check all` to call them in the same order ci.yml currently uses.
- Flip ci.yml's inlined `run: |` block to `cargo xtask check all` only after a
  side-by-side run shows identical pass/fail. Then delete the migrated scripts
  and their `.test.sh` partners in the same PR.

Wave 3 - `qualify` family (17 scripts).
- `qualify-release.sh` is an orchestrator that calls many sub-gates; port it as
  a composite that calls the already-migrated `check`/`verify` leaves plus the
  remaining qualify sub-scripts. Migrate the web3/comptroller sub-gates as
  leaves, then collapse the orchestrator.

Wave 4 - external-tool wrappers (`verify`, `fuzz`, `mutants`, `supply-chain`,
`release`).
- These stay thin. xtask owns the invocation + preflight + exit-code handling;
  the actual tool stays external. `check-kani-core.sh` (13 lines: preflight +
  one `cargo kani` line) becomes `verify kani --scope core`. Keep
  `tools/install-apalache.sh` as the imperative installer (optionally fronted by
  `tools install apalache`); do not reimplement apalache/kani/creusot/aeneas in
  Rust.

Scripts that legitimately STAY shell (do not migrate logic, keep as thin shims
or installers):
- `tools/install-apalache.sh` (and any future `install-*`): imperative external
  installers with checksum verification.
- Git plumbing helpers: `setup-git-merge-drivers.sh`, `cargo-lock-merge.sh`
  (these run in git hooks/merge-driver context where a compiled binary is
  awkward).
- Anything that is already a one-line `cargo <tool>` invocation can be absorbed
  cheaply, but pure passthrough wrappers may remain if the external tool's own
  CLI is the real interface.

Candidates for deletion (no behavior to preserve):
- The ~49 scripts not referenced by any workflow are local-only or potentially
  dead; audit each (the scripts-audit agent covers detail) and delete the truly
  unused rather than porting them.
- The 25 `scripts/tests/*.test.sh` files become Rust unit tests as their target
  gate migrates; delete each once its logic has Rust coverage.

Keeping CI green:
- Each PR migrates one gate (or one tight family), proves parity with a dual run
  (old script + new xtask leaf both invoked, asserted to agree) in the same PR,
  then flips the caller and deletes the script. The exit-code-only CI contract
  means a faithful port is indistinguishable from the script it replaces.
- Back-compat aliases on the six existing subcommands prevent any flag-day
  break for the current 3 xtask workflows and the Makefile.

Side consolidation (do alongside Wave 0/4): unify the three version mechanisms
(`tools/versions.toml`, `xtask/codegen-tools.lock.toml`, `.tooling/*.version`)
behind `cargo xtask tools doctor|versions`, so there is one place that reports
installed-vs-pinned and one source of truth for tool pins.

## Summary

xtask is already the right vehicle and is already declared canonical by the
Makefile, but it covers only 6 codegen/freeze subcommands while 90 `check-*`
and 17 `qualify-*` scripts (22k lines of bash) carry the real gate logic, with
only 3 of 72 workflows touching xtask. Grow xtask into a clap-based noun-verb
CLI (`gen`/`check`/`qualify`/`verify`/`fuzz`/`mutants`/`release`/`supply-chain`/
`tools`), move gate logic and the parallel `scripts/tests` harness into typed,
unit-tested Rust, reduce each CI job step to a single `cargo xtask` line, and
keep only thin external-tool wrappers and imperative installers as shell.
