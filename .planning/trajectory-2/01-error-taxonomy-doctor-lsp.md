# Milestone 01: Workspace Error Taxonomy + Doctor + LSP

## Lens

Single lens: developer experience. Every other trajectory-2 milestone reports
failures, edits `chio.yaml`, or stares at a kernel verdict. M01 is the
milestone that decides what those failures look like, what the editor can do
about them, and how a fresh checkout self-diagnoses on day one. There is no
secondary lens (no perf, no security, no protocol). If a proposal here would
also pull in another lens, it is out of scope and should be deferred to a
follow-on.

## Why this is on the trajectory

trajectory-1 closed with a partial, drifting error story. Three concrete
artifacts created the precondition for this milestone:

1. `crates/chio-control-plane/src/lib.rs:53` defines `pub enum CliError` with
   sixteen variants plus an `Other(String)` swallow-everything escape hatch.
   Workspace grep counts 976 `CliError::Other(format!(...))` call sites across
   `crates/chio-cli/`, `crates/chio-control-plane/`, and `crates/chio-hosted-mcp/`
   (measured 2026-04-29). Each one is an unstructured string the user sees
   on stderr and no tool can match on. The `report()` impl already emits
   stable string codes (`CHIO-CLI-CORE`, `CHIO-CLI-POLICY`, ... twenty so
   far) but the codes are ad hoc, untyped, and only seventeen variants out
   of seventeen-plus-`Other` reach them. The wire format
   `spec/errors/chio-error-registry.v1.json` is a separate, eleven-entry
   numeric-code registry (1000, 1100, 2100, ...) used by the JSON-RPC
   surface; it does not align with the CLI codes. The kernel emits a
   third dialect via `chio_kernel::StructuredErrorReport`. Three error
   vocabularies, no shared registry.
2. trajectory-1 M07.P2.T8 / M07.P3.T6 shipped per-provider error doctests at
   `crates/chio-openai/tests/error_taxonomy_doctest.rs`,
   `crates/chio-anthropic-tools-adapter/tests/error_taxonomy_doctest.rs`, and
   `crates/chio-bedrock-converse-adapter/tests/error_taxonomy_doctest.rs`
   (commits `d4e69be94`, `c7731103a`). Each crate parses its own README
   table between `<!-- error-taxonomy:start -->` and `<!-- error-taxonomy:end -->`
   markers. The tables agree on intent and disagree on spelling. Without a
   single registry to consume, every new provider in M07 forks the table
   again.
3. trajectory-1 M01 shipped JSON schemas under
   `spec/schemas/chio-wire/v1/{agent,capability,error,jsonrpc,kernel,provenance,receipt,result,trust-control}/`
   and the `chio-spec-codegen` codegen toolchain at
   `crates/chio-spec-codegen/`. M01 (this milestone) reuses both: codegen
   targets a new registry YAML, and the LSP reuses the wire-type schemas
   for `chio.yaml` validation without re-deriving them.

The dependency graph in the trajectory-2 README anchors M01 as the unblocker
for M02 (verdict diff classifies by code), M07 (each adapter consumes the
registry), M09 (lineage carries error provenance), and every CLI surface
(replay, doctor, LSP). M01 ships first or these cascade.

## Prior-art reckoning

What trajectory-1 already shipped that overlaps with this milestone:

- **Per-provider error taxonomies (M07.P2.T8, M07.P3.T6).** Preserved.
  The doctests stay; their tables become *consumers* of the new registry,
  not parallel sources. M01 does not delete the README tables; it converts
  them to be regenerated from `spec/errors/registry.yaml`.
- **`chio_kernel::StructuredErrorReport` and `CliError::report()`.**
  Preserved at the surface, replaced underneath. The public method names,
  JSON output keys (`code`, `message`, `context`, `suggested_fix`), and
  the existing `CHIO-*` string spellings stay. M01 reroutes them through
  the registry so the strings come from one place.
- **Wire-side `spec/errors/chio-error-registry.v1.json`.** Preserved as
  the JSON-RPC numeric-code mapping. M01 adds a `urn:chio:error:*` registry
  alongside it (not in place of it). The two are bridged: every
  `urn:chio:error:*` code carries an optional `jsonrpc_code` field that
  references the numeric registry when a wire mapping exists.
- **JSON schemas under `spec/schemas/chio-wire/v1/`.** Preserved. The LSP
  loads them directly for diagnostics, completion, and hover.
- **`chio-spec-codegen` Rust generator.** Preserved. M01 extends it with a
  registry-YAML loader and an `error_codes.rs` emit pass; we do not fork
  a new codegen crate.

What this milestone deliberately does not do:

- Does not unify the JSON-RPC numeric registry into the URN registry. They
  remain two surfaces with a one-way pointer. The wire format stays stable.
- Does not break the existing `CHIO-CLI-*` / `CHIO-KERNEL-*` string codes.
  Those are the public face of `chio --format json`. The new registry
  carries them as the `legacy_string_code` field of each entry.
- Does not own a JSON-RPC server; the LSP is `tower-lsp`-based and stops
  at the `chio.yaml` / manifest / guard-DSL document boundary.

## Hard counts (measured 2026-04-29)

Reproduce with the commands in parentheses; update if you re-run.

- `crates/chio-cli/src/cli/dispatch.rs`: 2,326 lines, 1 `fn` (`main`), 1
  `Err` site (the top-level dispatch failure path that calls
  `write_cli_error`). The file is the *router*; the actual error sites
  live in 14 sibling files included via `include!()` from
  `crates/chio-cli/src/main.rs:23-50`. (`wc -l` and `grep -cE '^fn|return Err'`)
- `crates/chio-cli/src/cli/types.rs`: 3,121 lines defining the clap surface
  (10 top-level `enum Commands` plus subcommands). This is where most of
  the error-aware command dispatch shape lives even though dispatch.rs
  carries the `match` arms. (`wc -l`)
- `crates/chio-cli/src/scaffold.rs`: 133 lines, single-file scaffolder
  used by `chio init`. (`wc -l`)
- `CliError::Other(format!(...))` call sites across the workspace: 976.
  (`grep -rE 'CliError::Other' crates/chio-cli/src/ crates/chio-control-plane/src/ crates/chio-hosted-mcp/src/ | wc -l`)
- Per-file CliError::Other concentration (top callers):
  `chio-cli/src/passport_verifier.rs` 83, `chio-cli/src/evidence_export.rs`
  77, `chio-cli/src/passport.rs` 61, `chio-cli/src/certify.rs` 44,
  `chio-cli/src/enterprise_federation.rs` 12, `chio-cli/src/scaffold.rs` 3.
  (`find ... | xargs grep -c 'CliError::Other'`)
- Existing `CHIO-*` stable code prefixes in
  `crates/chio-control-plane/src/lib.rs`: 20 distinct strings. (`grep -cE '"CHIO-' .../lib.rs`)
- Per-provider doctest README tables: 3 (`chio-openai`,
  `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`). One
  more lands per M07 P2 ticket; M01 must support N tables without
  forking the registry.
- Wire-side numeric registry entries in
  `spec/errors/chio-error-registry.v1.json`: 11. (`jq '.codes | length'`)
- JSON schemas under `spec/schemas/chio-wire/v1/`: 9 directories,
  each with 1-6 schema files. The LSP consumes them as a unit.
  (`find spec/schemas/chio-wire/v1 -name '*.schema.json' | wc -l`)
- Workspace clippy: `unwrap_used = "deny"`, `expect_used = "deny"`. Any
  generated code from M01 must satisfy both.
- Workspace toolchain: `cargo 1.93.0 (083ac5135 2025-12-15)`.
  (`cargo --version`)

## Workspace dependency state

Already pinned in `[workspace.dependencies]` of root `Cargo.toml`:

- `serde`, `serde_json`, `serde_yml`, `thiserror`, `clap`, `tokio`,
  `tracing`, `criterion` (used by trajectory-1).

New pins this milestone adds. Do not paste version values without
re-checking crates.io for the then-current latest patch on the day work
opens; treat the lower bounds below as floors:

- `miette = { version = "7", features = ["fancy"] }` for the diagnostic
  surface that `chio-errors`, `chio doctor`, and the LSP all share.
  Renders source-spans on `chio.yaml` diagnostics; degrades to plain
  text when stderr is not a TTY.
- `tower-lsp = "0.20"` for the LSP server skeleton at `crates/chio-lsp/`.
  Reuses the `tower` and `tokio` versions already pinned at the workspace
  root.
- `lsp-types = "0.95"` for the wire types behind `tower-lsp`. Pinned
  separately so the LSP can move ahead of `tower-lsp` minor bumps if
  needed.
- `dashmap = "6"` for the LSP document cache. M06 may also pin this; if
  M06 lands first, M01 reuses its pin.
- `notify = "6"` (dev-dep on `crates/chio-lsp/`) for file-watcher-driven
  diagnostic refresh in integration tests.
- `tempfile`, `assert_cmd`, `predicates` (dev-deps on `chio doctor` and
  the LSP integration crates).
- `oci-distribution` is already present from trajectory-1 M06; M01
  consumes it through `chio-guard-registry` for the doctor probe and
  does not add a fresh pin.
- `cosign-verify` (or the existing `chio-attest-verify` crate from
  trajectory-1 M06) is consumed read-only by the doctor probe.

The `chio-errors` crate is pure-`std` (no async, no I/O at the type
level) so SDK callers from `chio-cli`, `chio-kernel`, `chio-tool-call-fabric`,
and the M07 provider crates can all depend on it without inheriting a
transitive runtime.

## Scope

In:

- New crate `crates/chio-errors/` with the type
  `chio_errors::ChioError`, a `Code` newtype wrapping `&'static str`
  spelled `urn:chio:error:<domain>:<code>`, a `Domain` enum, and a
  `Severity` enum. Implements `std::error::Error`, `std::fmt::Display`,
  `miette::Diagnostic`, and `serde::Serialize` (output keys match the
  existing `report()` JSON: `code`, `message`, `context`, `suggested_fix`,
  `legacy_string_code`, `jsonrpc_code`). No `unwrap_used`,
  no `expect_used`.
- New registry document `spec/errors/registry.yaml` enumerating
  every code. Initial breadth: ~40 codes spanning eighteen domains
  seeded up front so downstream milestones contribute *codes*, not
  *domains*. Ten core domains carry the bulk of P1 codes
  (`capability`, `policy`, `guard`, `attest`, `replay`, `provider`,
  `manifest`, `kernel`, `transport`, `cli`); eight additional
  domains are reserved with one seed entry each for downstream
  trajectory-2 consumers (`delegation` for M04, `adversarial` and
  `threat` for M05, `arena` for M08, `economy` and `lineage` for
  M09, `custody` and `weights` for M10). The `Domain` Rust enum is
  `#[non_exhaustive]` and lists all eighteen variants at P1.T2;
  downstream milestones add codes under existing domains rather
  than extending the enum. See decisions.yml D25 for the
  ten-versus-eighteen choice.
  Each entry carries: `urn`, `domain`, `severity`, `summary`,
  `help`, `legacy_string_code` (for backward compatibility with the
  existing `CHIO-*` prefixes), `jsonrpc_code` (optional, points into
  the existing wire-side numeric registry), `since` (semver tag),
  `stability` (`stable | unstable | deprecated`), `consumed_by`
  (list of crate names so M07 can locate the registry consumers
  programmatically).
- Schema document `spec/errors/registry.schema.json` validating the
  YAML at load time. Loaded by `chio-spec-codegen` and by `chio doctor`.
- Codegen pass in `crates/chio-spec-codegen/` that reads
  `spec/errors/registry.yaml` and emits
  `crates/chio-errors/src/_generated/error_codes.rs` (a single file with
  one `pub const` per code plus a `pub static REGISTRY: &[Entry]`).
  The output carries the trajectory-1 `// DO NOT EDIT` header and is
  formatted via `prettyplease`.
- Migration of `crates/chio-cli/src/cli/dispatch.rs` and the 14
  `include!`-d sibling files plus `crates/chio-control-plane/src/lib.rs`
  to emit registry codes. Migrated in domain-grouped chunks (one
  ticket per domain) so each PR is small enough to read.
  `CliError::Other(String)` shrinks to zero by end of P2.
- M07 per-provider doctests (`provider_error/` consumers) become readers
  of `spec/errors/registry.yaml`. The README tables in `chio-openai`,
  `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter` are
  regenerated from the registry by an xtask check; CI fails if a
  README table drifts from the registry.
- New CLI subcommand `chio doctor` with five probe classes:
  toolchain, OCI registry reachability (consumes M06 substrate from
  trajectory-1), guard bundle cosign signature freshness (consumes M06
  cosign verify), OTEL endpoint resolution (consumes trajectory-1 M10
  receipt-exporter shape), kernel async runtime probe (consumes
  trajectory-1 M05 tower stack: HTTP `GET /metrics`, asserts the
  `chio_kernel_dispatch_inflight` gauge is reachable). One ticket per
  probe class. Each failure carries a `urn:chio:error:*` code; output
  is plain or `--json`. The `--fix` flag runs idempotent repairs only
  (refresh OCI cache, regenerate `chio.yaml` schema, no destructive
  actions); destructive operations are explicitly rejected and
  documented in the audit doc.
- New crate `crates/chio-lsp/` (tower-lsp) with: textDocument completion,
  hover, go-to-capability-definition, schema validation for `chio.yaml`,
  manifest documents, and the guard DSL. Schema source: trajectory-1 M01
  `spec/schemas/chio-wire/v1/` plus M06 guard-bundle schema. Diagnostics
  carry `urn:chio:error:*` codes via `lsp_types::DiagnosticRelatedInformation`.
  Server is a single binary `chio-lsp` (or `chio lsp` subcommand on the
  main `chio` binary).
- VSCode extension at `editors/vscode-chio/` and Zed extension at
  `editors/zed-chio/`, both consuming the `chio-lsp` binary. Snippets
  for common policy patterns: capability-allowlist scaffold, scope
  bound, guard pipeline composition. `editors/README.md` documents
  the install path for both editors and the
  `chio-lsp` invocation contract.

Out (and why):

- `chio diff`, `chio blame`, install pipeline, observe presets, web
  playground, replay TUI (DX-4 folds into M09 lineage UI), and
  `chio receipt diff/blame/bisect` (DX-6, pure CLI on top of M04
  engine, penciled for follow-on). Cut from M01 in synthesis; they
  are the province of follow-on milestones.
- IntelliJ / JetBrains editor extension as a separate package. Folded
  into the LSP work here: `tower-lsp` speaks LSP, so any editor
  including JetBrains IDEs can adopt the binary. First-party packaging
  is limited to VSCode and Zed for this milestone.
- Neovim editor extension. Same rationale as JetBrains; LSP-compatible
  but not first-party packaged here.
- Refactoring `dispatch.rs` into a non-`include!()` module structure.
  The 14-file `include!` arrangement is a pre-existing scaffolding
  decision; M01 changes the error story inside those files but does
  not re-cut the include topology.
- Promoting the JSON-RPC numeric-code registry into a URN registry.
  Two-way migration is out of scope; the URN registry only points at
  the JSON-RPC registry one direction.
- Replacing `clap` with a different command-line parser. The clap
  surface is the public CLI contract.
- A separate normative coverage matrix milestone (Protocol M11) and a
  separate schema migration discipline milestone (Protocol M17). Both
  are folded into the URN registry + codegen rules shipped here; no
  parallel milestone is opened.

## Phases

### P0 - Wave-opener Cargo.lock bump

Mirrors trajectory-1 M05.P0 in shape: pin the new workspace deps and land
a placeholder bench/audit so the comparison gates are wired before any
behaviour change.

- M01.P0.T1 - Pin miette / tower-lsp / lsp-types / dashmap / notify in
  workspace `Cargo.toml`; assert single-tokio resolution.
- M01.P0.T2 - Open audit doc `.planning/audits/M01-error-taxonomy.md`
  with starting counts (976 `CliError::Other`, 20 `CHIO-*` codes, 11
  numeric-registry entries, 9 schema directories).

### P1 - chio-errors crate genesis + registry codegen

- M01.P1.T1 - Author `spec/errors/registry.schema.json` and the seed
  `spec/errors/registry.yaml` covering ~40 codes across the eighteen
  domains (ten core plus eight reserved for downstream milestones per
  decisions.yml D25).
- M01.P1.T2 - Scaffold `crates/chio-errors/` with `Code`, `Domain`,
  `Severity`, `ChioError`, `Diagnostic` impls, plus a `lookup()` helper
  that resolves a code at runtime against the embedded `REGISTRY` slice.
- M01.P1.T3 - Extend `chio-spec-codegen` with a registry-YAML loader and
  emit `crates/chio-errors/src/_generated/error_codes.rs` (one `pub const`
  per code, plus a `pub static REGISTRY: &[Entry]`).
- M01.P1.T4 - Wire codegen into `cargo xtask codegen` and add a CI check
  that the committed `error_codes.rs` matches a fresh regeneration.
- M01.P1.T5 - Add the `chio-errors` -> JSON-RPC bridge: every entry with
  a `jsonrpc_code` field is round-tripped against the existing
  `spec/errors/chio-error-registry.v1.json` via a property test.

### P2 - dispatch.rs migration to registry codes

Migrated in domain-grouped chunks. One ticket per domain so each PR is
reviewable. The order is chosen to retire `CliError::Other` from the
highest-frequency call sites first.

- M01.P2.T1 - Capability + policy domains. Migrate
  `crates/chio-cli/src/passport.rs`, `crates/chio-cli/src/passport_verifier.rs`,
  `crates/chio-cli/src/cli/trust_commands.rs`. Retires ~150 `CliError::Other`
  sites.
- M01.P2.T2 - Guard + manifest domains. Migrate
  `crates/chio-cli/src/guard.rs`, `crates/chio-cli/src/guards/`,
  `crates/chio-cli/src/policies/`. Retires ~120 sites.
- M01.P2.T3 - Replay + provider domains. Migrate
  `crates/chio-cli/src/cli/replay/*.rs`, `crates/chio-cli/src/cli/conformance.rs`.
  Retires ~200 sites.
- M01.P2.T4 - Attest + transport domains. Migrate
  `crates/chio-cli/src/cli/runtime.rs`, `crates/chio-cli/src/certify.rs`,
  `crates/chio-cli/src/enterprise_federation.rs`. Retires ~140 sites.
- M01.P2.T5 - Kernel + cli domains and tail. Migrate
  `crates/chio-control-plane/src/lib.rs`, `crates/chio-cli/src/evidence_export.rs`,
  `crates/chio-cli/src/scaffold.rs`. Retires the residual ~366 sites.
  Asserts `grep -rE 'CliError::Other' crates/chio-cli/src/` returns 0.
- M01.P2.T6 - Convert M07 per-provider README tables to be regenerated
  from `spec/errors/registry.yaml`. Adds an xtask check
  `cargo xtask errors regen --check` that fails CI on drift.

### P3 - chio doctor subcommand

One ticket per probe class. Probes share a common `Probe` trait and the
`--json` / `--fix` flags. `--fix` only runs idempotent repairs; the
audit doc enumerates which repairs are allowed.

- M01.P3.T1 - `chio doctor` skeleton: clap subcommand, `--json` /
  `--fix` flags, `Probe` trait, ordered probe execution, exit codes
  driven by the worst severity observed.
- M01.P3.T2 - Toolchain probe. Reads `cargo --version`, the workspace
  MSRV from root `Cargo.toml`, and the `rust-toolchain.toml` file if
  present. Fails closed on mismatch.
- M01.P3.T3 - OCI registry reachability probe. Consumes
  `chio-guard-registry` (trajectory-1 M06) to do a HEAD against the
  configured registry and surface auth errors.
- M01.P3.T4 - Cosign signature freshness probe. Consumes
  `chio-attest-verify` (trajectory-1 M06) to verify the local guard
  bundle signature is current against the public-key set.
- M01.P3.T5 - OTEL endpoint resolution + kernel runtime probe.
  Resolves the OTEL endpoint via `OTEL_EXPORTER_OTLP_ENDPOINT` and
  pings the trajectory-1 M05 `/metrics` endpoint; reports inflight
  gauge presence.
- M01.P3.T6 - `chio.yaml` schema validation probe. Loads the project
  `chio.yaml`, validates against the embedded JSON schema, and
  surfaces line/column-anchored diagnostics with `urn:chio:error:*`
  codes.

### P4 - chio-lsp server

- M01.P4.T1 - Crate scaffold `crates/chio-lsp/` with `tower-lsp`
  skeleton, `initialize` / `initialized` / `shutdown` lifecycle, and
  document-cache via `dashmap`.
- M01.P4.T2 - Schema-bound diagnostics for `chio.yaml`. Reuses the
  `spec/schemas/chio-wire/v1/` schemas + the new
  `spec/errors/registry.yaml`. Emits `lsp_types::Diagnostic` with the
  `code` field set to the `urn:chio:error:*` URN.
- M01.P4.T3 - Completion provider for capability scopes, guard
  identifiers, and policy keys. Snippet-aware.
- M01.P4.T4 - Hover provider for capability definitions, guard
  identifiers, manifest fields. Renders the registry-side `help` text
  on hover.
- M01.P4.T5 - Go-to-definition for capability and guard references in
  `chio.yaml`. Resolves to the originating manifest or the on-disk
  guard bundle.
- M01.P4.T6 - Manifest + guard DSL diagnostics. Same pattern as P4.T2
  but for the manifest schema and the `chio-guard-sdk` DSL.

### P5 - Editor extensions and snippets

- M01.P5.T1 - VSCode extension scaffold at `editors/vscode-chio/`
  with `package.json`, `extension.ts`, and an LSP-client wiring that
  spawns `chio-lsp` (or `chio lsp`). Includes language IDs for
  `chio.yaml`, `*.chio-manifest.yaml`, and `*.chio-guard.yaml`.
- M01.P5.T2 - Zed extension at `editors/zed-chio/`. Same shape as
  the VSCode extension; uses Zed's LSP-adapter API.
- M01.P5.T3 - Snippets pack: capability-allowlist scaffold, scope
  bound pattern, guard pipeline composition, manifest skeleton.
  Lives in `editors/snippets/` and is consumed by both extensions.
- M01.P5.T4 - `editors/README.md` documenting the install path for
  both extensions, the LSP binary contract, and the snippet set.

## Cross-milestone interactions

Hard deps on trajectory-2 artifacts (express via `depends_on`):

- M01.P0.T1 (Cargo.lock bump) is the wave-opener for everything below
  in M01.

Cross-trajectory references (express in `soft_deps` as string sentences):

- "trajectory-1 M01 (`crates/chio-spec-codegen/`) is the codegen toolchain
  this milestone extends; the registry-YAML loader lands as a sibling
  pass to the existing wire-types pass."
- "trajectory-1 M06 (`crates/chio-guard-registry/`, `crates/chio-attest-verify/`)
  is the OCI + cosign substrate the doctor probes consume; M01 does not
  duplicate the verify path."
- "trajectory-1 M07.P2.T8 / M07.P3.T6 (provider error doctests in
  `chio-openai`, `chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`)
  is the consumer set the registry feeds; the README tables become
  regenerated from the registry."
- "trajectory-1 M05 (`crates/chio-tower/`) is the tower stack the
  kernel-runtime doctor probe queries via `/metrics`."
- "trajectory-1 M10 (`crates/chio-otel-receipt-exporter/`) defines the
  OTEL endpoint shape the doctor probe reads."

Forward references (other trajectory-2 milestones consuming M01):

- M02 verdict differential classifies failures by the `urn:chio:error:*`
  code surface that M01 ships.
- M07 framework adapter pack consumes the registry: each new adapter
  carries a registry-regenerated README table.
- M09 lineage anchors carry error provenance entries that quote
  `urn:chio:error:*` codes.

## Risks and mitigations

- **Codegen drift.** A registry edit landing without regenerating
  `error_codes.rs` produces a silent code-vs-data skew. Mitigation:
  P1.T4 wires a CI check that runs the codegen and `git diff --exit-code`s
  the result. Parallel mitigation: a `chio doctor` registry-freshness
  probe that flags stale generated code at run time.
- **`Other(String)` regression after migration.** Migration ticket lands
  green, then a follow-on PR re-introduces `CliError::Other(format!(...))`.
  Mitigation: end-of-P2 grep-gate fails CI if `CliError::Other` appears
  outside a single allowlisted helper used by the deprecation shim.
- **LSP performance pathology.** A naive `validate-on-keystroke`
  implementation freezes the editor on a 1k-line `chio.yaml`.
  Mitigation: debounce diagnostic refresh at 150 ms, cache parsed
  documents in `dashmap` keyed by URI, and bench LSP cold-start +
  steady-state diagnostic latency under `criterion` in
  `crates/chio-lsp/benches/`.
- **Cross-editor LSP behaviour drift.** VSCode and Zed differ in how
  they surface `code` and `codeDescription`. Mitigation: both
  extensions ship integration tests in CI that drive a real
  `chio-lsp` binary and assert diagnostic codes flow through.
- **Numeric-registry / URN-registry skew.** A code is added to one
  side and not the other. Mitigation: P1.T5 lands a property test
  that round-trips every entry with a `jsonrpc_code` against the wire
  registry; CI fails on mismatch.
- **Doctor `--fix` does the wrong thing.** A repair runs and breaks
  the user's checkout. Mitigation: every repair is idempotent,
  documented in the audit doc, and behind an `--apply` confirmation
  on first run; `--fix --dry-run` is the default.
- **Snippets divergence between editors.** VSCode and Zed snippet
  formats differ. Mitigation: the canonical snippet set lives in
  `editors/snippets/` in a tool-neutral form; both extensions
  generate their on-disk snippet files at install time from this
  source.

## Success criteria

A green light on M01 means all of the following are true:

- `crates/chio-errors/` exists, builds clean, passes clippy with the
  workspace `unwrap_used = "deny"` / `expect_used = "deny"` lints, and
  exposes the `Code`, `Domain`, `Severity`, `ChioError`, and
  `Diagnostic` surface.
- `spec/errors/registry.yaml` carries at least 40 codes spanning the
  eighteen seed domains (ten core plus eight reserved-for-downstream),
  validates against `spec/errors/registry.schema.json`,
  and is the source of truth for the regenerated
  `crates/chio-errors/src/_generated/error_codes.rs`.
- `cargo xtask errors regen --check` is green on `main` and fails on
  drift.
- `grep -rE 'CliError::Other' crates/chio-cli/src/` returns 0
  matches outside the deprecation shim. The 976-site count is gone.
- The three M07 per-provider doctests in `chio-openai`,
  `chio-anthropic-tools-adapter`, and `chio-bedrock-converse-adapter`
  pass against README tables regenerated from the registry.
- `chio doctor` is wired into the CLI and emits structured JSON when
  `--json` is set; the five probe classes report individually with
  `urn:chio:error:*` codes; `--fix` runs idempotent repairs only.
- `crates/chio-lsp/` builds clean, ships a `chio-lsp` binary, and
  passes the integration tests under `crates/chio-lsp/tests/`. Cold
  startup p99 < 200 ms, steady-state diagnostic latency p99 < 50 ms
  on a 1k-line `chio.yaml` (criterion bench in
  `crates/chio-lsp/benches/`).
- `editors/vscode-chio/` and `editors/zed-chio/` build clean against
  the latest stable VSCode and Zed manifests and surface
  registry-coded diagnostics in their respective integration tests.
- Audit doc `.planning/audits/M01-error-taxonomy.md` records the
  before-and-after for the four hard counts (sites, codes, registry
  entries, schemas) and pins a date for re-measurement after each
  phase merges.
