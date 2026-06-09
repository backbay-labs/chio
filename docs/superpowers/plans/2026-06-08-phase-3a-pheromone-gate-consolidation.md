# Phase 3a: pheromone gate consolidation (15 scripts -> 1 parameterized xtask leaf) - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task ends with the per-task gate in the "Gate (run after every task)" section; do not start the next task until it is green.

**Goal:** Collapse the 15 `scripts/check-chio-pheromone-*.sh` gates into one fail-closed, parameterized `cargo xtask check fixtures <facet> [--schema-only|--negative-only]` leaf, driven by a `ci-gates/pheromone.toml` manifest plus per-facet Rust handlers, proven behavior-identical by a dual-run parity harness, then flip the 15 workflows' `run:` line and delete the 15 scripts. The 15 workflow FILES stay (required-check names are owned by branch protection; collapsing them to a matrix is Phase 4).

**Architecture:** A new self-contained `xtask` module `fixtures.rs` (plus a small `fixtures_manifest.rs` if the file would exceed the hygiene cap). A `ci-gates/pheromone.toml` manifest captures the genuinely-*data* per facet (schema-id -> schema-file map, fixture dir, schema-validate doc list, simple `cargo test` invocations, recursion edges, node-dashboard flag, retired-marker / runbook guard inputs). The non-data per-facet imperative steps (the `relay` CLI orchestration with temp dirs, the `transit` fixture regen + `cmp`, the `relay-observability` npm test/build + sre-metrics call) live in named Rust handler functions keyed by facet. The clap leaf replaces nothing destructively: it adds a `Fixtures` variant to the already-present `CheckCommand` enum (which today holds only `CratePaths`). Dispatch routes it to `fixtures::run`.

**Tech stack:** Rust (`xtask` crate: std + `serde`/`toml` for the manifest, `std::process::Command` for cargo/npm/bash passthrough, the existing `chio-spec-validate` crate as a library or subprocess), bash (the old scripts, run only by the dual-run harness until deletion), GitHub Actions YAML.

---

## Reality check (verified against the tree on 2026-06-08, branch chio/arch-migration)

The research doc (`docs/superpowers/research/scripts-audit.md`) describes these 15 as "one parameterized gate masquerading as 15 ... differ only by facet name, schema id list, and fixture filenames ... DATA not logic." **Reading the actual scripts contradicts that in three load-bearing ways. The plan is built around the real shape, not the research summary.**

1. **They are a recursive dependency graph, not 15 independent leaves.** Many facets invoke sibling scripts with `--schema-only` (and two invoke a sibling with no flag, i.e. full run):
   - `relay-observability.sh:122-124` -> `directory-lifecycle`, `relay-ops`, `relay` (all `--schema-only`)
   - `relay-alert-delivery.sh:220-225` -> handoff, routing, observability, directory-lifecycle, relay-ops, relay (`--schema-only`)
   - `relay-alert-handoff.sh:204-208`, `relay-alert-routing.sh:199-202`, `relay-alert-assurance.sh:300-302`, `relay-alert-assurance-export.sh:246`, `relay-alert-assurance-archive.sh:222`, `relay-alert-assurance-archive-package.sh:481`, `directory-lifecycle.sh:213`, `relay-ops.sh:147` -> various siblings, `--schema-only`
   - `relay.sh:339` -> `runtime.sh` (FULL run, no flag)
   - `runtime.sh:332` -> `transit.sh` (FULL run, no flag)
   So `relay --schema-only` runs its own schema block; `relay` (full) runs the whole `runtime` chain which in turn runs the whole `transit` chain. The manifest MUST encode these edges and the new leaf MUST reproduce them, or the consolidated gate silently drops coverage (fail-open) - exactly the go-dark failure mode the spec forbids.

2. **Per-facet imperative logic, not just string data.** Verified non-data behavior:
   - `relay.sh`: a `CHIO_RELAY_RUN_BIND_TESTS` env branch with a 9-entry `--skip` list (`:39-52`), a `mktemp` temp dir, a generated signing-key JSON, six sequential `cargo run -p chio-cli ... pheromone relay {status,tick,enqueue,catchup}` invocations, three deliberate `if cargo run ...; then echo ...; exit 1; fi` negative assertions, and embedded python that mutates fixtures.
   - `transit.sh`: an `rg` retired-marker guard built at runtime as `printf '%s%s' 'chio' 'dos'` (`:39`), then fixture regeneration via `generate-chio-three-vendor-fixtures` + a `cmp` loop (`:190-198`).
   - `relay-observability.sh`: a `pushd crates/chio-cli/dashboard && npm test && npm run build` block (`:101-104`) and a call to `scripts/check-sre-metrics-registry.sh` (`:99`).
   - `relay.sh:33` and others run an `rg "Chio|CHIO|chio"` runbook guard that must FAIL if the doc cites those names.
   This is imperative orchestration. Encoding it as pure TOML would reinvent a shell in data. The chosen design keeps it in typed Rust handlers and uses the manifest only for the parts that genuinely are tables.

3. **There are ZERO pheromone meta-tests.** The task brief says "15 scripts/tests/*.test.sh meta-tests for them." Verified false: `grep -rl pheromone scripts/tests/` returns nothing; the 25 `*.test.sh` files cover other gates (cargo-vet, egress, hygiene, sdk-release, threat-coverage, etc.). **So there are no meta-test assertions to port for this cluster.** The behavior proof for this consolidation comes entirely from the dual-run parity harness (Task F), which is therefore non-optional, not a nicety.

4. **Node setup is split across the 15 workflows.** 5 set up node (the dashboard-touching facets: `relay-alert-assurance`, `relay-alert-delivery`, `relay-alert-handoff`, `relay-alert-routing`, `relay-observability`); 10 do not. The new leaf still shells `npm` for those 5, so their workflows keep their `setup-node` + `npm ci` steps; the 10 non-node workflows stay node-free. The run-line swap is per-workflow and must not add or remove node.

5. **`chio-spec-validate` CLI is positional:** `chio-spec-validate <schema.json> <document.json>`, exit 0 on success (`crates/chio-spec-validate/src/main.rs:6`). The scripts call it via `cargo run -p chio-spec-validate -- <schema> <doc>`. The new leaf reuses the crate as a library (it is already an xtask dependency: `xtask/Cargo.toml` lists `chio-spec-validate = { workspace = true }`), avoiding a `cargo run` per document.

### Design decision recorded

Hybrid manifest + handlers, NOT pure-data manifest. The manifest (`ci-gates/pheromone.toml`) is the single source of truth for the tabular per-facet data and the recursion edges; a `FacetKind` enum selects the imperative handler for facets whose body is more than schema validation. A facet whose body is *only* schema validation + a flat list of `cargo test` lines + recursion runs entirely from the manifest with the generic handler. This keeps the data/logic split honest and the file under the hygiene cap.

---

## The 15 facets (verified, exact)

Facet name = the script basename minus the `check-chio-pheromone-` prefix and `.sh` suffix; it is also the workflow basename minus `chio-pheromone-` and `.yml`. All 15:

| # | Facet | Body shape | Recurses into (--schema-only unless noted) | node |
| --- | --- | --- | --- | --- |
| 1 | `directory-lifecycle` | schema + cargo test | `relay-ops` | no |
| 2 | `relay-alert-assurance-archive-hardening` | schema + cargo test (no recursion) | - | no |
| 3 | `relay-alert-assurance-archive-package` | schema + cargo test + imperative (481 LOC) | `relay-alert-assurance-archive` | no |
| 4 | `relay-alert-assurance-archive` | schema + cargo test | `relay-alert-assurance-export` | no |
| 5 | `relay-alert-assurance-export` | schema + cargo test | `relay-alert-assurance` | no |
| 6 | `relay-alert-assurance-external-retention` | schema + cargo test (no recursion) | - | no |
| 7 | `relay-alert-assurance` | schema + cargo test | `relay-alert-delivery`, `relay-alert-handoff`, `relay-alert-routing` | yes |
| 8 | `relay-alert-delivery` | schema + cargo test | handoff, routing, observability, directory-lifecycle, relay-ops, relay | yes |
| 9 | `relay-alert-handoff` | schema + cargo test | routing, observability, directory-lifecycle, relay-ops, relay | yes |
| 10 | `relay-alert-routing` | schema + cargo test + sre-metrics | observability, directory-lifecycle, relay-ops, relay | yes |
| 11 | `relay-observability` | schema + cargo test + npm + sre-metrics | directory-lifecycle, relay-ops, relay | yes |
| 12 | `relay-ops` | schema + cargo test (env branch on negative-only) | `relay` | no |
| 13 | `relay` | schema + cargo test (env branch, --skip list) + heavy CLI orchestration | `runtime` (FULL, no flag) | no |
| 14 | `runtime` | schema + cargo test + imperative | `transit` (FULL, no flag) | no |
| 15 | `transit` | retired-marker rg guard + schema + cargo test + fixture-regen cmp | - | no |

(`FIXTURE_DIR` is `examples/chio-3vendor/fixtures/pheromone/relay` for the relay-family facets, `examples/chio-3vendor/fixtures/pheromone` for `transit` and `runtime`; `SCHEMA_DIR` is `spec/schemas/chio-pheromone/v1` for all 15. The five facets with an empty `FIXTURE_DIR=` in the audit grep set it locally inside per-section logic; the manifest records the effective dir per facet.)

---

## Manifest shape (chosen)

`ci-gates/pheromone.toml` (new file at repo root under a new `ci-gates/` dir, sibling to `scripts/`; path recorded so `check crate-paths` and future moves can find it). One `[[facet]]` array entry per facet. Shape:

```toml
# ci-gates/pheromone.toml
# Single source of truth for the pheromone fixture-and-schema gate cluster.
# Consumed by `cargo xtask check fixtures <facet>`. Fail-closed: this file MUST
# enumerate all 15 facets; an unknown facet on the CLI is an error, and the
# xtask test `manifest_enumerates_all_known_facets` rejects a short manifest.

schema_dir = "spec/schemas/chio-pheromone/v1"
schema_registry = "spec/schemas/registry.json"

[[facet]]
name = "relay-observability"
kind = "relay_observability"          # selects the Rust handler; "generic" for plain facets
fixture_dir = "examples/chio-3vendor/fixtures/pheromone/relay"
# schema_id -> schema filename, asserted registered + strict-object in the schema block
schemas = [
  { id = "chio.pheromone.relay-observability-report.v1", file = "relay-observability-report.schema.json" },
  { id = "chio.pheromone.relay-metrics-snapshot.v1",     file = "relay-metrics-snapshot.schema.json" },
  { id = "chio.pheromone.relay-event-report.v1",         file = "relay-event-report.schema.json" },
]
# (schema_file, document_file) pairs run through chio_spec_validate::validate
validate = [
  { schema = "relay-observability-report.schema.json", doc = "relay-observability-report.json" },
  { schema = "relay-observability-report.schema.json", doc = "relay-observability-degraded-report.json" },
  { schema = "relay-metrics-snapshot.schema.json",     doc = "relay-metrics-snapshot.json" },
  { schema = "relay-event-report.schema.json",         doc = "relay-event-report.json" },
  { schema = "relay-negative-fixture-corpus.schema.json", doc = "negative-cases.json" },
]
# cargo test invocations for the `all` (full) mode, in order. Each is an argv
# tail after `cargo test`; reproduced verbatim including `--test`, `--bin`, filters.
cargo_tests = [
  ["-p", "chio-pheromone-relay", "observability"],
  ["-p", "chio-cli", "--bin", "chio", "chio_pheromone"],
  ["-p", "chio-metrics-spec"],
]
needs_dashboard_npm = true            # pushd crates/chio-cli/dashboard; npm test; npm run build
sre_metrics_registry = true           # bash scripts/check-sre-metrics-registry.sh (kept as thin shell)
# recursion edges: each runs the named facet; `mode` is the flag passed
recurse = [
  { facet = "directory-lifecycle", mode = "schema-only" },
  { facet = "relay-ops",           mode = "schema-only" },
  { facet = "relay",               mode = "schema-only" },
]

# ... 14 more [[facet]] entries ...
```

Facets whose body has bespoke imperative steps (`relay`, `runtime`, `transit`, `relay-observability`, `relay-alert-*-package`, etc.) set `kind` to a dedicated handler key. The handler reads the same manifest entry for its data and adds the imperative steps the manifest cannot express. The per-facet python validators in the old scripts (the `python3 - ... <<'PY'` metadata-assertion blocks) are ported into the handler as typed Rust over `serde_json::Value` (the same checks: schema registered at the expected path, strict-object schema, negative-corpus required codes present, metrics labels bounded, etc.). This is the bulk of the porting work and is done facet-by-facet under Task D, each proven by the dual-run in Task F before the script is deleted.

Why not a Rust `static` table instead of TOML: the data is large (15 facets x up to 8 schemas x up to 5 validate pairs), it is exactly the kind of thing a non-Rust reviewer audits, and `check crate-paths` already parses repo config files as data; a TOML keeps the gate data reviewable and lets a future Phase-4 matrix workflow read the same file. The TOML is loaded once and deserialized into typed structs, so the type-safety argument for a Rust table is preserved at the boundary.

---

## File structure

- Create: `ci-gates/pheromone.toml` - the manifest (all 15 facets).
- Create: `xtask/src/fixtures.rs` - manifest types + `load_manifest`, facet lookup, arg handling, the generic handler, the per-facet imperative handlers, `run`, and the `#[cfg(test)]` module. If this would exceed ~1900 lines (hygiene cap is 2000), split the manifest structs + loader into `xtask/src/fixtures_manifest.rs` and keep handlers in `fixtures.rs`.
- Create: `xtask/tests/pheromone_parity.rs` - the dual-run parity integration test (gated behind an env flag so it does not run the multi-minute cargo chain on every `cargo test -p xtask`; CI runs it explicitly).
- Modify: `xtask/src/cli.rs` - add `Fixtures { facet: String, schema_only: bool, negative_only: bool }` to `CheckCommand`; add unit tests for the new parse.
- Modify: `xtask/src/dispatch.rs` - route `CheckCommand::Fixtures { .. }` to `fixtures::run`.
- Modify: `xtask/src/main.rs` - `mod fixtures;` (and `mod fixtures_manifest;` if split). No logic.
- Modify: `xtask/Cargo.toml` - add `toml` (pin to an already-vetted version; see Task B note) under `[dependencies]`, and `[dev-dependencies]` nothing new (the parity test shells out).
- Modify (Task G, only after all 15 dual-runs pass): the 15 `.github/workflows/chio-pheromone-*.yml` - swap the one `run:` line; keep each file's existing node setup.
- Delete (Task G): the 15 `scripts/check-chio-pheromone-*.sh`. KEEP `scripts/check-sre-metrics-registry.sh` (still invoked by handlers as thin shell) and `scripts/check-chio-pheromone-*` is the only deletion set.

---

## Gate (run after every task)

From repo root, all must be green before the next task:

```bash
cargo build -p xtask
cargo test  -p xtask
cargo clippy -p xtask -- -D warnings
cargo fmt --all -- --check
cargo xtask check crate-paths
python3 scripts/check-stub-surfaces.py
python3 scripts/check-rust-file-hygiene.py
```

Expected tail:
```
   Compiling xtask v...
    Finished ...
test result: ok. N passed; 0 failed; ...
    Finished ... (clippy, no warnings)
(fmt prints nothing on success)
xtask check crate-paths: all crate-path references resolve
check-stub-surfaces: OK
check-rust-file-hygiene: OK
```

`check-rust-file-hygiene.py` enforces the 2000-line cap; `main.rs` is 1923 lines today and this plan adds only a `mod` line to it, so it stays under. `fixtures.rs` must stay under 2000; split into `fixtures_manifest.rs` if it grows past ~1900 (Task D's stop rule). From Task F onward, also run the dual-run parity (Task F command) for every facet touched.

House rules enforced throughout: no em dashes (hyphens/parentheses only); fail-closed (unknown facet -> `XtaskError::Usage`, never a skip; manifest must list all 15 or a test fails); `unwrap_used`/`expect_used` denied, so handler and test code matches on `Result`/`Option` explicitly and `panic!`s in tests rather than unwrapping.

---

## Task A: scaffold the manifest with all 15 facets (data only, no behavior)

**Files:** create `ci-gates/pheromone.toml`; modify `xtask/Cargo.toml`.

- [ ] **Step A1: enumerate the 15 facets from the scripts into the manifest.** For each of the 15 scripts, extract `SCHEMA_DIR`, the effective `FIXTURE_DIR`, the `expected = { ... }` schema-id/file map from its python block, the `validate_schema` doc list, the `cargo test ...` lines (verbatim argv), the recursion edges (`bash "$ROOT/scripts/check-chio-pheromone-<facet>.sh"` calls and their flag), and the `needs_dashboard_npm`/`sre_metrics_registry`/retired-marker/runbook flags. Write one `[[facet]]` per script. Set `kind = "generic"` for the schema-only-plus-cargo-test facets (`directory-lifecycle`, `relay-alert-assurance-archive-hardening`, `relay-alert-assurance-external-retention`, `relay-alert-assurance-archive`, `relay-alert-assurance-export`, `relay-alert-assurance`, `relay-alert-delivery`, `relay-alert-handoff`) and a dedicated `kind` for the imperative ones (`relay`, `runtime`, `transit`, `relay-observability`, `relay-alert-routing`, `relay-alert-assurance-archive-package`, `relay-ops`).

  Source-of-truth commands to populate each entry (run, paste results into the TOML, do not eyeball):
  ```bash
  for f in scripts/check-chio-pheromone-*.sh; do
    echo "### $(basename "$f" .sh) ###"
    grep -nE 'SCHEMA_DIR=|FIXTURE_DIR=|expected = \{|cargo test|validate_schema "|bash .*scripts/check-chio-pheromone|npm |check-sre-metrics|RUN_BIND_TESTS|--skip ' "$f"
  done
  ```

- [ ] **Step A2: add the `toml` dependency.** In `xtask/Cargo.toml` add under `[dependencies]`:
  ```toml
  toml = "0.8"
  ```
  Note: confirm the resolved `toml` version is already in `Cargo.lock` / vetted, or add a `cargo vet` exemption in the same change (the repo gates `cargo-vet`; per project memory the vet store is at root `supply-chain/`). If `toml` is not yet vetted, prefer reusing an already-present TOML reader: check `cargo tree -p xtask -i toml` and `grep -r '^toml' Cargo.lock`. If unvetted and adding an exemption is undesirable, fall back to a hand-written Rust `static` table (the design's stated alternative) and skip the `toml` dependency.

**Gate:** the standard per-task gate. At this point `fixtures.rs` does not exist yet, so the manifest is unused; `cargo build -p xtask` must still succeed and `check crate-paths` must still pass (the new `ci-gates/pheromone.toml` contains `crates/...`? it does not embed `crates/chio-*` literals, so it is inert to that guard - confirm with `grep -c 'crates/chio-' ci-gates/pheromone.toml` returning 0).

---

## Task B: manifest types + loader + the fail-closed lookup (TDD, no gate behavior yet)

**Files:** create `xtask/src/fixtures.rs` (types, loader, lookup); modify `xtask/src/main.rs` (add `mod fixtures;`).

- [ ] **Step B1: write the failing unit tests first.** In `xtask/src/fixtures.rs` `#[cfg(test)] mod tests`:
  ```rust
  #[test]
  fn manifest_enumerates_all_known_facets() {
      let manifest = load_manifest_from(MANIFEST_PATH).expect("manifest loads");
      let mut names: Vec<&str> = manifest.facet.iter().map(|f| f.name.as_str()).collect();
      names.sort_unstable();
      let mut expected = KNOWN_FACETS.to_vec();
      expected.sort_unstable();
      assert_eq!(names, expected, "manifest must list exactly the 15 known facets");
  }

  #[test]
  fn unknown_facet_is_an_error_not_a_skip() {
      let manifest = load_manifest_from(MANIFEST_PATH).expect("manifest loads");
      match manifest.facet_by_name("does-not-exist") {
          Some(found) => panic!("unknown facet resolved to {}", found.name),
          None => {} // fail-closed: caller turns None into XtaskError::Usage
      }
  }

  #[test]
  fn every_known_facet_resolves() {
      let manifest = load_manifest_from(MANIFEST_PATH).expect("manifest loads");
      for name in KNOWN_FACETS {
          assert!(manifest.facet_by_name(name).is_some(), "missing facet {name}");
      }
  }

  #[test]
  fn recurse_edges_point_at_known_facets() {
      let manifest = load_manifest_from(MANIFEST_PATH).expect("manifest loads");
      for facet in &manifest.facet {
          for edge in &facet.recurse {
              assert!(
                  manifest.facet_by_name(&edge.facet).is_some(),
                  "{} recurses into unknown facet {}", facet.name, edge.facet
              );
          }
      }
  }
  ```
  Define the compile-time invariant list (this is the fail-closed enumeration; the spec requires the manifest enumerate all 15):
  ```rust
  pub(crate) const KNOWN_FACETS: [&str; 15] = [
      "directory-lifecycle",
      "relay-alert-assurance-archive-hardening",
      "relay-alert-assurance-archive-package",
      "relay-alert-assurance-archive",
      "relay-alert-assurance-export",
      "relay-alert-assurance-external-retention",
      "relay-alert-assurance",
      "relay-alert-delivery",
      "relay-alert-handoff",
      "relay-alert-routing",
      "relay-observability",
      "relay-ops",
      "relay",
      "runtime",
      "transit",
  ];
  ```

- [ ] **Step B2: implement the types and loader to make them pass.** Use `serde::Deserialize` structs mirroring the TOML; load via the workspace root (reuse the `workspace_root()` helper pattern from `main.rs:1110`, exposed to the module). Resolve `MANIFEST_PATH` as `workspace_root()?.join("ci-gates/pheromone.toml")`. No `unwrap`/`expect` in non-test code; return `XtaskError::Io`/a new `XtaskError::Manifest(String)` on parse failure (add the variant to `xtask/src/error.rs` with a `Display` arm; mirror the existing `Json`/`Yaml` arms).
  ```rust
  #[derive(serde::Deserialize)]
  pub(crate) struct Manifest {
      pub schema_dir: String,
      pub schema_registry: String,
      pub facet: Vec<Facet>,
  }
  #[derive(serde::Deserialize)]
  pub(crate) struct Facet {
      pub name: String,
      pub kind: String,
      pub fixture_dir: String,
      #[serde(default)] pub schemas: Vec<SchemaEntry>,
      #[serde(default)] pub validate: Vec<ValidatePair>,
      #[serde(default)] pub cargo_tests: Vec<Vec<String>>,
      #[serde(default)] pub needs_dashboard_npm: bool,
      #[serde(default)] pub sre_metrics_registry: bool,
      #[serde(default)] pub recurse: Vec<RecurseEdge>,
  }
  // SchemaEntry { id, file }; ValidatePair { schema, doc }; RecurseEdge { facet, mode }
  impl Manifest {
      pub(crate) fn facet_by_name(&self, name: &str) -> Option<&Facet> {
          self.facet.iter().find(|f| f.name == name)
      }
  }
  ```
  Add `mod fixtures;` to `main.rs`.

**Gate:** standard per-task gate. The four manifest tests pass; nothing dispatches yet.

---

## Task C: wire the clap leaf + arg handling (TDD on parse + dispatch error)

**Files:** modify `xtask/src/cli.rs`, `xtask/src/dispatch.rs`.

- [ ] **Step C1: extend `CheckCommand` and add parse tests.** In `cli.rs`, change `CheckCommand` from:
  ```rust
  pub enum CheckCommand {
      #[command(name = "crate-paths")]
      CratePaths,
  }
  ```
  to add:
  ```rust
      /// Run a pheromone fixture-and-schema gate by facet name.
      Fixtures {
          /// Facet name (e.g. `relay-observability`). See ci-gates/pheromone.toml.
          facet: String,
          /// Schema/metadata validation only; skip cargo tests and orchestration.
          #[arg(long, conflicts_with = "negative_only")]
          schema_only: bool,
          /// Negative-corpus path only.
          #[arg(long)]
          negative_only: bool,
      },
  ```
  Add to the `cli.rs` test module:
  ```rust
  #[test]
  fn check_fixtures_parses_with_facet() {
      match parse(&["xtask", "check", "fixtures", "relay-observability"]).command {
          Command::Check { command: CheckCommand::Fixtures { facet, schema_only, negative_only } } => {
              assert_eq!(facet, "relay-observability");
              assert!(!schema_only && !negative_only);
          }
          other => panic!("expected check fixtures, got {other:?}"),
      }
  }

  #[test]
  fn check_fixtures_schema_only_and_negative_only_conflict() {
      match Cli::try_parse_from(["xtask", "check", "fixtures", "relay", "--schema-only", "--negative-only"]) {
          Ok(_) => panic!("conflicting flags parsed"),
          Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict, "got: {err}"),
      }
  }

  #[test]
  fn check_fixtures_requires_a_facet() {
      // Fail-closed: a bare `check fixtures` with no facet is a parse error.
      match Cli::try_parse_from(["xtask", "check", "fixtures"]) {
          Ok(_) => panic!("missing facet parsed"),
          Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument, "got: {err}"),
      }
  }
  ```

- [ ] **Step C2: route dispatch.** In `dispatch.rs`, change the `Check` arm:
  ```rust
  cli::Command::Check { command } => match command {
      CheckCommand::CratePaths => crate_paths::run(Vec::new()),
      CheckCommand::Fixtures { facet, schema_only, negative_only } => {
          fixtures::run(&facet, fixtures::Mode::from_flags(schema_only, negative_only)?)
      }
  },
  ```
  Add `use crate::fixtures;`. Define in `fixtures.rs`:
  ```rust
  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  pub(crate) enum Mode { All, SchemaOnly, NegativeOnly }
  impl Mode {
      pub(crate) fn from_flags(schema_only: bool, negative_only: bool) -> Result<Self, XtaskError> {
          match (schema_only, negative_only) {
              (true, true) => Err(XtaskError::Usage(
                  "fixtures: --schema-only and --negative-only are mutually exclusive".into())),
              (true, false) => Ok(Mode::SchemaOnly),
              (false, true) => Ok(Mode::NegativeOnly),
              (false, false) => Ok(Mode::All),
          }
      }
  }
  ```
  (The clap `conflicts_with` already rejects the double-flag at parse time; `from_flags` keeps the invariant inside the module too, belt-and-suspenders, and is unit-tested.) Stub `run` to return `XtaskError::Usage("not yet implemented")` for now so it compiles; Task D fills it.

**Gate:** standard per-task gate. Parse tests pass; `cargo xtask check fixtures relay` currently errors with "not yet implemented" (fail-closed, expected). Confirm:
```bash
cargo run -p xtask -- check fixtures relay; echo "exit=$?"
# expected: xtask: usage: fixtures: not yet implemented ; exit=1
cargo run -p xtask -- check fixtures bogus-facet; echo "exit=$?"
# expected (after Task D wires lookup): a fail-closed unknown-facet error; exit=1
```

---

## Task D: implement the gate body, facet by facet (TDD, the bulk)

**Files:** `xtask/src/fixtures.rs` (and `fixtures_manifest.rs` if split).

Implement `run(facet_name, mode)`:
1. Load the manifest; `facet_by_name(facet_name)` -> `None` becomes `XtaskError::Usage(format!("unknown pheromone facet: {facet_name}"))` (fail-closed).
2. Run the schema/metadata block (manifest-driven, generic): for each `schemas` entry assert the file exists, is a strict object schema (`type=="object"`, `additionalProperties==false` OR `$id` present per the facet's original check; record which per facet in the manifest if they differ - `relay-observability` requires `additionalProperties:false`, `relay`/`transit` require `$id`), and is registered at `spec/schemas/chio-pheromone/v1/<file>` in `registry.json`. Then the per-facet metadata assertions ported from the python block (negative-corpus required codes, bounded metric labels, fixture binding invariants).
3. For each `validate` pair, call `chio_spec_validate::validate(&schema_path, &doc_path)` (library call) and map a failure to `XtaskError::Validation`.
4. If `mode == SchemaOnly`, return `Ok(())` (matches the scripts' `exit 0` after the schema block).
5. Else run `cargo_tests` in order via `cargo test` subprocess (helper below), then the facet's imperative handler steps (npm, sre-metrics, CLI orchestration, fixture regen + cmp, env-branch skip lists), then the recursion edges (each edge runs `run(edge.facet, edge.mode_as_Mode())`), honoring `mode == NegativeOnly` early-exits exactly where the scripts do.

Subprocess helper (reuse the `main.rs:735` pattern; surface `XtaskError::Process` on non-zero):
```rust
fn run_cargo_test(root: &Path, tail: &[String]) -> Result<(), XtaskError> {
    let status = std::process::Command::new("cargo")
        .arg("test").args(tail).current_dir(root).status()
        .map_err(|e| XtaskError::Io("cargo test".into(), e))?;
    if !status.success() {
        return Err(XtaskError::Process(format!("cargo test {tail:?} exited {}", status.code().unwrap_or(-1))));
    }
    Ok(())
}
```

Order the facets least-dependent first so each lands behind a green dual-run before its dependents need it:

- [ ] **Step D1: `transit`** (leaf of the chain, no recursion). Port: the runtime-built retired-marker `rg` guard (`printf '%s%s' 'chio' 'dos'` over `spec/CHIO_PHEROMONE.md`, must NOT match - reproduce as a Rust substring scan that errors if found), the python metadata block (deposit/batch/policy/concentration/negative invariants), the five `validate` pairs, `cargo test -p chio-pheromone` + `cargo test -p chio-federation pheromone`, then (mode == All) the fixture regen via `cargo run -p chio-three-vendor-example --bin generate-chio-three-vendor-fixtures -- --pheromone-out-dir <tmp>` and a `cmp` over the five filenames. Write the dual-run for `transit` (Task F recipe) and only then mark done.
- [ ] **Step D2: `runtime`** (recurses `transit` FULL). Port its python + cargo tests; its recursion edge is `{ facet="transit", mode="all" }`.
- [ ] **Step D3: `relay`** (recurses `runtime` FULL; the heaviest). Port: the runbook `rg "Chio|CHIO|chio"` guard (must NOT match), the `CHIO_RELAY_RUN_BIND_TESTS` env branch and its 9-entry `--skip` list, the schema block, the `mktemp`/signing-key/`relay status|tick|enqueue|catchup` CLI orchestration including the three `if cargo run ...; then exit 1` negative assertions, and the `negative-only` early-exit running `signed_relay_request_verifies_payload_hash_sender_and_replay_nonce`. Use `std::env::temp_dir()` + a unique subdir; clean up with a guard type (Drop) since `expect`/`unwrap` are denied.
- [ ] **Step D4: `relay-ops`, `directory-lifecycle`** (each recurses `relay --schema-only`).
- [ ] **Step D5: `relay-observability`** (npm + sre-metrics + recurses directory-lifecycle/relay-ops/relay schema-only). Port the `pushd crates/chio-cli/dashboard && npm test && npm run build` as two `Command::new("npm")` calls with `.current_dir(root.join("crates/chio-cli/dashboard"))`, the `bash scripts/check-sre-metrics-registry.sh` passthrough, and the negative-only degraded-report python check.
- [ ] **Step D6: `relay-alert-routing`, `relay-alert-handoff`, `relay-alert-delivery`, `relay-alert-assurance`** (the alert fan-out; multiple schema-only recursion edges each).
- [ ] **Step D7: `relay-alert-assurance-export`, `relay-alert-assurance-archive`, `relay-alert-assurance-archive-hardening`, `relay-alert-assurance-archive-package`, `relay-alert-assurance-external-retention`** (the archive sub-chain; `-package` is 481 LOC and the most imperative - port its embedded logic carefully and lean on its dual-run).

Stop rule: if `fixtures.rs` approaches 1900 lines, move the manifest structs + loader to `fixtures_manifest.rs` (Task B code) and, if still tight, move each `kind`'s handler into a `mod` within `fixtures.rs` or a sibling file; never let any file cross 2000 (the hygiene gate fails closed).

- [ ] **Step D8: per-facet `run`-shape unit tests.** For at least `transit`, `relay`, `relay-observability`, add a `#[cfg(test)]` test that the schema-only path returns `Ok(())` against the committed fixtures without invoking cargo (call a `run_schema_block(&manifest, facet)` sub-function directly so the test is fast and hermetic), and a test that a deliberately-corrupted in-memory schema map yields `Err(Validation)`.

**Gate (each step):** standard per-task gate PLUS the dual-run for that facet (Task F). Do not proceed to a dependent facet until the current one's dual-run is green.

---

## Task E: keep the sre-metrics shim, confirm no orphaned callers

**Files:** none modified; verification only.

- [ ] **Step E1:** confirm `scripts/check-sre-metrics-registry.sh` is still invoked (by the `relay-observability` and `relay-alert-routing` handlers) and is NOT in the deletion set. Confirm no other script outside the 15 calls a `check-chio-pheromone-*.sh` (so deleting them in Task G breaks nothing):
  ```bash
  grep -rl 'check-chio-pheromone-' scripts .github xtask docs Makefile 2>/dev/null \
    | grep -v '^scripts/check-chio-pheromone-' || echo "no external callers"
  ```
  Expected: only the 15 workflows (`.github/workflows/chio-pheromone-*.yml`) and the scripts' own intra-cluster recursion appear; nothing else. If anything else appears, STOP and add it to the migration scope.

**Gate:** standard per-task gate (no code change; the grep must show only the 15 workflows + intra-cluster recursion).

---

## Task F: dual-run parity harness (the safety gate)

**Files:** create `xtask/tests/pheromone_parity.rs`.

This is the load-bearing proof, because there are no meta-tests for this cluster. For each facet and each mode in `{all, schema-only, negative-only}`, run BOTH the old script and the new leaf in a clean checkout state and assert identical exit code.

- [ ] **Step F1: write the harness.** Gate it behind `CHIO_PHEROMONE_PARITY=1` so it does not fire on a normal `cargo test -p xtask` (the cargo chain is multi-minute):
  ```rust
  // xtask/tests/pheromone_parity.rs
  use std::process::Command;

  const FACETS: [&str; 15] = [ /* the 15 from KNOWN_FACETS */ ];

  fn root() -> std::path::PathBuf {
      std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent()
          .map(|p| p.to_path_buf()).unwrap_or_else(|| panic!("no workspace root"))
  }

  fn script_exit(root: &std::path::Path, facet: &str, mode: &[&str]) -> i32 {
      Command::new("bash")
          .arg(format!("scripts/check-chio-pheromone-{facet}.sh")).args(mode)
          .current_dir(root).status()
          .map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
  }
  fn xtask_exit(root: &std::path::Path, facet: &str, mode: &[&str]) -> i32 {
      let mut args = vec!["run", "-q", "-p", "xtask", "--", "check", "fixtures", facet];
      args.extend_from_slice(mode);
      Command::new("cargo").args(&args).current_dir(root).status()
          .map(|s| s.code().unwrap_or(-1)).unwrap_or(-1)
  }

  #[test]
  fn pheromone_dual_run_parity() {
      if std::env::var("CHIO_PHEROMONE_PARITY").ok().as_deref() != Some("1") {
          eprintln!("skipped: set CHIO_PHEROMONE_PARITY=1 to run the multi-minute parity gate");
          return;
      }
      let root = root();
      let modes: [&[&str]; 3] = [&[], &["--schema-only"], &["--negative-only"]];
      let mut mismatches = Vec::new();
      for facet in FACETS {
          for mode in modes {
              let old = script_exit(&root, facet, mode);
              let new = xtask_exit(&root, facet, mode);
              if old != new {
                  mismatches.push(format!("{facet} {mode:?}: script={old} xtask={new}"));
              }
          }
      }
      assert!(mismatches.is_empty(), "parity mismatches:\n{}", mismatches.join("\n"));
  }
  ```
  Note: this test mutates the working tree for `transit`/`relay` (temp dirs only, cleaned up) and may run `npm` for 5 facets; run it on a clean checkout. The `unwrap_or(-1)`/`unwrap_or_else(panic!)` here is test code (allowed under the lint config's test carve-out, matching `xtask/src/tests.rs`).

- [ ] **Step F2: run the full parity sweep and record the result.**
  ```bash
  CHIO_PHEROMONE_PARITY=1 cargo test -p xtask --test pheromone_parity -- --nocapture
  ```
  Expected: `test result: ok. 1 passed`. If any facet mismatches, the assertion prints `facet mode: script=X xtask=Y`; fix the handler until all 45 (15 facets x 3 modes) pairs match. Do NOT proceed to Task G until this is green for all 15.

**Gate:** the standard per-task gate PLUS a green full parity sweep.

---

## Task G: flip workflows, delete scripts (only after Task F is fully green)

**Files:** modify the 15 `.github/workflows/chio-pheromone-*.yml`; delete the 15 `scripts/check-chio-pheromone-*.sh`.

- [ ] **Step G1: swap each workflow `run:` line** from `run: bash scripts/check-chio-pheromone-<facet>.sh` to `run: cargo xtask check fixtures <facet>`. Keep each file's existing `setup-node` + `npm ci` steps where present (the 5 dashboard facets); do NOT add node to the 10 that lack it; do NOT collapse the 15 files into a matrix (deferred to Phase 4, which needs the branch-protection `ci-required` change). Also update each workflow's `paths:` filter: replace the `scripts/check-chio-pheromone-<facet>.sh` entry with `ci-gates/pheromone.toml` and `xtask/**`, and keep `scripts/check-sre-metrics-registry.sh` in the two workflows whose handler still calls it (`relay-observability`, `relay-alert-routing`). Preserve every other path entry verbatim (silent path-filter drift is the go-dark failure mode).

- [ ] **Step G2: delete the 15 scripts** in the same PR:
  ```bash
  git rm scripts/check-chio-pheromone-directory-lifecycle.sh \
    scripts/check-chio-pheromone-relay-alert-assurance-archive-hardening.sh \
    scripts/check-chio-pheromone-relay-alert-assurance-archive-package.sh \
    scripts/check-chio-pheromone-relay-alert-assurance-archive.sh \
    scripts/check-chio-pheromone-relay-alert-assurance-export.sh \
    scripts/check-chio-pheromone-relay-alert-assurance-external-retention.sh \
    scripts/check-chio-pheromone-relay-alert-assurance.sh \
    scripts/check-chio-pheromone-relay-alert-delivery.sh \
    scripts/check-chio-pheromone-relay-alert-handoff.sh \
    scripts/check-chio-pheromone-relay-alert-routing.sh \
    scripts/check-chio-pheromone-relay-observability.sh \
    scripts/check-chio-pheromone-relay-ops.sh \
    scripts/check-chio-pheromone-relay.sh \
    scripts/check-chio-pheromone-runtime.sh \
    scripts/check-chio-pheromone-transit.sh
  ```
  Because the scripts are gone, the Task F parity harness can no longer dual-run. Convert it to a guard: keep `xtask/tests/pheromone_parity.rs` but change the script branch to assert each script path is absent (so a future re-add is caught), OR delete the parity test and rely on the per-facet schema-only unit tests from Step D8. Recommended: keep a trimmed `pheromone_scripts_are_retired` test asserting `!root.join("scripts/check-chio-pheromone-transit.sh").exists()` etc., so the deletion stays enforced.

- [ ] **Step G3: confirm no dangling references.**
  ```bash
  grep -rl 'check-chio-pheromone-.*\.sh' . --include='*.yml' --include='*.sh' --include='*.md' \
    | grep -v docs/superpowers/plans || echo "no dangling script references"
  grep -rn 'bash scripts/check-chio-pheromone' .github/ || echo "no bash callers remain"
  ```
  Expected: both print the "no ..." sentinel (this plan file under `docs/superpowers/plans` is the only allowed mention).

**Gate:** the standard per-task gate. `cargo xtask check crate-paths` must still pass (the workflow `paths:` edits did not strand any `crates/chio-*` literal). Since the scripts no longer exist, the parity sweep is replaced by the retirement guard from G2.

---

## Self-Review

Before declaring this plan's work complete, verify every item:

- [ ] All 15 facets are in `ci-gates/pheromone.toml`; `manifest_enumerates_all_known_facets` is green (fail-closed enumeration).
- [ ] `cargo xtask check fixtures <facet>` exists as a real clap leaf for all 15 names; an unknown facet returns a non-zero `XtaskError::Usage`, never a silent skip.
- [ ] `--schema-only` and `--negative-only` behave exactly as the scripts did (early-exit points match), and the two flags conflict at parse time.
- [ ] The recursion graph is reproduced: `relay` (full) drives `runtime` -> `transit`; the schema-only fan-out edges all fire. No facet's coverage is dropped.
- [ ] The imperative per-facet steps are ported, not skipped: `transit` retired-marker guard + fixture-regen `cmp`; `relay` runbook guard + env-branch `--skip` list + CLI orchestration + negative assertions; `relay-observability` npm test/build + sre-metrics; the archive sub-chain.
- [ ] Dual-run parity (Task F) was green for all 15 facets x 3 modes BEFORE any workflow flip or script deletion. Evidence pasted into the PR.
- [ ] Each of the 15 workflows calls `cargo xtask check fixtures <facet>`; node setup preserved exactly (5 keep it, 10 stay node-free); `paths:` filters updated to `ci-gates/pheromone.toml` + `xtask/**`, with `scripts/check-sre-metrics-registry.sh` kept in the 2 workflows that need it; no file collapsed to a matrix.
- [ ] The 15 scripts are deleted; `scripts/check-sre-metrics-registry.sh` is kept; no dangling references (Step G3 sentinels).
- [ ] No `*.test.sh` meta-tests were deleted for this cluster (there were none); the parity test was converted to a retirement guard or the Step D8 unit tests stand in.
- [ ] House rules: no em dashes anywhere added; no `unwrap`/`expect` in non-test Rust; `fixtures.rs` (and any split file) and `main.rs` each under 2000 lines (`check-rust-file-hygiene.py` green); `check-stub-surfaces.py` green; `cargo xtask check crate-paths` green; `cargo build/test/clippy/fmt -p xtask` green.

---

## Phase 3 remaining slices (future sibling plans, NOT detailed here)

Phase 3 of the spec consolidates the whole `scripts/` gate pile into xtask in waves. This plan is wave 3a (the pheromone cluster, the worst offender). The remaining waves each get their own plan, written when scheduled, following this same TDD + dual-run-parity recipe:

- **3b - runtime cluster (6 -> 1).** Fold the 6 `check-chio-runtime-*` fixture gates into the same `check fixtures` leaf (extend the manifest with a `[runtime]`-family table, or a sibling `ci-gates/runtime.toml`). Same dual-run parity; same per-facet imperative-step porting. Smaller blast radius than pheromone (no deep recursion graph observed; verify before planning).
- **3c - pure-logic `check-*` ports.** Port the pure-logic bash/heredoc-python gates (egress, redaction, workspace-layering, transitive-surface, mutants-rationale, etc.) into `check <kind>` leaves. These DO have `scripts/tests/*.test.sh` meta-tests (e.g. `check-rust-file-hygiene.test.sh`, `check-stub-surfaces.test.sh`, `check-http-egress-contract.test.sh`); port each meta-test's assertions into Rust `#[cfg(test)]` as the target gate migrates, then delete the `.test.sh`.
- **3d - qualify family (17).** Fold `qualify-web3-*` (6), `qualify-comptroller-*` (4), and the bounded/mobile/browser/trust/universal-control-plane/release qualifiers into the `qualify` noun group (currently a reserved `Pending` leaf in `cli.rs`). Decide per-owner what to do with the 6 doc-grep-only `qualify-*` scripts (convert to real assertions or retire the doc claim).
- **3e - SDK-release shims.** The `check-sdk-release.sh` driver + its 7 thin `exec` shims already model the consolidation; either keep the shims for one cycle and route the driver through `cargo xtask sdk-release <lang>`, or fold the driver into xtask directly. Lowest risk of the four.

Cross-cutting Phase 3 rule (from the spec and project memory): flip each CI caller to `cargo xtask ...` only after a green dual-run, delete the migrated script + its meta-test in the same PR, keep external-tool wrappers thin, and never collapse workflow FILES to a matrix in Phase 3 (that touches required-check names and is Phase 4, gated by the owner branch-protection `ci-required` change).
