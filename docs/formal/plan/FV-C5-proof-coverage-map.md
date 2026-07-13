# FV-C5: Generated proof-coverage map - one page answering "what exactly is verified"

- Status: Implemented (2026-07-09)
- Theme: C - Turn verification into product surface
- Effort: S
- Depends on: none (all input registries exist today)
- Feeds: roadmap prioritization (single-lane surfaces stand out), the external evidence page behind FORM-* claims; consumes the [FV-B4](FV-B4-loom-registry-and-dst.md) Loom and DST registries plus advisory postures, with promotion governed by [FV-E5](FV-E5-lane-ratchets.md)
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md), [../CURRENT_STATE.md](../CURRENT_STATE.md), [FV-E3](FV-E3-pr-formal-smoke-tier.md), [FV-C1](FV-C1-receipt-trace-validation.md)

## Summary

`cargo xtask gen proof-coverage` joins the declared evidence registries into
`docs/formal/COVERAGE.md` and `target/formal/coverage.json`. The committed page
contains 41 primary Rust-surface rows, 111 attributed artifacts, 122 explicitly
unattributed artifacts, 44 content-addressed inputs, and zero mapping parse
warnings on the current tree. Required PR CI regenerates the page in memory and
fails on byte drift.

The matrix reports artifact identity and primary ownership, not verification
completeness. Every Kani harness and fuzz target has exactly one primary row.
Every mutation config is classified once as current, recorded-local,
historical, or inactive, and the live workspace mutation scope has one artifact
per package. The theorem inventory and differential-test files do not currently
carry machine-readable Rust-surface links, so the generator lists them as
unattributed rather than inferring coverage from names.

## Decisions

- Use a conservative primary-owner join. Exact single Rust files produce file
  rows. Multiple files in one package collapse to its crate row; cross-package
  or unresolved evidence stays unattributed with related surfaces retained.
  Crate and file rows may coexist.
- Identify artifacts by registry path plus native key. This prevents aliases
  such as the legacy Kani core registry from being double-counted.
- Treat the legacy Kani public manifest as a cross-check of the flat manifest,
  not a second harness source. Its core harness set must match exactly, and its
  global `covered_symbols` remain validation metadata rather than proof counts.
- Keep theorem inventory and differential-test artifacts unattributed until a
  registry supplies a Rust surface. Property-level all-to-all inference would
  overstate implementation linkage. Lean rows that do exist come from explicit
  MAPPING table entries.
- Preserve evidence qualifiers. Kani artifacts expose PR/nightly execution lane
  and explicit model-only scope; theorem entries expose kind, claim class, and
  assumed, proved, or unknown status in JSON and Markdown.
- Validate every MAPPING source file and named property. Missing Rust files do
  not license evidence cells, and malformed property-table headers create
  deterministic warnings instead of silently dropping a table.
- Expand mutation globs against the non-ignored workspace Rust path
  projection, subtract exclusions, cross-check per-crate configs against the
  live root config or a structured completed local run, and keep aggregate or
  historical evidence unattributed.
- Render compact counts in the matrix and full artifact IDs in detail blocks.
  This preserves reviewable source rows under 120 columns without replacing
  evidence identity with checkmarks.
- Enumerate assumptions and excluded surfaces in dedicated sections and JSON
  fields, not pseudo-rows. Scope boundaries should not look like code surfaces.
- Use the combined input digest in the committed page. A committed file cannot
  contain the hash of the commit that contains it. The actual invocation commit
  is written to `target/formal/coverage.json`, and the Proof Room packager
  resolves the page's single `@GIT_COMMIT@` token to the package commit.
- Emit one public rendering. The same detailed page serves repository review
  and Proof Room distribution; a shorter second source would create drift.
- Exclude last-green timestamps from deterministic coverage. Runtime freshness
  remains in `target/formal/proof-report.json`.
- Consume the active `.loom/harnesses.toml` and `.dst/harnesses.toml`
  registries plus their advisory postures in `releases.toml`. Registry
  presence does not license claims absent from `MAPPING.md`.
- Preserve Loom's required `scope = "bounded_abstract_model"` qualifier in
  both renderings. A Loom artifact cannot be displayed as production-primitive
  proof.
- Preserve A4 manual mirrors and Creusot contract twins as non-proof linkage
  metadata. These records support review and drift navigation but never add an
  evidence cell or license a claim.

## Motivation and evidence

- The inputs exist and are already load-bearing [v], verified present this session:
  - formal/proof-manifest.toml: `covered_rust_modules`, `covered_rust_symbols`, `property_matrix` P1-P10, `gate_commands`, `rust_refinement_lanes`.
  - formal/theorem-inventory.json: theorem entries with fields `id, leanName, file, kind, rootImported, claimClass, mapsTo, notes`, plus a separate `assumptions` block.
  - formal/MAPPING.md: grep-enforced property-to-Rust rows (scripts/check-mapping.sh).
  - formal/assumptions.toml: audited and retired assumptions.
  - .kani/harnesses.toml (schema `chio.kani.multi-crate.v1`, per-harness crate/lane/unwind) and formal/rust-verification/{kani-harnesses,kani-public-harnesses,creusot-contracts}.toml; formal/aeneas/{pilot,production}.toml named by `rust_refinement_lanes`.
  - fuzz/target-map.toml (27 targets with `crate`, `triggers`, `seeds`) and fuzz/owners.toml.
  - .cargo/mutants.toml plus audits/mutation/per-crate-configs/*.toml (`examine_globs`, e.g. chio-kernel-core.toml:27) and docs/fuzzing/trust-boundary-mutants-baseline.toml (2026-04-29 baseline, kill rate 30.7% [v]).
- Nobody could previously see the joins. For example, the generated
  `chio-kernel-core::receipts.rs` row carries one Creusot artifact and five Kani
  artifacts but no Lean or TLA cell. The matrix makes that lane mismatch visible
  without inferring links from names.
- External evidence: FORM-BOUNDARY and FORM-IMPLEMENTATION-LINKED (docs/reference/CLAIM_REGISTRY.md) point at the manifest and inventory; a joined, human-readable page is the natural public artifact behind those claims, and the Proof Room bundle (`cargo xtask verify launch-acceptance`, xtask/src/cli.rs:214-219) is its distribution channel.
- G4 (duplication drift): six registries that never get joined can drift apart
  silently; the join turns unknown crates and dangling property IDs into hard
  failures while retaining soundly unjoined artifacts as explicit unattributed
  entries.

## Current state

- `docs/formal/COVERAGE.md` is the committed deterministic matrix;
  `target/formal/coverage.json` is its machine-readable companion with the
  current invocation commit. `target/formal/proof-report.json` now hashes both
  artifacts while retaining gate results and tool versions.
- xtask has the right skeleton: a noun-verb clap tree with a `gen` group whose leaves all support `--check` drift gating (xtask/src/cli.rs:127-151, aliases at L84-96), and a `check` group (L153-170). The plan follows that shape; the earlier working name `cargo xtask generate proof-coverage` is spelled `cargo xtask gen proof-coverage` to match the existing `gen` noun.
- Precedent for the no-diff CI check: freeze-vectors `--check`, codegen `--check`, eval-receipt-regen `--check` all exit nonzero on byte drift.

## Design

### Generator

`xtask/src/proof_coverage.rs`, wired as `GenCommand::ProofCoverage { check: bool }`.

Pipeline:

1. Load registries (TOML via the existing xtask deps, JSON via serde; MAPPING.md via a tolerant table parser, below).
2. Build the row set: the union of (a) proof-manifest `covered_rust_modules`, (b) crates named by `.kani/harnesses.toml` entries, (c) crates named by fuzz/target-map.toml, (d) crates with mutation per-crate configs, (e) surfaces named in MAPPING.md "Rust path constrained" cells. Rows are normalized to `crate :: module-file` granularity (kernel-core modules individually, other crates at crate granularity unless a registry names a file).
3. Build the column set (evidence lanes): Lean, Aeneas, Creusot, Kani, Apalache/TLA, diff-tests, fuzz, mutants - plus loom/DST columns emitted only when the FV-B4/FV-E5 registries exist (feature-detect by file presence, so this doc needs no update when they land).
4. Fill primary cells with canonical artifact IDs, sorted. The matrix renders
   counts; per-row detail blocks retain full IDs. Evidence with no sound Rust
   join is retained in `unattributed_artifacts` rather than discarded.
5. Emit `docs/formal/COVERAGE.md` (matrix, details, assumptions, exclusions,
   input SHA-256 list, combined digest, generator version, and commit token) and
   `target/formal/coverage.json` (same declarations plus the actual invocation
   commit, schema `chio.proof-coverage.v1`).

Abridged `coverage.json` shape:

```json
{
  "schema": "chio.proof-coverage.v1",
  "commit": "<git sha>",
  "inputs": [
    { "path": "formal/proof-manifest.toml", "sha256": "..." },
    { "path": "formal/theorem-inventory.json", "sha256": "..." }
  ],
  "rows": [
    {
      "surface": "chio-kernel-core::receipts.rs",
      "lanes": {
        "lean": [],
        "creusot": ["formal/rust-verification/creusot-contracts.toml::chio_kernel_core::receipts::sign_receipt"],
        "kani": [".kani/harnesses.toml::chio-kernel-core/verify_receipt_roundtrip"],
        "diff": []
      }
    }
  ],
  "unattributed_artifacts": [
    {
      "id": "formal/diff-tests/tests/receipt_encoding_diff.rs",
      "lane": "diff",
      "reason": "differential-test files have no machine-readable Rust surface registry",
      "related_properties": []
    }
  ],
  "review_links": [
    {
      "kind": "manual_mirror",
      "relationship": "transliteration",
      "source": "crates/core/chio-core-types/src/capability/scope.rs",
      "target": "formal/lean4/Chio/Chio/Core/Capability.lean"
    }
  ],
  "excluded_surfaces": ["..."],
  "parse_warnings": []
}
```

### Determinism

Committed Markdown content is a pure function of checked-in registry bytes, a
normalized Cargo workspace projection, and the generator version. It contains
no timestamps or run results. The JSON companion additionally records the
current Git commit. All collections sort by stable keys. Two consecutive runs
are byte-identical; `--check` regenerates the Markdown in memory, writes the JSON
companion, and compares the committed page byte-for-byte.

### Parsing details

- MAPPING.md: parse markdown tables tolerantly - split rows on `|`, trim cells, skip separator rows and prose between tables, and record any malformed row as a deterministic `parse_warnings` entry in coverage.json instead of failing (the file is grep-enforced by scripts/check-mapping.sh, not schema-enforced, so tolerance is required; warnings keep tolerance honest).
- Fuzz attribution: `crate` is authoritative. Exactly one literal owner-local
  Rust trigger refines a target to a file; zero or multiple literal files keep
  the target at crate granularity, with files recorded as related surfaces.
- Mutants attribution: the live root config owns one crate row per active
  package. Canonical per-crate configs are labeled exact, subset, or
  recorded-local after workspace-file glob expansion and exclusions. Historical
  configs and the aggregate baseline remain explicit and unattributed.
- Kani attribution: exact MAPPING property matches may refine a harness to one
  primary file. Otherwise the harness stays at its declared crate, with a
  narrow kernel-core filename fallback for the two currently unmapped receipt
  harnesses. Registry-global `covered_symbols` validate registry linkage but are
  not counted as separate proof artifacts.
- Theorem and diff attribution: both remain explicit and unattributed because
  neither registry contains a Rust-surface key. The generator validates theorem
  property IDs, preserves theorem status and class, and does not treat a shared
  P1-P10 ID as a module join.
- Manual mirrors and Creusot contract twins: validate their declared pairings
  and preserve them under `review_links`, separate from attributed and
  unattributed proof artifacts.
- Concurrency registries: Loom validates crate, test, preemption, lane, abstract
  scope, notes, integration target, and named test declaration. DST identities
  join to exact MAPPING rows and carry `scope=single_process_single_store`;
  `scripts/run-dst.sh` separately validates the 64-seed corpus,
  10,000-episode count, source declarations, and compiled discovery. Coverage
  does not infer oracle strength beyond those mappings.

### Consistency checks (free with the join)

The generator fails (exit nonzero, even without `--check`) on: a
`covered_rust_module` that no lane artifact references; a theorem-inventory
`mapsTo` property id not present in the manifest `property_matrix`; a Kani
harness whose crate is not in the workspace; a fuzz target without a source
file or exact owner key; and malformed present optional registries.

## Implementation plan

1. Implemented the registry loaders, consistency checks, canonical joins, Markdown
   renderer, JSON renderer, CLI command, and deterministic drift check in `xtask`.
2. Added the generated `docs/formal/COVERAGE.md` and
   `target/formal/coverage.json` outputs without adding a dependency.
3. Added the required PR gate and proof-report generation, on-disk hash
   validation, and nightly artifact upload wiring.
4. Added the generated page to the Proof Room bundle and acceptance manifest.
5. Added optional loaders for loom, deterministic-simulation, and gate-ratchet
   registries. Missing optional registries leave their lanes absent, while
   malformed present registries fail closed.

## CI and gating changes

- New required PR check: `cargo xtask gen proof-coverage --check` (fails on
  regeneration diff and on any consistency-check violation). Runtime is local
  registry parsing plus a normalized `cargo metadata` projection, so it remains
  suitable for the required job and serves gap G1 with a cheap PR-time gate.
- Nightly: coverage.json archived with the proof report.
- No changes to existing formal lanes; the generator consumes their registries read-only.

## Acceptance criteria

- [x] `cargo xtask gen proof-coverage` produces `docs/formal/COVERAGE.md` and
  `target/formal/coverage.json`; two consecutive runs are byte-identical.
- [x] `--check` exits nonzero on any hand edit to `COVERAGE.md` and on
  registry/output drift.
- [x] Every proof-manifest `covered_rust_modules` entry, Kani harness, fuzz
  target, and live mutation package has exactly one primary row. Every per-crate
  mutation config has exactly one primary or unattributed classification.
- [x] `MAPPING.md` parsing records zero warnings on the current file; a malformed
  fixture row produces a deterministic warning instead of a crash.
- [x] Consistency checks reject a seeded registry naming a nonexistent crate.
- [x] Fuzz owner keys match target-map keys exactly; Loom and gate-posture
  registries reject missing, unknown, or unsupported fields and values.
- [x] The active DST registry contributes five mapped artifacts with the
  `single_process_single_store` qualifier and an advisory nightly posture.
- [x] Manual mirrors and Creusot contract twins are rendered as non-proof
  linkage metadata and never counted as evidence artifacts.
- [x] The matrix renders under 120 columns per Markdown source row.
- [x] `COVERAGE.md` carries the generated-file warning, input hashes, combined
  input digest, commit placeholder, and regeneration command. Runtime JSON and
  Proof Room outputs carry the actual checked commit.
- [x] The Proof Room bundle includes the generated page.

## Risks and mitigations

- The page overstates: readers may misread "cell has an id" as "surface fully verified". Mitigation: cells carry artifact ids, not checkmarks; the page header links CLAIM_REGISTRY.md and repeats its constraint that per-lane evidence classes, not this matrix, license claims (LEAN-4-VERIFIED and P4-END-TO-END remain disallowed [v]).
- MAPPING.md format drift breaks the parser. Mitigation: tolerant parsing with deterministic warnings; scripts/check-mapping.sh already constrains the file's content; a golden test pins the parse of the current file.
- Row-granularity churn (module vs crate) makes diffs noisy. Mitigation: granularity rules are fixed in the generator and documented in the page footer; changing them is a reviewed generator change, and the drift gate makes every output change visible in the same PR as its cause.
- theorem-inventory count drift: the generator never hardcodes inventory counts; it reports what it parses, and the consistency checks make dangling references loud.
- Two sources of truth (COVERAGE.md vs CURRENT_STATE.md prose). Mitigation: CURRENT_STATE.md gets a pointer to the generated page for per-surface questions; prose keeps narrative, the matrix keeps facts.

## Resolved questions

- Assumptions and excluded surfaces are first-class companion sections and JSON
  fields, not pseudo-rows that could look like verification evidence.
- A registry-provided file path creates a file-level row. Crate-only evidence
  remains on a crate-level row; multi-file same-package evidence collapses to
  that crate, while cross-package evidence remains unattributed.
- The committed page is also the Proof Room page. Bundle assembly resolves its
  commit placeholder, avoiding a second rendering with divergent content.
- Lane timestamps are omitted. Freshness belongs to the proof report, while the
  committed coverage page remains byte-deterministic.
- The committed page cannot include its own final Git commit hash without a
  cryptographic fixed point. It includes the combined input digest and an
  explicit commit placeholder; JSON and bundle outputs include the actual HEAD.

## Manifest and registry updates

- `formal/proof-manifest.toml`: includes
  `cargo xtask gen proof-coverage --check` in `gate_commands` and names
  `COVERAGE.md` as the generated registry join in `notes`.
- formal/MAPPING.md: the header notes that the coverage generator consumes its
  tables so format changes account for the parser.
- `formal/theorem-inventory.json` and `formal/assumptions.toml`: unchanged
  read-only inputs.
- `.kani/harnesses.toml`, `fuzz/target-map.toml`, `fuzz/owners.toml`,
  `.cargo/mutants.toml`, `audits/mutation/per-crate-configs/`, and
  `docs/fuzzing/trust-boundary-mutants-baseline.toml`: unchanged read-only inputs.
- `scripts/generate-proof-report.sh` and `scripts/check-proof-report.sh`: archive
  and validate the generated JSON with the proof report.
- Proof Room launch acceptance: copies the page, resolves the commit placeholder,
  and records it in the acceptance manifest.
- `docs/reference/CLAIM_REGISTRY.md`: names `COVERAGE.md` as derived public
  navigation; the matrix is not an evidence class and licenses no claim wording.
