# FV-C5: Generated proof-coverage map - one page answering "what exactly is verified"

- Status: Proposed (2026-07-09)
- Theme: C - Turn verification into product surface
- Effort: S
- Depends on: none (all input registries exist today)
- Feeds: roadmap prioritization (single-lane surfaces stand out), the external evidence page behind FORM-* claims; strengthened when [FV-B4](FV-B4-loom-registry-and-dst.md) and [FV-E5](FV-E5-lane-ratchets.md) add their registries
- Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md), [../CURRENT_STATE.md](../CURRENT_STATE.md), [FV-E3](FV-E3-pr-formal-smoke-tier.md), [FV-C1](FV-C1-receipt-trace-validation.md)

## Summary

Chio already has an unusually complete set of machine-readable verification registries - proof manifest, theorem inventory, mapping table, Kani manifests, fuzz target map, mutation configs - but no single artifact joins them. Answering "what exactly is verified, by which lane, for this file?" today means reading six files with different schemas. This plan adds a small generator (`cargo xtask gen proof-coverage`, module `xtask/src/proof_coverage.rs`) that joins the existing registries into a generated matrix, `docs/formal/COVERAGE.md` (TCB surfaces as rows, evidence lanes as columns, artifact ids in cells) plus `target/formal/coverage.json` for tooling. Generation is deterministic from checked-in registries plus the git commit sha, and a required PR check asserts regeneration produces no diff, following the repo's existing generated-artifact drift-check pattern.

## Motivation and evidence

- The inputs exist and are already load-bearing [v], verified present this session:
  - formal/proof-manifest.toml: `covered_rust_modules`, `covered_rust_symbols`, `property_matrix` P1-P10, `gate_commands`, `rust_refinement_lanes`.
  - formal/theorem-inventory.json: 83 theorem entries (fields `id, leanName, file, kind, rootImported, claimClass, mapsTo, notes`) plus a separate `assumptions` block.
  - formal/MAPPING.md: grep-enforced property-to-Rust rows (scripts/check-mapping.sh).
  - formal/assumptions.toml: audited and retired assumptions.
  - .kani/harnesses.toml (schema `chio.kani.multi-crate.v1`, per-harness crate/lane/unwind) and formal/rust-verification/{kani-harnesses,kani-public-harnesses,creusot-contracts}.toml; formal/aeneas/{pilot,production}.toml named by `rust_refinement_lanes`.
  - fuzz/target-map.toml (25 targets with `crate`, `triggers`, `seeds`) and fuzz/owners.toml.
  - .cargo/mutants.toml plus audits/mutation/per-crate-configs/*.toml (`examine_globs`, e.g. chio-kernel-core.toml:27) and docs/fuzzing/trust-boundary-mutants-baseline.toml (2026-04-29 baseline, kill rate 30.7% [v]).
- Nobody can currently see the joins. Example of the payoff: chio-core-types/src/merkle.rs is fuzzed and diff-tested but has no Lean, Kani, or Creusot lane today - exactly the gap [FV-C2](FV-C2-verified-inclusion-verifier.md) fills; the matrix makes such single-lane and lane-mismatch surfaces jump out mechanically instead of anecdotally.
- External evidence: FORM-BOUNDARY and FORM-IMPLEMENTATION-LINKED (docs/reference/CLAIM_REGISTRY.md) point at the manifest and inventory; a joined, human-readable page is the natural public artifact behind those claims, and the Proof Room bundle (`cargo xtask verify launch-acceptance`, xtask/src/cli.rs:214-219) is its distribution channel.
- G4 (duplication drift): six registries that never get joined can drift apart silently; the join itself is a consistency check (unknown crate names, dangling theorem ids, and orphan harnesses become generator warnings).

## Current state

- No COVERAGE.md, no coverage.json. The closest artifacts are target/formal/proof-report.json (gate results, tool versions, artifact hashes, produced by scripts/generate-proof-report.sh nightly and at release qualification [v]) and the prose in docs/formal/CURRENT_STATE.md - the former is about runs, the latter about narrative; neither is a per-surface matrix.
- xtask has the right skeleton: a noun-verb clap tree with a `gen` group whose leaves all support `--check` drift gating (xtask/src/cli.rs:127-151, aliases at L84-96), and a `check` group (L153-170). The plan follows that shape; the earlier working name `cargo xtask generate proof-coverage` is spelled `cargo xtask gen proof-coverage` to match the existing `gen` noun.
- Precedent for the no-diff CI check: freeze-vectors `--check`, codegen `--check`, eval-receipt-regen `--check` all exit nonzero on byte drift.

## Design

### Generator

`xtask/src/proof_coverage.rs`, wired as `GenCommand::ProofCoverage { check: bool }`.

Pipeline:

1. Load registries (TOML via the existing xtask deps, JSON via serde; MAPPING.md via a tolerant table parser, below).
2. Build the row set: the union of (a) proof-manifest `covered_rust_modules`, (b) crates named by `.kani/harnesses.toml` entries, (c) crates named by fuzz/target-map.toml, (d) crates with mutation per-crate configs, (e) surfaces named in MAPPING.md "Rust path constrained" cells. Rows are normalized to `crate :: module-file` granularity (kernel-core modules individually, other crates at crate granularity unless a registry names a file).
3. Build the column set (evidence lanes): Lean, Aeneas, Creusot, Kani, Apalache/TLA, diff-tests, fuzz, mutants - plus loom/DST columns emitted only when the FV-B4/FV-E5 registries exist (feature-detect by file presence, so this doc needs no update when they land).
4. Fill cells with artifact ids, sorted: theorem ids from the inventory (joined through `mapsTo` and MAPPING.md rows), harness names, fuzz target names, TLA invariant names, diff-test file names, mutation config + baseline reference. An empty cell renders as `-` deliberately: absence is the signal.
5. Emit `docs/formal/COVERAGE.md` (matrix plus a per-row detail section and a generation footer: input file list with sha256s, git commit sha, generator version) and `target/formal/coverage.json` (same content, schema `chio.proof-coverage.v1`).

coverage.json shape:

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
        "lean":    ["proof.receipt_sign_then_verify", "proof.receipt_immutability"],
        "kani":    ["sign_receipt public harness"],
        "diff":    ["receipt_encoding_diff"],
        "fuzz":    ["receipt_log_replay"],
        "mutants": ["audits/mutation/per-crate-configs/chio-kernel-core.toml"]
      }
    }
  ],
  "excluded_surfaces": ["..."],
  "parse_warnings": []
}
```

### Determinism

Content is a pure function of checked-in registry bytes plus the git commit sha; no timestamps, no tool-run results (proof-report.json is a run artifact and is deliberately NOT an input - the page states what evidence is declared and gated, and links to the proof report for the latest run results). All collections sort by stable keys. Two consecutive runs must be byte-identical; the `--check` mode regenerates to memory and diffs against the committed file.

### Parsing details

- MAPPING.md: parse markdown tables tolerantly - split rows on `|`, trim cells, skip separator rows and prose between tables, and record any malformed row as a deterministic `parse_warnings` entry in coverage.json instead of failing (the file is grep-enforced by scripts/check-mapping.sh, not schema-enforced, so tolerance is required; warnings keep tolerance honest).
- Fuzz attribution: fuzz/target-map.toml's `crate` field attributes each target to its owning crate; `triggers` globs additionally attribute targets to module rows when a glob names a specific file (e.g. the canonical_json target's trigger on crates/core/chio-core-types/src/canonical.rs).
- Mutants attribution: `examine_globs` from audits/mutation/per-crate-configs/*.toml map to rows the same way; the workspace .cargo/mutants.toml include-note about `include!`-based modules (chio-policy evaluate.rs, chio-credentials lib.rs) is honored by attributing to the umbrella file exactly as the config comments prescribe.
- Kani attribution: `[[harness]]` crate field, refined by `covered_rust_symbols` when a symbol pins a module.

### Matrix mock (shape reviewers should expect)

Illustrative, not generated; artifact ids abbreviated:

| Surface | Lean | Aeneas | Creusot | Kani | Apalache | Diff | Fuzz | Mutants |
|---|---|---|---|---|---|---|---|---|
| kernel-core capability_verify.rs | P1/P3 thms | prod | contracts | public_verify_capability | - | scope_diff | capability_receipt | examine |
| kernel-core scope.rs | P1 thms | prod | contracts | subset harnesses | - | scope_diff | capability_receipt | examine |
| kernel-core evaluate.rs | P3 thms | prod | contracts | evaluate harness | ReceiptBeforeAllow | - | receipt_log_replay | examine |
| kernel-core normalized.rs | P1 thms | - | contracts | is_subset_of harnesses | AttenuationPreserving | scope_diff | - | examine |
| kernel-core receipts.rs | P4 thms | - | - | sign_receipt harness | - | receipt_encoding_diff | receipt_log_replay | examine |
| kernel-core formal_core.rs | P3/P8 thms | prod | - | dpop/guard harnesses | KernelTransitionCancelSafe | - | - | examine |
| kernel-core formal_aeneas.rs | equiv thms | prod | - | equivalence harnesses | - | - | - | examine |
| core-types canonical.rs | (FV-C3) | - | - | - | - | canonical_json_diff | canonical_json | - |
| core-types merkle.rs | (FV-C2) | - | - | (FV-C2) | - | anchored_root | - | - |
| core-types capability delegate | delegation thms | - | - | verify_delegation_chain_step | - | - | capability_receipt | - |
| chio-kernel checkpoint.rs | bounded model | - | - | - | MonotoneLog | anchored_root | - | - |
| chio-kernel receipt_store/budget_store | - | - | - | - | MonotoneLog, ReceiptBeforeAllow | - | - | - |
| chio-policy evaluate | - | - | - | - | - | - | fuzz_policy_parse_compile | examine (umbrella) |
| chio-anchor batch/bundle | - | - | - | anchor harnesses | - | - | - | examine |
| revocation-oracle InclusionProof | P2 thms | - | - | oracle harnesses | RevocationCutCompleteness | - | - | - |

Reading it teaches the roadmap: rows whose only entries are fuzz or diff (canonical.rs, merkle.rs, policy evaluate) are exactly where FV-C2/C3/C4 aim; the mostly-empty receipt_store row is the FV-B1/B4 territory.

### Consistency checks (free with the join)

The generator fails (exit nonzero, even without `--check`) on: a `covered_rust_module` that no lane's artifact references; a theorem-inventory `mapsTo` property id not present in the manifest `property_matrix`; a Kani harness whose crate is not in the workspace; a fuzz target in target-map.toml without a corresponding fuzz_targets file. These are drift bugs today with no detector.

## Implementation plan

1. Phase 1 - generator and outputs.
   - Add `xtask/src/proof_coverage.rs` (registry loaders, join, renderers).
   - Modify `xtask/src/cli.rs` (add `GenCommand::ProofCoverage { check }`) and `xtask/src/main.rs` (dispatch).
   - Add generated `docs/formal/COVERAGE.md` (first committed generation) - note this is a new generated file, not a hand-edited doc; a header comment marks it generated with the regen command.
   - No new crates or dependencies (xtask already parses TOML/JSON).
2. Phase 2 - CI drift gate.
   - Modify the required PR workflow to run `cargo xtask gen proof-coverage --check` alongside the existing freeze-vectors/codegen drift checks.
   - Modify scripts/generate-proof-report.sh to copy `target/formal/coverage.json` into the proof-report artifact set so nightly runs archive the matrix at the checked commit.
3. Phase 3 - surfacing.
   - Modify the Proof Room bundle assembly (`cargo xtask verify launch-acceptance` path) to include COVERAGE.md, making it the public "what exactly is verified" page.
   - Add forward-compatible loaders for the FV-B4 loom registry and FV-E5 ratchet files (feature-detected by path; columns appear when files do).

## CI and gating changes

- New required PR check: `cargo xtask gen proof-coverage --check` (fails on regeneration diff and on any consistency-check violation). Runtime is file parsing only - well under a second - so it belongs in the required job, which also serves gap G1's direction of travel (a PR-time formal-adjacent gate that is actually cheap).
- Nightly: coverage.json archived with the proof report.
- No changes to existing formal lanes; the generator consumes their registries read-only.

## Acceptance criteria

- [ ] `cargo xtask gen proof-coverage` produces docs/formal/COVERAGE.md and target/formal/coverage.json; two consecutive runs are byte-identical.
- [ ] `--check` exits nonzero on any hand edit to COVERAGE.md and on registry/output drift.
- [ ] Every entry in proof-manifest `covered_rust_modules` and every `.kani/harnesses.toml` harness, fuzz/target-map.toml target, and per-crate mutants config appears in exactly one row's cells.
- [ ] MAPPING.md parsing tolerates the current file byte-for-byte and records zero warnings on it; a deliberately malformed fixture row produces a deterministic warning, not a crash.
- [ ] Consistency checks catch a seeded drift fixture (test with a fake registry naming a nonexistent crate).
- [ ] The matrix renders under 120 columns wide per row in Markdown source (reviewable diffs).
- [ ] COVERAGE.md carries the generation footer (input hashes, commit sha, regen command) and a generated-file warning header.
- [ ] Proof Room bundle includes the page (phase 3).

## Risks and mitigations

- The page overstates: readers may misread "cell has an id" as "surface fully verified". Mitigation: cells carry artifact ids, not checkmarks; the page header links CLAIM_REGISTRY.md and repeats its constraint that per-lane evidence classes, not this matrix, license claims (LEAN-4-VERIFIED and P4-END-TO-END remain disallowed [v]).
- MAPPING.md format drift breaks the parser. Mitigation: tolerant parsing with deterministic warnings; scripts/check-mapping.sh already constrains the file's content; a golden test pins the parse of the current file.
- Row-granularity churn (module vs crate) makes diffs noisy. Mitigation: granularity rules are fixed in the generator and documented in the page footer; changing them is a reviewed generator change, and the drift gate makes every output change visible in the same PR as its cause.
- theorem-inventory count drift (this session measured 83 theorem entries where earlier notes said 84): the generator never hardcodes counts; it reports what it parses, and the consistency checks make dangling references loud.
- Two sources of truth (COVERAGE.md vs CURRENT_STATE.md prose). Mitigation: CURRENT_STATE.md gets a pointer to the generated page for per-surface questions; prose keeps narrative, the matrix keeps facts.

## Open questions

- Should coverage.json also enumerate `excluded_surfaces` and assumptions as pseudo-rows so the page shows what is deliberately out of scope, not just what is in? (Leaning yes - it preempts the most common reviewer question.)
- Row identity for multi-file crates outside kernel-core: crate-level rows now, or file-level as soon as any registry names files? (Proposal: file-level whenever any input is file-granular for that crate.)
- Should the generator emit a second, shorter "external" rendering for the Proof Room (fewer internal ids, more prose), or is one artifact with a legend enough?
- Do we want per-cell lane freshness (last-green timestamp from proof-report.json) in a clearly-marked non-deterministic companion page, keeping COVERAGE.md itself deterministic?

## Manifest and registry updates

- formal/proof-manifest.toml: add `cargo xtask gen proof-coverage --check` to `gate_commands`; add a `notes` entry naming COVERAGE.md as the generated join of the registries.
- formal/MAPPING.md: unchanged as an input; the doc's header gains one line noting it is consumed by the coverage generator (so future format changes consider the parser).
- formal/theorem-inventory.json and formal/assumptions.toml: unchanged; read-only inputs.
- .kani/harnesses.toml, fuzz/target-map.toml, fuzz/owners.toml, .cargo/mutants.toml, audits/mutation/per-crate-configs/, docs/fuzzing/trust-boundary-mutants-baseline.toml: unchanged; read-only inputs.
- docs/reference/CLAIM_REGISTRY.md: add COVERAGE.md as a named public artifact under FORM-BOUNDARY / FORM-IMPLEMENTATION-LINKED evidence pointers ("the per-surface evidence matrix is generated from the same registries this registry cites"); no new claim wording is licensed by the matrix itself.
