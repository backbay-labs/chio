# Milestone 01: Spec-Driven Codegen + Canonical-JSON Vectors + Conformance Suite

Owner: Protocol / SDK track. Status: planned. Anchors: `RELEASE_AUDIT`, `QUALIFICATION`, `BOUNDED_OPERATIONAL_PROFILE`, `spec/PROTOCOL.md`, `spec/WIRE_PROTOCOL.md`.

## Goal

Make `spec/schemas/chio-wire/v1/` plus `spec/schemas/chio-http/v1/` (and a frozen canonical-JSON vector corpus under `tests/bindings/vectors/`) the single source of truth for Chio wire types, with generated SDK bindings in 3 languages (Rust, Python, TypeScript) and a packaged cross-implementation conformance harness that gates CI for all SDK languages.

## Why now

This was the strongest convergent pick across four debate lenses (architecture, risk, contributor experience, ecosystem). It closes the largest structural gap in the repo:

- `spec/PROTOCOL.md` is 2,421 lines of prose; `spec/WIRE_PROTOCOL.md` is another 625 lines.
- `spec/schemas/chio-wire/v1/` holds exactly 19 schema files (3 agent, 5 kernel, 5 result, 6 error). `spec/schemas/chio-http/v1/` adds 6 more for the HTTP edge. Trust-control payloads and JSON-RPC framing are not schema-ized at all (the wire README explicitly punts: "they are not represented as typed JSON Schema documents in this directory").
- Seven SDK languages re-implement the same wire types by hand. Counting only first-party model files: `sdks/python/chio-sdk-python/src/chio_sdk/models.py` is 575 lines; `sdks/typescript/packages/conformance/src/canonical.ts` is 73 lines (the encoder, plus companion types in `index.ts`); `sdks/go/chio-go-http/` is 1,323 LOC across 4 `.go` files (`types.go` alone is 147); `sdks/jvm/chio-sdk-jvm/` ships ~1,560 LOC of hand-written Kotlin including `ChioTypes.kt` (214) and `ChioClient.kt` (324); `sdks/dotnet/ChioMiddleware/src/ChioTypes.cs` is 295 lines.
- 17 of the 19 packages under `sdks/python/` (everything except `chio-sdk-python` itself and the `scripts/` helper) transitively import `chio_sdk.models`. Regenerating that one package's types ripples for free across `chio-airflow`, `chio-langchain`, `chio-fastapi`, `chio-django`, `chio-langgraph`, `chio-llamaindex`, `chio-temporal`, `chio-prefect`, `chio-dagster`, `chio-ray`, `chio-crewai`, `chio-autogen`, `chio-asgi`, `chio-streaming`, `chio-observability`, `chio-iac`, `chio-code-agent`. Every Python adapter is leveraged by exactly one schema generator.
- The existing conformance suite already does most of the work: `crates/chio-conformance/` has 17 test files (`{auth, mcp_core, nested_callbacks, notifications, tasks}_{,cpp_,go_}live.rs` plus `native_suite.rs`) driving `tests/conformance/scenarios/{mcp_core, auth, tasks, nested_callbacks, notifications, chio-extensions}` against `tests/conformance/peers/{cpp,js,python}`. But none of it is packaged for external consumers, none of it is anchored to a schema contract, and the vector corpus contains only 35 cases total (5 canonical, 5 manifest, 8 receipt, 10 capability, 3 hashing, 4 signing) versus a target of >= 120.

Until prose, schema, vectors, and SDKs share one freeze point, every other milestone (M02 fuzzing, M04 deterministic replay, M05 async kernel, M07 provider adapters, M08 browser-edge SDK, M10 tee/replay) re-litigates wire shape. This milestone makes drift detectable and codegen-driven, so subsequent work edits one schema file and propagates outward.

## In scope

- Codegen pipeline (`scripts/codegen/` plus a `chio-spec-codegen` Rust crate or `cargo xtask`) that consumes `spec/schemas/chio-wire/v1/` and `spec/schemas/chio-http/v1/` and produces typed bindings for Rust (cross-checked against `crates/chio-core-types/src/`), Python (`sdks/python/chio-sdk-python/src/chio_sdk/_generated/`), and TypeScript (`sdks/typescript/packages/conformance/src/_generated/`).
- Vector corpus expansion under `tests/bindings/vectors/{canonical,manifest,receipt,capability,hashing,signing}/v1.json`, frozen by SHA-256 manifests, with a workspace test that compares each language's encoder output byte-for-byte against the Rust oracle (`crates/chio-core-types/src/canonical.rs`, currently 524 lines).
- Schema completion: fill the gaps the current `spec/schemas/chio-wire/v1/README.md` flags as out-of-band (HTTP edge envelopes beyond the 6 already in `chio-http/v1/`, trust-control payloads, JSON-RPC framing, capability-token shapes, signed-receipt records) so `spec/schemas/` covers every wire shape `chio-conformance` exercises.
- Conformance harness packaging: lift the in-repo runner (`crates/chio-conformance/src/{lib,runner,model,load,report}.rs` plus `bin/`) into a publishable crate plus a CLI (`chio conformance run --peer <lang>`), so external implementers can exercise the same scenarios without checking out this repo.
- CI gates: (a) generated-code drift fails build (regenerate-and-diff), (b) schema-without-vector fails build, (c) cross-language vector comparison fails build, (d) `cargo test -p chio-formal-diff-tests` runs alongside spec parsing, (e) header-stamp check on every generated file.
- Extend `formal/diff-tests/tests/scope_diff.rs` (375 lines) pattern with a second differential file (`canonical_json_diff.rs`) covering canonical-JSON byte equivalence between spec parser and `chio_core_types::canonical::canonicalize`.

### Tooling decisions (locked Wave 1, 2026-04-25)

One primary toolchain per language; rationale in one line. All recommendations preserve hand-written code paths (canonical encoder, capability ops) and only generate type definitions. Versions pinned at first commit of Phase 3 and recorded in `xtask/codegen-tools.lock.toml`.

- **Rust**: `typify = "=0.4.3"` (Oxide's JSON Schema to Rust crate). Best mature option; emits `serde`-friendly `enum` + `struct` aligned with the `chio_core_types` style. Rejected: hand-rolled walker (more work, no upside).
- **Python**: `datamodel-code-generator = "==0.34.0"` targeting Pydantic v2 (the entire workspace is `pydantic>=2.5,<3` per all 14 adapter `pyproject.toml` files that pin it). No v1/v2 split exists in this repo, so we can target v2 exclusively. Rejected: `quicktype` (less Pydantic-aware), hand-rolled.
- **TypeScript**: `json-schema-to-typescript = "15.0.4"` for type aliases; `quicktype` only if we discover sum-type discrimination needs that `json-schema-to-typescript` cannot express. Rejected: TypeBox runtime types (overkill for a conformance package that already has hand-written `verify.ts`).
- **Go (deferred-but-checked-in)**: `oapi-codegen` (Wave 1 decision) in JSON Schema mode. Single regen script under `sdks/go/chio-go-http/scripts/regen-types.sh`; output is committed (no live pipeline parity). Pinned at `v2.4.1`.
- **Kotlin (out of scope, noted for M01+1)**: `kotlinx-serialization` codegen via Gradle plugin (Wave 1 decision) once we decide on `data class` vs `sealed class` mapping for the result/error sum types. Current code uses Jackson + `data class` only, which loses the discriminator union. Decision deferred.
- **C# (out of scope, noted for M01+1)**: `Microsoft.Json.Schema.ToDotNet` (Wave 1 decision). Current `ChioTypes.cs` (295 lines) is hand-written. Decision deferred.

## Out of scope

- Changing wire semantics or adding new message families. This milestone freezes the existing surface; it does not negotiate it.
- Adding new SDK languages. Kotlin (`sdks/jvm/`), .NET (`sdks/dotnet/`), and the 17 Python framework adapters consume the generated `chio-sdk-python` types but do not get their own codegen targets in M01 (Kotlin/.NET get a follow-up; the 17 Python adapters get the regeneration ripple for free).
- Replacing `spec/PROTOCOL.md` prose. Prose stays authoritative for behavior; schemas become authoritative for shape.
- Protocol-wide WIT (`wit/chio-guard/world.wit` stays guard-only). A WIT-for-everything design belongs to a later milestone.
- Live conformance against external implementations (M01 ships the harness; cross-vendor proofs come later).

## Success criteria (measurable)

- At least 35 JSON Schema files under `spec/schemas/chio-wire/v1/` (currently 19, target +16 wire) plus at least 10 under `chio-http/v1/` (currently 6, target +4 http). Wire additions: capability tokens (target: 3), receipt records (target: 2), JSON-RPC framing (target: 3), trust-control payloads (target: 4), provenance stamps (target: 4). HTTP additions: edge request/response envelopes (target: 4). Net add >= 20 schema files (16 wire + 4 http).
- 6 vector corpora under `tests/bindings/vectors/` each containing >= 20 cases (current totals: 5/5/8/10/3/4 = 35 across the six domains; target >= 120). Each case has fields `id`, `description`, `input` (or `input_json`), `canonical_json`, `sha256`, and (for signed types) `signed_bytes`. The receipt and capability domains additionally carry an optional `verify_only: bool` tag (default `false`) marking cases that exercise only the verify-side surface; M08's browser/edge subset selector consumes this tag to filter the M08 conformance subset (see M08 "Conformance subset definition"). The current `canonical/v1.json` already follows a near-identical shape; preserve its `version` and `generated_by` envelope.
- Generated types replace hand-typed equivalents in: `sdks/python/chio-sdk-python/src/chio_sdk/models.py` (575 lines now, expected to drop to a thin re-export from `_generated/`); `sdks/typescript/packages/conformance/src/index.ts` companion types (re-export from `_generated/`, leaving the encoder in `canonical.ts` untouched as the language-specific oracle); `sdks/go/chio-go-http/types.go` (147 lines, header-stamped generated file with manual regen script).
- CI gate `spec-drift` (new workflow `.github/workflows/spec-drift.yml`) fails build when (a) `spec/schemas/` changes without regenerated bindings (`git diff --exit-code` after `cargo xtask codegen`), (b) a schema lacks at least one vector, (c) any language encoder produces different bytes for the same input, (d) any generated file is hand-edited (header-stamp check).
- Cross-implementation conformance: Rust `chio-kernel` (existing), `tests/conformance/peers/python/server.py`, `tests/conformance/peers/js/server.mjs`, and `tests/conformance/peers/cpp/client.cpp` all pass the packaged scenario suite. The C++ kernel via `crates/chio-cpp-kernel-ffi` should pass at minimum `mcp_core` and `auth`.
- `formal/diff-tests/tests/canonical_json_diff.rs` lands with >= 6 proptest invariants covering: object key UTF-16 ordering, number shortest-form (incl. -0 and 1e21), nested array/object structure, string minimal escaping, surrogate-pair keys, and `NaN`/`Infinity` rejection.
- `crates/chio-conformance/tests/` grows from 17 to 17 + at least 1 new test file (`schema_validate_live.rs` or similar) that asserts every scenario JSON in `tests/conformance/scenarios/` parses against a schema in `spec/schemas/`.

## Phase breakdown

Phases are dependency-ordered: schemas (1) must exist before vectors (2) before codegen (3) before conformance packaging (4) before differential CI hardening (5).

Sizing legend: **S** = 1-3 days, **M** = 4-10 days, **L** = 2-4 weeks. Estimates assume one engineer-week per person per calendar week.

### Phase 1: Schema completion -- size **M** (8-10 days)

Sub-goal: bring `spec/schemas/chio-wire/v1/` plus `spec/schemas/chio-http/v1/` to wire-complete coverage of every payload `chio-conformance` and the HTTP edge emit.

First commit: `feat(spec): add capability-token schema 0.1.0` touching `spec/schemas/chio-wire/v1/capability/token.schema.json` (new), `spec/schemas/chio-wire/v1/capability/README.md` (new, 1 paragraph subtree note), and `spec/schemas/MANIFEST.sha256` (new, regen). Capability is first because it is the smallest standalone schema in the new subtrees and unblocks the vector corpus growth in Phase 2 (the hand-written `capability/v1.json` corpus already exists with 10 cases and will validate against it).

Tasks:

- **P1.T1**: Audit every payload emitted in `tests/conformance/scenarios/{mcp_core,auth,tasks,nested_callbacks,notifications,chio-extensions}` and `crates/chio-conformance/src/model.rs` to produce `spec/schemas/COVERAGE.md` listing every payload type and which schema covers it (or `MISSING`). Output is a checklist driving P1.T2-T5.
- **P1.T2**: Land `spec/schemas/chio-wire/v1/capability/{token,grant,revocation}.schema.json` (target: 3 files). First commit above.
- **P1.T3**: Land `spec/schemas/chio-wire/v1/receipt/{record,inclusion-proof}.schema.json` (target: 2 files). The `inclusion-proof` schema is the explicit M04 contract: `KernelCheckpoint` and `ReceiptInclusionProof` from `crates/chio-anchor/src/lib.rs` must round-trip through it. (NEW: this was implicit before; M04 expects a schema for `ReceiptInclusionProof` that today does not exist.)
- **P1.T4**: Land `spec/schemas/chio-wire/v1/jsonrpc/{request,response,notification}.schema.json` (target: 3 files), `spec/schemas/chio-wire/v1/trust-control/{lease,heartbeat,terminate,attestation}.schema.json` (target: 4 files), and `spec/schemas/chio-wire/v1/provenance/{stamp,context,attestation-bundle,verdict-link}.schema.json` (target: 4 files). The `provenance/stamp.schema.json` is the wire form of `ProvenanceStamp` (M07's contract; see Cross-doc references); M07 consumes this schema rather than defining its own.
- **P1.T5**: Extend `spec/schemas/chio-http/v1/` with `{stream-frame,session-init,session-resume,error-envelope}.schema.json` (target: 4 files).
- **P1.T6**: Land `crates/chio-spec-validate/` binary that walks every JSON in `tests/conformance/scenarios/` and asserts schema-conformance; wired as `cargo xtask validate-scenarios`.
- **P1.T7**: Update `spec/schemas/chio-wire/v1/README.md` to drop the "out-of-band" disclaimer; add subtree READMEs; stamp deprecation header on hand-typed model files (see Migration story below).

Migration story (hand-typed files do NOT change shape in Phase 1; they only get deprecation headers; actual flip lands in Phase 3):

- `chio-sdk-python/src/chio_sdk/models.py` (575 lines): no shape change. Add the deprecation header in P1.T7.
- `canonical.ts` (73 lines): unchanged forever; this is the TS-side encoder oracle. No header.
- `index.ts` companion types: header added; flip in P3.T3.
- `chio-go-http/types.go` (147 lines): no shape change yet; header added in P1.T7.
- JVM `ChioTypes.kt` (214 lines), `ChioClient.kt` (324 lines): not in M01 scope; deprecation header deferred to M01+1.
- .NET `ChioTypes.cs` (295 lines): not in M01 scope; deprecation header deferred to M01+1.

Deprecation header format (project standard, dash-only per house rules):

```
// chio-deprecation: this file is hand-written today and will be replaced by
// generated output from `cargo xtask codegen` after Phase 3 (M01) lands.
// Do not add new types here; add them to spec/schemas/chio-wire/v1/.
// Tracking: .planning/trajectory/01-spec-codegen-conformance.md P3.T*
```

(For Python, swap `//` for `#`.)

Exit test: `cargo run -p chio-spec-validate -- tests/conformance/scenarios/` exits 0; `find spec/schemas/chio-wire/v1 -name '*.schema.json' | wc -l` reports >= 35; `find spec/schemas/chio-http/v1 -name '*.schema.json' | wc -l` reports >= 10; `spec/schemas/COVERAGE.md` shows zero `MISSING` rows.

Rollback: revert the Phase 1 commits in reverse order. Schemas are additive; no generated artifact depends on them yet (codegen lands in Phase 3). The only persisted side effect is `spec/schemas/MANIFEST.sha256`; regenerate via `cargo xtask spec-manifest` on the prior tip.

### Phase 2: Vector corpus expansion and freeze -- size **M** (6-8 days)

Sub-goal: lock canonical-JSON byte semantics for every shape that has a schema.

First commit: `feat(vectors): expand canonical corpus to 20 cases` touching `tests/bindings/vectors/canonical/v1.json` (5 -> 20 cases), `tests/bindings/vectors/MANIFEST.sha256` (new), and `crates/chio-conformance/tests/vectors_oracle.rs` (new test file). Canonical is first because it is the smallest delta (5 -> 20) and gates Phase 5's differential. Receipt expansion follows once Phase 1 receipt schemas are merged.

Tasks:

- **P2.T1**: Land `crates/chio-conformance/tests/vectors_oracle.rs` that loads every vector and feeds it through `chio_core_types::canonical::canonicalize`, asserting `canonical_json` and `sha256` match. Test name: `vectors_oracle::byte_stable_against_rust_canonicalizer`. First commit.
- **P2.T2**: Grow `canonical/v1.json` to >= 20 cases (5 -> 20; +15). Reuse the existing `version` / `generated_by` envelope. Cover RFC 8785 edges: -0 from JSON parser, lone surrogate reject, `5e-324` denormal, `9007199254740993` precision-loss, `0.1 + 0.2`, surrogate-pair key sort.
- **P2.T3**: Grow `manifest/v1.json` (5 -> 20), `hashing/v1.json` (3 -> 20), `signing/v1.json` (4 -> 20). +47 cases total. Each case includes `id`, `description`, `input`, `canonical_json`, `sha256`, and (signing only) `signed_bytes`.
- **P2.T4**: Grow `receipt/v1.json` (8 -> 20) and `capability/v1.json` (10 -> 20). +22 cases total. Receipt cases must include all four allow/deny/cancelled/incomplete result variants and at least 4 anchored-inclusion-proof cases (the M04 contract). (NEW: explicit anchored-proof case requirement, was implicit.)
- **P2.T5**: Land `tests/bindings/vectors/MANIFEST.sha256` listing every vector file and its hash; CI verifies on every PR via the workflow added in Phase 5. Manifest produced by a new `cargo xtask freeze-vectors` that also rejects vector edits if any `sha256` field in any case fails to match the oracle output. (NEW: command-line freeze-and-verify, separating "regenerate vectors" from "verify vectors".)
- **P2.T6**: Add `crates/chio-conformance/tests/vectors_schema_pair.rs` that asserts every vector domain has at least one schema with the same name root (`canonical -> chio-wire/v1/canonical/*`, `receipt -> chio-wire/v1/receipt/*`, etc.) and that >= 1 case in each domain validates against the matching schema.

Exit test: `cargo test -p chio-conformance --test vectors_oracle -- --include-ignored` passes; `cargo test -p chio-conformance --test vectors_schema_pair` passes; `cargo xtask freeze-vectors --check` exits 0 (manifest matches); `wc -l` against each `v1.json` shows >= 20 case objects (target totals 6 * 20 = 120 minimum).

Observability / staleness alarm (NEW): a nightly job `vectors-staleness.yml` runs `cargo xtask freeze-vectors --check` against `main` and posts to the protocol channel if the manifest fails. This is how we know in 6 months the vectors remain byte-stable: a green nightly across 30 days plus a red nightly that opens an issue on the first divergence. Job artifact `vectors-manifest-<date>.txt` retained for 90 days. Alarm thresholds: 1 failed nightly opens an issue tagged `vector-drift`; 3 consecutive failures pages the protocol owner.

Rollback: vectors are additive within `v1.json`; revert the corpus growth commits and regenerate `MANIFEST.sha256`. If a downstream (M02 fuzzer, M04 replay corpus, M08 differential) has already adopted the expanded corpus, pin it to the pre-revert commit hash via Cargo `[patch]` or git submodule until M01's redo lands.

### Phase 3: Codegen pipeline (Rust + Python + TS) -- size **L** (12-15 days)

Sub-goal: produce generated bindings from schemas; wire CI drift detection.

First commit: `feat(codegen): scaffold chio-spec-codegen crate with typify Rust target` touching `crates/chio-spec-codegen/Cargo.toml` (new), `crates/chio-spec-codegen/src/main.rs` (new, ~80 lines), `crates/chio-spec-codegen/README.md` (new), `xtask/codegen-tools.lock.toml` (new), and root `Cargo.toml` (workspace member add). Rust target lands first because `typify` is a pure-Rust dependency and unblocks the cross-check in P3.T2 against `chio-core-types`.

Tasks:

- **P3.T1**: Scaffold `crates/chio-spec-codegen/` with `typify` Rust target wired up. `cargo xtask codegen --lang rust` writes `crates/chio-core-types/src/_generated/` (new module) and `_generated_check.rs` runs at build time asserting structural superset. First commit.
- **P3.T2**: Wire `cargo xtask codegen --lang python` to shell out to a pinned `datamodel-code-generator` invocation; write to `sdks/python/chio-sdk-python/src/chio_sdk/_generated/`. Add `pyproject.toml` toolchain pin via `[tool.uv.dev-dependencies]` and a `sdks/python/scripts/codegen-requirements.txt` file. Reduce `models.py` (575 lines) to a re-export from `_generated/`. Header-stamp every generated file.
- **P3.T3**: Wire `cargo xtask codegen --lang ts` to shell out to `json-schema-to-typescript` via a pinned npm install; write to `sdks/typescript/packages/conformance/src/_generated/` and re-export from `index.ts`. `canonical.ts` stays untouched. Header-stamp every generated file.
- **P3.T4**: Wire `cargo xtask codegen --lang go` to `oapi-codegen`; write to `sdks/go/chio-go-http/types.go` directly (header-stamped). Add the manual regen script `sdks/go/chio-go-http/scripts/regen-types.sh`.
- **P3.T5**: Land `make codegen-check` plus a matching CI step in `.github/workflows/spec-drift.yml` job `codegen-no-diff` that runs codegen and `git diff --exit-code`. Add a header-stamp grep gate (job `header-stamp-untouched`) that fails if any `_generated/` file lacks the stamp or has been edited (compare a stable hash of the file's first 5 lines to a known constant).
- **P3.T6**: Run all 17 Python framework adapter test suites against the regenerated `chio-sdk-python` to confirm no break.

Migration story (Phase 3 is when hand-typed files actually flip):

- `chio-sdk-python/src/chio_sdk/models.py` (575 lines) becomes a 10-line re-export shim: `from chio_sdk._generated import *  # noqa: F401,F403`. The original file is preserved as `models_legacy.py` for one release cycle so adapter authors can grep for unported usage; deletion lands in M01+1.
- `chio-go-http/types.go` (147 lines) is overwritten with header-stamped generated output. Pre-existing custom helpers move to a sibling `types_helpers.go` (hand-written, no header stamp).
- `canonical.ts` (73 lines) and `index.ts` companion types: companion types move into `_generated/` re-exports; the encoder stays.

Exit test: `cargo xtask codegen --check` exits 0 on a clean checkout; `git diff --exit-code` after a fresh codegen run is empty; `cargo test -p chio-core-types`, `pytest sdks/python/chio-sdk-python/tests`, and `pnpm --filter @chio-protocol/conformance test` all pass against generated types; CI job `codegen-no-diff` is green; CI job `header-stamp-untouched` is green; all 17 Python framework adapters under `sdks/python/` build via `uv sync --workspace` and pass their existing tests.

Observability / staleness alarm: `codegen-no-diff` runs on every PR plus a nightly cron. If `main` is ever inconsistent (codegen output drifts from committed) the nightly fails closed. Alarm: 1 failed nightly tags the protocol channel; 3 consecutive failures pages the protocol owner.

Rollback per generated language:

- Rust: revert `crates/chio-core-types/src/_generated/` directory and the `mod _generated;` line; `chio-core-types` falls back to its hand-written shape automatically.
- Python: replace the `models.py` re-export shim with the contents of `models_legacy.py`; delete `_generated/`; bump `chio-sdk-python` patch version.
- TypeScript: delete `_generated/`; restore the prior commit's `index.ts` companion types from git.
- Go: restore the prior commit's `types.go` from git.
- Schema-version pin (NEW): if a downstream pipeline requires the prior schema set, pin to the immediately previous schema-set tag via `spec/schemas/VERSION` (currently absent, lands in P3.T1). Vendor-tarball regen via `cargo xtask vendor-spec-tarball` produces `dist/chio-spec-<version>.tar.gz` that any external consumer can pin to.

### Phase 4: Conformance suite packaging -- size **M** (5-7 days)

Sub-goal: make the existing scenario runner usable outside the repo.

First commit: `feat(conformance): make crate publishable with included peer fixtures` touching `crates/chio-conformance/Cargo.toml` (drop path-only deps, add `[package.metadata.docs.rs]`, add `include = [...]`), `crates/chio-conformance/README.md` (consumer-facing rewrite), and `docs/conformance.md` (new). This is the smallest change that flips the crate to publishable shape and unblocks the CLI work in P4.T2.

Tasks:

- **P4.T1**: Make `crates/chio-conformance/Cargo.toml` publishable: drop path-only deps, add `[package.metadata.docs.rs]`, gate dev-only paths under a feature flag (`feature = "in-repo-fixtures"` opt-in), set `include = ["src/**", "tests/conformance/scenarios/**", "tests/conformance/peers/python/**", "tests/conformance/peers/js/**"]`. First commit.
- **P4.T2**: Add `chio conformance run --peer <lang> [--report json] [--scenario <name>]` subcommand to `chio-cli`. New file `crates/chio-cli/src/cli/conformance.rs`; register in `crates/chio-cli/src/cli/dispatch.rs`. Output shape matches `tests/conformance/reports/` artifact format already produced.
- **P4.T3**: Land `crates/chio-cli/tests/conformance_cli.rs` integration test invoking `chio conformance run --peer python --report json /tmp/r.json` and asserting all 5 scenarios green plus report-shape stability via `insta` snapshot.
- **P4.T4**: Add a `chio conformance fetch-peers` subcommand that downloads pinned peer binaries (sha256-pinned URLs in `crates/chio-conformance/peers.lock.toml`). (NEW: external implementers cannot rely on having Python/Node available; pre-built peer binaries must be fetchable. The lockfile names release-asset URLs from the M01 release artifacts, sha256-pinned.)
- **P4.T5**: Land `docs/conformance.md` describing the standalone consumer flow (`cargo install chio-conformance && chio conformance fetch-peers && chio conformance run --peer python /tmp/report.json`).
- **P4.T6**: C++ peer P0 coverage: confirm `mcp_core` and `auth` scenarios pass via `crates/chio-cpp-kernel-ffi`; defer `chio-extensions`, `tasks`, `nested_callbacks`, `notifications` to a follow-on milestone (Wave 1 decision 5). Add `cpp_peer_p0.rs` integration test asserting only the P0 scenarios.

Exit test: `cargo install --path crates/chio-conformance` succeeds and `chio conformance run --peer python --report json /tmp/r.json` runs all 5 scenarios green; `cargo test -p chio-cli --test conformance_cli` passes; `cargo test -p chio-conformance --test cpp_peer_p0` passes; on a separate clone with no other crates checked out, `cargo install chio-conformance --version 0.1.0 && chio conformance fetch-peers && chio conformance run --peer python /tmp/r.json` succeeds. Smoke job in `.github/workflows/conformance-matrix.yml` named `external-consumer-smoke` runs this on a fresh runner.

Observability / staleness alarm: the `external-consumer-smoke` job runs nightly on `ubuntu-latest` with the published crate (not the in-repo path) and posts to the protocol channel on failure. If crates.io drops a dependency or peer-binary URLs go stale, this catches it within 24 hours.

Rollback: yank the crates.io publish (`cargo yank --version 0.1.0 chio-conformance`); revert the `chio conformance` subcommand commits; the in-repo runner remains usable via the `in-repo-fixtures` feature flag.

### Phase 5: Differential and CI hardening -- size **M** (5-7 days)

Sub-goal: extend `formal/diff-tests/` and lock CI gates.

First commit: `test(diff): add canonical-json differential proptest` touching `formal/diff-tests/tests/canonical_json_diff.rs` (new, ~250 lines) and `formal/diff-tests/Cargo.toml` (no shape change expected, but listed for completeness). This is the smallest standalone test file and proves the proptest harness works before the receipt-encoding sibling lands.

Tasks:

- **P5.T1**: Land `formal/diff-tests/tests/canonical_json_diff.rs` with >= 6 proptest invariants: object key UTF-16 ordering, number shortest-form (incl. -0 and 1e21), nested array/object structure, string minimal escaping, surrogate-pair keys, NaN/Infinity rejection. First commit.
- **P5.T2**: Land `formal/diff-tests/tests/receipt_encoding_diff.rs` with >= 4 invariants covering signed-receipt byte equivalence between the Rust oracle, the Python encoder (via `chio-sdk-python`), and the TS encoder (via `@chio-protocol/conformance`). Drives subprocess invocations to encode the same inputs across all three.
- **P5.T3**: Land `.github/workflows/spec-drift.yml` with five jobs: `codegen-no-diff`, `vectors-byte-stable`, `schema-coverage` (every schema must have at least one vector case validating against it; reuses the P2.T6 test), `cross-lang-bytes` (drives all language encoders against `tests/bindings/vectors/` and asserts byte equivalence), `header-stamp-untouched` (greps every `_generated/` tree).
- **P5.T4**: Land `.github/workflows/conformance-matrix.yml` with two jobs: `vectors-byte-stable` (re-runs P2 vector oracle nightly) and `external-consumer-smoke` (P4 standalone consumer flow nightly).
- **P5.T5**: Wire the `schema-breaking-change` PR comment job using `json-schema-diff` against `main`; non-blocking until M01+1, advisory comment only. (NEW: today the doc says "breaking changes require an explicit BREAKING: tag" but does not specify the bot that surfaces them. Land the bot now, advisory only; flip blocking after M01+1.)

Exit test: full one-liner from `CLAUDE.md` (`cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`) green on a clean checkout; `cargo test -p chio-formal-diff-tests --test canonical_json_diff` green; `cargo test -p chio-formal-diff-tests --test receipt_encoding_diff` green; CI workflow `.github/workflows/spec-drift.yml` jobs `codegen-no-diff`, `vectors-byte-stable`, `schema-coverage`, `cross-lang-bytes`, `header-stamp-untouched` all green on `main` for 7 consecutive days; CI workflow `.github/workflows/conformance-matrix.yml` job `external-consumer-smoke` green on the first nightly after Phase 4 ships.

Observability / staleness alarm: `spec-drift.yml` is required on `main` and every PR; `conformance-matrix.yml` runs nightly with the same alarm thresholds as Phase 2 / Phase 3 (1 fail = issue, 3 consecutive = page). Aggregate dashboard published as a static page from `docs/conformance-dashboard/` updated by the nightly job.

Rollback: each new CI workflow can be deleted independently; the differential tests are additive (`cargo test --workspace` keeps passing if the files are removed). The `schema-breaking-change` PR bot can be disabled by deleting its workflow file; no persistent state.

## Test taxonomy

| Crate / location | Test file | Type | What it proves |
|---|---|---|---|
| `crates/chio-conformance/tests/` | `vectors_oracle.rs` | integration | every vector's `canonical_json` and `sha256` match the Rust canonicalizer output byte-for-byte |
| `crates/chio-conformance/tests/` | `vectors_schema_pair.rs` | integration | every vector domain has a matching schema and >= 1 case validates |
| `crates/chio-conformance/tests/` | `schema_validate_live.rs` | integration | every scenario JSON parses against a schema in `spec/schemas/` |
| `crates/chio-conformance/tests/` | `cpp_peer_p0.rs` | conformance | P0 scenarios (`mcp_core`, `auth`) pass against the C++ kernel FFI |
| `crates/chio-conformance/tests/` | `{auth,mcp_core,nested_callbacks,notifications,tasks}_{,cpp_,go_}live.rs` | conformance | existing scenario runners (17 files preserved) |
| `crates/chio-cli/tests/` | `conformance_cli.rs` | integration | `chio conformance run` subcommand emits stable report shape |
| `crates/chio-core-types/src/_generated/` | build-time `_generated_check.rs` | unit (build-time) | generated Rust types are a structural superset of hand-written `chio_core_types` |
| `formal/diff-tests/tests/` | `canonical_json_diff.rs` | property (proptest) | spec parser and Rust canonicalizer produce identical bytes across >= 6 invariants |
| `formal/diff-tests/tests/` | `receipt_encoding_diff.rs` | differential (cross-impl) | Rust, Python, and TS encoders produce identical signed-receipt bytes (>= 4 invariants) |
| `formal/diff-tests/tests/` | `scope_diff.rs` (existing) | property (proptest) | scope diff invariants (375 lines, unchanged in M01) |
| `crates/chio-spec-validate/` | `tests/scenarios.rs` | integration | every JSON in `tests/conformance/scenarios/` validates against a schema |
| `xtask/` | `freeze-vectors.rs` | tool | regenerates and verifies `tests/bindings/vectors/MANIFEST.sha256` |
| `sdks/python/chio-sdk-python/tests/` | (existing 4 files) | unit + integration | generated Pydantic models round-trip; existing tests preserved |
| `sdks/typescript/packages/conformance/test/` | (existing) | unit | TS encoder produces canonical bytes; tests survive `_generated/` migration |

Fuzz targets (M02 owns; listed for cross-doc traceability): `crates/chio-fuzz/fuzz_targets/canonical_roundtrip.rs` consumes `tests/bindings/vectors/canonical/v1.json` as a seed corpus.

## Dependencies and downstream consumers

Upstream:

- Wire-protocol prose in `spec/PROTOCOL.md` (2,421 lines) and `spec/WIRE_PROTOCOL.md` (625 lines) must be stable enough to schema-ize. Any in-flight wire changes should land before Phase 1 or be deferred.
- `crates/chio-core-types/src/canonical.rs` (524 lines) is the byte-semantics anchor; M01 freezes its output but does not modify it.

Downstream artifacts each milestone needs from M01:

- **M02 (fuzzing)** consumes the Phase 2 vector corpus as a libFuzzer / cargo-fuzz seed corpus. Specifically, the canonical and signing vectors seed `crates/chio-fuzz/fuzz_targets/canonical_roundtrip.rs` and similar.
- **M04 (deterministic replay)** consumes the Phase 1 receipt schemas (`spec/schemas/chio-wire/v1/receipt/{record,inclusion-proof}.schema.json`, landed in P1.T3) as the contract that golden bundles under `tests/replay/goldens/<family>/<name>/receipts.ndjson` and `checkpoint.json` must validate against. M04's golden gate adds a `chio-spec-validate` step on every receipt before byte comparison; an M01 schema change without an M04 golden re-bless surfaces as a P1 break in M04 first. M04 also consumes the Phase 2 receipt vectors as the canonical-JSON freeze that `tests/replay/fixtures/` builds on. The format relationship is: M01 owns `tests/bindings/vectors/receipt/v1.json` (a single JSON file, schema-driven test cases); M04 owns `tests/replay/goldens/<family>/<name>/receipts.ndjson` (one signed receipt per line, M10 tee-stream byte-compatible). Both serialize the same `Receipt` schema; M04 goldens are the streaming form, M01 vectors are the case-table form.
- **M07 (provider-native adapters)** consumes the Phase 1 `ToolInvocation` and `ProvenanceStamp` schemas so `chio-tool-call-fabric` defines its trait surface against codegen-frozen types. M07 explicitly notes "If M01 ships first, the fabric crate inherits its types." The `ProvenanceStamp` shape is owned by M07 (`provider`, `request_id`, `api_version`, `principal`, `received_at`); M01 ships the schema for the wire form and gate-tests round-trip equality against the M07 trait surface.
- **M08 (browser-edge SDK)** consumes the Phase 2 `tests/bindings/vectors/{canonical,receipt,capability}/v1.json` corpus as a browser-runtime differential; the four browser/Workers/Edge/Deno targets must produce byte-identical output to the Rust oracle. M08 also adds `formal/diff-tests/tests/browser_canonical_json_diff.rs` as an additional differential target on top of the M01 differential file.
- **M10 (tee/replay harness)** consumes the Phase 1 `ToolInvocation` schema as the basis for the `chio-tee-frame.v1` NDJSON capture format. Frame schema versions on M01 schema; bumps require a documented migration. M10 also notes that the `chio-provider-conformance` NDJSON shape (M07) and the `chio-tee-frame.v1` shape are alignment-required: if both ship, they share one schema version namespace owned by M10.
- **M06 (WASM guard platform)** consumes M01's conformance harness as the host for guard-side fixtures targeting `chio:guard@0.2.0`. M06 ships the additive fixtures (`host.fetch-blob`, `policy-context`); M01's Phase 4 packaging includes them. M06 Phase 1 also reserves the `chio:guards/redact@0.1.0` WIT namespace for M10.
- **M09 (supply-chain attestation)** consumes M01's canonical-JSON identity rules for SBOM component identity: every component identity emitted by `syft` round-trips through the M01 canonical-JSON encoder, and SBOM signatures use the same Sigstore tooling that M09 lands.

Parallelism:

- Can run in parallel with M02 (fuzzing): M02 consumes the Phase 2 corpus as a seed corpus.
- Can run in parallel with M05 (async kernel): the schemas describe wire shape, not transport, so async work proceeds independently.

## Risks and mitigations

- **Schema drift vs prose.** Mitigated by `chio-spec-validate` running against every scenario JSON in `tests/conformance/scenarios/` (Phase 1) plus a doctest extracting JSON blocks from `spec/PROTOCOL.md` and validating them.
- **Codegen drift (generated files edited by hand).** Mitigated by a header-stamp check in CI plus `git diff --exit-code` after `cargo xtask codegen` (Phase 3).
- **Codegen toolchain churn.** `typify`, `datamodel-code-generator`, and `json-schema-to-typescript` each have their own release cadence and may emit different output across versions. Mitigation: pin exact versions in `xtask/codegen-tools.lock.toml`, `sdks/python/scripts/codegen-requirements.txt`, and `sdks/typescript/scripts/package-lock.json` (or pnpm lockfile); CI runs against the pinned versions and a Renovate-style bot opens a PR for upgrades that re-runs codegen so diffs are visible.
- **Schema-versioning policy.** Pin schemas under `v1/` only; introduce `v2/` only with an explicit migration vector and a written compatibility note. Generated SDK types live under `_generated/` namespaces so v2 can co-exist. Vector corpora live under `tests/bindings/vectors/<domain>/v1.json`; future versions add `v2.json` siblings.
- **Breaking-change detection in CI.** Add a `schema-breaking-change` CI step that runs `json-schema-diff` (or equivalent) between the PR and `main` and surfaces field-removed / type-narrowed / required-added changes as PR comments. Breaking changes require an explicit `BREAKING:` tag in the commit message to land. Advisory until M01+1 (P5.T5).
- **Multi-language tooling overhead.** Rust, Python, and TS only in M01. Go gets a checked-in generated file with a manual regen script. Kotlin, .NET, and the 17 Python framework adapters consume `chio-sdk-python` transitively and are unaffected this milestone.
- **RFC 8785 conformance edge cases.** Specifically:
  - `NaN` and `Infinity`: not representable in JSON; the encoder must reject. Add explicit reject vectors.
  - `-0` vs `0`: RFC 8785 collapses to `0`. The current `canonical/v1.json` `number_formatting` case already covers this; expand to include `-0.0` from a JSON parser (not just a Rust literal).
  - UTF-16 surrogate pairs: object keys with paired surrogates must sort by UTF-16 code unit, not UTF-8 byte. The current `utf16_key_ordering` case covers BMP-vs-supplementary; add cases with lone surrogates (must reject) and split-surrogate keys.
  - Number shortest form: `1e21` vs `1000000000000000000000` round-trip. Cover `5e-324` (smallest denormal), `9007199254740993` (loss of precision), `0.1 + 0.2`.
  - Mitigation: reuse the existing `chio_core_types::canonical` implementation as the oracle; encode every edge case explicitly into the canonical vectors; add proptest differentials in `formal/diff-tests/`.
- **Pydantic v1 vs v2 split.** The repo is uniformly Pydantic v2 (`pydantic>=2.5,<3`) per all 14 adapter `pyproject.toml` pins. No split exists today. Mitigation: target Pydantic v2 exclusively; add a CI grep that fails if any `pyproject.toml` pins v1; if a future adapter needs v1, it owns the conversion shim in its own package.
- **Kotlin data class vs sealed class split.** The result/error sum types (`Ok` / `Err` / `Cancelled` / `Incomplete` / `StreamComplete`) want Kotlin sealed classes; current `sdks/jvm/chio-sdk-jvm/` uses `data class` everywhere with no discriminator handling. Mitigation: defer Kotlin codegen to M01+1 and document the choice in the M01+1 follow-up. M01 leaves Kotlin hand-written.
- **External-implementer ergonomics.** The packaged `chio-conformance` crate must run without checking out this repo. Mitigation: include `tests/conformance/{scenarios, fixtures, peers/python, peers/js}/` in the crate's `include` list; add a `chio conformance fetch-peers` subcommand that downloads pinned peer binaries (P4.T4); document the standalone flow in `docs/conformance.md`; nightly `external-consumer-smoke` job (P5.T4) runs the standalone flow.

## Code touchpoints

Created:

- `/Users/connor/Medica/backbay/standalone/arc/spec/schemas/chio-wire/v1/{trust-control,jsonrpc,capability,receipt,provenance}/*.schema.json` (new subtrees, target +16 files; receipt subtree includes `inclusion-proof.schema.json` for M04; provenance subtree owns the M07 `ProvenanceStamp` wire form)
- `/Users/connor/Medica/backbay/standalone/arc/spec/schemas/chio-http/v1/*.schema.json` (extend, target +4 files)
- `/Users/connor/Medica/backbay/standalone/arc/spec/schemas/COVERAGE.md` (new, P1.T1)
- `/Users/connor/Medica/backbay/standalone/arc/spec/schemas/MANIFEST.sha256` (new, regen)
- `/Users/connor/Medica/backbay/standalone/arc/spec/schemas/VERSION` (new, P3.T1)
- `/Users/connor/Medica/backbay/standalone/arc/scripts/codegen/` (codegen entry script with pinned tool versions)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-spec-codegen/` (new Rust crate)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-spec-validate/` (new binary, P1.T6)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/python/chio-sdk-python/src/chio_sdk/_generated/` (generated Python types)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/conformance/src/_generated/` (generated TS types)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/go/chio-go-http/scripts/regen-types.sh` (manual regen)
- `/Users/connor/Medica/backbay/standalone/arc/formal/diff-tests/tests/canonical_json_diff.rs` (new differential, >= 6 invariants)
- `/Users/connor/Medica/backbay/standalone/arc/formal/diff-tests/tests/receipt_encoding_diff.rs` (new differential, >= 4 invariants)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/tests/schema_validate_live.rs` (new, +1 to the existing 17)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/tests/vectors_oracle.rs` (new)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/tests/vectors_schema_pair.rs` (new)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/tests/cpp_peer_p0.rs` (new)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/peers.lock.toml` (new, P4.T4)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-cli/src/cli/conformance.rs` (new)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-cli/tests/conformance_cli.rs` (new)
- `/Users/connor/Medica/backbay/standalone/arc/.github/workflows/spec-drift.yml` (CI gate, 5 jobs)
- `/Users/connor/Medica/backbay/standalone/arc/.github/workflows/conformance-matrix.yml` (CI gate, 2 jobs incl. nightly)
- `/Users/connor/Medica/backbay/standalone/arc/.github/workflows/vectors-staleness.yml` (nightly, P2 staleness alarm)
- `/Users/connor/Medica/backbay/standalone/arc/tests/bindings/vectors/MANIFEST.sha256` (new)
- `/Users/connor/Medica/backbay/standalone/arc/xtask/codegen-tools.lock.toml` (new, P3.T1)
- `/Users/connor/Medica/backbay/standalone/arc/docs/conformance.md` (standalone consumer docs)
- `/Users/connor/Medica/backbay/standalone/arc/docs/conformance-dashboard/` (static dashboard, P5)

Modified:

- `/Users/connor/Medica/backbay/standalone/arc/spec/schemas/chio-wire/v1/README.md` (drop the "out-of-band" disclaimer; document the new subtrees)
- `/Users/connor/Medica/backbay/standalone/arc/tests/bindings/vectors/{canonical,manifest,receipt,capability,hashing,signing}/v1.json` (each grows to >= 20 cases)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/python/chio-sdk-python/src/chio_sdk/models.py` (reduce 575-line hand-written file to a re-export from `_generated`; original preserved as `models_legacy.py` for one cycle)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/typescript/packages/conformance/src/index.ts` (re-export from `_generated/`; leave `canonical.ts` 73-line encoder untouched)
- `/Users/connor/Medica/backbay/standalone/arc/sdks/go/chio-go-http/types.go` (147-line file becomes header-stamped generated file)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/Cargo.toml` (publishable shape)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-conformance/src/{runner,model,load}.rs` (consume generated types)
- `/Users/connor/Medica/backbay/standalone/arc/crates/chio-cli/src/cli/dispatch.rs` (register `conformance` subcommand)

## Open questions (all locked Wave 1, 2026-04-25)

1. **Codegen toolchain primary per language.** Locked: `typify` (Rust), `datamodel-code-generator` (Python), `json-schema-to-typescript` (TS), `oapi-codegen` (Go), `kotlinx-serialization` (Kotlin, M01+1), `Microsoft.Json.Schema.ToDotNet` (C#, M01+1).
2. **`chio-core-types` direction.** Locked: byte-semantics oracle. Schema codegen output is asserted to be a structural superset; full inversion deferred to a later milestone.
3. **Vector format granularity.** Locked: keep single `v1.json` per domain; 20 cases per domain is reviewable.
4. **Conformance crate publish target.** Locked: crates.io as `chio-conformance` at `0.1.0`, ratchet through `0.x` until wire stabilizes at v1.
5. **C++ kernel coverage scope.** Locked: P0 = `mcp_core`, `auth`. Deferred = `chio-extensions`, `tasks`, `nested_callbacks`, `notifications`.
