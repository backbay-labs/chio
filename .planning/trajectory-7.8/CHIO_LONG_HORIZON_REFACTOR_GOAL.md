# Chio Long Horizon Refactor Goal

Use this plan after the Chio Orchestration/Treaty P2 Closure pass completes.

Repo: this repository
PR: `https://github.com/bb-connor/arc/pull/683`
Branch: `codex/chio-7-8-live-treaty-buyer-closure`

Do not merge the PR unless explicitly instructed.

## Mission

Perform the long-horizon Chio architecture hardening and refactor pass. This is not cosmetic cleanup. The objective is to make the Chio implementation read and behave like a principal-engineer Rust system: typed invariants, small coherent modules, fail-closed verifier boundaries, thin CLI glue, maintainable test surfaces, and clear ownership across runtime, kernel, federation, schemas, examples, scripts, and docs.

## Prior Goal Gate

Before starting this refactor, verify the previous goal actually completed:

1. Run `git status --short --branch`.
2. Query fresh unresolved non-outdated review threads for PR #683.
3. Inspect fresh PR checks.
4. Confirm no actionable P0/P1/P2 review threads remain from treaty/orchestration closure.
5. Re-run or inspect local validation evidence from the previous goal.
6. If P0/P1/P2 correctness gaps remain, stop this refactor goal and close those first.

## Operating Standard

- Work like a principal Rust engineer.
- Do not trust prior completion claims.
- Preserve behavior unless a fail-closed correction is justified and tested.
- Prefer typed domain APIs over `serde_json::Value` in security, proof, and evidence paths.
- Keep public APIs stable where practical. If changing them is justified, migrate call sites cleanly.
- Avoid superficial wrapper modules. Extract around real ownership boundaries.
- Do not leave half-extracted code, duplicate validation logic, or temporary architecture.
- Keep commits and review chunks coherent.
- Push validated fixes back to PR #683.

## Architecture Goals

### 1. Decompose `chio-runtime-core`

Split `crates/chio-runtime-core/src/lib.rs` into real modules with clear responsibilities, preserving public re-exports where needed:

- `schema`: schema IDs, schema hash constants, schema manifest helpers.
- `error`: runtime error types and conversions.
- `types`: core Chio domain structs and enums.
- `store`: store traits and implementations, with submodules for memory, json, sqlite, and trust-floor state.
- `treaty`: treaty references, ladder intersection, treaty admission, treaty artifact verification.
- `buyer`: buyer review packages, buyer proof verification, buyer-facing reports.
- `orchestration`: runtime plans, resume/status/drift validation, run evidence, orchestration reports.
- `ops`: health, retention, provider status, runtime ops reports.
- `admission_hook`: kernel hook integration and fail-closed admission path.
- `pheromone_policy`: relay and pheromone policy evaluation.
- `validation`: shared typed validators used by runtime and CLI.

### 2. Move Core Validation Out Of CLI

`crates/chio-cli/src/cli/dispatch.rs` should parse args, read and write files, call runtime APIs, and render output. It should not own Chio security logic.

Move reusable invariants into `chio-runtime-core`, especially:

- orchestration evidence validation,
- status evidence validation,
- drift comparison and freshness checks,
- resume plan validation,
- buyer proof package validation,
- treaty artifact validation,
- schema/hash binding checks.

### 3. Reduce CLI Command Mass

Review `crates/chio-cli/src/cli/types.rs` and `crates/chio-cli/src/cli/dispatch.rs`.

- Split Chio command handling into dedicated CLI modules if the project pattern allows it.
- Keep command bodies small and boring.
- Remove duplicated JSON loading, hash checking, and report code.
- Preserve UX and output compatibility unless a change is clearly better and tested.

### 4. Harden Typed Proof And Evidence Boundaries

Audit Chio proof and buyer paths for ad hoc `.get()`, string field probing, loosely typed `serde_json::Value`, and duplicated hash checks.

- Introduce typed parsed envelopes where practical.
- Make schema ID and schema hash mismatches explicit errors.
- Ensure buyer-verifiable artifacts are checked through one canonical path.
- Ensure corrupt, stale, forged, missing, reordered, or cross-boundary evidence fails closed.

### 5. Clean Up Treaty And Federation Boundaries

Review `chio-federation` bilateral treaty and DSSE verification plus runtime call sites.

- Confirm strict DSSE verification has one clear library entrypoint.
- Confirm treaty ladder, bilateral, and quorum semantics cannot silently downgrade.
- Confirm buyer-facing verification and runtime admission use compatible rules.
- Remove duplicated or conflicting treaty verification logic.

### 6. Audit Kernel Admission Boundary

Review `chio-kernel` runtime admission hook integration.

- Preserve pre-dispatch fail-closed behavior.
- Ensure governed calls cannot bypass Chio admission.
- Ensure hook errors, missing hooks, stale treaty refs, consumed continuations, or invalid evidence deny access.
- Strengthen tests if the refactor touches this path.

### 7. Audit Scarcity And Economics Representation

Cross-check Chio scarcity docs against code.

- Keep economics claims honest: sqrt caps and newcomer discounts are sizing assumptions, not proofs.
- Ensure runtime admission and market/scarcity signals do not overclaim sybil resistance.
- Add explicit validation or docs where assumptions are currently implicit.

### 8. Keep Schemas And Manifests Honest

Review the active Chio schema domain directories under `spec/schemas/`.

- If semantics change, update schemas, schema hashes, fixtures, examples, and manifest references together.
- Add schema-negative tests for fields used in proof, treaty, buyer, and admission paths.
- Do not change schema names or hashes casually.

### 9. Improve Test And Fixture Architecture

The current Chio runtime test surface is too large.

- Split tests by invariant domain where practical: admission, treaty, buyer, orchestration, store, policy, and kernel hook.
- Keep fixtures typed and reusable.
- Add focused negative tests for each fail-closed invariant touched.
- Avoid giant opaque JSON blobs when typed builders can express the invariant.

### 10. Improve Scripts And Workflows

Review:

- `scripts/check-chio-runtime-spine.sh`
- `scripts/check-chio-live-treaty-buyer-closure.sh`
- `scripts/check-chio-treaty-buyer-hero-loop.sh`
- related GitHub Actions

Improve them where it materially helps:

- reduce duplicated shell/Python fixture generation,
- move complex validation into Rust APIs or tests,
- keep scripts as orchestration gates,
- make failure output precise,
- distinguish local branch failures from hosted Actions billing or spending-limit failures.

### 11. Clarify Loopback And Demo Boundaries

Review `chio-attest-loopback` and the CLI dependency on it.

- If loopback is a supported operator or demo command, make that boundary explicit.
- Keep deterministic keys and demo material out of generic production paths.
- Ensure examples and scripts use loopback intentionally, not accidentally.

### 12. Align Documentation With Code

Update docs only where code semantics or operator workflows change.

Cross-reference:

- `docs/research/CHIO_CONCEPT.md`
- `docs/research/CHIO_SCARCITY_ECONOMICS.md`
- `.planning/trajectory-7.8/*`
- relevant examples and workflow docs

Docs should describe actual implemented behavior, not aspirational features.

## Suggested Execution Order

1. Build a fresh gap map from current code, PR threads, CI, docs, and local tests.
2. Rank gaps P0/P1/P2/P3.
3. Fix any P0/P1/P2 correctness or security gap before refactoring.
4. Extract runtime modules with behavior-preserving moves.
5. Move CLI-owned invariants into typed runtime APIs.
6. Harden buyer, proof, treaty, typed verification where touched.
7. Split or tighten tests around the extracted domains.
8. Clean scripts and workflows only after the library/API boundary is stable.
9. Run full validation.
10. Push and re-check PR threads and CI.

## Required Validation

- `cargo fmt --all -- --check`
- `git diff --check`
- `rg '\x{2014}' <touched files>` and remove prohibited em dashes
- `cargo clippy -p chio-runtime-core -p chio-cli -p chio-federation -p chio-kernel --all-targets -- -D warnings`
- `cargo test -p chio-runtime-core`
- `cargo test -p chio-cli`
- `cargo test -p chio-federation`
- relevant `chio-kernel` tests
- Chio runtime spine script
- Chio live treaty buyer closure script
- any additional tests required by changed schemas, examples, or workflows
- fresh unresolved review-thread query
- fresh PR checks inspection

If GitHub Actions are blocked by billing or spending limits, say so explicitly and distinguish hosted-infra failure from branch regression. Use local gates as the working signal only when hosted failure is genuinely infrastructure.

## Completion Bar

- No actionable P0/P1/P2 Chio architecture, security, or correctness gaps remain.
- Runtime monolith is materially decomposed into coherent modules.
- CLI no longer owns core Chio validation logic.
- Proof, buyer, treaty, orchestration, and admission invariants are typed and fail closed where touched.
- Test surfaces are more maintainable and still cover critical negative cases.
- Scripts remain useful gates, not hidden implementations of core validation.
- Docs and schemas match implemented behavior.
- Local gates pass.
- Fixes are pushed to PR #683.

## Final Output Requirements

The final response must include:

- what changed architecturally,
- what correctness/security invariants were strengthened,
- remaining non-blocking P3 debt, if any,
- exact local validation run,
- PR review-thread state,
- PR/CI state,
- whether any hosted failures are infrastructure-only,
- a short recommendation for the next follow-up goal.
