# Chiodos Runtime Modularization Wave 2 Goal

Use this plan after the Orchestration/Treaty P2 Closure pass and the first long-horizon refactor pass have completed.

PR: `https://github.com/bb-connor/arc/pull/683`
Branch: `codex/chiodos-7-8-live-treaty-buyer-closure`

Do not merge the PR unless explicitly instructed.

## Mission

Continue Chiodos architecture hardening with a targeted second modularization wave. The goal is to remove the remaining high-risk concentration points left after the first extraction: runtime store contracts, treaty admission and hook logic, buyer proof verification, loopback harness code, CLI command mass, and oversized tests/scripts.

This is not cosmetic file shuffling. Extract only around real ownership boundaries, preserve behavior unless a fail-closed correction is justified, and keep all security, proof, treaty, buyer, admission, and orchestration invariants tested.

## Fresh State Gate

Before editing:

1. Run `git status --short --branch`.
2. Confirm the branch head matches the pushed PR branch.
3. Query fresh unresolved non-outdated review threads for PR #683.
4. Inspect fresh PR checks. If GitHub Actions jobs have no logs or no steps because hosted infrastructure is blocked, distinguish that from branch regressions.
5. Inspect current local module sizes with `wc -l` for:
   - `crates/chio-chiodos-runtime/src/lib.rs`
   - `crates/chio-chiodos-runtime/src/*.rs`
   - `crates/chio-cli/src/cli/dispatch.rs`
   - `crates/chio-cli/src/cli/types.rs`
   - `crates/chio-chiodos-runtime/tests/*.rs`
6. If any actionable P0/P1/P2 review thread remains, close it before doing broad refactor work.

## Current Review Findings To Address

### 1. Fail-Closed Store Trait Contract

`RuntimeAdmissionStore` still carries treaty replay methods with no-op defaults. The hook relies on `consume_treaty_continuation` to reserve treaty continuations before dispatch, so a custom store can accidentally compile with no continuation replay protection.

Fix direction:

- Remove silent no-op defaults for treaty continuation consume/release, or make unsupported operations return a rejected fail-closed error by default.
- Prefer splitting storage responsibilities into smaller traits if that keeps the contract honest:
  - admission bundle lookup,
  - treaty artifact lookup,
  - destructive lease reservation,
  - treaty continuation reservation,
  - trust-floor state.
- Keep bundled stores fully implemented.
- Add regression tests proving a store without treaty continuation support cannot admit treaty-bound continuations silently.

### 2. Extract Runtime Store Modules

The root runtime module still owns store traits and in-memory, JSON, trust-floor, and SQLite store implementations.

Target module layout:

- `src/store/mod.rs`
- `src/store/traits.rs`
- `src/store/memory.rs`
- `src/store/json.rs`
- `src/store/sqlite.rs`
- `src/store/trust_floor.rs`

Requirements:

- Preserve public re-exports from `lib.rs` where needed.
- Keep SQL schema and migrations contained in the SQLite module.
- Keep store validation helpers close to the store modules.
- Avoid changing persistence semantics unless the change is a fail-closed correction and tested.

### 3. Extract Treaty And Admission Hook Logic

Treaty parsing, request-context validation, treaty evidence loading, treaty admission, DSSE evidence verification, and kernel hook logic are still concentrated in `lib.rs`.

Target module layout:

- `src/treaty.rs`: ladder intersection, treaty scope validation, cross-boundary admission, treaty evidence review.
- `src/admission_hook.rs`: `ChiodosRuntimeAdmissionHook`, kernel metadata, reservation/release behavior.
- `src/request_context.rs` or equivalent: typed parsing for Chiodos admission/treaty context embedded in governed intents.

Requirements:

- Preserve pre-dispatch fail-closed behavior.
- Ensure federated Chiodos calls cannot bypass treaty context.
- Keep continuation reservation and release behavior explicit and tested.
- Ensure treaty ladder, bilateral, and quorum semantics cannot silently downgrade.

### 4. Type Buyer Proof Verification

Buyer review verification still relies on `serde_json::Value` and manual field probing for proof package and verifier report checks.

Target module layout:

- `src/buyer.rs`
- Optional submodules:
  - `buyer/artifacts.rs`
  - `buyer/proof.rs`
  - `buyer/report.rs`
  - `buyer/strict_dsse.rs`

Requirements:

- Introduce a typed hydrated buyer review artifact set.
- Parse proof packages through `chio_chiodos` typed APIs where possible.
- Keep raw JSON only where canonical hash preservation requires it.
- Replace ad hoc `.get()` field probing with typed helper APIs or small boundary adapters.
- Preserve all current negative cases: corrupt, missing, stale, forged, reordered, duplicate, cross-boundary, strict DSSE signer, and verifier report failures.

### 5. Move Loopback Harness Out Of CLI

`cmd_chiodos_runtime_run_loopback` remains a large local harness inside CLI dispatch. It owns scenario parsing, tool server setup, deterministic key material, treaty context construction, proof generation, parity checks, buyer packet creation, and artifact writing.

Fix direction:

- Move loopback execution into `chio-chiodos-loopback` or a dedicated harness module/crate.
- Expose a small typed API such as `run_runtime_loopback_scenario`.
- Keep CLI as argument parsing, path validation, API invocation, and report output.
- Keep deterministic demo keys and static fixture material clearly inside the loopback boundary.
- Preserve script and example behavior.

### 6. Reduce CLI Command Mass

`crates/chio-cli/src/cli/dispatch.rs` and `types.rs` still contain too much Chiodos-specific command surface.

Fix direction:

- Split Chiodos dispatch into dedicated CLI modules if the current CLI include pattern permits it:
  - `cli/chiodos/runtime.rs`
  - `cli/chiodos/treaty.rs`
  - `cli/chiodos/buyer.rs`
  - `cli/chiodos/pheromone.rs`
  - `cli/chiodos/authority.rs`
  - `cli/chiodos/loopback.rs`
- Keep command bodies small.
- Remove duplicated JSON loading, hashing, path validation, report writing, and error wrapping where practical.
- Do not alter user-visible CLI behavior unless there is a tested reason.

### 7. Split Tests By Invariant Domain

`runtime_admission.rs` still covers admission, stores, treaty, kernel hook, pheromone, buyer, DSSE, and fixtures in one file.

Target test layout:

- `tests/runtime_admission.rs`
- `tests/runtime_store.rs`
- `tests/runtime_treaty.rs`
- `tests/runtime_kernel_hook.rs`
- `tests/runtime_pheromone_policy.rs`
- `tests/runtime_buyer_review.rs`
- `tests/runtime_orchestration.rs`

Requirements:

- Move tests with behavior-preserving extraction first.
- Keep reusable fixtures typed.
- Avoid giant opaque JSON blobs when typed builders can express the invariant.
- Add focused tests for every fail-closed contract touched.

### 8. Shrink Script Validation Logic

Chiodos shell gates are large and contain complex fixture generation. They should orchestrate checks, not become hidden implementations of runtime behavior.

Focus scripts:

- `scripts/check-chiodos-runtime-spine.sh`
- `scripts/check-chiodos-treaty-buyer-hero-loop.sh`
- `scripts/check-chiodos-runtime-orchestration.sh`
- `scripts/check-chiodos-runtime-ops-hardening.sh`
- `scripts/check-chiodos-treaty-bound-provenance.sh`

Fix direction:

- Move complex validation into Rust library APIs or integration tests where practical.
- Keep scripts as stable operator gates.
- Preserve script names and CI entrypoints.
- Improve failure output when changing scripts.

## Suggested Execution Order

1. Re-check PR threads and CI state.
2. Fix the fail-closed store trait contract first.
3. Extract store modules and keep public re-exports stable.
4. Extract treaty and admission hook modules.
5. Type buyer review verification and move it into a buyer module.
6. Move loopback harness out of CLI.
7. Split tests along the extracted domains.
8. Reduce CLI module mass after core logic is moved.
9. Shrink script validation logic only after library boundaries are stable.
10. Run full local validation and push.

## Required Validation

- `cargo fmt --all -- --check`
- `git diff --check`
- `rg '\x{2014}' <touched files>` and remove prohibited em dashes
- `cargo clippy -p chio-chiodos-runtime -p chio-cli -p chio-chiodos-loopback -p chio-federation -p chio-kernel --all-targets -- -D warnings`
- `cargo test -p chio-chiodos-runtime`
- `cargo test -p chio-chiodos-loopback`
- relevant `chio-cli` tests or command integration tests
- relevant `chio-federation` tests for DSSE/treaty paths touched
- relevant `chio-kernel` runtime admission hook tests
- `scripts/check-chiodos-runtime-spine.sh`
- `scripts/check-chiodos-live-treaty-buyer-closure.sh`
- additional Chiodos scripts touched by the refactor
- fresh unresolved non-outdated PR review-thread query
- fresh PR checks inspection

If hosted Actions are blocked by billing, spending limits, or no-log runner startup failure, state that explicitly and use local gates as the working signal only when the hosted failure is genuinely infrastructure.

## Completion Bar

- No actionable P0/P1/P2 Chiodos architecture, security, or correctness gaps remain in the touched areas.
- Store trait contracts fail closed by default.
- Runtime store code is extracted into coherent modules.
- Treaty and admission hook code have clear module ownership.
- Buyer review verification is materially more typed.
- CLI no longer owns the loopback harness internals.
- CLI Chiodos command code is smaller and less duplicated.
- Tests are split by invariant domain where practical.
- Scripts remain gates, not hidden validators.
- Local gates pass.
- Fixes are pushed to PR #683.

## Final Output Requirements

The final response must include:

- what changed architecturally,
- what fail-closed invariants were strengthened,
- what tests moved or were added,
- exact local validation run,
- PR review-thread state,
- PR/CI state,
- whether hosted failures are infrastructure-only,
- remaining non-blocking P3 debt,
- recommended next follow-up goal.
