# Chio P3 Modular Polish Goal

## Current State

PR: #683
Branch: `codex/chio-7-8-live-treaty-buyer-closure`
Reviewed head: `7b3283fcb9a9746c3b516c74f567e724d9df5fa6`

The Chio P0, P1, and P2 behavior work is treated as closed unless a fresh
first-principles review finds a real fail-closed, proof, economics, treaty,
buyer, scarcity, admission, or runtime regression. This goal is intentionally a
P3 modular-polish pass. It should improve maintainability without weakening the
security model or changing public semantics.

Live review state at goal creation:

- Worktree was clean at reviewed head.
- Non-outdated unresolved review threads were not found.
- Cursor Bugbot was green after the latest pass.
- Hosted Actions remained red with zero-step jobs that failed within seconds.
  Treat hosted CI as infrastructure-blocked unless fresh logs show a real branch
  regression. Local gates remain the working signal.

## Mission

Finish the next Chio architecture cleanup pass:

1. Split the remaining large Chio pheromone CLI dispatch and type files into
   focused modules.
2. Move the remaining runtime `lib.rs` serialization, validation, admission,
   hash, ops, and pheromone-policy clusters into narrower runtime modules while
   preserving public API compatibility.
3. Shrink the runtime spine shell gate so checked-in fixtures carry data and the
   script only orchestrates validation.
4. Preserve all current Chio fail-closed behavior and regression coverage.

Do not merge the PR.

## Review Findings To Close

### P3: Pheromone CLI Dispatch Still Has Too Many Responsibilities

`crates/chio-cli/src/cli/chio/dispatch/pheromone.rs` is about 2156 lines and
still combines all of these concerns:

- Runtime receive and query commands.
- Relay lint, serve, enqueue, tick, catchup, status, observe, metrics, and trend
  commands.
- Alert evaluate, handoff, normalize, review, delivery, drift, and window
  commands.
- Assurance package, export, verify, replay, retention, recovery, archive, and
  closeout commands.
- Directory inspection, promotion, rejection, and supervisor linting.
- Local JSON, path, hash, and report helpers.

Recommended split:

- `crates/chio-cli/src/cli/chio/dispatch/pheromone.rs`
  - Keep as a small aggregator and command router.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/runtime.rs`
  - Receive and query.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/relay.rs`
  - Relay lint, serve, enqueue, tick, catchup, status, observe, metrics, and
    trend.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/alerts.rs`
  - Alert evaluate, handoff, normalize, and review.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/delivery.rs`
  - Delivery import, ack, drift, and window handling.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/assurance.rs`
  - Assurance package, export, verify, replay, retention, recovery, archive,
    and closeout.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/directory.rs`
  - Directory inspect, promote, reject, supervisor lint, and peer directory
    helpers.
- `crates/chio-cli/src/cli/chio/dispatch/pheromone/io.rs`
  - Shared JSON, file, path, hash, and report helpers.

Keep helpers private to their domain module unless they are genuinely shared.
Avoid generic utility dumping grounds.

### P3: Pheromone CLI Types Are Also Still Dense

`crates/chio-cli/src/cli/chio/types/pheromone.rs` is about 984 lines and
tracks the same command families as dispatch. Split only if it reduces real
coupling and does not make clap annotations harder to follow.

Suggested type modules:

- `types/pheromone.rs` as a small aggregator.
- `types/pheromone/root.rs`
- `types/pheromone/relay.rs`
- `types/pheromone/alerts.rs`
- `types/pheromone/delivery.rs`
- `types/pheromone/assurance.rs`
- `types/pheromone/directory.rs`

The rule is readability, not a target line count. Preserve command names,
arguments, aliases, defaults, and help text exactly unless a bug is found.

### P3: Runtime `lib.rs` Is Still A Runtime Core Monolith

`crates/chio-runtime-core/src/lib.rs` is about 2797 lines. It already has
major domains extracted, but still owns too many independent clusters:

- `*_from_json` and `*_json` parsing and writing helpers.
- Runtime orchestration plan and operational report generation.
- Runtime proof drift, evidence sink health, provider health, artifact
  retention, ops status, and validation logic.
- Runtime admission input and evaluation.
- Runtime trust input and trust-floor transition validation.
- Runtime pheromone advisory parsing and policy evaluation.
- Canonical hash helpers, typed JSON extraction helpers, and generic validation
  helpers.

Recommended split:

- `crates/chio-runtime-core/src/serde_io.rs`
  - Public and crate-visible JSON parse/write entrypoints.
- `crates/chio-runtime-core/src/hash.rs`
  - Canonical SHA-256 and hash validation helpers.
- `crates/chio-runtime-core/src/validation.rs`
  - Shared validators for labels, non-empty strings, monotonic values, expiry,
    paths, and hash formats.
- `crates/chio-runtime-core/src/admission.rs`
  - `RuntimeAdmissionInput`, runtime admission evaluation, trust input
    validation, and trust-floor transition validation.
- `crates/chio-runtime-core/src/pheromone_policy.rs`
  - Runtime pheromone advisory parsing and runtime policy evaluation.
- `crates/chio-runtime-core/src/ops.rs`
  - Evidence sink health, provider health, retention, proof drift, and ops
    status report generation plus their validators.

Keep `lib.rs` as the public surface and orchestration of exports. Preserve all
existing public functions, type names, and error variants unless a rename is
unambiguously internal.

### P3: Runtime Admission Tests Still Carry Mixed Domains

`crates/chio-runtime-core/tests/runtime_admission.rs` is about 2702 lines.
It still appears to contain mixed admission, treaty continuation, runtime trust,
ops, and fixture support logic.

Recommended split:

- Keep admission-only tests in `runtime_admission.rs`.
- Move trust input and trust-floor transition cases into
  `runtime_trust.rs` if the file does not already exist.
- Move ops, evidence sink, provider health, retention, and drift cases into
  `runtime_ops.rs`.
- Move shared fixture builders into `tests/support/` only if duplication becomes
  meaningful. Do not create a support abstraction for one or two call sites.

All negative tests that prove fail-closed behavior must remain as specific and
readable as they are now.

### P3: Runtime Spine Gate Still Embeds Too Much Fixture Data

`scripts/check-chio-runtime-spine.sh` is about 825 lines and still writes
large inline JSON fixtures. The treaty buyer hero-loop script is now correctly
small and fixture-driven; apply that pattern here.

Recommended split:

- Move static fixture JSON into a checked-in fixture directory, preferably under
  `examples/chio-3vendor/fixtures/runtime-spine/` unless the runtime harness
  already has a better local convention.
- Keep generated per-run files in the temp directory only when the data is
  genuinely dynamic.
- Keep shell responsible for wiring commands together, asserting exit codes,
  and comparing expected artifacts.
- Avoid embedding Python validators unless a Rust command or checked-in fixture
  cannot express the invariant.

## Optional Inventory Only

`crates/chio-pheromone-relay/src/lib.rs` is about 8511 lines and
`crates/chio-pheromone-relay/tests/relay.rs` is about 2915 lines. This is likely
the next major architecture target after the CLI/runtime P3 polish. Do not
refactor it in this goal unless the pheromone CLI split exposes a small,
obviously safe extraction with focused tests.

## Guardrails

- Preserve all Chio runtime, treaty, buyer, economics, scarcity, DSSE,
  evidence, and admission semantics unless a new defect is proven.
- Maintain fail-closed behavior on malformed inputs, missing evidence, forged
  evidence, stale evidence, manifest drift, quorum downgrade, replay, and buyer
  proof failures.
- Do not add superficial wrapper modules. Each module should own a coherent
  domain.
- Do not introduce new public API churn for line-count reasons.
- Do not use `unwrap` or `expect`.
- Do not add em dashes in code, comments, docs, or shell output assertions.
- Do not merge PR #683.

## Validation Required

Run at minimum:

```bash
cargo fmt --all -- --check
git diff --check
rg '\x{2014}' <touched files>
cargo clippy -p chio-cli -p chio-runtime-core -p chio-runtime-harness -p chio-attest-loopback -p chio-federation -p chio-kernel --all-targets -- -D warnings
cargo test -p chio-runtime-core
cargo test -p chio-attest-loopback
cargo test -p chio-cli chio_
cargo test -p chio-federation strict_chio_treaty_review_binds_live_material --lib
cargo test -p chio-kernel chio_runtime_admission --lib
scripts/check-chio-runtime-spine.sh
scripts/check-chio-live-treaty-buyer-closure.sh
scripts/check-chio-treaty-buyer-hero-loop.sh
```

Also run any narrower tests for files touched during the split. If schema
semantics change, update schemas and manifest hashes, but this goal should
normally avoid schema semantics changes.

Before declaring completion, inspect:

- Fresh PR #683 review threads.
- Fresh PR #683 checks.
- Cursor Bugbot and Codex review state.

If Actions still fail with empty jobs and no runner steps, classify that as
hosted infrastructure failure and report local gates separately.

## Completion Bar

Stop only when:

- The listed P3 modularity issues are closed or explicitly deferred with a
  concrete reason.
- No fresh P0, P1, or P2 Chio behavior issue is discovered.
- Local validation passes.
- PR #683 has no actionable current review thread.
- The final report names any remaining P3 or next-horizon architecture debt,
  especially the pheromone relay crate if it remains untouched.
