# Kernel Bench Stub Foundation Plan

> **For agentic workers:** This is a planning artifact for PR 652 follow-up work. It does not authorize latency claims and does not implement benchmark repairs in this docs-only PR.

**Goal:** Replace the 11 stubbed `chio-kernel` Criterion benches with real measured paths, add feature gating where benches depend on optional crates, and capture a baseline before any latency-sensitive planning cites benchmark data.

**Scope:** `crates/chio-kernel/benches/*`, `crates/chio-kernel/Cargo.toml`, CI bench wiring, and research docs that make latency-sensitive claims.

**Non-goals:** Adapter implementation, voice implementation, Cedar migration, hybrid signing optimization, or any new public API.

## Current Finding

PR 652 review found 11 kernel benches that still measure `black_box(0_u64)`:

- `single_guard.rs`
- `cap_verify_ed25519.rs`
- `receipt_sign.rs`
- `guard_pipeline_5.rs`
- `scope_match.rs`
- `time_bound.rs`
- `revocation_lookup.rs`
- `budget_decrement.rs`
- `receipt_append.rs`
- `session_lookup.rs`
- `dispatch_deny.rs`

Until those benches exercise real kernel paths, latency-sensitive tickets must not cite them.

## Task 1: Inventory And Feature Gating

- [ ] Confirm the exact stub list with `rg 'black_box\\(0_u64\\)' crates/chio-kernel/benches`.
- [ ] For each bench, document the real code path, required fixture data, optional features, and setup that must stay outside the measured loop.
- [ ] Add `required-features` entries in `crates/chio-kernel/Cargo.toml` for benches that need optional signing, storage, or guard features.
- [ ] Update CI or local bench runbooks so gated benches are skipped cleanly when features are unavailable.

Acceptance criteria:

- [ ] Every bench has a named real code path.
- [ ] No bench silently runs a stub because an optional feature is absent.
- [ ] The bench inventory names any bench that cannot be repaired without a separate code change.

## Task 2: Replace Stub Bodies

Implementation principles:

- Measure the narrow operation named by the bench.
- Use deterministic local fixtures.
- Keep network, sleeps, random key generation, file creation, and policy compilation outside `b.iter`.
- Prefer existing constructors, guards, stores, and receipt signers over test-only shortcuts.
- Preserve fail-closed behavior in setup rather than bypassing validation for speed.

Required replacements:

| Bench | Real path to measure |
|---|---|
| `single_guard.rs` | One guard evaluation over a representative tool call. |
| `cap_verify_ed25519.rs` | Ed25519 capability verification with a prebuilt token and key. |
| `receipt_sign.rs` | Canonical receipt body signing with deterministic payload. |
| `guard_pipeline_5.rs` | Five-guard pipeline over one allowed and one denied tool call case. |
| `scope_match.rs` | Scope matching against realistic nested scope entries. |
| `time_bound.rs` | Time-window validation for valid, expired, and future capabilities. |
| `revocation_lookup.rs` | Revocation lookup against an initialized local revocation store. |
| `budget_decrement.rs` | Budget decrement with success and exhausted-budget cases. |
| `receipt_append.rs` | Append to the configured receipt store without reinitializing the store inside the loop. |
| `session_lookup.rs` | Session lookup from the kernel session store with existing session state. |
| `dispatch_deny.rs` | Denied dispatch through the normal kernel pre-dispatch path. |

Acceptance criteria:

- [ ] `rg 'black_box\\(0_u64\\)' crates/chio-kernel/benches` returns no matches.
- [ ] Each bench includes at least one setup assertion that proves the measured fixture is valid.
- [ ] Deny-path benches assert the denial reason outside the measured loop.

## Task 3: Baseline Capture

- [ ] Run the repaired benches locally with the minimal feature set needed for all 11 benches.
- [ ] Capture baseline output in the follow-up PR notes, including host, Rust toolchain, feature set, and command line.
- [ ] If CI supports bench artifacts, attach Criterion reports. If not, record local baseline numbers as non-release evidence until CI bench capture exists.
- [ ] Update any protocol-strategy docs that currently imply measured latency and mark them as blocked on this baseline.

Suggested commands:

```bash
rg 'black_box\(0_u64\)' crates/chio-kernel/benches
cargo bench -p chio-kernel
git diff --check
```

Acceptance criteria:

- [ ] Bench results are real enough to cite in latency-sensitive planning.
- [ ] Latency claims name the exact bench commit and feature set.
- [ ] Voice, Cedar latency, async receipt durability, and hybrid signing plans remain blocked until this baseline exists.

## Ticket Gate

Any implementation ticket that depends on these benches must include:

- `boundary_class` and `planning_status` if it touches a trust boundary.
- The receipt schema emitted by the path.
- Verifier downgrade behavior.
- Mediated, trace-only, or advisory-only posture.
- The real bench name, command, commit, and feature set.
