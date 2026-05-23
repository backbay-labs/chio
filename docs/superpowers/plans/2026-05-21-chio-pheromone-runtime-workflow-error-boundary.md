# Chio Pheromone Runtime Workflow Error Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop `chio-pheromone-runtime` from exposing the historical proof package error type through its public workflow verification error boundary.

**Architecture:** The Chio pheromone runtime may still call the historical proof package verifier for read-only signed artifact validation while the deeper crate split continues. That implementation detail must stay behind a Chio-owned runtime error boundary. Public receiver APIs and public error variants should speak Chio workflow verification, not Chio verifier internals.

**Tech Stack:** Rust integration tests, `chio-pheromone-runtime`, cargo test filters, source-level public API guard tests.

---

### Task 1: Add A Red Public-Surface Guard

**Files:**
- Modify: `crates/chio-pheromone-runtime/tests/public_surface.rs`

- [x] **Step 1: Assert workflow verification errors are Chio-owned**

Add a test that scans `../src/lib.rs` and fails when public error variants or
public signatures expose historical `Chio*` verifier types.

- [x] **Step 2: Run the focused test and verify red**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-pheromone-runtime --test public_surface chio_pheromone_runtime_workflow_verification_error_is_chio_owned -- --nocapture
```

Expected: fail before implementation because `WorkflowVerification` exposes
`ChioPackageError`.

### Task 2: Hide Historical Verifier Errors Behind Chio Runtime

**Files:**
- Modify: `crates/chio-pheromone-runtime/src/lib.rs`

- [x] **Step 1: Replace the public historical error payload**

Change `PheromoneRuntimeError::WorkflowVerification` so it stores a Chio-owned
message rather than `ChioPackageError`.

- [x] **Step 2: Convert verifier failures explicitly**

Keep `verify_package` as an internal implementation call, but convert verifier
errors into `PheromoneRuntimeError::WorkflowVerification(error.to_string())`.

- [x] **Step 3: Preserve the Chio resolver surface**

Do not rename `VerifiedChioWorkflowResolver` or remove the existing successful
workflow evidence path in this slice.

### Task 3: Verify

**Files:**
- All files above

- [x] **Step 1: Run focused runtime tests**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-pheromone-runtime --test public_surface
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-pheromone-runtime
```

- [x] **Step 2: Run hygiene checks**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo clippy -p chio-pheromone-runtime --all-targets -- -D warnings
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo fmt --all -- --check
git diff --check
git diff --cached --check
rg -n 'WorkflowVerification\\(#\\[from\\] ChioPackageError\\)|pub .*ChioPackageError' crates/chio-pheromone-runtime/src/lib.rs
rg -n $'\xE2\x80\x94|\xE2\x80\x93' docs/superpowers/plans/2026-05-21-chio-pheromone-runtime-workflow-error-boundary.md crates/chio-pheromone-runtime/src/lib.rs crates/chio-pheromone-runtime/tests/public_surface.rs
```

Expected: all pass, except both `rg` checks exit 1 with no output.

### Task 4: Wire CLI Pheromone Dispatch Through Chio Wrappers

**Files:**
- Modify: `crates/chio-cli/src/cli/chio/dispatch/pheromone.rs`

- [x] **Step 1: Fix the CLI integration boundary exposed by focused tests**

Update `load_chio_verified_workflow_resolver` so the Chio CLI constructs
`ChioWorkflowProofPackage`, `ChioWorkflowVerifierTrustBundle`, and
`ChioWorkflowVerificationContext` instead of calling the historical verifier
parsers directly before invoking `VerifiedChioWorkflowResolver`.

- [x] **Step 2: Re-run the focused CLI tests that caught the break**

Run:

```bash
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-cli --test legacy_chio_cli -- --nocapture
CARGO_TARGET_DIR=/private/tmp/chio-985a-target cargo test -p chio-cli --bin chio_attest -- --nocapture
```

Expected: both pass after the dispatch fix.
