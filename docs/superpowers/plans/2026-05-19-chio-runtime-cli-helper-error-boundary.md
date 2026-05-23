# Chio Runtime CLI Helper Error Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Ensure CLI-facing `chio-runtime` helper functions return `ChioRuntimeError` instead of exposing `chio_runtime_core::ChioRuntimeError`.

**Architecture:** Keep the historical runtime implementation as the private execution backend for this slice, but stop direct public reexports for fallible helper functions used by `chio-cli` runtime dispatch. Add thin facade wrappers with identical function names and Chio-owned errors so downstream callers can use Chio namespace APIs without binding to historical error types.

**Tech Stack:** Rust workspace crates `chio-runtime`, `chio-cli`, and `chio-runtime-core`; standard Rust unit tests; Cargo test, clippy, fmt, and diff hygiene checks.

---

### Task 1: Runtime Facade Boundary Regression Tests

**Files:**
- Modify: `crates/chio-runtime/tests/runtime_boundary.rs`

- [x] **Step 1: Write the failing tests**

Add tests that fail while `runtime_admission_profile_from_json`, `runtime_orchestration_profile_from_json`, and `runtime_peer_weights_sha256` are direct historical reexports:

```rust
#[test]
fn runtime_cli_helper_parsers_return_chio_errors() {
    let admission_error = match chio_runtime::runtime_admission_profile_from_json("{") {
        Ok(_) => panic!("invalid runtime admission profile JSON should fail"),
        Err(error) => error,
    };
    assert_eq!(
        std::any::type_name_of_val(&admission_error),
        "chio_runtime::ChioRuntimeError"
    );
    assert_eq!(admission_error.code(), "runtime_admission_json");

    let orchestration_error = match chio_runtime::runtime_orchestration_profile_from_json("{") {
        Ok(_) => panic!("invalid runtime orchestration profile JSON should fail"),
        Err(error) => error,
    };
    assert_eq!(
        std::any::type_name_of_val(&orchestration_error),
        "chio_runtime::ChioRuntimeError"
    );
    assert_eq!(orchestration_error.code(), "runtime_admission_json");
}

#[test]
fn runtime_cli_hash_helpers_return_chio_errors() {
    let weights = chio_runtime::RuntimePeerWeights {
        schema: chio_runtime::CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
        issuer_id: "issuer-1".to_string(),
        issued_at_unix_ms: 1,
        expires_at_unix_ms: 2,
        weights: vec![chio_runtime::RuntimePeerWeight {
            peer_id: "peer-1".to_string(),
            weight: f64::NAN,
        }],
    };

    let error = match chio_runtime::runtime_peer_weights_sha256(&weights) {
        Ok(_) => panic!("non-finite runtime peer weight should fail canonical hashing"),
        Err(error) => error,
    };
    assert_eq!(
        std::any::type_name_of_val(&error),
        "chio_runtime::ChioRuntimeError"
    );
    assert_eq!(error.code(), "runtime_admission_canonical");
}

#[test]
fn runtime_cli_helper_reexports_are_not_historical_error_reexports() {
    let lib = include_str!("../src/lib.rs");
    for helper in [
        "runtime_admission_profile_from_json",
        "runtime_admission_bundle_from_json",
        "runtime_request_binding_from_json",
        "runtime_orchestration_profile_from_json",
        "runtime_run_contract_from_json",
        "runtime_supervisor_profile_from_json",
        "runtime_artifact_retention_profile_from_json",
        "runtime_provider_bindings_from_json",
        "runtime_peer_weights_sha256",
        "runtime_orchestration_profile_sha256",
        "runtime_run_contract_sha256",
        "evaluate_runtime_admission",
        "build_runtime_orchestration_plan",
    ] {
        assert!(
            !lib.contains(&format!("    {helper},")),
            "{helper} must be wrapped by chio-runtime instead of direct-reexported"
        );
    }
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo test -p chio-runtime runtime_cli_helper -- --nocapture`

Expected: FAIL because the error type is still `chio_runtime_core::error::ChioRuntimeError` and the helpers are still listed in the direct `pub use chio_runtime_core::{ ... }` block.

### Task 2: Runtime Facade Wrappers

**Files:**
- Modify: `crates/chio-runtime/src/lib.rs`

- [x] **Step 1: Remove selected helpers from the historical reexport block**

Remove these names from `pub use chio_runtime_core::{ ... }`:

```rust
build_runtime_orchestration_plan
evaluate_runtime_admission
generate_runtime_artifact_retention_plan
generate_runtime_evidence_sink_health_report
generate_runtime_proof_drift_report
generate_runtime_provider_health_report
load_runtime_orchestration_evidence
runtime_admission_bundle_from_json
runtime_admission_profile_from_json
runtime_admission_report_json
runtime_artifact_retention_plan_json
runtime_artifact_retention_profile_from_json
runtime_evidence_manifest_json
runtime_evidence_sink_health_report_json
runtime_ops_status_report_json
runtime_orchestration_plan_json
runtime_orchestration_profile_from_json
runtime_orchestration_profile_sha256
runtime_orchestration_resume_plan_json
runtime_orchestration_run_report_json
runtime_orchestration_status_report_json
runtime_peer_weights_sha256
runtime_pheromone_advisory_from_query_report_json
runtime_proof_drift_report_json
runtime_proof_parity_report_json
runtime_proof_regeneration_input_json
runtime_proof_regeneration_report_json
runtime_provider_bindings_from_json
runtime_provider_health_report_json
runtime_recovery_drill_report_json
runtime_request_binding_from_json
runtime_run_contract_from_json
runtime_run_contract_sha256
runtime_scheduler_tick_report_json
runtime_supervisor_profile_from_json
runtime_supervisor_profile_sha256
runtime_trusted_verifier_keys_from_json
runtime_workflow_run_report_json
sign_runtime_admission_report
signed_runtime_admission_report_from_json
signed_runtime_admission_report_json
signed_runtime_peer_weights_from_json
signed_runtime_pheromone_policy_from_json
signed_runtime_pheromone_query_report_from_json
signed_runtime_pheromone_query_report_json
signed_runtime_verifier_trust_bundle_from_json
validate_runtime_artifact_retention_plan
validate_runtime_artifact_retention_profile
validate_runtime_evidence_manifest
validate_runtime_evidence_sink_health_report
validate_runtime_ops_status_report
validate_runtime_orchestration_plan
validate_runtime_orchestration_profile
validate_runtime_orchestration_profile_fresh
validate_runtime_orchestration_resume_plan
validate_runtime_orchestration_run_report
validate_runtime_orchestration_status_report
validate_runtime_proof_drift_report
validate_runtime_proof_parity_report
validate_runtime_proof_regeneration_input
validate_runtime_proof_regeneration_report
validate_runtime_provider_bindings
validate_runtime_provider_health_report
validate_runtime_recovery_drill_report
validate_runtime_run_contract
validate_runtime_run_lease
validate_runtime_scheduler_tick_report
validate_runtime_supervisor_profile
validate_runtime_workflow_run_report
verify_signed_runtime_admission_report
```

- [x] **Step 2: Add private conversion from historical errors**

Add the private method:

```rust
impl ChioRuntimeError {
    fn from_historical(source: HistoricalRuntimeError) -> Self {
        Self {
            code: source.code(),
            source,
        }
    }
}
```

- [x] **Step 3: Add thin wrappers**

For each removed function, add a wrapper with the same parameters and return type, replacing `HistoricalRuntimeError` with `ChioRuntimeError`:

```rust
pub fn runtime_admission_profile_from_json(
    json: &str,
) -> Result<RuntimeAdmissionProfile, ChioRuntimeError> {
    chio_runtime_core::runtime_admission_profile_from_json(json)
        .map_err(ChioRuntimeError::from_historical)
}
```

Apply the same pattern for the other removed helpers. For helpers returning `Result<_, RuntimeOrchestrationEvidenceFailure>`, leave them reexported because they already expose their own non-historical failure type.

- [x] **Step 4: Run the focused runtime test**

Run: `cargo test -p chio-runtime runtime_cli_helper -- --nocapture`

Expected: PASS.

### Task 3: Architecture Evidence Update

**Files:**
- Modify: `docs/architecture/CHIO_FINAL_ARCHITECTURE.md`

- [x] **Step 1: Update runtime boundary evidence**

Add a concise note to the runtime facade evidence section:

```markdown
- CLI-facing runtime facade helpers now return `chio_runtime::ChioRuntimeError` through thin wrappers instead of direct-reexporting historical fallible helper signatures.
```

- [x] **Step 2: Run doc and source hygiene checks**

Run: `rg -n $'\xE2\x80\x94|\xE2\x80\x93' crates/chio-runtime/src/lib.rs crates/chio-runtime/tests/runtime_boundary.rs docs/architecture/CHIO_FINAL_ARCHITECTURE.md docs/superpowers/plans/2026-05-19-chio-runtime-cli-helper-error-boundary.md`

Expected: no matches, exit 1.

### Task 4: Verification

**Files:**
- Test: `crates/chio-runtime/tests/runtime_boundary.rs`
- Test through caller: `crates/chio-cli/src/cli/chio/dispatch/runtime/*.rs`

- [x] **Step 1: Run targeted runtime tests**

Run: `cargo test -p chio-runtime`

Expected: PASS.

- [x] **Step 2: Run targeted CLI runtime tests**

Run: `cargo test -p chio-cli --bin chio_runtime`

Expected: PASS.

- [x] **Step 3: Run clippy checks**

Run: `cargo clippy -p chio-runtime --all-targets -- -D warnings`

Expected: PASS.

Run: `cargo clippy -p chio-cli --bin chio -- -D warnings`

Expected: PASS.

- [x] **Step 4: Run workspace formatting check**

Run: `cargo fmt --all -- --check`

Expected: PASS.

- [x] **Step 5: Run diff hygiene**

Run: `git diff --check`

Expected: PASS.

- [x] **Step 6: Confirm selected helpers are no longer direct historical reexports**

Run: `rg -n "runtime_admission_profile_from_json|runtime_orchestration_profile_from_json|runtime_peer_weights_sha256" crates/chio-runtime/src/lib.rs`

Expected: Each helper appears in wrapper definitions, not as an item in the `pub use chio_runtime_core::{ ... }` list.
