# Transaction Passport First Sprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the smallest verifier-grade Transaction Passport slice that can prove one governed tool call and fail for one real policy digest mismatch.

**Architecture:** Add schema and verifier support before adding UI. The first slice should create `chio.transaction-passport.v1`, `chio.transaction.evidence-graph.v1`, and `chio.transaction.verifier-report.v1` as registry-backed artifacts, then expose a minimal `chio proof verify` path over committed fixtures.

**Tech Stack:** Rust workspace, `serde`, `serde_json`, existing canonical JSON/signature helpers, `spec/schemas/registry.json`, `chio-core-types`, `chio-control-plane` or a new `chio-proof` module if owner review chooses a split.

---

## File Structure

Create or modify these paths:

- Create: `spec/schemas/chio-transaction/v1/transaction-passport.schema.json`
- Create: `spec/schemas/chio-transaction/v1/evidence-graph.schema.json`
- Create: `spec/schemas/chio-transaction/v1/verifier-report.schema.json`
- Modify: `spec/schemas/registry.json`
- Modify: `spec/schemas/MANIFEST.sha256`
- Modify: `scripts/check-chio-schema-registry.sh`
- Modify: `spec/registries/claim-registry.v1.json`
- Modify: `spec/registries/proof-manifest.v1.json`
- Modify: `crates/chio-core-types/src/signed_artifact.rs`
- Modify: `crates/chio-core-types/tests/signed_artifact_schema.rs`
- Create: `crates/chio-control-plane/src/transaction_passport.rs`
- Modify: `crates/chio-control-plane/src/lib.rs`
- Create: `crates/chio-control-plane/tests/transaction_passport.rs`
- Modify: `crates/chio-cli/src/cli/types.rs`
- Modify: `crates/chio-cli/src/cli/dispatch.rs`
- Create: `crates/chio-cli/src/cli/dispatch/proof.rs`
- Create: `crates/chio-cli/tests/proof_verify.rs`
- Create: `fixtures/chio-launch/minimal-passport/valid/transaction-passport.json`
- Create: `fixtures/chio-launch/minimal-passport/invalid-policy-digest-mismatch/transaction-passport.json`

Both `chio-control-plane` and `chio-cli` already have `chio-test-support` in dev-dependencies. Use `use chio_test_support::prelude::*;` in new tests rather than `.unwrap()` or `.expect()`.

## Task 1 - Register Schemas

- [ ] **Step 1: Add failing registry test**

Create or extend `crates/chio-core-types/tests/signed_artifact_schema.rs` with a test that asserts the three schema IDs are recognized by the signed-artifact compatibility gate. Follow local style in that test file if it intentionally keeps its existing clippy allowance; otherwise prefer `chio_test_support::prelude::*`.

```rust
use chio_test_support::prelude::*;

#[test]
fn transaction_passport_schemas_are_known() {
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.transaction-passport.v1"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.transaction.evidence-graph.v1"
    ));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        "chio.transaction.verifier-report.v1"
    ));
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p chio-core-types --test signed_artifact_schema transaction_passport_schemas_are_known
```

Expected: fail because the schema constants are not accepted.

- [ ] **Step 3: Add schema files, registry entries, manifest hashes, and script coverage**

Add minimal JSON schemas with required `schema`, `id`, `issued_at`, and digest fields. Add all three IDs to `spec/schemas/registry.json` using the existing fields: `schema`, `artifactKind`, `introducedBy`, and `schemaFile`. Update `spec/schemas/MANIFEST.sha256`. Add `spec/schemas/chio-transaction/` to the checked roots in `scripts/check-chio-schema-registry.sh`. Add constants and acceptance entries in `crates/chio-core-types/src/signed_artifact.rs`.

- [ ] **Step 4: Run the test again**

Run:

```bash
cargo test -p chio-core-types --test signed_artifact_schema transaction_passport_schemas_are_known
scripts/check-chio-schema-registry.sh
```

Expected: both pass.

- [ ] **Step 5: Add launch claim and proof manifest rows**

Add proposed rows for `claim.transaction.passport_root_verified`, `claim.transaction.evidence_graph_digest_bound`, and `claim.transaction.policy_digest_bound` in `spec/registries/claim-registry.v1.json`. Add matching entries in `spec/registries/proof-manifest.v1.json` that reference the new tests and fixtures.

## Task 2 - Fail Closed On Unknown Passport Schema

- [ ] **Step 1: Add failing verifier test**

Extend `crates/chio-control-plane/tests/transaction_passport.rs` with:

```rust
use chio_test_support::prelude::*;

#[test]
fn transaction_passport_rejects_unknown_schema_id() {
    let passport = chio_control_plane::transaction_passport::TransactionPassport {
        schema: "chio.transaction-passport.v999".to_string(),
        id: "passport-invalid-schema".to_string(),
        evidence_graph_sha256: "0".repeat(64),
        verifier_policy_sha256: "1".repeat(64),
    };

    let error = chio_control_plane::transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("unknown schema id must fail closed");
    assert!(error.to_string().contains("unsupported transaction passport schema"));
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p chio-control-plane --test transaction_passport transaction_passport_rejects_unknown_schema_id
```

Expected: fail because the module and types do not exist.

- [ ] **Step 3: Add minimal verifier module**

Create `crates/chio-control-plane/src/transaction_passport.rs`:

```rust
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const TRANSACTION_PASSPORT_SCHEMA_ID: &str = "chio.transaction-passport.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPassport {
    pub schema: String,
    pub id: String,
    pub evidence_graph_sha256: String,
    pub verifier_policy_sha256: String,
}

#[derive(Debug, Error)]
pub enum TransactionPassportError {
    #[error("unsupported transaction passport schema: {0}")]
    UnsupportedSchema(String),
}

pub fn verify_minimal_passport_schema(
    passport: &TransactionPassport,
) -> Result<(), TransactionPassportError> {
    if passport.schema != TRANSACTION_PASSPORT_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedSchema(
            passport.schema.clone(),
        ));
    }
    Ok(())
}
```

Export the module from `crates/chio-control-plane/src/lib.rs`.

- [ ] **Step 4: Run the test again**

Run:

```bash
cargo test -p chio-control-plane --test transaction_passport transaction_passport_rejects_unknown_schema_id
```

Expected: pass.

## Task 3 - Verify Minimal Digest Shape

- [ ] **Step 1: Add failing digest tests**

Add tests for invalid digest length and non-hex characters.

```rust
#[test]
fn transaction_passport_rejects_bad_digest_shape() {
    let mut passport = valid_minimal_passport();
    passport.evidence_graph_sha256 = "abc".to_string();

    let error = chio_control_plane::transaction_passport::verify_minimal_passport_schema(&passport)
        .test_expect_err("short digest must fail");
    assert!(error.to_string().contains("invalid evidence graph digest"));
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p chio-control-plane --test transaction_passport transaction_passport_rejects_bad_digest_shape
```

Expected: fail because digest validation is not implemented.

- [ ] **Step 3: Add digest validation**

Add a helper that requires exactly 64 ASCII hex characters for `evidence_graph_sha256` and `verifier_policy_sha256`. Return separate error messages naming the failing field.

- [ ] **Step 4: Run the test again**

Run:

```bash
cargo test -p chio-control-plane --test transaction_passport transaction_passport_rejects_bad_digest_shape
```

Expected: pass.

## Task 4 - Add CLI Verification Stub

- [ ] **Step 1: Add failing CLI test**

Create `crates/chio-cli/tests/proof_verify.rs` with a test that runs the binary against the valid fixture.

```rust
use chio_test_support::prelude::*;

#[test]
fn proof_verify_accepts_minimal_passport_fixture() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "proof",
            "verify",
            "fixtures/chio-launch/minimal-passport/valid/transaction-passport.json",
        ])
        .output()
        .test_expect("chio command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).test_expect("stdout is utf8");
    assert!(stdout.contains("chio.transaction.verifier-report.v1"));
    assert!(stdout.contains("\"verdict\":\"verified\""));
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p chio-cli --test proof_verify proof_verify_accepts_minimal_passport_fixture
```

Expected: fail because the command and fixture do not exist.

- [ ] **Step 3: Add fixtures and command path**

Add a minimal valid fixture. Add a `Proof` command variant and `ProofCommands::Verify { path: PathBuf }` in `crates/chio-cli/src/cli/types.rs`. Add `crates/chio-cli/src/cli/dispatch/proof.rs` with a `dispatch_proof` function that loads the JSON, calls the minimal verifier, and writes compact JSON with `schema`, `verdict`, and `passport_id`. Wire the module and match arm in `crates/chio-cli/src/cli/dispatch.rs`.

- [ ] **Step 4: Run the CLI test again**

Run:

```bash
cargo test -p chio-cli --test proof_verify proof_verify_accepts_minimal_passport_fixture
```

Expected: pass.

## Task 5 - Add Semantic Policy Mismatch Negative Fixture

- [ ] **Step 1: Add failing negative CLI test**

Add a test that runs `chio proof verify` against the invalid policy mismatch fixture and expects nonzero exit plus a field-specific error. This fixture must be a real digest mismatch, not a malformed hash: the passport references policy digest `A`, while the bundled policy bytes hash to `B`.

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test -p chio-cli --test proof_verify proof_verify_rejects_policy_digest_mismatch_fixture
```

Expected: fail until the invalid fixture and digest comparison path exist.

- [ ] **Step 3: Add invalid fixture and error mapping**

Create the invalid fixture with valid hex digests that do not match the bundled policy bytes. Ensure the CLI exits nonzero and prints `verifier policy digest mismatch`.

- [ ] **Step 4: Run targeted tests**

Run:

```bash
cargo test -p chio-control-plane --test transaction_passport
cargo test -p chio-cli --test proof_verify
```

Expected: both pass.

## Completion Gate

Run:

```bash
cargo fmt --all -- --check
cargo test -p chio-control-plane --test transaction_passport
cargo test -p chio-cli --test proof_verify
```

The sprint is complete only when all commands pass and the fixtures prove one accepted minimal passport plus one rejected authority-relevant mismatch.
