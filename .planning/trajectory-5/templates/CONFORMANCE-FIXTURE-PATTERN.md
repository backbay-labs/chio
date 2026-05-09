# Trajectory 5 Conformance Fixture Pattern

**Status**: normative for Lane B and Lane C. Lane A (threat-coverage) follows a
parallel JSON-evidence pattern documented in
`.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 1.3.

**Purpose**: every primitive that closes under the release work Evidence Gate
(Artifact C, Artifact D) ships a negative conformance test that exercises
production code and fails when the enforcement is reverted. This document
defines the file layout, naming, dependency rules, CI hook, and skeleton.

**Anti-pattern this document exists to prevent**: the trj4 pattern of tests
that pass against schema validation, against test-local copies of production
types, or against mocked verifiers. See
`.planning/trajectory-5/templates/EVIDENCE-GATE.md` sections 2.3 and 2.8.

---

## 1. File Layout

### 1.1 Lane B (protocol primitive negatives)

Path: `crates/chio-conformance/tests/<lane>_<primitive>_<negative_case>.rs`

The lane prefix uses the release work sub-lane id (e.g. `b1`, `b2`, `b3`):

| Sub-lane | Primitive | Example file |
|---|---|---|
| B1 | Single-entry verifier | `crates/chio-conformance/tests/b1_capability_partial_entry_disallowed.rs` |
| B2 | Receipt v2 mandatory | `crates/chio-conformance/tests/b2_receipt_v1_under_v2_negotiation_rejected.rs` |
| B3 | Anchor-batch async | `crates/chio-conformance/tests/b3_anchor_batch_sync_under_public_witness_rejected.rs` |
| B4 | DSSE-conformant bilateral signing (per R4 BLOCKER 1) | `crates/chio-conformance/tests/b4_bilateral_dsse_pae_only_is_conformant.rs` |

One test file per negative case. Multiple `#[test]` functions per file are
permitted only when they exercise the same production call site under
distinct attack inputs.

### 1.2 Lane C (forcing demo cross-org negatives)

Path: `crates/chio-conformance/tests/c_<demo>_<negative_case>.rs`
plus `examples/<demo>/fixtures/<case>.rs` for the executable fixture body.

| Sub-lane | Demo | Example file |
|---|---|---|
| C1 | Bilateral cosign | `crates/chio-conformance/tests/c_bilateral_single_signer_rejected.rs` |
| C2 | Capability lease + budget bond | `crates/chio-conformance/tests/c_lease_overdraft_rejected.rs` |
| C3 | Anchored receipts | `crates/chio-conformance/tests/c_anchor_missing_witness_rejected.rs` |
| C4 | Selective disclosure (bbs-stub feature) | `crates/chio-conformance/tests/c_zk_disclosure_unauthorized_view_rejected.rs` |

Lane C tests MUST also export a fixture artifact under `examples/<demo>/fixtures/`
that the demo binary consumes, so the demo run replays exactly the input the
test rejected.

---

## 2. Production Call Path Rule

### 2.1 The rule

The test imports the kernel, verifier, anchor, federation, or kernel-core
module from the actual workspace crate. It does not import a copy. It does
not redeclare any production type.

### 2.2 Allowed imports

```rust
use chio_anchor::{...};
use chio_core::{...};
use chio_core_types::{...};
use chio_federation::{...};
use chio_kernel::{...};
use chio_kernel_core::{...};
```

Plus standard test helpers (`assert_matches`, `serde_json`, `tokio` for
async tests, `tempfile`, etc.). Plus the `tests/common/` shared helpers
already in `crates/chio-conformance/tests/common/`, which themselves MUST
NOT redeclare production types.

### 2.3 Disallowed imports

- Any module path containing `mock`, `stub`, `fake`, or `_test_only` for the
  type under test. (Mocking externalities like HTTP or time is fine; mocking
  the verifier is not.)
- Any test-local re-declaration of `CapabilityToken`, `ChioReceipt`,
  `AnchorBatch`, `KernelTrustExchange`, or any other primitive whose
  enforcement the test is supposed to verify.
- Any import from a `[dev-dependencies]` crate that wraps the production
  type and re-exports it (this is how the trj4 mock-not-runtime pattern
  slipped through).

### 2.4 How CI checks the rule

Wave 1 lands `scripts/check-conformance-imports.sh` (TBD-from-W1) which
parses each `crates/chio-conformance/tests/*.rs` file and asserts:

- The set of `use` statements importing the function-under-test resolves to
  one of the allowed crates above.
- The function-under-test name is one of `verify_*`, `dispatch_*`, `mint_*`,
  `sign_*`, `build_*`, `attest_*`, or appears in
  `scripts/conformance-allowed-verbs.txt`.

The script runs in `.github/workflows/ci.yml` on every PR.

---

## 3. Fails-When-Reverted Rule

### 3.1 The rule

The test MUST be paired with proof that, if the production enforcement is
removed, the test fails. The proof is one of:

1. A CI run URL (recorded in the test header comment) where the test failed
   on a deliberate revert commit, OR
2. A `git stash`-style procedure documented in the test header comment that
   any reviewer can follow locally to reproduce the failure.

### 3.2 Header comment format

Every release work conformance test MUST begin with:

```rust
//! Trj5 negative conformance for <primitive>.
//!
//! Spec MUST: spec/PROTOCOL.md section <N.M.K> lines <a>-<b>
//! Enforced call site: crates/<crate>/src/<file>:<line>
//! Production call path: <function chain>
//!
//! Reverts-to-fail proof: <CI URL or revert procedure>
//!
//! Threat: <one-paragraph attacker model>
//!
//! Why this passes Artifact D: this test imports <crate>::<fn> directly
//! and drives it with <input>. Mocks: <list, or "none beyond OS time">.
```

### 3.3 Stub-revert diff (worked example)

For B2 (receipt v2 mandatory), the test header MUST cite a diff like:

```diff
--- a/crates/chio-kernel/src/kernel/mod.rs
+++ b/crates/chio-kernel/src/kernel/mod.rs
@@ -1574,1591 +1574,1574 @@
-                // B2 enforced: named peer not pinned fresh -> fail closed.
-                return Err(KernelError::ReceiptNegotiationDowngrade {
-                    expected: KernelReceiptVersion::V2BodyHash,
-                    actual: KernelReceiptVersion::V1Legacy,
-                    reason: NegotiationDowngradeReason::PeerNotPinnedFresh { ... },
-                });
+                // Reverted: warn-and-downgrade restored at the canonical
+                // pre-B2 location (kernel_receipt_version_for_remote).
+                tracing::warn!("v2 receipt minting falling back to v1 because federation peer is not pinned fresh");
+                return KernelReceiptVersion::V1Legacy;
```

When this diff is applied, the test
`b2_receipt_v1_under_v2_negotiation_rejected.rs` MUST fail. The CI run URL
(or local-reproduction steps) is in the test header.

---

## 4. Naming Convention

### 4.1 File name

`<lane>_<primitive>_<negative_case>.rs`

- `<lane>`: lower-case sub-lane id (`b1`, `b2`, `b3`, `c1`, etc.).
- `<primitive>`: snake_case name of the protocol primitive
  (`capability_partial_entry`, `receipt_v1`, `anchor_batch_sync`).
- `<negative_case>`: snake_case description of the attack or violation
  (`disallowed`, `rejected`, `fails_closed`, `is_denied`).

### 4.2 Test function name

`<primitive>_<negative_case>_under_<context>_<rejects|denies|fails_closed>`

Example: `receipt_v1_under_v2_negotiation_is_rejected`.

### 4.3 Avoid

- Generic names like `negative_test_1`, `it_works`, `test_capability`.
- Names that imply happy-path coverage (`verifies_correctly`).
- Names that describe what the test DOES (`signs_and_verifies`) rather than
  what it ASSERTS (`tampered_signature_is_rejected`).

---

## 5. Cargo.toml Dev-Dependencies

The `crates/chio-conformance/Cargo.toml` `[dev-dependencies]` section is the
ONLY place a release work conformance test pulls in helpers. Additions for release work:

```toml
[dev-dependencies]
chio-anchor = { workspace = true }
chio-core = { workspace = true }
chio-core-types = { workspace = true }
chio-federation = { workspace = true }
chio-kernel = { workspace = true }
chio-kernel-core = { workspace = true }
# Async (Lane B3 anchor-batch-async, Lane C bilateral)
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
# Optional Lane C selective-disclosure (gated)
# chio-federation = { workspace = true, optional = true }
```

If a test needs a dependency not on this list, the addition MUST be reviewed
against the no-mock rule before merge. Adding `mockall` or `wiremock` is
permitted only for HTTP edge tests where the externality (the remote server)
is the thing being mocked; the verifier remains real.

---

## 6. CI Hook

### 6.1 Workflows that gate release work conformance

| Workflow | Gate | New for release work? |
|---|---|---|
| `.github/workflows/ci.yml` | `cargo test -p chio-conformance` runs every PR | existing |
| `.github/workflows/conformance-matrix.yml` | matrix of OS/feature flags | existing |
| `.github/workflows/threat-model-coverage.yml` | runs `scripts/check-threat-coverage.sh` | existing |
| `.github/workflows/close-bar-tracker.yml` | runs `scripts/check-release work-evidence-gate.sh` | extended (Wave 1) |
| `.github/workflows/spec-drift.yml` | spec MUST citations resolve | extended (Wave 1) |

### 6.2 New scripts (Wave 1 deliverables)

- `scripts/check-release work-evidence-gate.sh` (TBD-from-W1): walks
  `.planning/trajectory-5/audits/*.md` and validates the four-artifact rule.
- `scripts/check-conformance-imports.sh` (TBD-from-W1): enforces the
  production-call-path rule (section 2 above).
- `scripts/check-anchor-batch-async-witness.sh` (B3 deliverable): grep-based
  lint for `verify_anchor_batch(` callers under `require_public_witness=true`.
- `scripts/check-verify-capability-full.sh` (B1 deliverable): grep-based lint
  for partial-entry callers in production crates.

Each script exits non-zero on violation. Each is invoked from the matching
workflow.

---

## 7. Sample Skeleton

```rust
//! Trj5 B2 negative conformance: receipt v1 minting is rejected when peer
//! negotiation selected `chio.capability.v2`.
//!
//! Spec MUST: spec/PROTOCOL.md section 6 lines 714-741.
//! Enforced call site: crates/chio-kernel/src/kernel/mod.rs:1574-1591 (post-B2 patch; function `kernel_receipt_version_for_remote`). Note: synthesis line 31 cited :1148-1165 which is the resolver helper, not the runtime downgrade.
//! Production call path: Kernel::dispatch_tool_call -> Kernel::mint_receipt
//!   -> Kernel::select_receipt_version (B2 hardens this).
//!
//! Reverts-to-fail proof: see `git log --grep "B2 revert proof"` in
//!   the release work audit doc; local repro via `git revert <commit> && cargo test`.
//!
//! Threat: an adversarial peer advertises `accepts_receipt_v2: true` during
//!   negotiation, then triggers a kernel build path that previously
//!   warn-and-downgraded to receipt v1, forging a receipt that does not
//!   carry `body_hash`.
//!
//! Why this passes Artifact D: this test imports `chio_kernel::Kernel`
//!   directly, runs the production `mint_receipt` path, and asserts a
//!   typed `KernelError::ReceiptVersionMismatch` rather than schema rejection.
//!   Mocks: only the OS clock and the random nonce source.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::Keypair;
use chio_core_types::capability::CapabilityToken;
use chio_kernel::{Kernel, KernelBuilder, KernelError, PeerFeatures};
use chio_kernel_core::clock::FixedClock;

#[tokio::test]
async fn receipt_v1_under_v2_negotiation_is_rejected() {
    // 1. Build a kernel whose negotiation result claims v2.
    let kp = Keypair::generate();
    let kernel = KernelBuilder::new()
        .with_keypair(kp.clone())
        .with_clock(FixedClock::from_unix_seconds(1_700_000_000))
        .with_peer_features(PeerFeatures {
            accepts_receipt_v2: true,
            ..PeerFeatures::default()
        })
        .build()
        .expect("kernel builds");

    // 2. Construct an inbound request shaped so the receipt-version
    //    selector would have downgraded under the legacy code path.
    let request = chio_kernel::test_support::governed_request_under_v2();

    // 3. Drive the production dispatch path.
    let result = kernel.dispatch_tool_call(&request).await;

    // 4. Assert the typed fail-closed outcome.
    match result {
        Err(KernelError::ReceiptVersionMismatch { negotiated, attempted }) => {
            assert_eq!(negotiated, "chio.receipt.v2");
            assert_eq!(attempted, "chio.receipt.v1");
        }
        other => panic!(
            "expected KernelError::ReceiptVersionMismatch, got {other:?}; \
             this test guards spec/PROTOCOL.md section 6 lines 714-741"
        ),
    }
}
```

The skeleton is illustrative. The real test in `crates/chio-conformance/tests/`
will use the actual struct names from the production crate. Anything that
deviates from the import rules in section 2 is a violation.

---

## 8. Anti-Patterns Specific to Conformance Fixtures

### 8.1 Schema-only test

```rust
// ANTI-PATTERN. Do not do this.
let bad_token: CapabilityToken = serde_json::from_str(BAD_JSON).unwrap();
schema_validator.validate(&bad_token).expect_err("schema rejects");
```

The schema is part of the contract, but the runtime is what enforces. A test
that only validates the schema does not exercise the verifier. See
`.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 2.8.

### 8.2 Near-copy of production type

```rust
// ANTI-PATTERN. Do not do this.
struct CapabilityToken {  // shadowing the production type
    pub schema: String,
    pub signature: Vec<u8>,
}
fn verify(token: &CapabilityToken) -> Result<(), &'static str> { ... }
```

Test passes; production verifier is unaffected. See
`.planning/trajectory-5/templates/EVIDENCE-GATE.md` section 2.3.

### 8.3 Side-effecting setup that bypasses the gate

```rust
// ANTI-PATTERN. Do not do this.
let kernel = Kernel::test_only_unsafe_disable_negotiation_check();
```

Any helper named `test_only_*`, `unsafe_*`, or `_disable_*` that bypasses the
production decision path makes the test useless. The whole point of the
fixture is to exercise the production path. If a test setup helper exists
because the production path is hard to reach, the production path needs
restructuring, not bypassing.

### 8.4 Asserting on the structural shape

```rust
// ANTI-PATTERN. Do not do this.
assert!(error.to_string().contains("rejected"));
```

Production code can change the error string at any time. Tests that match
on string content rot. release work conformance tests MUST match on typed error
variants (`KernelError::Foo { ... }`) not stringly-typed substrings. The
header comment may quote the substring as documentation; the assertion
matches the variant.

### 8.5 One file, fifteen unrelated tests

A conformance test file MUST exercise one negative case (or a small set of
attack inputs against the same call site). A file with twenty `#[test]`
functions covering five different primitives is a code-review failure. Split
to one file per primitive per negative case.

---

## 8a. B4 Negative-Conformance Fixture Pattern (DSSE-conformant bilateral signing)

The B4 fixture defends against the failure mode R4 BLOCKER 1 identified:
claiming spec §6 conformance via the legacy `DualSignedReceipt` (whose
preimage shares zero bytes with the §6 PAE preimage). Pattern:

```rust
//! Trj5 B4 negative conformance: bilateral DSSE envelope is the §6-conformant
//! artifact; legacy `DualSignedReceipt` is NOT.
//!
//! Spec MUST: spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md §6 lines 338-353.
//! Enforced call site: crates/chio-federation/src/bilateral_dsse.rs (NEW per B4).
//! Production call path: federation hot path -> `bilateral_dsse::sign_envelope`
//!   -> Ed25519 over DSSE PAE bytes of canonical-JSON in-toto Statement.
//!
//! Reverts-to-fail proof: revert B4.2 on a draft branch (delete `bilateral_dsse.rs`),
//!   wire the demo to verify only `DualSignedReceipt::verify`; the fixture FAILS
//!   because the spec §6 PAE-shaped envelope is not produced.

use chio_federation::bilateral_dsse::{sign_dsse_envelope, verify_dsse_envelope};
use chio_federation::bilateral::{CoSigningBody, DualSignedReceipt};
use chio_core::Keypair;

#[test]
fn legacy_dual_signed_receipt_alone_is_not_section_6_conformant() {
    // Build the legacy receipt (lines 41-77 of bilateral.rs).
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let dual = build_legacy_dual_signed(&kp_a, &kp_b);

    // The legacy preimage is canonical-JSON of CoSigningBody.
    let legacy_preimage = dual_signed_canonical_bytes(&dual);

    // The DSSE PAE preimage (per §6) is "DSSEv1" SP LEN(payload-type) ...
    let dsse_envelope = sign_dsse_envelope(&dual.body, &kp_a, &kp_b).unwrap();
    let dsse_preimage = dsse_envelope.pae_bytes();

    // The two preimages share zero bytes (R4 finding).
    assert_ne!(legacy_preimage, dsse_preimage);
    assert!(no_shared_bytes(&legacy_preimage, &dsse_preimage));

    // The §6-conformant verifier accepts the DSSE envelope but rejects
    // an attempt to claim §6 conformance from `DualSignedReceipt::verify`.
    verify_dsse_envelope(&dsse_envelope, &kp_a.public(), &kp_b.public()).unwrap();
}

#[test]
fn tampered_pae_bytes_rejected_by_section_6_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let mut envelope = sign_dsse_envelope(&example_receipt(), &kp_a, &kp_b).unwrap();

    // Flip a bit in the payload (changes PAE bytes via LEN(payload)).
    envelope.payload_b64.push('X');

    let result = verify_dsse_envelope(&envelope, &kp_a.public(), &kp_b.public());
    assert!(result.is_err());
}
```

Critical assertions:

- The legacy `CoSigningBody` preimage and the DSSE PAE preimage share
  zero bytes (R4 finding `bilateral.rs:41-77` vs §6 lines 338-353). The
  fixture asserts this byte-level inequality.
- The §6-conformant verifier (`verify_dsse_envelope`, NEW in B4) accepts
  the DSSE envelope; the legacy `DualSignedReceipt::verify` (line 108)
  is NOT a §6 verifier and the fixture asserts its output cannot be
  used to claim §6 conformance.
- Tampered PAE bytes (e.g. payload bit-flip, payload-type swap) are
  rejected.

The reverse-test: revert B4.2 (delete `bilateral_dsse.rs`); the test
FAILS because the §6-conformant envelope is no longer produced, and the
demo's "spec §6 conformance" claim is contradicted.

---

## 9. Where This Pattern Comes From

- The strongest existing trj4 example is
  `crates/chio-conformance/tests/anchor_batch_forged_root_rejected.rs`
  (W2.3 commit `7ee1ddbcc`). It imports `chio_anchor::{build_anchor_batch,
  verify_anchor_batch, ...}`, mutates the body, and asserts a typed
  `expect_err` on `AnchorBatch::sign`. This pattern is the model for release work
  Lane B fixtures.
- The trj4 anti-pattern is `crates/chio-conformance/tests/protocol_primitives_t1.rs`
  combined with the placeholder evidence files in `audits/evidence/threats/`:
  the test file is real, but the evidence JSONs that flip the
  `coverage_state` are placeholders, so the test pass does not refute the
  adversary the row claims to cover.

The pattern is: emulate the strong example, refuse the weak one.
