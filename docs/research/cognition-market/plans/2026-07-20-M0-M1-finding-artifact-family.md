# Finding Artifact Family (M0 + M1) Implementation Plan

> **Execution status:** Implementation began from `origin/main` `9ec6814a2`
> on 2026-07-27; the qualified gate completed overnight on 2026-07-27/28.
> This is both the execution record and an exact reconstruction guide for the
> landed milestone.

## Goal and boundary

Ship one public artifact family, `chio.finding.v1`, in a new leaf crate,
`chio-finding`. It provides:

- pure artifact types;
- fail-closed structural and canonical-representation validation;
- a content-addressed finding id;
- issuer-bound inline Ed25519 signing and strict verification;
- one registered JSON Schema;
- one deterministic signed golden fixture; and
- a test-only open-market progress specification.

M0/M1 adds no kernel, service, storage, CLI, settlement, challenge, reveal, or
status-feed production wiring. Challenge and status wire artifacts remain
owned by M5 and M6.

The M1 integrity boundary proves only structure, the content-address binding,
and the issuer signature. It does not authenticate evidence receipts or
checkpoints, resolve bond/status/pricing references, bind evidence lineage,
check wall-clock liveness, or establish the truth of a guarantee or evidence
class. M2 owns those checks.

## Landed commits

1. `01538197571073434443e26f3219be6ae2a415cc` - crate scaffold and workspace
   registration
2. `6db2e9e00dd1da65434da262763cac76e67d3e46` - artifact types and structural
   validation
3. `d6dcc8038cd8765f7cf7331b5c49558fa7a75578` - issuer-bound inline signing
4. `e398cf3fbeafd8597bc49498d5fd93c67ee22814` - canonical representation
   hardening
5. `16bd38da35fc17a4d80d4882c8e5ec6b05945e56` - public schema, registry,
   manifest, and normative protocol
6. `24f96df1ef7be2b60ac91c828e154d5f80a9066a` - deterministic signed golden
   and persistent conformance
7. `c679cce1cbc5c9b9c143ff410a36cd44d08140fc` - test-only open-market progress
   spec advanced to M1
8. `04f5d3e665c237b12bb0973a9862c2c26b884a5b` - strict Ed25519 verification,
   currency/receipt hardening, exact preimages, and real-bid tests

`88d4bde1f336e0c3c9b6b94b90637e40771c680b` is a separate cleanup of a
pre-existing `chio-cli` test initializer needed by the workspace clippy gate.
It is not cognition-market production wiring.

Four post-gate refinements preserve the same production surface:

9. `e429963d8677fdceec7739b4caf31fde28700cbc` - make the progress spec state
   its bid-only coverage and pin the missing DPoP seam
10. `20cdc7f8379488cb53f179914b95fb8fe4f5c594` - qualify the M1 evidence-cost
    and collateral-reference documentation
11. `1efbbc112507b04490d1e54e03789fe635dce34c` - distinguish a well-formed
    stale finding id from malformed digest syntax
12. `ea105498de16de7e5e2051ad58c1c61830f5730a` - clarify that M1 validates
    issuer-bound integrity rather than issuer authorization

## Exact reconstruction

The byte-exact route from base `9ec6814a2` is:

```bash
git cherry-pick \
  01538197571073434443e26f3219be6ae2a415cc \
  6db2e9e00dd1da65434da262763cac76e67d3e46 \
  d6dcc8038cd8765f7cf7331b5c49558fa7a75578 \
  e398cf3fbeafd8597bc49498d5fd93c67ee22814 \
  16bd38da35fc17a4d80d4882c8e5ec6b05945e56 \
  24f96df1ef7be2b60ac91c828e154d5f80a9066a \
  c679cce1cbc5c9b9c143ff410a36cd44d08140fc \
  04f5d3e665c237b12bb0973a9862c2c26b884a5b
```

To reproduce the recorded full workspace gate as well as the feature, apply
the separate baseline clippy cleanup after the feature series:

```bash
git cherry-pick 88d4bde1f336e0c3c9b6b94b90637e40771c680b
```

Then apply the post-gate test/documentation refinements to reproduce the
current source:

```bash
git cherry-pick \
  e429963d8677fdceec7739b4caf31fde28700cbc \
  20cdc7f8379488cb53f179914b95fb8fe4f5c594 \
  1efbbc112507b04490d1e54e03789fe635dce34c \
  ea105498de16de7e5e2051ad58c1c61830f5730a
```

For an independent TDD reconstruction, use each task's commit-pinned snapshot
in sequence. Do not copy the final `04f5d3e66` test target before the schema
and fixture tasks: it intentionally uses compile-time fixture inclusion.
Apply exact inspected content through the normal editing mechanism, then run
the named red/green checks.

## Files

- `Cargo.toml`
- `Cargo.lock`
- `crates/core/chio-core-types/src/crypto.rs`
- `crates/core/chio-core-types/src/lib.rs`
- `crates/core/chio-core-types/src/signed_artifact.rs`
- `crates/economy/chio-finding/Cargo.toml`
- `crates/economy/chio-finding/src/lib.rs`
- `crates/economy/chio-finding/src/types.rs`
- `crates/economy/chio-finding/src/validate.rs`
- `crates/economy/chio-finding/tests/finding.rs`
- `crates/economy/chio-open-market/Cargo.toml`
- `crates/economy/chio-open-market/tests/cognition_market_flow.rs`
- `fixtures/proof-room/finding/verified-fix-basic/finding.json`
- `fixtures/proof-room/finding/verified-fix-basic/README.md`
- `scripts/check-chio-schema-registry.sh`
- `spec/PROTOCOL.md`
- `spec/README.md`
- `spec/schemas/COVERAGE.md`
- `spec/schemas/MANIFEST.sha256`
- `spec/schemas/chio-finding/v1/finding.schema.json`
- `spec/schemas/registry.json`
- `docs/adr/ADR-0017-cognition-market-finding-artifacts.md` (verification only)

## Non-negotiable invariants

- Fail closed on every invalid artifact.
- Use RFC 8785 canonical JSON for both identifiers and signatures.
- Use I-JSON integers. `evidence_cost.units`, `issued_at`, and `expires_at`
  must be at most `2^53 - 1`, or `9_007_199_254_740_991`.
- At the complete raw-ingress boundary, `finding_id`, SHA-256 fields,
  `issuer`, and `signature` use exact lowercase hexadecimal encodings.
  Prefixes and uppercase alternatives reject. Typed deserialization alone is
  intentionally not the canonical-spelling boundary.
- Finding issuers use Ed25519 only. Low-order or otherwise weak Ed25519 public
  keys reject.
- `runtime_assurance_tier = None` means the property is absent.
  `Some(RuntimeAssuranceTier::None)`, JSON `"none"`, and explicit JSON `null`
  are non-canonical and reject.
- `evidence_cost.currency` is exactly three uppercase ASCII letters.
- Evidence receipt ids are nonblank and unique.
- Deterministic replay requires `replay_recipe_sha256`.
- Any non-asserted guarantee, non-asserted evidence class, or present runtime
  assurance tier requires at least one evidence receipt reference.
- Signing validates the finding, including its content-address, before
  producing a signature.
- Published verification uses strict Ed25519 verification.
- Unknown JSON fields reject.
- No em dashes appear in code, comments, or documentation.
- No new variant is added to an existing frozen wire enum.

## Task 1: Scaffold the crate

### Files

- Modify `Cargo.toml`.
- Create `crates/economy/chio-finding/Cargo.toml`.
- Create `crates/economy/chio-finding/src/lib.rs`.
- Create empty `types.rs` and `validate.rs` modules.

### Steps

- [x] Confirm `chio-core-types`, `serde`, and `thiserror` exist in
  `[workspace.dependencies]`:

  ```bash
  rg -n '^(chio-core-types|serde|thiserror)\\s*=' Cargo.toml
  ```

- [x] Add `crates/economy/chio-finding` to the root workspace member list and
  add `chio-finding` to the root workspace dependencies.

- [x] Create the crate manifest with:

  ```toml
  [package]
  name = "chio-finding"
  description = "Chio cognition-market finding artifact"
  version.workspace = true
  edition.workspace = true
  rust-version.workspace = true
  license.workspace = true
  repository.workspace = true
  publish = false

  [lib]
  name = "chio_finding"

  [dependencies]
  chio-core-types = { workspace = true }
  serde = { workspace = true }
  thiserror = { workspace = true }

  [lints]
  workspace = true
  ```

- [x] Make `src/lib.rs` forbid unsafe code, declare `types` and `validate`,
  re-export both modules, and re-export `canonical_json_bytes` and `crypto`
  from `chio-core-types`.

- [x] Verify:

  ```bash
  cargo check -p chio-finding
  ```

- [x] Commit:

  ```bash
  git add Cargo.toml Cargo.lock crates/economy/chio-finding
  git commit -m "feat(chio-finding): scaffold cognition-market artifact crate"
  ```

## Task 2: Add the artifact shape and structural validation

### Exact source

Copy the Task 2 snapshots, not the final test target:

```bash
git show 6db2e9e00dd1da65434da262763cac76e67d3e46:crates/economy/chio-finding/src/types.rs
git show 6db2e9e00dd1da65434da262763cac76e67d3e46:crates/economy/chio-finding/src/validate.rs
git show 6db2e9e00dd1da65434da262763cac76e67d3e46:crates/economy/chio-finding/tests/finding.rs
```

### Required public surface

```rust
pub const FINDING_SCHEMA_V1: &str = "chio.finding.v1";

impl Finding {
    pub fn validate(&self) -> Result<(), FindingError>;
    pub fn verify_finding_id(&self) -> Result<(), FindingError>;
}

pub fn compute_finding_id(
    finding: &Finding,
) -> Result<String, FindingError>;
```

The exact `Finding` fields are:

```text
schema
finding_id
descriptor { topic, context_sha256, outcome_class }
guarantee_class
payload_sha256
payload_media_type
evidence_receipt_ids
evidence_checkpoint_ref
evidence_cost
runtime_assurance_tier
evidence_class
replay_recipe_sha256
intent_commitment_receipt_id
bond_ref
status_feed_ref
license_ref
price_hint_ref
issuer
issued_at
expires_at
signature
```

The enums are:

```text
FindingOutcomeClass: NullResult, VerifiedFix, PositiveResult
FindingGuaranteeClass: DeterministicReplay, MeteredAttested, Asserted
FindingEvidenceClass: Asserted, Observed, Verified
```

`Finding` and `FindingDescriptor` use `deny_unknown_fields`. Optional fields
use `default` plus `skip_serializing_if = "Option::is_none"`.

### Identifier preimage

`compute_finding_id` clones the finding, clears both `finding_id` and
`signature`, canonicalizes the complete body, and returns
`sha256_hex(canonical_bytes)`. `Finding::validate` finishes by recomputing and
comparing this id. Empty or stale ids reject.

### Red/green sequence

- [x] First add the 13 baseline tests from the pinned snapshot: schema
  mismatch, empty/stale ids, malformed payload digest, missing deterministic
  recipe, invalid validity window, missing/blank evidence receipts,
  guarantee/evidence/runtime receipt requirements, blank intent reference,
  and unknown fields.

- [x] Confirm the red state before implementation:

  ```bash
  cargo test -p chio-finding --test finding
  ```

- [x] Implement the baseline validator and exact id preimage. Task 3 adds
  canonical and issuer hardening after the baseline is green.

- [x] Run the initial green target:

  ```bash
  cargo test -p chio-finding --test finding
  ```

  Exact Task 2 result: 13 passed.

- [x] Commit the baseline type/validator slice:

  ```bash
  git add crates/economy/chio-finding
  git commit -m "feat(chio-finding): finding artifact type with fail-closed validation"
  ```

## Task 3: Add signing and canonical representation hardening

### Files and exact source

First copy the baseline signing slice, then the canonical-hardening slice:

```bash
git show d6dcc8038cd8765f7cf7331b5c49558fa7a75578:crates/economy/chio-finding/src/validate.rs
git show d6dcc8038cd8765f7cf7331b5c49558fa7a75578:crates/economy/chio-finding/tests/finding.rs
git show e398cf3fbeafd8597bc49498d5fd93c67ee22814:crates/economy/chio-finding/src/validate.rs
git show e398cf3fbeafd8597bc49498d5fd93c67ee22814:crates/economy/chio-finding/tests/finding.rs
```

At this sequential point, signing uses `verify_canonical`. The final strict
Ed25519 boundary lands in Task 7, after the schema and compile-time golden
fixture exist.

### Canonical hardening in this task

- bound `evidence_cost.units`, `issued_at`, and `expires_at` to the I-JSON
  maximum;
- restrict typed issuers to Ed25519;
- reject `Some(RuntimeAssuranceTier::None)` in favor of property omission;
- require exact lowercase signature encoding; and
- call `finding.validate()` after clearing the signature and before signing.

### Finding signing surface

```rust
pub fn sign_finding(
    finding: Finding,
    keypair: &Keypair,
) -> Result<Finding, FindingError>;

pub fn verify_finding_signature(
    finding: &Finding,
) -> Result<(), FindingError>;

pub fn verify_finding(
    finding: &Finding,
) -> Result<(), FindingError>;
```

The signing preimage is the complete finding with `signature` cleared and the
validated, nonempty `finding_id` retained. `sign_finding` must:

1. require `finding.issuer == keypair.public_key()`;
2. clear `signature`;
3. call `finding.validate()` before signing, so a stale id or malformed
   artifact cannot be signed;
4. call `Keypair::sign_canonical`; and
5. store the bare lowercase 128-character Ed25519 signature.

`verify_finding_signature` must:

1. reject anything other than exactly 128 lowercase hexadecimal characters;
2. parse with `Signature::from_hex`;
3. clear the cloned body's `signature`; and
4. in this task, call `finding.issuer.verify_canonical`; Task 7 replaces it
   with `verify_canonical_strict`.

`verify_finding` calls structural/id validation first, then signature
verification.

### Red/green sequence

- [x] Add regressions for signed round-trip, tampering, uppercase and
  `0x`-prefixed signatures, wrong signer, stale-id signing, non-Ed25519
  issuer, I-JSON boundaries, and explicit runtime `none`.

- [x] Verify red before the new APIs, then green after implementation:

  ```bash
  cargo test -p chio-finding --test finding
  cargo clippy -p chio-finding --tests -- -D warnings
  ```

- [x] Keep the historical commit split shown in the execution record. The
  baseline signing commit is:

  ```bash
  git add crates/economy/chio-finding
  git commit -m "feat(chio-finding): inline artifact signing verified against the issuer"
  ```

  Canonical hardening landed in `e398cf3fb`. The strict crypto boundary lands
  in Task 7 at `04f5d3e66`.

## Task 4: Register the final schema and protocol family

### Files and exact source

Copy the schema-registration snapshot. Task 7 later replaces its schema with
the final currency/uniqueness-hardened version:

```bash
git show 16bd38da35fc17a4d80d4882c8e5ec6b05945e56:crates/core/chio-core-types/src/signed_artifact.rs
git show 16bd38da35fc17a4d80d4882c8e5ec6b05945e56:crates/core/chio-core-types/src/lib.rs
git show 16bd38da35fc17a4d80d4882c8e5ec6b05945e56:crates/economy/chio-finding/src/types.rs
git show 16bd38da35fc17a4d80d4882c8e5ec6b05945e56:spec/schemas/chio-finding/v1/finding.schema.json
```

The code registry adds:

```rust
pub const CHIO_FINDING_V1_SCHEMA: &str = "chio.finding.v1";
```

and this exact metadata tuple:

```rust
(
    CHIO_FINDING_V1_SCHEMA,
    Some(("finding", "finding-market-v1")),
),
```

The JSON registry row is:

```json
{
  "schema": "chio.finding.v1",
  "artifactKind": "finding",
  "introducedBy": "finding-market-v1",
  "schemaFile": "spec/schemas/chio-finding/v1/finding.schema.json"
}
```

### Schema requirements

The final JSON Schema complements the typed validator and closes
raw-spelling distinctions that typed deserialization cannot retain:

- `additionalProperties: false` for the artifact, descriptor, and money
  object;
- exact lowercase `[0-9a-f]{64}` digests and issuer;
- exact lowercase `[0-9a-f]{128}` signature;
- `iJsonU64` with maximum `9007199254740991`;
- currency pattern `^[A-Z]{3}$`;
- `uniqueItems: true` for evidence receipt ids;
- a nonblank-string definition using `\S`;
- runtime tiers limited to `basic`, `attested`, and `verified`, excluding
  `"none"` and JSON `null`;
- `deterministic_replay` conditionally requiring the recipe digest; and
- any non-asserted guarantee, non-asserted evidence class, or present runtime
  tier conditionally requiring at least one receipt.

Only `chio.finding.v1` is registered in M0/M1.

### Red/green sequence

- [x] Confirm the registry test passes before adding the code constant:

  ```bash
  cargo test -p chio-core-types --test signed_artifact_schema
  ```

- [x] Add the constant and tuple, then confirm the test fails because the JSON
  registry is behind.

- [x] Add the schema, registry row, root re-export, registry-check root,
  protocol section, spec index entry, and coverage row.

- [x] Regenerate `spec/schemas/MANIFEST.sha256` with the checker’s exact
  inventory predicate:

  ```bash
  python3 - <<'PY'
  import hashlib
  import pathlib
  import re
  import subprocess

  root = pathlib.Path(".")
  manifest = "spec/schemas/MANIFEST.sha256"
  tracked = subprocess.run(
      [
          "git", "ls-files", "-z", "--cached", "--others",
          "--exclude-standard", "--", "spec/schemas",
      ],
      check=True,
      stdout=subprocess.PIPE,
  ).stdout.decode().split("\0")
  kept = sorted(
      path
      for path in tracked
      if path.endswith(".schema.json")
      or (
          path.startswith("spec/schemas/chio-economy/")
          and re.search(r"\.v[1-9][0-9]*\.json\Z", path) is not None
      )
      or path in {
          manifest,
          "spec/schemas/registry.json",
          "spec/schemas/VERSION",
      }
  )
  other_lines = [
      f"{hashlib.sha256((root / path).read_bytes()).hexdigest()}  {path}\n"
      for path in kept
      if path != manifest
  ]
  self_hash = hashlib.sha256("".join(other_lines).encode()).hexdigest()
  content = "".join(
      f"{self_hash}  {path}\n"
      if path == manifest
      else f"{hashlib.sha256((root / path).read_bytes()).hexdigest()}  {path}\n"
      for path in kept
  )
  (root / manifest).write_text(content)
  print(f"regenerated {manifest} entries: {len(kept)}")
  PY
  ```

  The landed manifest contains 404 entries.

- [x] Verify:

  ```bash
  cargo test -p chio-core-types --test signed_artifact_schema
  bash scripts/check-chio-schema-registry.sh
  bash scripts/tests/check-chio-schema-registry.test.sh
  ```

- [x] Commit:

  ```bash
  git add \
    crates/core/chio-core-types/src/lib.rs \
    crates/core/chio-core-types/src/signed_artifact.rs \
    scripts/check-chio-schema-registry.sh \
    spec/PROTOCOL.md \
    spec/README.md \
    spec/schemas
  git commit -m "feat(chio-core-types): register chio.finding.v1 artifact family"
  ```

## Task 5: Add the deterministic golden and persistent conformance test

### Files and dependencies

`crates/economy/chio-finding/Cargo.toml` must contain:

```toml
[dev-dependencies]
chio-spec-validate = { workspace = true }
serde_json = { workspace = true }
```

Copy the exact golden-commit test and fixture. Task 7 later replaces the test
with the final five additional strict-hardening cases:

```bash
git show 24f96df1ef7be2b60ac91c828e154d5f80a9066a:crates/economy/chio-finding/tests/finding.rs
git show 24f96df1ef7be2b60ac91c828e154d5f80a9066a:fixtures/proof-room/finding/verified-fix-basic/finding.json
git show 24f96df1ef7be2b60ac91c828e154d5f80a9066a:fixtures/proof-room/finding/verified-fix-basic/README.md
```

### Path helpers and generator

The test defines:

```rust
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/proof-room/finding/verified-fix-basic/finding.json")
}

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1/finding.schema.json")
}
```

Bootstrap the absent fixture with a runtime file read. Only after the
generator creates the file, switch the persistent test to:

```rust
const GOLDEN_FIXTURE_RAW: &str =
    include_str!("../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json");
```

The ignored `regenerate_golden_fixture() -> TestResult` uses
`Keypair::from_seed(&[9_u8; 32])`, computes the id, signs the finding, resolves
`fixture_path()`, creates its parent, and writes pretty JSON plus one trailing
newline. It propagates every error.

### Persistent boundary

`golden_verified_fix_fixture_validates` must perform all five checks:

1. strict raw I-JSON parsing with `canonical_json_bytes_from_str`;
2. JSON Schema validation through the `chio-spec-validate` library;
3. typed `Finding` deserialization;
4. equality between strict raw canonical bytes and typed canonical bytes; and
5. `verify_finding`, including id and strict issuer signature.

The schema parity tests reject:

- an integer above the I-JSON maximum;
- `runtime_assurance_tier = "none"`;
- a prefixed issuer;
- explicit `null` for an optional field;
- deterministic replay without a recipe;
- lowercase currency;
- attested/observed/runtime-assured findings without receipts; and
- duplicate receipt ids.

They also accept a fully asserted finding with absent runtime tier and no
receipts.

### Red/green sequence

- [x] Before the fixture exists, run the runtime-reading golden test and
  observe a missing-file failure.

- [x] Generate the fixture:

  ```bash
  cargo test -p chio-finding --test finding \
    regenerate_golden_fixture -- --ignored --exact
  ```

- [x] Validate the now-present fixture through the schema CLI:

  ```bash
  cargo run -p chio-spec-validate -- \
    spec/schemas/chio-finding/v1/finding.schema.json \
    fixtures/proof-room/finding/verified-fix-basic/finding.json
  ```

- [x] Switch to compile-time inclusion and run the final target:

  ```bash
  cargo test -p chio-finding --test finding
  ```

  Exact Task 5 result: 34 passed, 0 failed, 1 ignored. Task 7 raises the
  final target to 39 passed, 1 ignored.

- [x] Commit:

  ```bash
  git add \
    Cargo.lock \
    crates/economy/chio-finding/Cargo.toml \
    crates/economy/chio-finding/tests/finding.rs \
    fixtures/proof-room/finding/verified-fix-basic
  git commit -m "test(chio-finding): golden verified-fix fixture with schema conformance"
  ```

## Task 6: Advance the open-market executable specification

### Files

- Add a test-only `chio-finding` dependency to
  `crates/economy/chio-open-market/Cargo.toml`.
- Add
  `crates/economy/chio-open-market/tests/cognition_market_flow.rs`.

Copy the exact landed spec:

```bash
git show 04f5d3e665c237b12bb0973a9862c2c26b884a5b:crates/economy/chio-open-market/tests/cognition_market_flow.rs
```

Then apply the current architecture-alignment delta shown by:

```bash
git diff 04f5d3e665c237b12bb0973a9862c2c26b884a5b -- \
  crates/economy/chio-open-market/tests/cognition_market_flow.rs
```

That delta pins the bearer-grant/DPoP seam, names the estimate and budget
inputs as buyer-local rather than authenticated platform facts, and attributes
digest enforcement to the output-aware kernel finalizer.

The passing tests use a real signed Finding and the real `bid()` path. They
prove that listing/bid shapes and the buyer-local elicitation ceiling require
no new generic marketplace machinery. They do not claim that acceptance,
authoritative reservation, governed reveal, or settlement is implemented.

The ignored `cognition_market_reveal_flow_spec` names four missing seams and
fails first at the kernel output-aware finalizer.

- [x] Run the passing cases:

  ```bash
  cargo test -p chio-open-market --test cognition_market_flow
  ```

  Exact result: 3 passed, 0 failed, 1 ignored.

- [x] Run the diagnostic deliberately:

  ```bash
  cargo test -p chio-open-market --test cognition_market_flow \
    cognition_market_reveal_flow_spec -- --ignored --exact
  ```

  Expected first error:

  ```text
  missing seam (a): no output-aware kernel finalizer binds receipt content_hash to the committed payload_sha256
  ```

- [x] Commit:

  ```bash
  git add \
    Cargo.lock \
    crates/economy/chio-open-market/Cargo.toml \
    crates/economy/chio-open-market/tests/cognition_market_flow.rs
  git commit -m "test(chio-open-market): advance cognition market spec to M1"
  ```

## Task 7: Apply the final strict verification hardening

At this point the schema and fixture exist, so the final `04f5d3e66` source
and complete test target can be copied without a compile-time fixture failure:

```bash
git show 04f5d3e665c237b12bb0973a9862c2c26b884a5b:crates/core/chio-core-types/src/crypto.rs
git show 04f5d3e665c237b12bb0973a9862c2c26b884a5b:crates/economy/chio-finding/src/validate.rs
git show 04f5d3e665c237b12bb0973a9862c2c26b884a5b:crates/economy/chio-finding/tests/finding.rs
git show 04f5d3e665c237b12bb0973a9862c2c26b884a5b:spec/schemas/chio-finding/v1/finding.schema.json
```

### Core crypto additions

```rust
#[must_use]
pub fn is_weak_ed25519(&self) -> bool;

#[must_use]
pub fn verify_strict(
    &self,
    message: &[u8],
    signature: &Signature,
) -> bool;

pub fn verify_canonical_strict<T: Serialize>(
    &self,
    value: &T,
    signature: &Signature,
) -> Result<bool>;
```

- `is_weak_ed25519` delegates to `VerifyingKey::is_weak`; other algorithms
  return `false`.
- `verify_strict` delegates Ed25519 to `VerifyingKey::verify_strict`, retains
  the existing P-256/P-384 verification, and applies strict verification to
  the classical part of hybrid signatures.
- `verify_canonical_strict` canonicalizes with
  `canonical_json_shared_bytes` and calls `verify_strict`.
- `verify_finding_signature` must call `verify_canonical_strict`, never the
  loose canonical verifier.
- `Finding::validate` rejects a non-Ed25519 issuer and rejects
  `is_weak_ed25519()`.
- The final hardening also adds uppercase currency and unique-receipt checks
  to both typed validation and JSON Schema.

The core regression constructs the compressed Edwards identity key and an
identity-point/zero-scalar signature, then proves strict verification rejects
the no-private-key forgery. The Finding regression proves the same issuer
cannot forge a signed Finding.

- [x] Verify:

  ```bash
  cargo test -p chio-core-types \
    crypto::tests::strict_verification_rejects_weak_ed25519_key
  cargo test -p chio-finding --test finding
  cargo clippy -p chio-finding --tests -- -D warnings
  ```

  Final Finding result: 39 passed, 0 failed, 1 ignored.

- [x] Commit:

  ```bash
  git add \
    crates/core/chio-core-types/src/crypto.rs \
    crates/economy/chio-finding/src/validate.rs \
    crates/economy/chio-finding/tests/finding.rs \
    crates/economy/chio-open-market/tests/cognition_market_flow.rs \
    fixtures/proof-room/finding/verified-fix-basic/README.md \
    spec/PROTOCOL.md \
    spec/schemas
  git commit -m "fix(chio-finding): harden artifact verification boundaries"
  ```

## Task 8: Verify ADR-0017 amendments

This is verification-only. The amendments were already present in the base
ADR and were refined during execution.

- [x] Use separate fixed-string checks so Markdown line wrapping cannot join
  unrelated clauses or create a false miss:

  ```bash
  rg -F 'optional pre-outcome intent-commitment receipt reference' \
    docs/adr/ADR-0017-cognition-market-finding-artifacts.md
  rg -F 'existing `ToolServer` actor' \
    docs/adr/ADR-0017-cognition-market-finding-artifacts.md
  rg -F 'Venue audits are selected from the' \
    docs/adr/ADR-0017-cognition-market-finding-artifacts.md
  ```

  Each command must return at least one match. Do not use the old
  `ToolServer.*actor` or `probabilistic audits` grep: the former depended on
  physical prose layout, and the latter predates the current signed-epoch
  audit-selection wording.

- [x] Check the no-em-dash rule:

  ```bash
  if rg -n $'\u2014' \
    docs/adr/ADR-0017-cognition-market-finding-artifacts.md; then
    exit 1
  fi
  ```

## Task 9: Run the complete gate

Run the qualified gate from one shell with the explicit mask:

```bash
umask 022
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
cargo clippy -p chio-finding --tests -- -D warnings
bash scripts/check-chio-owned-v1-only.sh
bash scripts/check-chio-schema-registry.sh
cargo test -p chio-core-types --test signed_artifact_schema
cargo test -p chio-finding --test finding
cargo test -p chio-open-market --test cognition_market_flow
```

### Recorded exact results at `88d4bde1f336`

| Gate | Result |
|---|---|
| `cargo build --workspace` | PASS in 82.68 seconds |
| `cargo test --workspace` | PASS in 2,982.74 seconds |
| Workspace test totals | 855 targets; 12,275 passed; 0 failed; 43 ignored; 788 filtered |
| `cargo clippy --workspace -- -D warnings` | PASS in 296.10 seconds |
| `cargo fmt --all -- --check` | PASS in 15.72 seconds |
| Finding test-target clippy | PASS in 12.76 seconds |
| v1-only checker | PASS in 0.68 seconds |
| schema-registry checker | PASS in 0.34 seconds |
| signed-artifact-schema target | 21 passed; 0 failed |
| finding target | 39 passed; 0 failed; 1 ignored |
| cognition-market target | 3 passed; 0 failed; 1 ignored |

After the full gate, `e429963d8` passed the cognition-market target, its
test-target clippy check, and formatting; its exact ignored invocation failed
at the intended output-aware finalizer seam. `20cdc7f83`, `1efbbc112`, and
`ea105498d` then passed the Finding target, Finding test-target clippy, and
formatting. These later changes refine test coverage, diagnostics, and
documentation without adding market wiring.

### Environment qualification

The host shell initially inherited `umask 002`. Under that mask, ten existing
`chio-cli` permission tests created mode-0775 serving directories that
`SqliteServingOwner` correctly rejected. The same ten failures reproduced in
a separate untouched worktree at exact `origin/main` `9ec6814a2`; they passed
under `umask 022` and under `077`.

This is a baseline-equivalent test-fixture/environment interaction, not a
cognition-market regression. The unqualified default-mask workspace test did
not pass. The complete gate recorded above is specifically the `umask 022`
run.

## M0/M1 exit criteria

- [x] `chio-finding` is a pure leaf crate with no production wiring.
- [x] `chio.finding.v1` is the only public Finding schema registered.
- [x] The artifact has exact id and signature preimages.
- [x] Structural validation, raw schema validation, and the typed-canonical
  equality boundary together enforce the I-JSON, optional-field, currency,
  receipt, and encoding rules.
- [x] Ed25519 issuers are algorithm-checked and weak-key checked.
- [x] Public signatures use `verify_canonical_strict`.
- [x] The deterministic signed golden crosses raw, schema, typed canonical,
  id, and signature boundaries.
- [x] The open-market passing tests prove only the machinery actually reused.
- [x] The ignored reveal test names the first unimplemented seam.
- [x] The full qualified workspace gate and supplemental checks pass.
