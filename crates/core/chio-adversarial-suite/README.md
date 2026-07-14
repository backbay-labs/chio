# chio-adversarial-suite

Curated corpus of malicious-but-well-formed adversarial cases for Chio's trust
boundary, plus the loader and validation that give the corpus one schema.
Concrete vectors live under `cases/`, grouped by attack class. The crate has
no dependency on any other `chio-*` crate: it is pure data and validation,
consumed by downstream test suites as a deny-assertion answer key.

## Responsibilities

- Define the on-disk case envelope (`AdversarialCase`) and enforce it two
  ways: a JSON Schema (`schema/case.schema.json`, exposed as
  `CASE_SCHEMA_JSON`) and semantic Rust validation (`AdversarialCase::validate`).
- Embed the full corpus (40 case files, 5 per attack class) at compile time
  via `include_str!` into `BUNDLED_CASES`, so consumers need no filesystem
  access.
- Exclude untriaged (`pending: true`) cases from coverage through
  `into_coverage_case` / `CoverageCase`.
- Produce a deterministic cross-SDK manifest (`manifest::Manifest`) pinning
  each non-pending case's id, class, expected verdict and reason, threat id,
  path, and content sha256, checked in at `manifest.json`.

## Public API

- `AdversarialCase` - the case envelope; `from_slice`, `from_path`, `validate`,
  `into_coverage_case`.
- `CoverageCase` - a validated, non-pending case; `as_case`, `into_inner`.
- `bundled_cases`, `bundled_coverage_cases`, `bundled_cases_by_class` - load
  the embedded corpus.
- `AttackClass` - the 8 attack classes, with `as_str` for the stable
  snake_case tag; `ATTACK_CLASSES` lists them all.
- `BUNDLED_CASES`, `CASE_SCHEMA_VERSION`, `CASE_SCHEMA_JSON`.
- `ExpectedVerdict` - a single `Deny` variant (`"DENY"` on the wire).
- `CaseError` - load and validation failures, including `ManifestDrift`.
- `manifest::{Manifest, ManifestEntry, MANIFEST_PRODUCER, MANIFEST_SCHEMA_VERSION}`,
  re-exported at the crate root.

## Usage

```rust
use chio_adversarial_suite::{bundled_cases_by_class, AttackClass, CaseError};

fn kernel_denies_replays() -> Result<(), CaseError> {
    for case in bundled_cases_by_class(AttackClass::ReplayedNonce)? {
        let coverage_case = case.into_coverage_case()?;
        // assert the trust boundary under test denies
        // `coverage_case.as_case()` with its `expected_reason`.
    }
    Ok(())
}
```

## Testing

`cargo test -p chio-adversarial-suite`

`tests/manifest_emit.rs` fails if `manifest.json` drifts from a freshly
computed `Manifest::from_bundled()`. After adding or editing a case,
regenerate it with:

```
cargo test -p chio-adversarial-suite --test manifest_emit -- --ignored regenerate
```

## See also

- `chio-kernel-core`, `chio-attest-verify`, `chio-conformance` - dev-depend on
  this crate to deny-assert their guard, attestation, and threat-model
  coverage against the bundled corpus.
