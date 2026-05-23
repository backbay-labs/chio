# Chio attest buyer review schema cutover

## Objective

Move the buyer attestation full review boundary to Chio-native attest schema IDs:

- `chio.attest.buyer-attestation-review-package.v1`
- `chio.attest.buyer-attestation-review-report.v1`

Historical `Chio-native schema IDs` buyer review packages remain read-compatible for
already signed artifacts, but new package/report emitters use the Chio IDs.

## Plan

1. Add a failing `chio-attest-buyer` regression for a Chio review package that
   expects a Chio review report.
2. Add Chio review package/report schema constants and re-export them through
   the buyer crate.
3. Accept legacy or Chio review package/report inputs, while emitting Chio
   review reports from new verifier paths.
4. Switch the CLI buyer package emitter to the Chio review package schema.
5. Add schema files, registry entries, manifest hashes, and doc evidence.
6. Run focused buyer, schema, clippy, formatting, and hygiene gates.

## Verification

- [x] `cargo test -p chio-attest-buyer chio_buyer_review_package_schema --test buyer_review` fails before implementation.
- [x] `cargo test -p chio-attest-buyer chio_buyer_review_package_schema --test buyer_review`
- [x] `cargo test -p chio-attest-buyer`
- [x] `cargo test -p chio-runtime-core --test runtime_buyer_review`
- [x] `cargo test -p chio-cli chio_attest_buyer --bin chio`
- [x] `bash scripts/check-chio-schema-registry.sh`
- [x] `cargo clippy -p chio-attest-buyer --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-runtime-core --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-cli --bin chio -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
