# Chio attest buyer schema cutover

## Objective

Move buyer packet verification to Chio-native attest schema IDs for the live
packet/report boundary:

- `chio.attest.buyer-attestation-packet.v1`
- `chio.attest.buyer-attestation-verification-report.v1`

Historical `chio.chiodos.*` buyer packet inputs remain read-compatible. The
strict DSSE behavior must not change: hash-only packets remain unresolved until
hydrated DSSE evidence is supplied by full review.

## Plan

1. Add a failing `chio-attest-buyer` test using the Chio packet schema and
   expecting a Chio verification report schema.
2. Add Chio attest schema constants while preserving historical constants.
3. Update buyer packet/report validators to accept legacy or Chio schemas, and
   update report emitters to write Chio schemas.
4. Add Chio attest schema files, registry entries, and manifest hashes.
5. Run buyer tests, schema registry checks, and hygiene gates.

## Verification

- [x] `cargo test -p chio-attest-buyer chio_buyer_packet_schema --test buyer_packet`
      fails before implementation.
- [x] `cargo test -p chio-attest-buyer chio_buyer_packet_schema --test buyer_packet`
- [x] `cargo test -p chio-attest-buyer`
- [x] `cargo test -p chio-chiodos-runtime buyer_hash_only_packet --test runtime_buyer_review`
- [x] `bash scripts/check-chio-schema-registry.sh`
- [x] `cargo clippy -p chio-attest-buyer --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-chiodos-runtime --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
