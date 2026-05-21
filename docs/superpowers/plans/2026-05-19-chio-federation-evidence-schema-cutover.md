# Chio federation evidence schema cutover

## Objective

Allow Chio buyer packets to be backed by Chio-native federation evidence IDs:

- `chio.federation.cross-kernel-continuation.v1`
- `chio.federation.receipt-lineage-statement.v1`
- `chio.federation.bilateral-invocation.v1`
- `chio.federation.receipt-lineage-bundle.v1`

Historical `chio.chiodos.*` IDs remain read-compatible for already signed
evidence.

## Plan

1. Add a failing buyer packet regression that uses Chio federation evidence
   schemas under a Chio buyer packet.
2. Add Chio federation evidence constants and re-export them.
3. Update treaty validators to accept Chio or historical Chiodos schema IDs.
4. Add schema files, registry entries, manifest hashes, and architecture notes.
5. Run focused buyer/runtime tests, schema registry checks, clippy, formatting,
   whitespace, and dash scans.

## Verification

- [x] `cargo test -p chio-attest-buyer buyer_packet_without_hydrated_dsse --test buyer_packet` fails before implementation.
- [x] `cargo test -p chio-attest-buyer buyer_packet_without_hydrated_dsse --test buyer_packet`
- [x] `cargo test -p chio-attest-buyer`
- [x] `cargo test -p chio-chiodos-runtime --test runtime_buyer_review`
- [x] `bash scripts/check-chio-schema-registry.sh`
- [x] `cargo clippy -p chio-attest-buyer --all-targets -- -D warnings`
- [x] `cargo clippy -p chio-chiodos-runtime --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
