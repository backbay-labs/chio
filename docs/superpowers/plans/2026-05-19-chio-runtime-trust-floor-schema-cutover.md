# Chio runtime trust-floor schema cutover

## Objective

Move the JSON runtime trust-floor state store to live Chio schema emission:
`chio.runtime.trust-floor-state.v1`.

The cutover must preserve read compatibility for existing
`chio.chiodos.runtime-trust-floor-state.v1` files, but new writes must use the
Chio-native schema. The historical schema file remains byte-preserving
compatibility material and is not rewritten.

## Plan

1. Add regression tests proving the JSON trust-floor store writes the Chio
   schema and normalizes a legacy file on the next write.
2. Add a Chio-native trust-floor schema constant while keeping the historical
   Chiodos constant for read compatibility.
3. Update the JSON trust-floor store to accept legacy state, normalize to the
   Chio schema in memory, and persist Chio-native state.
4. Correct the Chio runtime trust-floor JSON schema to match the Rust state
   shape and refresh `spec/schemas/MANIFEST.sha256`.
5. Run focused runtime trust tests and schema gates.

## Verification

- [x] `cargo test -p chio-chiodos-runtime runtime_trust_floor --test runtime_trust`
      fails before implementation.
- [x] `cargo test -p chio-chiodos-runtime runtime_trust_floor --test runtime_trust`
- [x] `cargo test -p chio-chiodos-runtime layered_store_keeps_trust_floor_separate_from_admission_state --test runtime_trust`
- [x] `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- [x] `bash scripts/check-chio-schema-registry.sh`
- [x] `cargo test -p chio-chiodos-runtime --test runtime_trust`
- [x] `cargo clippy -p chio-chiodos-runtime --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
