# Chio schema registry compatibility gate

## Objective

Make the schema registry enforce the final architecture boundary for legacy
Chio artifacts:

- Active Chio schemas must not use `chio_*` artifact kinds.
- Entries pointing at `spec/schemas/chio/` are compatibility-only and must
  be marked `retired`.
- This must not rewrite historical schema files, signed schema IDs, or
  compatibility verifier semantics.

## Plan

1. Add `scripts/check-chio-schema-registry.sh` as the failing regression gate.
2. Run it red against the current registry to prove missing compatibility
   metadata is detected.
3. Add `status: retired` to every legacy registry entry
   whose `schemaFile` lives under `spec/schemas/chio/`.
4. Run the new gate, existing focused schema gates, and hygiene checks.

## Verification

- [x] `bash scripts/check-chio-schema-registry.sh` fails before the registry
      metadata fix.
- [x] `bash scripts/check-chio-schema-registry.sh` passes after the fix.
- [x] `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- [x] `bash scripts/check-chio-pheromone-transit.sh --schema-only`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
