# Chio federation treaty schema cutover

## Objective

Move the live federation treaty path to Chio-native schema IDs:

- `chio.federation.treaty-scope.v1`
- `chio.federation.ladder-intersection.v1`
- `chio.federation.cross-boundary-admission-report.v1`

Historical `Chio-native schema IDs` treaty artifacts remain read-compatible. New
computed ladder intersections and admission reports must use the Chio IDs.

## Plan

1. Add failing treaty tests for Chio-native treaty input and Chio-native
   intersection/admission output.
2. Add Chio federation schema constants while keeping Chio constants for
   compatibility.
3. Update treaty validators to accept legacy or Chio schema IDs, and update
   emitters to write Chio IDs.
4. Add Chio federation schema files, registry entries, and manifest hashes.
5. Run treaty tests, schema registry checks, and hygiene gates.

## Verification

- [x] `cargo test -p chio-runtime-core chio_federation_treaty_schema --test runtime_treaty`
      fails before implementation.
- [x] `cargo test -p chio-runtime-core chio_federation_treaty_schema --test runtime_treaty`
- [x] `cargo test -p chio-runtime-core --test runtime_treaty`
- [x] `bash scripts/check-chio-schema-registry.sh`
- [x] `cargo clippy -p chio-runtime-core --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
