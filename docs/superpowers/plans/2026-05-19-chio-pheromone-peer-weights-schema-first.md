# Chio pheromone peer weights schema-first loading

## Objective

Make peer weight loading schema-first so unknown fields and schema drift reject
before serde can ignore them.

## Plan

1. Add a failing runtime regression proving `peer_weights_from_json` rejects
   unknown top-level peer weight fields with `schema_invalid`.
2. Validate peer weight JSON against
   `spec/schemas/chio-pheromone/v1/peer-weights.schema.json` before serde.
3. Add `deny_unknown_fields` to peer weight serde structs as a defensive second
   line after schema validation.
4. Run focused runtime tests, clippy, formatting, schema gate, whitespace, dash
   scan, and status.

## Verification

- [x] `cargo test -p chio-pheromone-runtime peer_weights_loader_rejects_unknown_fields_before_serde --test runtime_receiver` fails before implementation.
- [x] `cargo test -p chio-pheromone-runtime peer_weights_loader_rejects_unknown_fields_before_serde --test runtime_receiver`
- [x] `cargo test -p chio-pheromone-runtime --test runtime_receiver`
- [x] `cargo clippy -p chio-pheromone-runtime --all-targets -- -D warnings`
- [x] `bash scripts/check-chio-pheromone-runtime.sh --schema-only`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
