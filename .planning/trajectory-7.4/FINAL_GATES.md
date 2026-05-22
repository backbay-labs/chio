# Final Gates

- `cargo test -p chio-runtime-core runtime_orchestration`
- `cargo test -p chio-runtime-core runtime_proof_drift`
- `cargo test -p chio-runtime-core runtime_proof_regeneration`
- `cargo test -p chio-kernel chio_runtime`
- `cargo test -p chio-cli --bin chio_runtime`
- `cargo test -p chio-three-vendor-example`
- `cargo test -p chio-attest-buyer-core`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chio-runtime-orchestration.sh`
- `bash scripts/check-chio-runtime-orchestration.sh --schema-only`
- `bash scripts/check-chio-runtime-orchestration.sh --negative-only`
- Existing runtime proof-parity, runtime policy, runtime spine, proof-package,
  authority issuance, pheromone runtime, bounded, diagnostic, and threat-mutant
  gates where disk permits.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
