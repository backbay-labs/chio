# Final Gates

- `cargo test -p chio-chiodos-runtime runtime_orchestration`
- `cargo test -p chio-chiodos-runtime runtime_proof_drift`
- `cargo test -p chio-chiodos-runtime runtime_proof_regeneration`
- `cargo test -p chio-kernel chiodos_runtime`
- `cargo test -p chio-cli --bin chio chiodos_runtime`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-runtime-orchestration.sh`
- `bash scripts/check-chiodos-runtime-orchestration.sh --schema-only`
- `bash scripts/check-chiodos-runtime-orchestration.sh --negative-only`
- Existing runtime proof-parity, runtime policy, runtime spine, proof-package,
  authority issuance, pheromone runtime, bounded, diagnostic, and threat-mutant
  gates where disk permits.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
