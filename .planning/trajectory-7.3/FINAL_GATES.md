# Final Gates

- `cargo test -p chio-chiodos-runtime runtime_proof_regeneration`
- `cargo test -p chio-cli --bin chio chiodos_runtime`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-federation chiodos`
- `cargo test -p chio-workflow`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-runtime-proof-parity.sh`
- `bash scripts/check-chiodos-runtime-proof-parity.sh --schema-only`
- `bash scripts/check-chiodos-runtime-proof-parity.sh --negative-only`
- Existing runtime spine, runtime policy, proof-package, authority issuance, and
  pheromone runtime gates where practical.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
