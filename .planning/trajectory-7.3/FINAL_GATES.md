# Final Gates

- `cargo test -p chio-runtime-core runtime_proof_regeneration`
- `cargo test -p chio-cli --bin chio_runtime`
- `cargo test -p chio-three-vendor-example`
- `cargo test -p chio-attest-buyer-core`
- `cargo test -p chio-federation chio`
- `cargo test -p chio-workflow`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chio-runtime-proof-parity.sh`
- `bash scripts/check-chio-runtime-proof-parity.sh --schema-only`
- `bash scripts/check-chio-runtime-proof-parity.sh --negative-only`
- Existing runtime spine, runtime policy, proof-package, authority issuance, and
  pheromone runtime gates where practical.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
