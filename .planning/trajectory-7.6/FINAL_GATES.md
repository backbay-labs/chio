# Final Gates

- `cargo test -p chio-runtime-core treaty_ --test runtime_admission`
- `cargo test -p chio-runtime-core buyer_attestation --test runtime_admission`
- `cargo check -p chio-cli --bin chio`
- `bash scripts/check-chio-treaty-bound-provenance.sh`
- `bash scripts/check-chio-treaty-bound-provenance.sh --schema-only`
- `bash scripts/check-chio-treaty-bound-provenance.sh --negative-only`
- Existing runtime spine, runtime policy, runtime proof parity, runtime orchestration, runtime ops, proof-package, authority, pheromone runtime, bounded, diagnostic, and threat-mutant gates when workstation space permits.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
