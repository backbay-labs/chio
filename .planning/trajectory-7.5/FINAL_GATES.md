# Chio 7.5 Final Gates

- `cargo test -p chio-runtime-core runtime_ops`
- `cargo test -p chio-runtime-core runtime_orchestration`
- `cargo test -p chio-cli --bin chio_runtime_ops`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chio-runtime-ops-hardening.sh`
- `bash scripts/check-chio-runtime-ops-hardening.sh --schema-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --negative-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --tick-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --recovery-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --evidence-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --provider-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --retention-only`
- `bash scripts/check-chio-runtime-ops-hardening.sh --failure-codes-only`
- Existing runtime orchestration, proof parity, policy, spine, proof-package,
  authority, pheromone runtime, bounded, diagnostic, and threat-mutant gates.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
