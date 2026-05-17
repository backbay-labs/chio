# Chiodos 7.5 Final Gates

- `cargo test -p chio-chiodos-runtime runtime_ops`
- `cargo test -p chio-chiodos-runtime runtime_orchestration`
- `cargo test -p chio-cli --bin chio chiodos_runtime_ops`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --schema-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --negative-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --tick-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --recovery-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --evidence-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --provider-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --retention-only`
- `bash scripts/check-chiodos-runtime-ops-hardening.sh --failure-codes-only`
- Existing runtime orchestration, proof parity, policy, spine, proof-package,
  authority, pheromone runtime, bounded, diagnostic, and threat-mutant gates.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
