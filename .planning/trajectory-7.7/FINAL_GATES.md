# Final Gates

- `cargo test -p chio-chiodos-runtime treaty_runtime`
- `cargo test -p chio-chiodos-runtime buyer_review --test runtime_admission`
- `cargo test -p chio-cli --bin chio chiodos_buyer`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh`
- `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh --schema-only`
- `bash scripts/check-chiodos-treaty-buyer-hero-loop.sh --negative-only`
- Existing treaty provenance and runtime proof gates as workstation space allows.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
