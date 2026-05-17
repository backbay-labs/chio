# Chiodos 7.8 Final Gates

- `cargo test -p chio-chiodos-runtime treaty_runtime`
- `cargo test -p chio-chiodos-runtime buyer_review`
- `cargo test -p chio-kernel chiodos_runtime`
- `cargo test -p chio-federation chiodos`
- `cargo test -p chio-chiodos`
- `cargo test -p chio-cli --bin chio chiodos_buyer`
- `cargo test -p chiodos-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --schema-only`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --negative-only`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --runtime-only`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --dsse-only`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --lineage-only`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --proof-only`
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh --buyer-only`
- Existing treaty provenance, treaty buyer hero loop, runtime proof parity,
  runtime policy, runtime spine, proof-package, authority issuance, and
  pheromone runtime gates.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
