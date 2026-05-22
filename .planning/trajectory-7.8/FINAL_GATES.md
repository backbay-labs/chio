# Chio 7.8 Final Gates

- `cargo test -p chio-runtime-core treaty_runtime`
- `cargo test -p chio-runtime-core buyer_review`
- `cargo test -p chio-kernel chio_runtime`
- `cargo test -p chio-federation chio`
- `cargo test -p chio-attest-buyer-core`
- `cargo test -p chio-cli --bin chio_buyer`
- `cargo test -p chio-three-vendor-example`
- `cargo test -p chio-spec-validate`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --schema-only`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --negative-only`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --runtime-only`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --dsse-only`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --lineage-only`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --proof-only`
- `bash scripts/check-chio-live-treaty-buyer-closure.sh --buyer-only`
- Existing treaty provenance, treaty buyer hero loop, runtime proof parity,
  runtime policy, runtime spine, proof-package, authority issuance, and
  pheromone runtime gates.
- `cargo fmt --all -- --check`
- Targeted clippy for touched crates with `-D warnings`.
