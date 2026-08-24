#!/usr/bin/env bash
# PR-tier CI gate mirroring the "Build, lint, test" job in .github/workflows/ci.yml.
# Invoked by `make ci`. For the heavier local gate (formal proof report), use
# `make ci-workspace` which runs scripts/ci-workspace.sh.
set -euo pipefail

cd "$(dirname "$0")/.."

# Mirror .github/workflows/ci.yml workflow env and per-step cargo settings so
# `make ci` matches the PR-tier "Build, lint, test" job coverage and warning
# posture. Callers can override any variable for a faster local run.
export PROPTEST_CASES="${PROPTEST_CASES:-256}"
export CHIO_CI_RUSTFLAGS="${CHIO_CI_RUSTFLAGS:--D warnings -C link-arg=-Wl,--threads=1}"
export RUSTFLAGS="${RUSTFLAGS:-${CHIO_CI_RUSTFLAGS} -C debuginfo=0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

./scripts/check-proptest-coverage.sh

./scripts/check-release-inputs.sh
./scripts/check-workspace-layering.sh
python3 scripts/check-review-slices.py
bash scripts/tests/check-sidecar-docker-context.test.sh
bash scripts/tests/check-sidecar-image-workflow.test.sh
python3 scripts/check-rust-public-surface.py
bash scripts/tests/check-rust-public-surface.test.sh
python3 scripts/check-architecture-docs.py
./scripts/check-sre-metrics-registry.sh
./scripts/check-log-redaction.sh
./scripts/check-http-egress-contract.sh
bash scripts/tests/check-http-egress-contract.test.sh

./scripts/check-anchor-batch-async-witness.sh

cargo xtask check crate-paths

cargo fmt --all -- --check

python3 scripts/check-rust-file-hygiene.py
bash scripts/tests/check-rust-file-hygiene.test.sh

python3 scripts/check-stub-surfaces.py
bash scripts/tests/check-stub-surfaces.test.sh
bash scripts/tests/check-sdk-release-python-generated.test.sh
bash scripts/tests/check-sdk-release-ts-bun.test.sh
bash scripts/tests/conformance-matrix-peer-target.test.sh
bash scripts/tests/qualify-release-provider-replay.test.sh
bash scripts/tests/qualify-release-peer-smoke.test.sh
bash scripts/tests/release-qualification-formal-tools.test.sh
bash scripts/tests/release-npm-package-matrix.test.sh
bash scripts/tests/release-pypi-package-matrix.test.sh
bash scripts/tests/provider-fixture-claims.test.sh

cargo clippy --workspace --lib --bins --examples -- -D warnings
cargo build --workspace
cargo test --workspace --exclude chio-wasm-guards
cargo test -p chio-wasm-guards --lib

RUSTFLAGS="${CHIO_CI_RUSTFLAGS} -C debuginfo=0 --cfg tokio_unstable" \
  cargo test -p chio-kernel --features tokio-console-smoke --test tokio_console_smoke
