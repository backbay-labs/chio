#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/check-release-inputs.sh
./scripts/check-workspace-layering.sh
python3 scripts/check-review-slices.py
bash scripts/tests/check-sidecar-docker-context.test.sh
bash scripts/tests/check-sidecar-image-workflow.test.sh
python3 scripts/check-rust-public-surface.py
bash scripts/tests/check-rust-public-surface.test.sh
python3 scripts/check-architecture-docs.py
./scripts/check-formal-proofs.sh
bash scripts/tests/lean-mutants.test.sh
bash scripts/tests/spec-mutants.test.sh
./scripts/check-aeneas-pilot.sh
./scripts/check-aeneas-production.sh
./scripts/check-aeneas-equivalence.sh
./scripts/check-rust-verification-gates.sh
bash scripts/tests/check-creusot-contract-sync.test.sh
bash scripts/tests/check-rust-verification-gates.test.sh
bash scripts/tests/check-receipt-trace-bindings.test.sh
./scripts/check-adapter-no-bypass.sh
./scripts/check-portable-kernel.sh
./scripts/generate-proof-report.sh
./scripts/check-proof-report.sh --require-strict
bash scripts/tests/check-proof-report.test.sh
bash scripts/tests/lane-gate.test.sh
bash scripts/tests/formal-workflow-wiring.test.sh
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
# The CI warning gate covers repo-shipping targets; test/bench-only lint is
# exercised by `cargo test`.
cargo clippy --workspace --lib --bins --examples -- -D warnings
cargo build --workspace
./scripts/check-policy-analysis.sh target/debug/chio
# `chio-wasm-guards` pulls in large wasmtime-backed integration binaries when
# features unify across the workspace, which has been tripping the Linux CI
# linker. Keep the default lane on the full workspace minus that package and
# run its lighter library tests separately.
cargo test --workspace --exclude chio-wasm-guards
cargo test -p chio-wasm-guards --lib
