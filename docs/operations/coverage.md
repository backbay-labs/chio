# Coverage Artifacts

`./scripts/run-coverage.sh` generates repository coverage reports with
`cargo-tarpaulin`. The script prefers a local `cargo tarpaulin` binary and
falls back to the official Docker image documented by the tarpaulin project.
The baseline workspace run measured `67.43%` line coverage, so CI and release
qualification now enforce a `67%` floor via `COVERAGE_FAIL_UNDER=67`.

Generated outputs:

- `coverage/html/index.html`: human-readable HTML coverage report.
- `coverage/lcov.info`: LCOV output for downstream tooling.
- `coverage/tarpaulin-report.json`: machine-readable tarpaulin JSON report.
- `coverage/tarpaulin.log`: raw tarpaulin stdout/stderr captured by the runner.
- `coverage/summary.txt`: measured coverage percentage and the configured floor.

The release qualification lane copies this directory into
`target/release-qualification/coverage/`, and the CI coverage lane uploads the
same directory as a workflow artifact.
