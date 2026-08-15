# Verdict Matrix

The verdict matrix is the cross-SDK semantic equality harness for Chio tool
access decisions. The Rust kernel path ships first, with the scenario corpus,
driver, and diff oracle living under `crates/tooling/chio-conformance/verdict_matrix/`.

## Corpus

The active corpus contains 60 JSON scenarios:

| Class | Directory | Count |
| --- | --- | --- |
| Capability subset | `scenarios/capability_subset/` | 12 |
| Revocation propagation | `scenarios/revocation_propagation/` | 12 |
| Replay verdict | `scenarios/replay_verdict/` | 12 |
| Redaction determinism | `scenarios/redaction_determinism/` | 12 |
| Delivery contract | `scenarios/delivery_contract/` | 12 |

`manifest.toml` pins the corpus with `scenario_index_hash`. The hash is computed
over sorted relative paths and each file SHA-256 digest:

```text
relative/path.json<TAB>file_sha256<LF>
```

The active `corpus_sha256` is
`6ef424c7410290675d796330ec46aef1a1c3a4c56952349f452c72cdc139f0d3`.

The manifest also records the active drivers and the tuple fields asserted by
the oracle.

## Required Drivers

The required verdict-matrix gates are:

| Driver | Required | Gate |
| --- | --- | --- |
| `rust-kernel` | yes | `cargo test -p chio-conformance --test verdict_matrix_rust_driver --quiet` |
| `python-sdk` | yes | `cd sdks/python/chio-sdk-python && python -m pytest tests/test_verdict_matrix.py -q` |
| `go-http-sdk` | yes | `cd sdks/go/chio-go-http && go test -run VerdictMatrix ./...` |
| deployment-shape smoke | yes | `cargo test -p chio-conformance --test deployment_shape_smoke --quiet` |
| `typescript-node-http` | no | advisory transport client, sidecar required |
| `wasm-browser` | no | advisory partial browser surface |

Required drivers must emit all 60 tuples with `unsupported = 0` and zero
divergence from the Rust kernel expected tuple for each scenario.

## Corpus rotation

The corpus rotation process is intentionally narrow. A rotation changes one or
more files under `crates/tooling/chio-conformance/verdict_matrix/scenarios/`, recomputes
the sorted scenario index hash, updates both `scenario_index_hash` and
`corpus_sha256` in `manifest.toml`, and updates this page with the new
scenario count and hash. The diff-oracle self test must pass before
the rotated corpus can be treated as active.

## Tuple Contract

Drivers emit one semantic tuple per scenario:

```text
(verdict, reason_code, scope_set)
```

`verdict` is `allow`, `deny`, or `error`. `reason_code` is either
`urn:chio:error:none` or a value from `spec/errors/registry.yaml`. `scope_set`
is sorted before comparison.

The Rust driver fails closed:

- invalid scenario JSON is a load failure
- unknown top-level scenario fields are rejected
- unsupported scenario requirements are reported as unsupported
- revocation, replay, scope, and guard denials produce deny or error tuples

## Python and Go Driver Boundaries

The Python SDK driver is required. It emits local semantic tuples for all 60
scenarios by issuing a mock SDK capability, evaluating the requested tool call
through `MockChioClient`, and deriving the tuple from the receipt decision and
scenario requirements. Capability subset, revocation propagation, replay
verdict, redaction determinism, and delivery contract must all report
`unsupported = 0`. The delivery-contract class is a mock that does not enforce
output digests: it denies any request carrying the `output_digest_sha256`
constraint from carrier admission alone (deny-on-unsupported-constraint),
reporting `urn:chio:error:kernel:delivery-contract-unsupported-carrier`, or
`urn:chio:error:kernel:delivery-contract-digest-mismatch` for a declared
mismatch.

The Go HTTP SDK driver is required. It emits local semantic tuples for all 60
scenarios through the Go verdict-matrix driver under
`crates/tooling/chio-conformance/verdict_matrix/drivers/go/` and is checked from
`sdks/go/chio-go-http` with `go test -run VerdictMatrix ./...`. The required
CI job fails if the driver reports unsupported scenarios or diverges from the
expected tuple set.

## Rust Driver Boundary

The Rust driver evaluates scenarios through an in-process `ChioKernel`. It
issues real capabilities, optionally revokes them, registers a tool server,
runs kernel evaluation, and compares signed receipt-backed outcomes.

The scenario format uses driver-neutral labels, so the Rust driver adapts them
to existing kernel surfaces:

- `capability_scopes` labels become native `ToolGrant` entries.
- Input redaction allow cases are represented as signed receipt metadata until
  the pre-execution guard interface can carry allow-with-redaction details.
- Output redaction uses the kernel post-invocation hook pipeline.
- Replay verdicts use execution-nonce verification. The missing-trace case is
  mapped from the strict-mode missing-nonce gate because the current kernel
  response type does not expose an error verdict.

## TypeScript And Browser Driver Boundary

The TypeScript node-http driver is a transport client around
`ChioSidecarClient.evaluate`. It reports scenarios as unsupported unless
`CHIO_VERDICT_MATRIX_SIDECAR_URL` or `CHIO_SIDECAR_URL` points to a live sidecar
that emits verdict matrix receipt metadata. It does not patch `globalThis.fetch`
or derive verdicts from scenario fields.

The WASM browser driver exercises the real `chio-kernel-browser` `evaluate_pure`
path for the capability subset. It reports revocation propagation, replay
verdict, redaction determinism, and delivery contract as unsupported because that
browser surface does not include a revocation store, execution nonce store,
guard pipeline, or output-aware delivery terminal.

## Local Gates

Run these gates locally:

```bash
test -d crates/tooling/chio-conformance/verdict_matrix/scenarios/capability_subset
test -d crates/tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation
test -d crates/tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict
test -d crates/tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism
test "$(find crates/tooling/chio-conformance/verdict_matrix/scenarios/capability_subset -name '*.json' | wc -l)" -ge 12
test "$(find crates/tooling/chio-conformance/verdict_matrix/scenarios/revocation_propagation -name '*.json' | wc -l)" -ge 12
test "$(find crates/tooling/chio-conformance/verdict_matrix/scenarios/replay_verdict -name '*.json' | wc -l)" -ge 12
test "$(find crates/tooling/chio-conformance/verdict_matrix/scenarios/redaction_determinism -name '*.json' | wc -l)" -ge 12
cargo test -p chio-conformance --test verdict_matrix_rust_driver --quiet
cargo test -p chio-conformance --test diff_oracle_self_test --quiet
cargo test -p chio-conformance --test verdict_matrix_cross_language --quiet
cd sdks/python/chio-sdk-python && python -m pytest tests/test_verdict_matrix.py -q
cd ../../go/chio-go-http && go test -run VerdictMatrix ./...
cd ../../..
test -f docs/conformance/verdict-matrix.md
python3 - <<'PY'
from pathlib import Path

docs = Path("docs/conformance/verdict-matrix.md").read_text()
cross_language = "verdict_matrix_" + "cross_language"
docs_command = (
    "cargo test -p chio-conformance --test "
    + cross_language
    + " --quiet"
)
if docs_command not in docs:
    raise SystemExit("cross-language verdict-matrix docs gate is missing")
PY
```
