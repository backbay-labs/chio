# Verdict Matrix

The verdict matrix is the cross-SDK semantic equality harness for Chio tool
access decisions. The Rust kernel path ships first, with the scenario corpus,
driver, and diff oracle living under `crates/chio-conformance/verdict_matrix/`.

## Corpus

The active corpus contains 48 JSON scenarios:

| Class | Directory | Count |
| --- | --- | --- |
| Capability subset | `scenarios/capability_subset/` | 12 |
| Revocation propagation | `scenarios/revocation_propagation/` | 12 |
| Replay verdict | `scenarios/replay_verdict/` | 12 |
| Redaction determinism | `scenarios/redaction_determinism/` | 12 |

`manifest.toml` pins the corpus with `scenario_index_hash`. The hash is computed
over sorted relative paths and each file SHA-256 digest:

```text
relative/path.json<TAB>file_sha256<LF>
```

The manifest also records the active drivers and the tuple fields asserted by
the oracle.

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

The Python SDK driver currently emits actual tuples only for capability subset
scenarios. It issues a mock SDK capability, evaluates the requested tool call
through `MockChioClient`, and derives the tuple from the returned receipt
decision. Revocation, replay, and redaction scenarios are reported as
unsupported until those verdict-emitting SDK surfaces exist locally.

The Go HTTP SDK driver reports the current corpus as unsupported. The Go HTTP
SDK forwards requests to a sidecar and decodes the sidecar verdict; it does not
yet contain a local semantic verdict emitter for scope, revocation, replay, or
redaction matrix scenarios.

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

## Local Gates

Run the same gates used by the workflow:

```bash
test -d crates/chio-conformance/verdict_matrix/scenarios/capability_subset
test -d crates/chio-conformance/verdict_matrix/scenarios/revocation_propagation
test -d crates/chio-conformance/verdict_matrix/scenarios/replay_verdict
test -d crates/chio-conformance/verdict_matrix/scenarios/redaction_determinism
test "$(find crates/chio-conformance/verdict_matrix/scenarios/capability_subset -name '*.json' | wc -l)" -ge 12
test "$(find crates/chio-conformance/verdict_matrix/scenarios/revocation_propagation -name '*.json' | wc -l)" -ge 12
test "$(find crates/chio-conformance/verdict_matrix/scenarios/replay_verdict -name '*.json' | wc -l)" -ge 12
test "$(find crates/chio-conformance/verdict_matrix/scenarios/redaction_determinism -name '*.json' | wc -l)" -ge 12
cargo test -p chio-conformance --test verdict_matrix_rust_driver --quiet
cargo test -p chio-conformance --test diff_oracle_self_test --quiet
test -f .github/workflows/verdict-matrix.yml
grep -q 'verdict_matrix' .github/workflows/verdict-matrix.yml
test -f docs/conformance/verdict-matrix.md
```
