# Verdict Matrix

The verdict matrix is the cross-SDK semantic equality harness for Chio tool
access decisions. P4 ships the Rust kernel path first, with the scenario corpus,
driver, and diff oracle living under `crates/chio-conformance/verdict_matrix/`.

## Corpus

The P4 corpus contains 48 JSON scenarios:

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
