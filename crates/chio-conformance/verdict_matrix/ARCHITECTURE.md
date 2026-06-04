# chio-conformance-verdict-matrix Architecture Notes

## Module Boundaries

This directory is a standalone Cargo workspace, not a root workspace member.
`lib.rs` exposes shared verdict tuple types and schema constants.
`driver.rs` owns scenario loading, scenario validation, and the in-process Rust
kernel driver. `diff_oracle.rs` owns manifest loading, corpus hashing,
reason-code registry validation, and expected-versus-driver tuple diffs.
`cross_language.rs` aggregates per-driver reports and enforces tuple equality
across drivers. The language and deployment drivers under `drivers/` consume
the same scenario corpus but run in their native package contexts.

## Trust Boundaries

The scenario corpus is the root input. `manifest.toml` pins the schema,
scenario count, scenario root, and SHA-256 scenario index. Scenario JSON files
must deserialize with denied unknown fields and pass local validation before
any driver evaluates them.

Driver reports are comparison inputs, not authority inputs. Required drivers
must emit a tuple for every expected scenario, optional drivers may skip
unsupported scenarios, and every emitted tuple must match both the scenario
expected tuple and every other emitted driver tuple for the same scenario.

## Security And API Constraints

- Keep the standalone workspace shape. The root workspace tests compile these
  sources directly, while this crate must still build from its own
  `Cargo.toml`.
- Keep verdict tuple normalization deterministic and limited to scope ordering.
  Do not deduplicate scope entries because duplicate-scope preservation is an
  explicit tuple-contract test.
- Reject malformed scenario identity material at load time rather than letting
  padded ids, reason codes, requirement labels, or scope labels become map
  keys in the diff oracle.
- Preserve the existing scenario corpus hash unless scenario fixtures are
  intentionally changed and reindexed.

## Completed Material Improvement

`VerdictScenario::validate` now rejects empty, whitespace-padded, or
control-bearing identity fields for scenario ids, tags, requirements, expected
reason codes, expected scopes, script operations, script tools, capability
scopes, and required scopes. This keeps the manifest-bound corpus and
cross-driver report keys canonical before the verdict matrix compares tuples.
