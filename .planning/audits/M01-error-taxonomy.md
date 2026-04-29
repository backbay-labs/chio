# M01 Error Taxonomy Audit

Measured: 2026-04-29

Scope: P0 baseline only for the workspace error taxonomy, doctor, and LSP
milestone. This document records starting counts before registry work begins.

## Starting Counts

| Surface | Baseline | Reproduce |
| ------- | -------- | --------- |
| Unstructured CLI errors | 976 `CliError::Other` occurrences across `crates/chio-cli/src/`, `crates/chio-control-plane/src/`, and `crates/chio-hosted-mcp/src/` | `grep -rE 'CliError::Other' crates/chio-cli/src/ crates/chio-control-plane/src/ crates/chio-hosted-mcp/src/ \| wc -l` |
| Stable string codes | 20 existing `CHIO-*` prefixes in `crates/chio-control-plane/src/lib.rs` | `grep -cE '"CHIO-' crates/chio-control-plane/src/lib.rs` |
| Numeric wire registry | 11 entries in `spec/errors/chio-error-registry.v1.json` | `jq '.codes \| length' spec/errors/chio-error-registry.v1.json` |
| Wire schemas | 9 schema directories under `spec/schemas/chio-wire/v1/` | `find spec/schemas/chio-wire/v1 -mindepth 1 -maxdepth 1 -type d \| wc -l` |

## Registry Direction

`spec/errors/registry.yaml` is the next source of truth for registry-backed
error codes. It should preserve existing `CHIO-*` spellings as legacy string
codes, bridge numeric JSON-RPC entries through an optional `jsonrpc_code`, and
feed codegen, provider README tables, `chio doctor`, and LSP diagnostics from
one shared registry.

Later phases should append before-and-after rows when the registry lands and
when `CliError::Other` migration retires the starting count.
