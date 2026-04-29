# M01: Workspace Error Taxonomy + Doctor + LSP

**Wave:** W1  |  **Trust-boundary:** no  |  **Tickets:** 29  |  **Effort:** 38.00 days

## In one paragraph

M01 ends the three-vocabulary error regime (CLI string codes, JSON-RPC numerics, kernel structured-report) by shipping a single `urn:chio:error:<domain>:<code>` registry, a `chio-errors` crate generated from it, a `chio doctor` self-diagnosis subcommand, and a `chio-lsp` server with VSCode + Zed extensions. It is the unblocker for M02 verdict classification, M07 per-provider error doctests, and every CLI surface that reports failures.

## Phases at a glance

| Phase | Tickets | One-liner |
|---|---|---|
| P0 | 2 | Pin miette/tower-lsp/lsp-types/dashmap/notify; open audit doc with starting counts |
| P1 | 5 | `chio-errors` crate genesis, registry.yaml seed (40 codes / 18 domains), codegen pass |
| P2 | 6 | Migrate `dispatch.rs` to registry codes (one ticket per domain); retire 976 `CliError::Other` |
| P3 | 6 | `chio doctor` skeleton + five probes (toolchain, OCI, cosign, OTEL, schema) |
| P4 | 6 | `chio-lsp` server: completion, hover, go-to-def, schema diagnostics |
| P5 | 4 | VSCode + Zed extensions, snippet pack, `editors/README.md` |

## Load-bearing artifacts

- `spec/errors/registry.yaml` (M01.P1.T1 ships first version)
- `spec/errors/registry.schema.json` (M01.P1.T1)
- `crates/chio-errors/` (M01.P1.T2 scaffolds)
- `crates/chio-errors/src/_generated/error_codes.rs` (M01.P1.T3 codegen)
- `chio doctor` subcommand (M01.P3.T1)
- `crates/chio-lsp/` server binary (M01.P4.T1)
- `editors/vscode-chio/`, `editors/zed-chio/` (M01.P5.T1, M01.P5.T2)

## Cross-trajectory deps

- trajectory-1 M01 (`chio-spec-codegen`) - extended via soft_dep on M01.P0.T1
- trajectory-1 M06 (`chio-guard-registry`, `chio-attest-verify`) - consumed by doctor probes (soft_dep)
- trajectory-1 M07 provider error doctests - consumer set, README tables become registry-regenerated
- trajectory-2 M02, M07, M09 - hard consumers of the registry (forward references)

## Locked decisions

- D05 URN scheme `urn:chio:error:<domain>:<code>` with `CHIOxxxx` numeric alias

## Active freezes

none.

## When this milestone is done

- `crates/chio-errors/` builds clean with workspace `unwrap_used`/`expect_used` deny lints; exposes `Code`, `Domain`, `Severity`, `ChioError`, `Diagnostic`.
- `spec/errors/registry.yaml` carries >= 40 codes across 18 domains; validates against the schema; is sole source for the regenerated `error_codes.rs`.
- `cargo xtask errors regen --check` is green; `grep -rE 'CliError::Other' crates/chio-cli/src/` returns 0 matches outside the deprecation shim.
- The three M07 provider doctests pass against registry-regenerated README tables.
- `chio doctor` emits structured `--json` with five probe classes, each carrying a `urn:chio:error:*` code; `--fix` runs idempotent repairs only.
- `chio-lsp` ships a binary, passes integration tests, drives diagnostic codes through both VSCode and Zed extensions.
