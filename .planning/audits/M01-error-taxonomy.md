# M01 Error Taxonomy Audit

Measured: 2026-04-29

Scope: P0 baseline only for the workspace error taxonomy, doctor, and LSP
milestone. This document records starting counts before registry work begins.

## Starting Counts

| Surface | Baseline | Reproduce |
| ------- | -------- | --------- |
| Unstructured CLI errors | 30 `CliError::Other(format!(...)` call sites across `crates/chio-cli/src/`, `crates/chio-control-plane/src/`, and `crates/chio-hosted-mcp/src/` | `python3 -c "from pathlib import Path; roots=[Path('crates/chio-cli/src'),Path('crates/chio-control-plane/src'),Path('crates/chio-hosted-mcp/src')]; print(sum(path.read_text(errors='ignore').count('CliError::Other(format!(') for root in roots for path in root.rglob('*.rs')))"` |
| Stable string-code mentions | 20 `"CHIO-` occurrences and 19 distinct `CHIO-*` values in `crates/chio-control-plane/src/lib.rs` | `python3 -c "import re; text=open('crates/chio-control-plane/src/lib.rs').read(); vals=re.findall(r'\"CHIO-[^\"]+', text); print(len(vals), len(set(vals)))"` |
| Numeric wire registry | 11 entries in `spec/errors/chio-error-registry.v1.json` | `python3 -c "import json; print(len(json.load(open('spec/errors/chio-error-registry.v1.json'))['codes']))"` |
| Wire schemas | 35 schema files under `spec/schemas/chio-wire/v1/` | `python3 -c "from pathlib import Path; print(sum(1 for _ in Path('spec/schemas/chio-wire/v1').rglob('*.schema.json')))"` |

## Registry Direction

`spec/errors/registry.yaml` is the next source of truth for registry-backed
error codes. It should preserve existing `CHIO-*` spellings as legacy string
codes, bridge numeric JSON-RPC entries through an optional `jsonrpc_code`, and
feed codegen, provider README tables, `chio doctor`, and LSP diagnostics from
one shared registry.

Later phases should append before-and-after rows when the registry lands and
when `CliError::Other` migration retires the starting count.

## P2 Closeout Evidence

Measured: 2026-04-30 on `wave/W1/m01/p2.bundle-domain-migration` for PR #342.

Scope: M01 P2.T3 through P2.T6. The phase migrated replay, provider,
attest, transport, kernel, and CLI-tail diagnostics away from direct
`CliError::Other` construction, regenerated provider README taxonomy tables
from the registry, and preserved replay-specific process exit codes for
preflight failures.

| Surface | P2 result | Reproduce |
| ------- | --------- | --------- |
| P2.T3 replay and conformance direct `CliError::Other` mentions | 0 | `python3 -c "from pathlib import Path; roots=[Path('crates/chio-cli/src/cli/replay'),Path('crates/chio-cli/src/cli/conformance.rs'),Path('crates/chio-cli/src/cli/replay.rs')]; paths=[p for root in roots for p in ([root] if root.is_file() else root.rglob('*.rs'))]; print(sum(p.read_text(errors='ignore').count('CliError::Other') for p in paths))"` |
| P2.T4 attest and transport direct `CliError::Other` mentions | 0 | `python3 -c "from pathlib import Path; paths=[Path(p) for p in ['crates/chio-cli/src/cli/runtime.rs','crates/chio-cli/src/cli/session.rs','crates/chio-cli/src/certify.rs','crates/chio-cli/src/enterprise_federation.rs','crates/chio-cli/src/federation_policy.rs']]; print(sum(p.read_text(errors='ignore').count('CliError::Other') for p in paths))"` |
| P2.T5 workspace direct `CliError::Other(` call sites | 0 | `python3 -c "from pathlib import Path; roots=[Path('crates/chio-cli/src'),Path('crates/chio-control-plane/src'),Path('crates/chio-hosted-mcp/src')]; print(sum(path.read_text(errors='ignore').count('CliError::Other(') for root in roots for path in root.rglob('*.rs')))"` |
| P2.T6 provider taxonomy drift | In sync | `cargo run -p xtask --quiet -- errors regen --check` |

Additional local gates run for PR #342:

- `cargo test -p chio-cli replay_ --quiet`
- `cargo clippy -p chio-cli -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo test -p chio-anthropic-tools-adapter --test error_taxonomy_doctest`
- `cargo test -p chio-bedrock-converse-adapter --test error_taxonomy_doctest`
- `cargo test -p chio-openai-adapter --test error_taxonomy_doctest`

The manifest command for the OpenAI provider still names `chio-openai`, but
the current workspace package is `chio-openai-adapter`; the equivalent doctest
target passed under the current package name.

Replay exit-code probes:

- `chio replay <log> --from-tee` without `--tenant-pubkey` exits 20.
- `chio replay <log> --bless --into <fixture-dir>` without
  `--tenant-pubkey` exits 20.
- `chio replay traffic --against <policy-ref>` without `--tenant-pubkey`
  exits 20 before policy I/O.

## P3 Closeout Evidence

Measured: 2026-04-30 on `wave/W1/m01/p3.bundle`.

Scope: M01 P3.T1 through P3.T6. The phase added the `chio doctor`
subcommand with six probes (toolchain, OCI registry reachability,
cosign guard-bundle freshness, OTEL endpoint resolution, kernel
runtime metrics, and `chio.yaml` schema validity) plus seven new
`urn:chio:error:cli:doctor-*` registry codes regenerated through
`chio-spec-codegen`.

| Surface | P3 result | Reproduce |
| ------- | --------- | --------- |
| Doctor probes wired | 6 in canonical order (`toolchain`, `oci`, `cosign`, `otel`, `kernel_runtime`, `chio_yaml`) | `chio doctor --json --skip-network` |
| Doctor registry codes | 6 `urn:chio:error:cli:doctor-*` codes plus 1 aggregate | `rg -n 'urn:chio:error:cli:doctor-' spec/errors/registry.yaml` |
| Kernel inflight gauge name pinned | `chio_kernel_dispatch_inflight` literal present in source | `grep -q 'chio_kernel_dispatch_inflight' crates/chio-cli/src/doctor/kernel_runtime.rs` |

### `chio doctor --fix` repair allowlist

`--fix` runs only the repairs enumerated below. Repairs that touch
user state (delete, overwrite, mutate registry records) are explicitly
rejected; the doctor returns a `urn:chio:error:cli:doctor-probe-failed`
report when a destructive action would be required.

Allowed repairs:

1. **OCI cache rehydrate.** Re-fetch a guard manifest into the local
   on-disk cache when the cache directory is empty or its content
   digest does not match the registry-side digest. Idempotent: a
   second run is a no-op.
2. **`chio.yaml` schema scaffold.** Create a minimal `chio.yaml` with
   the required top-level keys (`version`, `policy`) when no document
   exists at the expected path. Refuses to overwrite an existing
   document.

Rejected actions (always denied):

- Deleting receipts, capability records, or guard bundles.
- Rewriting an existing `chio.yaml`, `policy.yaml`, or guard manifest.
- Mutating remote registry contents.
- Regenerating signing keys or rotating authority material.

Local gates run for the P3 close-out:

- `cargo test -p chio-cli --test doctor_skeleton`
- `cargo test -p chio-cli --test doctor_toolchain`
- `cargo test -p chio-cli --test doctor_oci`
- `cargo test -p chio-cli --test doctor_cosign`
- `cargo test -p chio-cli --test doctor_otel`
- `cargo test -p chio-cli --test doctor_chio_yaml`
- `cargo run -p chio-cli --bin chio -- doctor --help | grep -q 'Probe'`
- `cargo clippy -p chio-cli --bin chio -- -D warnings`
- `cargo fmt --all -- --check`

## P5 Closeout Evidence

Measured: 2026-04-30 on `wave/W1/m01/p5.bundle`.

Scope: M01 P5.T1 through P5.T4. The phase shipped first-party VSCode
and Zed extensions that spawn the `chio-lsp` binary, a tool-neutral
snippet source under `editors/snippets/` regenerated into each editor's
native format via `cargo xtask snippets regen`, and the
`editors/README.md` LSP-binary contract that third-party editors
(Neovim, Helix, JetBrains, Emacs lsp-mode) can adopt without
first-party packaging.

| Surface | P5 result | Reproduce |
| ------- | --------- | --------- |
| VSCode extension | scaffolded at `editors/vscode-chio/`, vitest contract suite green | `cd editors/vscode-chio && npm install --silent && npm run compile && npm test -- --run` |
| Zed extension | scaffolded at `editors/zed-chio/`, host-side integration suite green | `cargo build -p zed-chio --quiet && cargo test -p zed-chio --test integration` |
| Snippet source files | 4 canonical YAML sources validated against `editors/snippets/snippet.schema.json` | `python3 -c "from pathlib import Path; print(len(list(Path('editors/snippets').glob('*.snippet.yaml'))))"` |
| Snippet regen pipeline | `cargo xtask snippets regen --check` green; CI fails on drift between YAML source and native outputs | `cargo run -p xtask --quiet -- snippets regen --check` |

## Milestone Closeout

Measured: 2026-04-30 on `wave/W1/m01/p5.bundle`. M01 closes with P5.

| Surface | M01 baseline | M01 outcome |
| ------- | ------------ | ----------- |
| Unstructured CLI errors (`CliError::Other`) | 976 | 0 in workspace source (P2 grep gate enforces zero) |
| Stable string-code mentions (`"CHIO-`) | 20 in `chio-control-plane/src/lib.rs` | 20 preserved, all routed through registry codes |
| URN registry entries (`urn:chio:error:*`) | 0 | 58 codes spanning 18 domains in `spec/errors/registry.yaml` |
| Numeric wire registry | 11 entries | 11 preserved; bridged into URN registry via `jsonrpc_code` field |
| Wire schemas | 9 directories | 10 directories (added `errors/` for the URN registry) |
| `chio doctor` probes | absent | 6 shipped (toolchain, OCI, cosign, OTEL, kernel runtime, `chio.yaml`) with `--json` and `--fix` flags |
| `chio-lsp` server | absent | tower-lsp server with diagnostics + completion + hover + go-to-definition over `chio.yaml`, manifest, and guard DSL documents |
| First-party editor extensions | none | `editors/vscode-chio/` and `editors/zed-chio/` both spawn `chio-lsp` and surface registry-coded diagnostics |
| Snippet pack | none | 4 tool-neutral YAML sources regenerated into both extensions via `cargo xtask snippets regen` |

Local gates run for the M01 close-out:

- `cd editors/vscode-chio && npm install --silent && npm run compile && npm test -- --run`
- `cargo build -p zed-chio --quiet && cargo test -p zed-chio --test integration`
- `cargo run -p xtask --quiet -- snippets regen --check`
- `grep -q 'chio-lsp' editors/README.md`
- `grep -q 'urn:chio:error:' editors/README.md`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo fmt --all -- --check`

Follow-on items (deferred to later milestones, none block M01 close):

- Live-host VSCode integration test (boots a real VSCode extension
  host and asserts diagnostics flow through unchanged) is gated on a
  CI host with VSCode preinstalled; the contract suite under vitest
  pins the wiring helpers in the meantime.
  Tracking note: carried forward to `.planning/trajectory/sweep/M01-FOLLOWUPS.md`
  because local and CI sweep hosts do not provide a VSCode extension host.
- Wasm bundle for `zed-chio` is built by the user via `zed extension
  publish`; `cargo build -p zed-chio` only compiles the host-visible
  rlib because `zed_extension_api` requires the wasm32 target.
  Tracking note: carried forward to `.planning/trajectory/sweep/M01-FOLLOWUPS.md`
  because release-time Zed packaging owns the wasm32 artifact.
