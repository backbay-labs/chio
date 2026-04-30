# M01 Error Taxonomy Audit

Measured: 2026-04-29

Scope: P0 baseline only for the workspace error taxonomy, doctor, and LSP
milestone. This document records starting counts before registry work begins.

## Starting Counts

| Surface | Baseline | Reproduce |
| ------- | -------- | --------- |
| Unstructured CLI errors | 976 `CliError::Other` occurrences across `crates/chio-cli/src/`, `crates/chio-control-plane/src/`, and `crates/chio-hosted-mcp/src/` | `grep -rE 'CliError::Other' crates/chio-cli/src/ crates/chio-control-plane/src/ crates/chio-hosted-mcp/src/ \| wc -l` |
| Stable string-code mentions | 20 `"CHIO-` occurrences and 19 distinct `CHIO-*` values in `crates/chio-control-plane/src/lib.rs` | `grep -cE '"CHIO-' crates/chio-control-plane/src/lib.rs`; `rg -o '"CHIO-[^"]+' crates/chio-control-plane/src/lib.rs \| sort -u \| wc -l` |
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

## P2 Closeout Evidence

Measured: 2026-04-30 on `wave/W1/m01/p2.bundle-domain-migration` for PR #342.

Scope: M01 P2.T3 through P2.T6. The phase migrated replay, provider,
attest, transport, kernel, and CLI-tail diagnostics away from direct
`CliError::Other` construction, regenerated provider README taxonomy tables
from the registry, and preserved replay-specific process exit codes for
preflight failures.

| Surface | P2 result | Reproduce |
| ------- | --------- | --------- |
| P2.T3 replay and conformance direct `CliError::Other` mentions | 0 | `grep -rcE 'CliError::Other' crates/chio-cli/src/cli/replay/ crates/chio-cli/src/cli/conformance.rs crates/chio-cli/src/cli/replay.rs \| awk -F: '{s+=$2} END {print s+0}'` |
| P2.T4 attest and transport direct `CliError::Other` mentions | 0 | `grep -cE 'CliError::Other' crates/chio-cli/src/cli/runtime.rs crates/chio-cli/src/cli/session.rs crates/chio-cli/src/certify.rs crates/chio-cli/src/enterprise_federation.rs crates/chio-cli/src/federation_policy.rs \| awk -F: '{s+=$2} END {print s+0}'` |
| P2.T5 workspace direct `CliError::Other(` call sites | 0 | `grep -rcE 'CliError::Other\\(' crates/chio-cli/src/ crates/chio-control-plane/src/ crates/chio-hosted-mcp/src/ \| awk -F: '{s+=$2} END {print s+0}'` |
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
| Doctor probes wired | 6 in canonical order (`toolchain`, `oci`, `cosign`, `otel`, `kernel_runtime`, `chio_yaml`) | `chio doctor --json --skip-network \| jq '.reports[].probe'` |
| Doctor registry codes | 6 `urn:chio:error:cli:doctor-*` codes plus 1 aggregate | `rg -n 'urn:chio:error:cli:doctor-' spec/errors/registry.yaml \| wc -l` |
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
