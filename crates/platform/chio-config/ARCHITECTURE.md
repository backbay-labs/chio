# chio-config architecture

## Overview

`chio-config` owns the path from operator-authored `chio.yaml` text to a
validated, typed `ChioConfig`, plus the one bridge (`ChioConfig::to_kernel_config`)
that lowers a validated config into the runtime's `chio_kernel::KernelConfig`.
Its only I/O is reading the config file (`load_from_file`) and reading
environment variables during interpolation; it does not construct a kernel,
start adapters, resolve guard modules, or open storage connections. Every stage
of the load sequence is fail-closed: unknown fields, unresolved interpolation
variables, YAML-scalar-breaking values, and invalid field combinations are all
rejected before a caller receives a config.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations, top-level re-exports (`load_from_file`, `load_from_str`, schema types), and `ConfigError`. |
| `src/schema.rs` | Typed `chio.yaml` shape (`ChioConfig` and its sections), serde defaults, and the `chio_kernel` bridge (`ChioConfig::to_kernel_config`, `KernelConfig::signing_keypair`, `KernelDeadlinesFileConfig::to_hot_path_deadline_config`). |
| `src/interpolation.rs` | `${VAR}` / `${VAR:-default}` expansion over raw YAML text, in two policies: unrestricted (`interpolate`) and YAML-scalar-safe (`interpolate_for_loader`). |
| `src/loader.rs` | The canonical ingest sequence -- interpolate, reject stray tabs, deserialize, validate -- behind `load_from_file` / `load_from_str`. |
| `src/validation.rs` | Post-deserialization cross-field checks: adapter/edge uniqueness and references, auth block completeness, kernel deadline floors, logging enum values. |
| `src/fuzz.rs` | Feature-gated (`fuzz`) libFuzzer entry point that drives arbitrary bytes through `loader::load_from_str`. |

## Load sequence

1. `load_from_file` reads the file into a string (or a caller starts directly
   at `load_from_str`).
2. `interpolation::interpolate_for_loader` expands `${VAR}` / `${VAR:-default}`
   against the process environment. It rejects any resolved value, from either
   the environment or a `:-default`, that could change YAML scalar structure:
   surrounding whitespace, control characters, or `"`, `'`, `#`. It scans the
   whole document before failing: every unset variable is named together in
   one error; if none are missing, every YAML-unsafe resolved value is named
   together instead.
3. `loader::reject_yaml_tabs` scans the interpolated text and rejects literal
   tab characters outside quoted scalars, comments, and `|`/`>` block scalars.
4. `serde_yml::from_str` deserializes into `ChioConfig`. Every struct in
   `schema.rs` uses `deny_unknown_fields`.
5. `validation::validate` runs the cross-field checks and collects every
   failure into one `ConfigError::Validation`.
6. A caller that needs a runtime kernel calls `ChioConfig::to_kernel_config`,
   which resolves `kernel.signing_key` into a keypair and lowers the validated
   config into `chio_kernel::KernelConfig`.

## Invariants and failure modes

- Every struct in `schema.rs` denies unknown fields: an unrecognized config key
  is a parse error, not a silently ignored value.
- Interpolation on the loader path is stricter than the general-purpose
  `interpolate` function: `interpolate_for_loader` rejects values that could
  inject YAML structure, open an unterminated quote, or turn part of a value
  into a comment. Only `loader::load_from_str` uses the strict policy.
- `validate` never stops at the first problem; it collects every failing check
  into a single `ConfigError::Validation(Vec<String>)`.
- `kernel.deadlines.receipt_append_budget_ms`, if set, must be >= 250ms;
  `receipt_writer_poll_ms` and `receipt_writer_stall_ms`, if set, must be
  non-zero. These floors mirror the runtime kernel's own minimum append budget
  so a config cannot describe an unbounded wedged-writer stall.
- `bearer` and `api_key` auth entries must carry a non-empty, unpadded
  `header`; `cookie`, `mtls`, and `none` do not require one.
- `ChioConfig::to_kernel_config` fills every kernel field the file schema does
  not yet expose with the kernel's own fail-closed defaults: no external
  capability authorities (`ca_public_keys` empty), nested sampling and
  elicitation disabled, `require_web3_evidence` false, and both
  `allow_ephemeral_receipt_log` and `allow_ephemeral_revocation_store` false,
  so a config-built kernel refuses non-durable receipt and revocation storage.
- Regression tests pin that the underlying `serde_yml` (`libyml`) parser caps
  alias-expansion repetition and recursion depth on its own, so a crafted
  `chio.yaml` cannot exhaust memory or overflow the stack before
  `deny_unknown_fields` runs.
- The `fuzz` feature (`dep:arbitrary`) adds no dependency to a default build;
  `fuzz/owners.toml` maps its `chio_yaml_parse` target to this crate's
  `loader::load_from_str` boundary.

## Dependencies

`chio-core` supplies `crypto::Keypair`, used by `KernelConfig::signing_keypair`
to turn `signing_key` into an Ed25519 keypair. `chio-kernel` supplies the
runtime `KernelConfig`, `HotPathDeadlineConfig`, `RetentionConfig`, and
`MemoryBudgetConfig` types that `to_kernel_config` lowers into. `serde` /
`serde_yml` deserialize the YAML; `thiserror` derives `ConfigError`; `regex`
implements the `${VAR}` interpolation pattern. `arbitrary` is pulled in only by
the optional `fuzz` feature.
