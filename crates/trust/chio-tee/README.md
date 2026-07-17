# chio-tee

`chio-tee` is the Chio shadow-runner sidecar. It implements the `TrafficTap`
hook trait to observe kernel-bound `AgentMessage` requests and the
`ChioReceipt` decisions the kernel emits for them, then runs every
observation through a fail-closed redact-persist-sign pipeline that appends
tenant-signed `chio-tee-frame.v1` records to an append-only NDJSON capture
file for later replay via `chio replay --bless`.

The frame wire format is defined and validated in `chio-tee-frame`; this
crate constructs, signs, and writes frames, it does not own the schema. It
ships as both a library (`ShadowRunner` implements `TrafficTap` and embeds
directly in a kernel host) and the `chio-tee` binary, a standalone process
that drains a stdin `Observation` stream.

## Responsibilities

- Define `TrafficTap`, the hook trait a kernel host drives with observed
  request/receipt pairs.
- Run every captured payload through a mandatory, fail-closed redactor pass
  before it can be persisted or framed, including a `--paranoid` zero-match
  refusal heuristic, and zeroize pre-redaction plaintext on drop.
- Persist redacted request/response blobs encrypted under a tenant key via
  `chio-store-sqlite`.
- Build, sign (Ed25519), and append `chio-tee-frame.v1` records to an
  append-only NDJSON capture file.
- Resolve the `verdict-only` / `shadow` / `enforce` mode from env > sidecar
  TOML > tenant manifest > default, and expose a SIGUSR1 runtime hot-toggle
  gated by capability token for upgrades.
- Ship the `chio-tee` binary: a `run` subcommand that resolves configuration
  from `CHIO_TEE_*` env vars and drives the pipeline over a stdin
  `Observation` stream.

## Public API

- `tap::TrafficTap` - hook trait (`before_kernel`, `after_kernel`) a kernel
  host drives with observed request/receipt pairs.
- `runner::ShadowRunner` - the pipeline orchestrator (`RunnerConfig`,
  `Observation`, `RunSummary`, `RunnerError`); implements `TrafficTap`.
- `mode::{Mode, ResolvedMode, MoteState}` - the `verdict-only`/`shadow`/
  `enforce` lattice, its precedence resolver, and the lock-free hot-toggle
  cell.
- `config::{load_env_mode, load_toml_mode, load_tenant_manifest_mode}` - the
  three mode-precedence loaders `ResolvedMode::resolve` consumes.
- `redact::RedactPass` - the mandatory fail-closed redactor pass (`Redactor`
  trait, `DefaultRedactor` backend, `PARANOID_ZERO_MATCH_THRESHOLD`).
- `buffer::RawPayloadBuffer` - zeroize-on-drop carrier for pre-redaction
  plaintext.
- `persist::TeeBlobPersistence`, `spool::TeeBlobSpool` - encrypted blob
  persistence over `chio-store-sqlite`.
- `capture::CaptureWriter` - the append-only NDJSON writer (`sign_frame`,
  `new_event_id`, `rfc3339_millis`).
- `frame::*` - `chio-tee-frame`'s wire types (`Frame`, `FrameInputs`,
  `Verdict`, ...), re-exported at the crate root; `canonicalize`/`parse` are
  renamed to `canonicalize_frame`/`parse_frame`.
- `DEFAULT_REDACTION_PASS_ID`, `TEE_VERSION` - crate-level constants.

| Binary command | Behavior |
|---|---|
| `chio-tee run` | Resolve mode, load the tenant signing key, open the capture file, drain stdin `Observation` NDJSON through `ShadowRunner`. Reads `CHIO_TEE_*` env vars; run `chio-tee --help` for the full list. |
| `chio-tee --help` / `-h` | Print usage. Safe for image smoke tests. |
| `chio-tee --version` / `-V` | Print `chio-tee {TEE_VERSION}`. |

## Feature flags

| Flag | Effect |
|------|--------|
| `fips` | Routes signing through `chio-core-types`'s aws-lc-rs FIPS backend (`chio-core/fips`). Used by the `chio-tee fips smoke` CI job; default builds are unaffected. |

## Testing

`cargo test -p chio-tee`. Integration suites under `tests/` cover mode
precedence, redactor fail-closed/paranoid behavior, blob encryption, spool
backpressure, and the `chio-tee` binary end to end (`tests/cli.rs`, via
`CARGO_BIN_EXE_chio-tee`).

## See also

- `chio-tee-frame` - defines and validates the `chio-tee-frame.v1` wire
  schema this crate signs and writes.
- `chio-data-guards-redactors-default` - the default `Redactor` backend.
- `chio-store-sqlite` - encrypted BLOB store backing `TeeBlobPersistence`.
- `chio-cli` - `chio replay --bless` consumes the NDJSON capture stream this
  crate writes.
