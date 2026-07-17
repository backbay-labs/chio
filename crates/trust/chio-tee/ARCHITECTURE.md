# chio-tee architecture

## Overview

`chio-tee` is an observability sidecar, not a decision-making component on
the kernel's request path. It implements `TrafficTap` to watch
`(AgentMessage, ChioReceipt)` pairs a kernel host feeds it; in `verdict-only`
and `shadow` mode it never blocks, and in `enforce` mode it can only reject
by returning `Err` from `after_kernel`, after the kernel has already decided
and the frame has already been written. The design is one linear pipeline
(canonicalize -> redact fail-closed -> persist encrypted -> sign -> append)
that runs identically across modes; only the post-capture "would this have
blocked" gate changes. The `chio-tee-frame.v1` schema is not owned here:
`chio-tee-frame` defines and validates `Frame`, and `src/frame.rs` is a
re-export bridge, not the schema. The crate ships as both a library and the
`chio-tee` binary, a standalone process that drains a stdin `Observation`
stream.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module list and crate-root re-exports; declares `DEFAULT_REDACTION_PASS_ID` and `TEE_VERSION`. |
| `src/main.rs` | `chio-tee` binary: `run` / `--help` / `--version`, env-var wiring, tenant key loading, SIGUSR1 installation. Fails closed on every error path. |
| `src/tap.rs` | `TrafficTap`: the `before_kernel` / `after_kernel` hook trait a kernel host drives. |
| `src/runner.rs` | `ShadowRunner`: the capture pipeline; implements `TrafficTap`; owns mode and verdict semantics. |
| `src/mode.rs` | `Mode` lattice (`VerdictOnly < Shadow < Enforce`), precedence resolver (`ResolvedMode`), `MoteState` (lock-free hot-toggle cell). |
| `src/config.rs` | Env / sidecar-TOML / tenant-manifest mode loaders; SIGUSR1 handler installation (`cfg(unix)`). |
| `src/redact.rs` | `RedactPass` / `Redactor`: the mandatory fail-closed redactor pass and the paranoid zero-match heuristic. |
| `src/buffer.rs` | `RawPayloadBuffer`: zeroize-on-drop carrier for pre-redaction plaintext. |
| `src/persist.rs` | `TeeBlobPersistence`: encrypted blob read/write over `chio-store-sqlite`. |
| `src/spool.rs` | `TeeBlobSpool`: pairs redacted request/response persistence into one call. |
| `src/capture.rs` | ULID `event_id` and RFC3339-ms timestamp generation, `sign_frame`, `CaptureWriter` (append-only NDJSON). |
| `src/frame.rs` | Re-export bridge to `chio-tee-frame`'s wire types under `chio_tee::frame::*`. |

## Capture pipeline

Steps `ShadowRunner` runs per observed evaluation (`runner.rs`, `capture`):

1. `before_kernel` canonicalizes the request to confirm it is well-formed
   before the kernel acts; nothing is captured yet. `after_kernel`
   canonicalizes the request, the receipt's tool parameters (the frame's
   inline `invocation`), and the full signed receipt to bytes.
2. Every one of those byte strings runs through
   `RedactPass::redact_or_fail_closed`. An `Err` (redactor failure or the
   `--paranoid` zero-match refusal) aborts the capture before anything is
   persisted or framed.
3. The redacted request/response bytes are persisted as encrypted blobs via
   `TeeBlobSpool::persist_traffic`, then SHA-256 hashed.
4. The receipt's `Decision` maps to a frame `Verdict`
   (`verdict_from_decision`); `would_have_blocked` is derived from `Mode`
   (always `false` in `VerdictOnly`).
5. A `FrameInputs` is assembled (ULID `event_id`, RFC3339-ms `ts`, redacted
   invocation, blob hashes, verdict), signed with the tenant Ed25519 key
   (`sign_frame`), and appended as one NDJSON line by `CaptureWriter::append`,
   which flushes after every write.
6. In `Mode::Enforce`, a blocking verdict makes `after_kernel` return
   `Err(RunnerError::EnforceBlocked)` after the frame is already durably
   appended, so the rejection remains auditable.

## Invariants and failure modes

- Redaction is mandatory and fail-closed: `RedactPass::redact_or_fail_closed`
  runs on every captured payload before persistence (a redactor error
  surfaces as `RunnerError::RedactFailed`), and `--paranoid` quarantines a
  payload longer than `PARANOID_ZERO_MATCH_THRESHOLD` (256 bytes) whose
  redaction manifest reports zero matches. `RawPayloadBuffer` exposes no
  owned-bytes accessor and is zeroized on drop, so pre-redaction plaintext
  cannot outlive the redactor call.
- Mode precedence is fixed: env > sidecar TOML > tenant manifest >
  `Mode::VerdictOnly` default. Both the `[tee]` TOML table and the
  `[tenant.tee]` manifest table use `deny_unknown_fields`, so a typo'd key
  fails closed at load time instead of silently falling through to the
  default.
- SIGUSR1 hot-toggle: downgrades (`enforce -> shadow -> verdict-only`) are
  unconditional; upgrades require a non-empty (post-trim) capability token
  string. `MoteState::transition` checks only that a token was supplied;
  verifying its signature, freshness, audience, and scope against the
  chio-control-plane capability service is documented as the caller's
  responsibility and is not implemented in this crate.
- The capture file is append-only NDJSON; `CaptureWriter::append` flushes
  after every line, and run ids are validated against a filename-safe
  charset (`validate_run_id`) to reject path traversal.
- The runner records the kernel's own verdict from the observed
  `ChioReceipt`; it does not independently re-run the guard/policy pipeline
  TEE-side to double-check that decision. That would require the kernel's
  trust-root, policy, and guard configuration, which the tap boundary does
  not see, and is out of scope for this orchestrator.
- The crate is `#![forbid(unsafe_code)]`.

## Dependencies

Internal: `chio-tee-frame` supplies the `chio-tee-frame.v1` wire schema this
crate signs and writes. `chio-data-guards-redactors-default` supplies the
shipping `Redactor` implementation and `PASS_ID`
(`DEFAULT_REDACTION_PASS_ID`). `chio-store-sqlite` supplies
`SqliteEncryptedBlobStore`, `TenantId`, and `TenantKey` for encrypted blob
persistence. The `chio-core` dependency is aliased to `chio-core-types` (not
the `chio-core` facade crate), supplying `AgentMessage`, `ChioReceipt`,
canonical JSON, and Ed25519 signing (`Keypair`).

External: `zeroize` (derive feature) backs `RawPayloadBuffer`; `arc-swap`
backs the lock-free `MoteState` cell; `signal-hook` (unix-only target
dependency) delivers SIGUSR1; `toml`, `serde` / `serde_json`, `base64`, and
`chrono` support config parsing and frame encoding.

## Extension points

`Redactor` is the backend seam for the mandatory redaction pass:
`RedactPass::new` accepts any `Box<dyn Redactor>`, so a sandboxed backend
(for example, a wasmtime-hosted guest) can replace `DefaultRedactor` without
changing call sites. `TrafficTap` is the seam a kernel host implements
against, or, as `ShadowRunner` does here, drives directly to observe request
and receipt pairs.
