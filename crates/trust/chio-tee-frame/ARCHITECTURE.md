# chio-tee-frame architecture

## Overview

`chio-tee-frame` is a pure data crate: in-memory types, schema validation, and
canonical-JSON codec logic, with no I/O and no runtime state
(`#![forbid(unsafe_code)]`). It defines the `chio-tee-frame.v1` wire format:
the signed capture record `chio-tee` emits per kernel evaluation. The
`schema` module also owns the reference Ed25519 signing-payload and
verification logic for a frame's `tenant_sig`, so the same canonical-payload
construction covers both the signing and verifying side of a captured frame.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations, crate-root re-exports, and the `FRAME_VERSION` schema-name constant. |
| `src/frame.rs` | `Frame` and nested types (`Upstream`, `UpstreamSystem`, `Provenance`, `Otel`, `Verdict`), `FrameError`, `Frame::build`, `canonicalize`, `parse`. |
| `src/schema.rs` | `SchemaError`, the per-field `validate_*` checks, `validate`, `validate_signed`, `signing_payload`, `verify_tenant_sig`. |

## Frame lifecycle

1. A caller builds a `FrameInputs` and calls `Frame::build`, or constructs a
   `Frame` struct literal directly (every field is `pub`).
2. `Frame::build`, `canonicalize`, and `parse` each call `schema::validate`
   before returning; a `Frame` assembled as a bare struct literal and never
   passed through one of these three is never validated.
3. `canonicalize` re-validates, then serializes through
   `chio_core::canonical::canonical_json_bytes` (RFC 8785) for a
   deterministic, sorted-key byte encoding.
4. `parse` decodes with `serde_json::from_slice` under
   `#[serde(deny_unknown_fields)]`, then validates the result. Malformed or
   unrecognized JSON fails as `FrameError::Json`; a well-formed frame that
   violates an invariant fails as `FrameError::Schema`.
5. `signing_payload` re-serializes the frame to a `serde_json::Value`, strips
   `tenant_sig`, and canonicalizes the remaining fields. `verify_tenant_sig`
   decodes the `ed25519:<base64>` signature and checks it against that
   payload with a caller-supplied public key. `validate_signed` composes
   `validate` and `verify_tenant_sig`.

## Invariants and failure modes

- Every `validate_*` check in `schema.rs` fails closed: unknown enum values,
  out-of-range lengths, pattern mismatches, and non-canonical casing all
  reject rather than coerce or truncate.
- `deny_reason` is gated on `verdict`: required and pattern-checked when
  `verdict` is `deny` or `rewrite`, forbidden when `verdict` is `allow`
  (`validate_deny_reason_gate`).
- `schema_version` is pinned to the literal `"1"`; this module has no
  migration path for a future schema version.
- `Frame`'s fields are all `pub`, so the type alone does not enforce
  well-formedness. Validation is a property of the entry points
  (`Frame::build`, `canonicalize`, `parse`, `validate`, `validate_signed`),
  not of the type itself.
- `invocation` is stored as an opaque `serde_json::Value` and is only checked
  for being a JSON object; the canonical-JSON `ToolInvocation` validator is
  the source of truth for its contents.
- `ts` must match the fixed-width `YYYY-MM-DDTHH:MM:SS.mmmZ` pattern and parse
  as a real RFC3339 instant (checked with `chrono::DateTime::parse_from_rfc3339`
  after the byte-position pattern check).

## Dependencies

`chio-core` is aliased to `chio-core-types` in `Cargo.toml`
(`chio_core::` in code resolves to that crate) and supplies
`canonical::canonical_json_bytes` and the `crypto::{PublicKey, Signature}`
Ed25519 primitives. `serde`/`serde_json` handle (de)serialization, `chrono`
parses and validates RFC3339 timestamps, `base64` decodes the `tenant_sig`
payload, and `thiserror` derives `FrameError` and `SchemaError`. Dev-only:
`proptest` drives the round-trip property suite in `tests/`.
