# chio-tee-frame

`chio-tee-frame` defines the `chio-tee-frame.v1` wire format: the signed
capture record a TEE runner emits per kernel decision. It owns the Rust types
that mirror the JSON schema field-for-field (`frame`) and the structural,
pattern, and signing invariants that gate construction and parsing (`schema`).

The crate is pure data: no I/O, no runtime state, `#![forbid(unsafe_code)]`.
Encoding reuses `chio_core::canonical::canonical_json_bytes` (RFC 8785) so a
frame signed in Rust round-trips byte-for-byte to verifiers in other
languages. Capture itself lives in `chio-tee`; this crate only defines and
validates the frame shape.

## Responsibilities

- Define `Frame` and its nested types (`Upstream`, `UpstreamSystem`,
  `Provenance`, `Otel`, `Verdict`) matching the v1 JSON schema field-for-field.
- Validate every structural and pattern invariant in the v1 schema
  (`schema::validate`) and fail closed on the first violation.
- Canonicalize a frame to RFC 8785 bytes and parse bytes back into a validated
  `Frame` (`canonicalize`, `parse`).
- Compute the canonical Ed25519 signing payload for a frame and verify an
  embedded `tenant_sig` against a tenant public key (`signing_payload`,
  `verify_tenant_sig`, `validate_signed`).

## Public API

- `Frame`, `FrameInputs`, `FrameError` - the frame type, its builder input,
  and build/parse errors. `Frame::build` validates before returning.
- `Upstream`, `UpstreamSystem`, `Provenance`, `Otel`, `Verdict` - nested frame
  types, re-exported at the crate root from `frame`.
- `canonicalize(&Frame) -> Result<Vec<u8>, FrameError>`,
  `parse(&[u8]) -> Result<Frame, FrameError>` - validate-and-encode to
  canonical JSON, and decode-and-validate back.
- `schema::{validate, validate_signed, verify_tenant_sig, signing_payload,
  SchemaError, SCHEMA_ID, SCHEMA_VERSION}` - re-exported at the crate root;
  `schema::upstream_system_from_str` is not.
- `FRAME_VERSION` - the schema name literal `"chio-tee-frame.v1"`, distinct
  from the wire `schema_version` field (`"1"`).

## Testing

`cargo test -p chio-tee-frame` runs the unit tests plus the round-trip
proptest suite in `tests/property_roundtrip.rs` (256 cases per property by
default; set `PROPTEST_CASES` to override).

## See also

- `chio-core-types` (imported as `chio_core`) - supplies canonical JSON
  encoding and Ed25519 verification primitives.
- `chio-tee` - the shadow runner that captures kernel decisions and emits
  `chio-tee-frame.v1` records using these types.
- `chio-cli`, `chio-replay-corpus`, `chio-arena` - replay, corpus, and
  scenario-promotion tooling that consumes captured frames.
