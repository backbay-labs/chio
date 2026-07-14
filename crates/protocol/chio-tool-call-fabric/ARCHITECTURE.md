# chio-tool-call-fabric architecture

## Overview

`chio-tool-call-fabric` is a pure protocol crate: in-memory types, a trait,
and a state machine, with no I/O and no runtime state. It defines the
contract native provider adapters use to lift an upstream tool call into a
normalized `ToolInvocation` and lower a kernel `VerdictResult` back into
provider-native bytes. Values crossing this boundary are untrusted until
`ToolInvocation::validate` runs; the kernel's `provider_verdict` module is the
only place fabric vocabulary is converted into kernel-internal types, so
adapters and the kernel never share a type beyond this crate.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public facade: crate docs, module declarations, root re-exports, `FABRIC_VERSION`. |
| `src/types.rs` | `ProviderId`, `Principal`, `ProvenanceStamp`, `ToolInvocation` and `validate`, `Redaction`, `ReceiptId`, `DenyReason`, `VerdictResult`. |
| `src/adapter.rs` | Opaque `ProviderRequest` / `ProviderResponse` / `ToolResult` byte wrappers and the `ProviderAdapter` trait. |
| `src/error.rs` | `ProviderError`, the shared error taxonomy `lift` / `lower` return. |
| `src/stream.rs` | `StreamPhase` state machine, `StreamEvent`, `BlockKind`, `BufferedBlock`, `StreamError`, buffering limits. |
| `src/provenance.rs` | `sign_provenance` / `verify_signed_provenance`, the detached `SignedProvenance` envelope. |

## Tool-call lifecycle

1. A native adapter receives upstream bytes (`ProviderRequest`) and calls
   `ProviderAdapter::lift`, producing a `ToolInvocation` stamped with a
   `ProvenanceStamp` (provider, request id, API version, provider-scoped
   `Principal`).
2. The caller runs `ToolInvocation::validate()` before trusting the value: it
   checks provider/provenance agreement, provider/principal agreement,
   non-empty non-control-character identity fields, and that `arguments` are
   canonical-JSON bytes (RFC 8785).
3. For streaming providers, `StreamPhase::transition` buffers the tool-call
   block's bytes (`Idle -> Buffering -> Emitting`) so nothing reaches the wire
   while a verdict is outstanding; `Close` is terminal from any phase.
4. `chio-kernel::provider_verdict` (outside this crate) converts the validated
   `ToolInvocation` into a kernel `ToolCallRequest`, evaluates policy, and
   converts the resulting kernel `ToolCallResponse` into a fabric
   `VerdictResult` (`Allow` with `redactions` and a `receipt_id`, or `Deny`
   with a `DenyReason` and a `receipt_id`).
5. The adapter's `ProviderAdapter::lower` takes the `VerdictResult` plus a
   `ToolResult` (canonical-JSON tool output bytes) and produces the
   `ProviderResponse` bytes sent back upstream.

## Invariants and failure modes

- `ToolInvocation::validate` fails closed on provider/provenance mismatch,
  provider/principal mismatch (for example an OpenAI invocation carrying a
  Bedrock IAM principal), empty or whitespace-padded identity fields, control
  characters in identity fields, non-JSON `arguments`, and non-canonical
  `arguments` bytes.
- `StreamPhase::transition` rejects `AppendBytes` / `FinishBlock` with no
  block in flight, `StartBlock` while a block is already buffering, and any
  event once `Closed` (terminal). The default `transition` caps buffered
  bytes at `DEFAULT_MAX_BUFFERED_BLOCK_BYTES` (1 MiB); `transition_with_limit`
  takes a caller-chosen cap, including 0 (no buffering) or `usize::MAX`.
  `DEFAULT_MAX_BUFFERED_RAW_FRAMES` is exported as a companion budget for
  raw-frame counts but is not itself enforced by `StreamPhase`, which tracks
  cumulative bytes only; a caller that needs the frame cap applies it.
- `verify_signed_provenance` checks the envelope's `algorithm` against the
  signature's own algorithm, then re-canonicalizes `stamp` and compares it
  against `signed_bytes` before checking the signature, so canonicalization
  drift is reported distinctly from a bad signature.
- `fixtures/lift_lower/{openai,anthropic,bedrock}/*.json` pin the
  canonical-JSON encoding of 9 representative `ToolInvocation` values (3 per
  provider). `tests/lift_lower_fixtures.rs` fails on any byte drift and only
  regenerates them under `CHIO_BLESS_LIFT_LOWER=1`, which CI never sets.
- `#![forbid(unsafe_code)]` at the crate root.

## Dependencies

Internal: `chio-core` is aliased to `chio-core-types`
(`chio-core = { package = "chio-core-types" }`). The fabric uses its
`canonical::canonical_json_bytes` for argument and stamp canonicalization, its
`crypto` module (`PublicKey`, `Signature`, `SigningAlgorithm`,
`SigningBackend`, `sign_canonical_with_backend`) for provenance signing, and
its `error::Error` for provenance error conversion. External: `serde` /
`serde_json` for the wire types, `thiserror` for the error enums,
`async-trait` for the dyn-compatible `ProviderAdapter` trait, `anyhow` for
`ProviderError::Other`. Dev-only: `proptest` backs the eight invariants in
`tests/invariants.rs`.

## Extension points

`ProviderAdapter` is the trait a new provider integration implements
(`provider`, `api_version`, `lift`, `lower`). It is `Send + Sync` and
object-safe (`lib.rs` asserts `dyn ProviderAdapter` compiles), so a caller can
hold heterogeneous adapters behind one dyn pointer. A crate can also consume
the fabric's types (`ToolInvocation`, `ProviderError`, `VerdictResult`) in its
own lift/lower functions without implementing the trait, as the Gemini, Groq,
Mistral, Cohere, and Ollama adapters do today.
