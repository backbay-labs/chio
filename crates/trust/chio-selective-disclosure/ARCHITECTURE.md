# chio-selective-disclosure architecture

## Overview

`chio-selective-disclosure` is a pure library: no I/O, no runtime state,
`#![forbid(unsafe_code)]`. It sits in the trust layer next to
`chio-disclosure-lineage`, depends on it, and re-exports most of its public
API. Its own job is narrower: turn a Chio receipt-shaped body into a
deterministic, versioned BBS message vector, sign that vector, and
derive/verify proofs that disclose a chosen subset of it. `chio-attest-buyer-core`
and `chio-proof-room` call into this crate to produce or verify the disclosed
proof packages that a `chio-disclosure-lineage` bundle then references.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Core types (`Projection`, `SignedProjection`, `SelectiveDisclosureProof`, `TransparencyInclusionProof`, `SelectiveDisclosureError`), the three body projectors, BBS signing and proof functions (feature `bbs`), projection-manifest generation/verification, and transparency inclusion proof verification. |
| `src/encoding.rs` | Private byte-encoding helpers: canonical-JSON hashing, hex digest decode/validate, fixed-width scalar encodings, and `push_message`, which assigns each projected field its message index. |
| `src/projection_manifest.rs` | `BbsProjectionManifest` and its slot/predicate types: the data model for a projection's per-field disclosure policy. Holds no logic; `lib.rs` builds and checks manifests against these types. |
| `src/crypto_context.rs` | Declares the `policy` (feature `bbs`) and `types` submodules, re-exports `types`' public items, and defines `verify_selective_disclosure_with_context` (feature `bbs`). |
| `src/crypto_context/types.rs` | `CryptoVerificationContext`, `DisclosureKeyState`, `DisclosureRevocationSnapshot`, and their status enums; re-exports the privacy-profile and report types owned by `chio-disclosure-lineage`. |
| `src/crypto_context/policy.rs` | Fail-closed shape validation and the individual context checks (proof binding, key state, revocation, audience, nonce, holder binding, transparency state, presentation age). |

## Projection and proof lifecycle

1. **Project.** `project_receipt_body` / `project_workflow_receipt_body` /
   `project_step_record` walk a fixed field list for their input type and push
   one `ProjectionMessage` per field via `push_message`, which assigns each
   message's index in vector order. Each message carries an `encoding` tag:
   `H` (SHA-256 of the field's canonical JSON), `Hx` (an existing hex digest,
   decoded and validated), `S` (raw UTF-8 bytes), `Opt<S>` (string bytes, or a
   single `\0` byte when absent), `U64` (little-endian), or `Bool`. Messages
   marked `wholesale_only` can never be individually disclosed. The step
   projection's subject hash covers `(workflow_id, step)` together; the other
   two projections hash the body alone.
2. **Sign.** `sign_projection` (feature `bbs`) domain-separates each message
   (`MESSAGE_DOMAIN_V1`) and builds a proof header (`HEADER_DOMAIN_V1` plus
   projection version, subject hash, issuer fingerprint, and ciphersuite),
   then produces one BBS signature over the full vector.
3. **Derive.** `derive_selective_disclosure_proof` re-verifies the full
   signature and the issuer key, validates the requested `DisclosureSet`, and
   calls `affinidi_bbs::proof_gen` to produce a `SelectiveDisclosureProof`
   carrying only the disclosed messages in the clear.
4. **Verify.** `verify_selective_disclosure_proof` looks up the issuer's key in
   an `InMemoryIssuerRegistry`, recomputes the implied message count from the
   proof's byte length, and calls `affinidi_bbs::proof_verify` before trusting
   any disclosed field.
5. **Bind (optional).** `verify_bbs_projection_manifest` checks disclosed slots
   against a declared `BbsProjectionManifest`; `verify_transparency_inclusion_proof`
   checks a Merkle path to a log root; `verify_selective_disclosure_with_context`
   runs a BBS proof verification and the `crypto_context::policy` checks
   together.

## Invariants and failure modes

- Only the SHA-256 BLS12-381 ciphersuite (`BBS_CIPHERSUITE_SHA256`) is
  supported; `message_count_from_bbs_sha256_proof`'s byte-length math is
  specific to that ciphersuite's fixed proof size.
- `Hx` fields must decode to exactly 32 lowercase-hex-encoded bytes; uppercase
  or malformed hex is rejected before projection or verification succeeds
  (`decode_hx_field`).
- `exact_timing_direct_disclosure_field` (currently `duration_ms`) can never
  be marked `Disclosed` in a manifest; `verify_bbs_projection_manifest`
  rejects such a manifest even when the underlying BBS proof is valid.
- `verify_selective_disclosure_proof` requires `proof.disclosed` to be in
  ascending index order matching the sorted disclosure set; reordering the
  same disclosed messages causes rejection.
- `sign_chio_receipt_with_bbs` recomputes `content_hash` from the caller's
  `ReceiptSigningHandle` and refuses to sign (`ContentHashMismatch`) before
  any BBS material is produced, closing a render-A/sign-B forgery at the BBS
  boundary the same way the classical and backend Ed25519 signers do.
- `verify_transparency_inclusion_proof` walks the inclusion path level by
  level and requires it to land exactly on `index == 0, width == 1`; a path
  that is too short or too long is rejected.
- `TransparencyInclusionProof`, `DisclosedMessage`, `SelectiveDisclosureProof`,
  the `BbsProjectionManifest` family, and the `crypto_context` types
  (`CryptoVerificationContext`, `DisclosureKeyState`,
  `DisclosureRevocationSnapshot`) derive `#[serde(deny_unknown_fields)]`.
- `BbsKeyPair` and `VerifiedDisclosure` derive neither `Serialize` nor
  `Deserialize`, so secret key material and verification results cannot
  round-trip through JSON.

## Dependencies

Internal: `chio-disclosure-lineage` supplies the lineage bundle, leakage
ledger, and privacy-profile types this crate re-exports; this crate layers
BBS proof verification on top of them via `crypto_context`. `chio-core-types`
supplies `ChioReceiptBody`, `ChioReceipt`, `ReceiptSigningHandle`,
`TrustLevel`, the Ed25519 `Keypair` type, and `canonical_json_bytes`.
`chio-workflow` supplies `WorkflowReceiptBody` and `StepRecord`. External:
`affinidi-bbs` (pinned to `=0.1.0`, feature `bbs`) is the only BBS
implementation; `sha2` and `hex` perform the crate's own SHA-256 hashing and
hex encoding; `serde` (`derive`) supplies the wire types' `Serialize`/
`Deserialize` impls; `thiserror` derives `SelectiveDisclosureError` and
`DisclosureCryptoContextError`.
