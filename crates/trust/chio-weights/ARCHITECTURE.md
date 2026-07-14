# chio-weights architecture

## Overview

`chio-weights` is a trust-boundary library: card schema, canonical-JSON
encoding, and cryptographic verification for signed model cards, with no
I/O of its own (cosign bundle verification is delegated to
`chio-attest-verify`'s `AttestVerifier` trait). `lib.rs` forbids
`unsafe_code`, `clippy::unwrap_used`, and `clippy::expect_used` at the
crate level: every `Ok(_)` a public function returns means the named
precondition held in full, never a partial verification. The crate
supplies the schema and the comparison primitives (`StringSet::covers`,
`StringSet::intersects`, `weights_hash_of`) but does not itself decide
whether a provider may bind; `chio-kernel`'s `weights_binding.rs` composes
them into the three-gate bind-time refusal.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate-level `forbid` lints, module declarations, and the re-export surface. |
| `src/card.rs` | `ModelCard` schema, `StringSet`, RFC 8785 canonical-JSON encode/decode, structural validation, `weights_hash_of`. |
| `src/bundle.rs` | `verify_model_card_bundle`: cosign bundle verification via `chio-attest-verify`, plus issuer-identity agreement and liveness. |
| `src/lineage.rs` | `ModelCardLineageAnchor`: digest projection and verification for published cards, built on `chio-lineage`'s anchor shapes. |
| `src/error.rs` | `WeightsError`, the crate's sole error type, mapped to `urn:chio:error:weights:*` codes. |
| `src/kani_public_harnesses.rs` | Kani proofs over `weights_hash_of`, `require_live`, the `card_version` pin, and `WeightsError::urn`. Compiled only under the `kani` cfg. |

## Card lifecycle

1. **Construct.** `ModelCard::new` builds a card and runs `validate()`:
   64-char lowercase-hex `weights_hash`, non-empty/untrimmed text fields,
   `expires_at >= issued_at`, and non-empty/untrimmed entries in both
   `StringSet`s.
2. **Encode and sign.** `to_canonical_json` serializes through
   `chio_core_types::canonical::canonical_json_bytes` (RFC 8785 / JCS:
   sorted keys, sorted-unique set arrays, no inter-token whitespace).
   Cosign signs exactly these bytes; signing itself happens outside this
   crate.
3. **Verify.** `verify_model_card_bundle` calls `AttestVerifier::verify_bundle`
   (implemented by `chio_attest_verify::SigstoreVerifier`), then checks the
   decoded card's `issuer` against the verified certificate identity and
   `expires_at` against the caller-supplied `now`. Returns
   `VerifiedModelCard { card, attestation }` only when every check holds.
4. **Anchor (optional).** `anchor_model_card` takes a `VerifiedModelCard`
   plus the original card bytes, rejects if they do not decode to the same
   card, and derives a `ModelCardLineageAnchor` whose digest covers the
   card bytes and the attestation's `(subject_digest_sha256,
   certificate_identity, certificate_oidc_issuer, rekor_log_index,
   rekor_inclusion_verified)` tuple. `verify_model_card_anchor` recomputes
   the digest and rejects on any field mismatch.

Downstream, the kernel recomputes `weights_hash_of` over weight bytes a
provider exposes through `chio-core-types`'s separate `LoadedWeights`
trait, then compares the digest, `StringSet::covers`, and
`StringSet::intersects` against the verified card; see `chio-kernel`.

## Invariants and failure modes

- Every public function that returns `Ok(_)` means the full named
  precondition held; there is no partial-verification success path.
- `from_canonical_json` round-trips through `to_canonical_json` and
  rejects any input that is not byte-identical to the canonical
  re-encoding (catches non-canonical whitespace, key order, or
  duplicate/blank set entries).
- `ModelCard` deserialization uses `#[serde(deny_unknown_fields)]`.
- `verify_model_card_bundle` enforces card liveness independently of the
  cosign certificate's own validity window; an expired card rejects even
  when the certificate itself is still valid.
- `anchor_model_card` refuses to anchor `card_bytes` that do not decode to
  the same card carried by the `VerifiedModelCard`, so stale or swapped
  bytes cannot be anchored under a valid attestation.
- `verify_model_card_anchor` rejects every imported `SigningState::Signed`
  anchor: no local verifier is wired for lineage signature payloads yet,
  so only `UnsignedSignerStubbed` or `UnsignedSoftDepAbsent` can verify.
- `WeightsError` is `#[non_exhaustive]`, so callers cannot exhaustively
  match and silently miss a future variant.

## Dependencies

Internal: `chio-core-types` for canonical-JSON encoding
(`canonical::canonical_json_bytes`); `chio-attest-verify` for the
`AttestVerifier` trait and cosign/Sigstore bundle verification this crate
wraps rather than forks; `chio-lineage` for the `anchor` module's
`FrontierDigest`, `CanonicalSource`, and `SigningState` shapes the
`lineage` module reuses verbatim. External: `chrono` for RFC 3339
timestamps, `sha2`/`hex` for digesting, `serde`/`serde_json` for the card
and anchor schemas, `thiserror` for `WeightsError`. Dev-only:
`chio-provider-conformance` backs the `smoke`-gated cross-provider
equivalence test; `toml` parses its fixture manifest.
