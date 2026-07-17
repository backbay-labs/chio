# chio-did architecture

## Overview

`chio-did` is a pure library: no I/O, no runtime state, `#![forbid(unsafe_code)]`.
It owns the `did:chio` method end to end, identifier derivation, parsing, and
resolution, all of which are self-certifying functions of the public key
bytes. Downstream crates (`chio-credentials`, `chio-control-plane`, `chio-cli`)
treat a resolved `DidChio` as an identity anchor, so the validation performed
here is the compatibility boundary for every consumer.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | The full public surface: `DidChio`, `DidDocument` and its parts, `DidService`, `ResolveOptions`, `DidError`, and `resolve_did_arc`. |
| `src/fuzz.rs` | `fuzz` feature only. `fuzz_did_resolve`, the libFuzzer entry point driving the crate's parse paths. |

## Resolution flow

1. A caller holds an Ed25519 `chio_core::PublicKey`.
2. `DidChio::from_public_key` checks `SigningAlgorithm::Ed25519` and wraps the
   key; any other algorithm is rejected with `UnsupportedKeyAlgorithm`.
3. `DidChio::as_str` / `Display` render `did:chio:<64 lowercase hex chars>`.
4. `DidChio::from_str` (or the `resolve_did_arc` convenience) reverses this:
   strip the `did:chio:` prefix, require exactly 64 lowercase hex bytes,
   decode the public key, and re-check the algorithm.
5. `resolve` / `resolve_with_options` build a `DidDocument`: one
   `Ed25519VerificationKey2020` verification method (multibase-encoded key
   with the `0xed01` Ed25519 multicodec prefix), referenced by both
   `authentication` and `assertionMethod`, plus any `service` entries carried
   in `ResolveOptions`.
6. A caller may attach `DidService` entries (`receipt_log`, `passport_status`,
   or `new` for a custom type); each is validated at construction time.

## Invariants and failure modes

- The method-specific identifier must be exactly 64 lowercase hex characters;
  wrong length, uppercase, or non-hex bytes all fail with
  `InvalidMethodSpecificId`.
- Only `SigningAlgorithm::Ed25519` keys form a valid `did:chio`; `P256`,
  `P384`, and `Hybrid` keys fail with `UnsupportedKeyAlgorithm`, checked both
  on construction from a `PublicKey` and after parsing from a string.
- Every `DidService` endpoint must parse as a URL with an `https` scheme;
  anything else (`http`, `file`, `ftp`, or unparseable) fails with
  `InvalidServiceEndpoint` at construction, so an invalid service can never
  reach a `DidDocument`.
- `DidService::receipt_log` and `::passport_status` deduplicate same-kind
  services deterministically: the first entry is unsuffixed (`#receipt-log`),
  later ones get `-2`, `-3`, and so on.
- Resolution is pure: no I/O, no network, no registry. A `DidDocument` is a
  deterministic function of the DID's own bytes and the caller-supplied
  `ResolveOptions`.
- `DidDocument` and its parts (de)serialize with the DID-spec field names
  (`@context`, `verificationMethod`, `assertionMethod`, `serviceEndpoint`,
  `publicKeyMultibase`); `service` is omitted entirely when empty.

## Dependencies

`chio-core` supplies `PublicKey` and `SigningAlgorithm` (production) and
`Keypair` (tests). `serde` (with `derive`) implements the document
(de)serialization; `thiserror` implements `DidError`; `bs58` encodes the
multibase public key; `url` parses and validates service-endpoint URLs. The
`fuzz` feature adds `arbitrary` and `serde_json`, used only by the standalone
`fuzz` workspace's `did_resolve` target.
