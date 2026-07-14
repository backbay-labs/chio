# chio-federation-authority architecture

## Overview

`chio-federation-authority` is a local issuer, not a runtime kernel component:
it holds no kernel state, serves no requests, and does no networking or
storage I/O. An operator runs it, directly or through `chio-cli`'s
`federation authority` commands, with local signing seeds to mint the signed
artifacts that other Chio trust crates later verify. The core design idea is
seed-to-profile binding: a local seed is never trusted by name alone, it is
first derived to a public key and compared against the public key the
authority profile declares for that authority before it signs anything.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Document types and schema constants (profile, issuance request/bundle, signing keys, revocation publication, peer pins), `ChioAuthorityError`, JSON parse/serialize helpers, shared field validators, and the three issuance entry points (`issue_authority_bundle`, `publish_revocation_checkpoint`, `assemble_verifier_trust_bundle`). |
| `src/profile.rs` | `AuthorityProfileDocument::validate` and the `lease_authority` / `governance_authority` lookup helpers issuance uses to resolve a request's named issuer against the profile. |
| `src/tests.rs` | Unit tests, `#[cfg(test)]`-gated. |

## Issuance flow

`issue_authority_bundle(profile, request, signing_keys)`:

1. Validate `profile`, `request`, and `signing_keys` independently.
2. Resolve the request's `lease_authority_issuer` and
   `governance_authority_kernel` against the profile; derive each keypair from
   the matching local seed and confirm the derived public key equals the
   authority's declared public key.
3. Confirm both authorities are `Active` and that each authority's own
   validity window is non-empty.
4. For each step: confirm the lease authority allows the step's action class,
   confirm the lease interval fits inside the lease authority's window, then
   build and sign a `CapabilityLeaseArtifact` and its `LeaseScopeBindingArtifact`.
5. For destructive steps: confirm the governance authority allows
   `DestructiveAuthorization`, confirm the governance interval fits inside
   both the governance authority's window and the step's own lease interval,
   then build and sign a `GovernanceReceiptArtifact`.
6. Return the signed leases, scope bindings, and governance receipts as one
   `ChioIssuanceBundle`.

`publish_revocation_checkpoint` follows the same validate-then-bind-then-sign
shape for the revocation authority. `assemble_verifier_trust_bundle` differs:
it does not sign. It validates `profile` and `peer_pins`, hashes the workflow
intersection with `canonical_json_bytes` + `sha256_hex`, assembles a
`ChioVerifierTrustBundleDocument` around the caller-supplied peer pins and a
pre-signed checkpoint, and round-trips the result through
`ChioVerifierTrustBundle::from_document` to confirm strict verifier
compatibility before returning it.

## Invariants and failure modes

- Every `*_from_json` function validates immediately; malformed shape or a
  wrong schema string never reaches a caller as a live document.
- Every document's `schema` field must equal this crate's declared constant.
- A local seed signs only after its derived public key matches the profile's
  declared public key for that authority (`ensure_key_matches_authority`).
- An authority must be `ChioAuthorityStatus::Active` to sign or be issued
  against; a present-but-inactive authority is rejected.
- Every issued interval must be non-empty (`expires > issued`) and fit fully
  inside its authority's validity window; a destructive step's governance
  interval must additionally fit inside that step's own lease interval.
- Destructive steps (`destructive: true`) require the `NarrowDestructive`
  action class plus a governance receipt id, issue/expiry times, and step
  hash; non-destructive steps must carry none of those fields. The two shapes
  are mutually exclusive.
- A revocation checkpoint's `epoch_height` must be strictly greater than
  `previous_epoch_height` when present.
- Duplicates are rejected throughout: lease ids, step indices, signing-seed
  ids, BBS issuers, lease/governance authority issuer ids, runtime-policy
  issuer keys (which also must not reuse any lease, governance, or revocation
  authority key), revoked-key fingerprints, and peer/vendor/action-class ids.
- Peer pins must include both `WORKFLOW_GRANT_ISSUE_ACTION_CLASS_ID` and
  `WORKFLOW_AGGREGATE_PUBLISH_ACTION_CLASS_ID` before a trust bundle assembles.
- `assemble_verifier_trust_bundle` trusts its `checkpoint` and
  `disclosure_policy` arguments as given; it does not re-validate a checkpoint
  it did not itself produce, relying on `ChioVerifierTrustBundle::from_document`
  as the final gate.
- `#![forbid(unsafe_code)]`.

## Dependencies

Internal: `chio-attest-buyer-core` supplies the verifier trust-bundle,
lease-scope-binding, verification-context, disclosure-policy, and revocation
checkpoint types this crate assembles and issues into, plus the
`ChioPackageError` this crate's error converts into. `chio-core-types`
supplies canonical JSON hashing (`canonical_json_bytes`, `sha256_hex`),
`Keypair` / `PublicKey`, and the `SignedExportEnvelope::sign` primitive used to
sign every artifact this crate emits. `chio-federation` supplies `Keyid` for
the key-id-matches-public-key check. `chio-governance` supplies the capability
lease and governance receipt artifact and schema types this crate signs.
External: `serde` / `serde_json` for document (de)serialization, `thiserror`
for `ChioAuthorityError`. No dependency aliasing. `hex` is a dev-dependency
used only by `src/tests.rs` to encode fixture seeds.
