# chio-federation-authority

Local issuer for signed Chio federation authority artifacts. An operator
supplies an authority profile (which lease, governance, BBS, and revocation
authorities are trusted, with their public keys and validity windows), local
signing seeds, and a request; the crate validates every input fail-closed,
binds each local seed to the public key its profile entry declares, and signs
the resulting capability leases, governance receipts, revocation checkpoints,
and verifier trust bundles.

It sits in `crates/trust/` alongside `chio-federation` (the admission and
reputation-clearing contract types this crate's output feeds) and
`chio-federation-transport-iroh` (a network accept-time admission gate with no
dependency on this crate). This crate does no networking or storage; it is
pure validation and signing over documents it is given.

## Responsibilities

- Define the JSON document schemas an authority operator supplies: authority
  profile, issuance request, local signing keys, revocation publication
  request, and peer pins (`*_SCHEMA` constants).
- Validate every document fail-closed (schema match, required fields,
  SHA-256/hex shape, duplicate rejection, validity windows) before signing.
- Bind local signing seeds to the authority profile: a seed signs only after
  its derived public key matches the profile's declared public key.
- Issue signed capability leases and lease-scope bindings per requested step,
  plus a signed governance receipt for destructive steps.
- Publish signed revocation checkpoints with monotonic epoch enforcement.
- Assemble a verifier trust bundle and confirm it parses through
  `chio-attest-buyer-core`'s strict verifier parser before returning it.

## Public API

- `AuthorityProfileDocument`, `LocalAuthoritySigningKeysDocument`,
  `ChioIssuanceRequest` / `ChioIssuanceStepRequest`, `ChioIssuanceBundle`,
  `RevocationPublicationRequest`, `PeerPinsDocument`, `ChioRevocationAuthority`,
  `NamedSeedHex` - document types, each with a `validate()` method.
- `authority_profile_from_json`, `issuance_request_from_json`,
  `signing_keys_from_json`, `revocation_publication_request_from_json`,
  `peer_pins_from_json` - parse and validate a document in one step.
- `authority_profile_json`, `issuance_request_json`, `signing_keys_json`,
  `issuance_bundle_json`, `revocation_publication_request_json`,
  `peer_pins_json`, `signed_revocation_checkpoint_json` - pretty-printed
  serialization.
- `issue_authority_bundle(profile, request, signing_keys) ->
  Result<ChioIssuanceBundle, ChioAuthorityError>` - signs capability leases,
  lease-scope bindings, and governance receipts for one issuance request.
- `publish_revocation_checkpoint(profile, request, signing_keys) ->
  Result<SignedChioRevocationCheckpoint, ChioAuthorityError>`.
- `assemble_verifier_trust_bundle(profile, peer_pins, workflow_intersection,
  disclosure_policy, checkpoint) ->
  Result<ChioVerifierTrustBundleDocument, ChioAuthorityError>`.
- `ChioAuthorityError` - fail-closed error type (`Profile`, `Request`,
  `SigningKeys`, `Issuance`, `Revocation`, `TrustBundle`, `Json`, `Canonical`),
  convertible into `chio_attest_buyer_core::error::ChioPackageError`.

## Testing

`cargo test -p chio-federation-authority`

## See also

- `chio-attest-buyer-core` - owns the verifier trust-bundle, disclosure, and
  revocation-checkpoint types this crate assembles and issues into.
- `chio-federation` - owns the peer/quorum/admission contracts this crate's
  authorities and peer pins feed.
- `chio-governance` - owns the capability-lease and governance-receipt
  artifact definitions this crate signs.
- `chio-attest-loopback` - re-exports this crate's issuance surface for its
  deterministic buyer/auditor loopback harness.
- `chio-cli` - hosts the `federation authority issue` / `checkpoint` /
  `trust-bundle assemble` commands built directly on this crate.
