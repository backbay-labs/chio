# chio-federation-authority Architecture

`chio-federation-authority` is the local issuer for signed Chio federation
authority artifacts. Operators feed it authority profiles, local signing seeds,
issuance requests, revocation publication requests, and peer pins; it validates
those inputs and mints the signed documents consumed by verifier and
federation-contract crates.

## Boundaries

- `chio-attest-buyer-core` owns verifier trust-bundle contracts, lease-scope
  bindings, revocation checkpoint shapes, and verifier parsing.
- `chio-governance` owns capability lease and governance receipt artifact
  validation.
- `chio-federation` owns peer ladder references and federation contract
  primitives.
- This crate owns authority-side input validation, local seed lookup, signer to
  authority-key binding, and artifact issuance.

## Source Layout

- `src/lib.rs` defines the authority request, bundle, signing-key, revocation,
  and peer-pin contracts plus JSON helpers, signing orchestration, checkpoint
  publication, and verifier trust-bundle assembly.
- `src/profile.rs` validates authority profiles and owns the profile lookup
  helpers used by issuance.
- `src/tests.rs` covers the deterministic authority issuance and validation
  behavior families.

## Trust Invariants

- Authority profiles must contain active lease, governance, runtime-policy, BBS,
  and revocation authority material.
- Authority key IDs must match their public keys, and runtime policy issuer keys
  must not reuse lease, governance, or revocation authority keys.
- Local signing seeds are never trusted by name alone. Each seed is derived to a
  public key and compared with the authority profile before signing.
- Issued lease and governance intervals must fit inside the corresponding
  authority validity windows.
- Peer pins are validated before trust-bundle assembly, including duplicate
  peer, vendor, and action-class rejection.

## Testing Focus

Unit tests cover verifier-compatible issuance, schema wrapping, authority
status checks, key-id binding, revocation monotonicity, and peer-pin validation.
The crate has no network or storage side effects; deterministic seed fixtures
make signing behavior reproducible.
