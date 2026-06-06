# chio-attest-buyer-core Architecture

## Boundary

`chio-attest-buyer-core` is the offline proof-package verifier for Chio buyers and auditors. It verifies proof packages without network access by replaying workflow signatures, vendor cosignatures, trust-bundle pins, revocation checkpoints, lease scope bindings, governance receipts, federation DSSE envelopes, and BBS selective-disclosure proofs.

The crate owns verifier-side package parsing, trust-bundle validation, and report construction. It does not own runtime admission, receipt issuance, governance artifact creation, or network resolution. All trust material must already be present in the package or in explicit verifier input.

## Trust Inputs

The trust bundle is verifier policy input, not advisory metadata. Its parser must fail closed on unknown top-level and nested fields so ignored side channels cannot travel with trusted roots, authorities, workflow intersections, or disclosure policy.

The verifier treats issuer registries, lease authorities, governance authorities, revocation checkpoints, and workflow intersections as separate policy surfaces. A package is accepted only when each referenced artifact is schema-valid, canonical-hash-bound, and authorized by the trust bundle section that owns it.

## Module Map

- `lib.rs`: crate documentation, dependency aliases, and public module declarations.
- `issuer.rs`: trusted BBS issuer documents and issuer registry lookup.
- `revocation.rs`: revocation checkpoint documents, pinned epoch material, checkpoint signature validation, and revoked-key set construction.
- `oracle.rs`: offline revocation oracle adapter used by federation verification.
- `disclosure.rs`: verifier disclosure policy validation, projection selection, and BBS proof contract checks.
- `context.rs`: verifier context document, nonce preimage, JSON parsing, rendering, and context hash helpers.
- `trust_bundle.rs`: verifier trust bundle document, authority roots, workflow trust roots, trust-bundle parsing, rendering, and trust-bundle hash helpers.
- `claims.rs`: proof claim flags, peer and vendor bindings, workflow intersection structs, and lease scope bindings.
- `proof_package.rs`: proof package document, JSON parsing, rendering, package hash, and package-claim validation.
- `report.rs`: verifier report types, package verification orchestration, phase/failure mapping, workflow checks, lease checks, governance checks, and report JSON helpers.
- `validation.rs`: shared internal field, hash, lifecycle, canonical JSON, and fingerprint helpers.
- `error.rs`: public package verification error type.
- `tests.rs`: crate-local offline verifier behavior tests.

## Invariants

- Verification is offline and deterministic.
- Unknown JSON fields in trust-bearing inputs fail closed.
- Canonical hashes are computed over stable canonical JSON bytes.
- Signed envelopes must verify before their contents influence package state.
- Rejected packages must retain phase and failure-code evidence for audit.

## Output

Accepted verification reports carry canonical hashes for the package, trust bundle, and verifier context. Rejected reports preserve the checks completed before failure and map each error to a stable phase and failure code for auditors.
