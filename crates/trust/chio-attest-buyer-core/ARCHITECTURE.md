# chio-attest-buyer-core architecture

## Overview

`chio-attest-buyer-core` is a pure, offline verification library: no network
I/O, no filesystem access beyond the JSON strings a caller provides, and
`#![forbid(unsafe_code)]`. It is the hardened core behind the public boundary
crate `chio-attest-buyer`, but kernel-side code (`chio-runtime-core`,
`chio-runtime-harness`) and tooling (`chio-cli`) also call it directly, so its
types and JSON codecs are public rather than crate-internal.

The design treats the proof package as untrusted input end to end: every
artifact it references (peer, vendor, lease authority, governance authority,
BBS issuer, workflow intersection) must independently resolve against, and
match, the verifier's own trust bundle. The package's self-reported hints are
never authoritative on their own.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations; `#![forbid(unsafe_code)]`. |
| `src/proof_package.rs` | `ChioProofPackage`, its JSON codec and canonical hash, and proof-claim support checks. |
| `src/trust_bundle.rs` | `ChioVerifierTrustBundleDocument` / `ChioVerifierTrustBundle`: parses and indexes trusted issuers, peers, vendors, action classes, workflow intersections, lease/governance authorities, disclosure policy, and the signed revocation checkpoint. |
| `src/context.rs` | `ChioVerificationContext`: audience/challenge/purpose binding and the derived BBS proof nonce. |
| `src/report.rs` | Verification orchestration (`verify_package`, `verify_package_report`), the per-phase checks, and `VerifierReport` construction with stable failure codes/phases. |
| `src/claims.rs` | Proof claim flags, peer/vendor key bindings, workflow-intersection artifact shapes, `LeaseScopeBindingArtifact` and its scope-digest preimage. |
| `src/disclosure.rs` | `ChioDisclosurePolicy` validation and BBS projection selection/contract checks. |
| `src/revocation.rs` | Revocation checkpoint schema, signature verification, revoked-fingerprint set construction. |
| `src/issuer.rs` | `TrustedIssuerRegistry`: BBS issuer fingerprint to public key lookup. |
| `src/oracle.rs` | `OfflineRevocationOracle`, a `RevocationOracle` adapter over the trust bundle's revoked-key set. The module is declared `pub` but exports nothing outside the crate (the struct is `pub(crate)`). |
| `src/validation.rs` | `pub(crate)` field, hash, and lifecycle validation helpers shared across modules. |
| `src/error.rs` | `ChioPackageError`, the crate's unified error type. |
| `src/tests.rs` | Verifier behavior tests, driven by fixtures under `examples/chio-3vendor/fixtures/`. |

## Verification lifecycle

`report::verify_package_inner` runs these phases in order, appending a
`VerifierCheck` as each one passes:

1. Schema and claims: the package schema must be `PROOF_PACKAGE_SCHEMA`, and
   `verify_claims` rejects any package claim this verifier does not support.
2. Context freshness: the context validates, its issue/expiry window brackets
   the trust bundle's pinned checkpoint time, and the checkpoint is still
   active just before the context expires.
3. Workflow signature: the workflow receipt's kernel signature verifies.
4. Trust hints: every peer and vendor binding in the package matches a
   non-revoked, non-stale trust bundle entry.
5. Workflow intersection: the intersection artifact hash-matches a trusted
   intersection; its vendor signers and peers must be trusted, and its
   step-class bindings must match the workflow receipt's steps and the trust
   bundle's action classes.
6. Vendor cosignatures: the vendor signatures required by the trusted
   intersection verify against the workflow receipt.
7. Step links: each workflow step cross-checks against its DSSE envelope,
   tool receipt, and capability lease, with parent-hash chaining across steps
   and destructive-flag agreement with the lease's action class.
8. Lease scope bindings: each binding validates, and its canonical scope
   digest matches the lease it names.
9. Capability leases: each lease is signed by a trusted, time-valid lease
   authority for its action class and passes `verify_capability_lease` against
   its scope digest.
10. Governance receipts and destructive steps: governance receipts come from
    trusted, time-valid authorities, and every destructive step's
    receipt/lease pair passes `verify_destructive_authorization`.
11. Bilateral envelopes: each DSSE envelope verifies under
    `chio_federation::bilateral_verifier` with an `allow` joint verdict.
12. Selective disclosure: the BBS issuer is trusted and non-revoked, the proof
    satisfies the trust bundle's disclosure policy, and the BBS signature
    verifies.

`verify_package` returns `Err` at the first failed phase. `verify_package_report`
always returns a `VerifierReport`, mapping any error to a stable `code` and
`phase` (`failure_code`, `failure_phase`) while preserving the checks completed
before failure.

## Invariants and failure modes

- Fail closed on shape: every artifact type derives
  `#[serde(deny_unknown_fields)]`, so unrecognized fields in a package, trust
  bundle, checkpoint, or context are a parse error.
- The package's own trust hints are never sufficient; each must resolve to,
  and match, a corresponding trust bundle entry.
- Revocation is enforced against a signed `ChioRevocationCheckpoint`; peer,
  vendor, lease/governance authority keys, and the BBS issuer fingerprint are
  all checked against its revoked set before use.
- Lease and governance authorities require an explicit `keyId` matching their
  public key fingerprint, an `Active` status, and a `[validFrom, validUntil)`
  window covering both the verifier's current time and the artifact's issue
  time.
- Destructive workflow steps must carry a governance receipt id matching both
  the workflow step and the DSSE predicate; non-destructive steps must carry
  none.
- `oracle::OfflineRevocationOracle` is this crate's only implementation of
  `chio_federation`'s `RevocationOracle` trait. It ignores the epoch height
  argument and treats a fingerprint as active unless the trust bundle's
  checkpoint lists it as revoked.

## Dependencies

- `chio-core-types` - canonical JSON, SHA-256 hashing, `PublicKey`, and the
  `ChioReceipt` / `SignedExportEnvelope` types packages and checkpoints embed.
- `chio-federation` - bilateral DSSE envelopes, the bilateral verifier (peer
  pins, receipt/lease/governance stores, the `RevocationOracle` trait), and
  ladder-manifest trust establishment.
- `chio-governance` - capability lease and governance-receipt verification
  (`verify_capability_lease`, `verify_destructive_authorization`,
  `verify_step_governance_boundary`).
- `chio-workflow` - `WorkflowReceipt` and vendor signature requirements.
- `chio-selective-disclosure` (`bbs` feature) - BBS+ projection, signing, and
  proof verification for selective disclosure.
- `serde` / `serde_json`, `thiserror` - artifact (de)serialization and the
  crate's error type.

No dependency aliasing: every `chio-*` dependency name matches the crate path
used in source (`chio_core_types::`, `chio_federation::`, and so on).
