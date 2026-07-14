# chio-selective-disclosure

Produces and verifies BBS selective-disclosure projections and proof packages
over Chio receipts. A holder projects a receipt-shaped body into an ordered,
versioned BBS message vector, signs the full vector once, then derives a
proof that discloses a chosen subset of messages to a buyer or auditor while
keeping the rest hidden but bound to the same signature.

It also re-exports `chio-disclosure-lineage`'s public types and verification
functions (disclosure bundles, leakage ledgers, privacy profiles, lineage
subgraph signing and verification), so a caller that needs both the BBS proof
layer and the lineage-bundle layer can depend on this crate alone. See "See
also" for how the two crates divide responsibility.

## Responsibilities

- Project `ChioReceiptBody`, `WorkflowReceiptBody`, and `StepRecord` into
  fixed, versioned BBS message vectors (`project_receipt_body`,
  `project_workflow_receipt_body`, `project_step_record`).
- Sign a full projection and derive or verify selective disclosure proofs over
  it using `affinidi-bbs` (feature `bbs`).
- Bind BBS signature material to a receipt's `content_hash` under the same
  WYSIWYS gate the classical Ed25519 signer enforces, so a receipt can never
  carry a BBS signature over content other than what it claims to hash
  (`sign_chio_receipt_with_bbs`).
- Generate and verify a `BbsProjectionManifest` that makes each message
  slot's disclosure policy (disclosed, hidden, wholesale-only) explicit and
  verifier-checkable.
- Verify Merkle inclusion proofs binding a disclosed artifact to a
  transparency log checkpoint (`verify_transparency_inclusion_proof`).
- Layer verifier-side policy checks (key state, revocation freshness,
  audience, nonce replay, holder binding, transparency state) on top of a
  verified BBS proof (`verify_selective_disclosure_with_context`).

## Public API

- `project_receipt_body`, `project_workflow_receipt_body`, `project_step_record` - project a body into a `Projection` of `ProjectionMessage`s.
- `bbs_projection_manifest_from_projection`, `verify_bbs_projection_manifest` - generate and check a `BbsProjectionManifest`.
- `verify_transparency_inclusion_proof` - check a `TransparencyInclusionProof` Merkle path.
- `generate_bbs_keypair`, `sign_projection`, `verify_signed_projection` - BBS key generation and full-vector signing (feature `bbs`).
- `derive_selective_disclosure_proof`, `derive_selective_disclosure_proof_from_receipt`, `verify_selective_disclosure_proof` - derive and verify a `SelectiveDisclosureProof` against an `InMemoryIssuerRegistry` (feature `bbs`).
- `sign_chio_receipt_with_bbs`, `receipt_signed_projection` - bind BBS material to a `ChioReceipt` (feature `bbs`).
- `verify_selective_disclosure_with_context` - `CryptoVerificationContext`-gated verification, returning a `DisclosureCryptoContextReport` (feature `bbs`).
- `SelectiveDisclosureError` - the crate's error type.
- Re-exported from `chio-disclosure-lineage`: `DisclosureLineageBundle`, `DisclosureCapsule`, `DisclosureLeakageLedger`, `DisclosureVerifierPrivacyProfile`, `SignedLineageSubgraph`, and their signing/verification functions.

## Usage

```rust
use chio_selective_disclosure::{
    derive_selective_disclosure_proof, generate_bbs_keypair, project_workflow_receipt_body,
    sign_projection, DisclosureSet,
};

let projection = project_workflow_receipt_body(&workflow_receipt_body)?;
let keypair = generate_bbs_keypair(b"at-least-32-bytes-of-key-material", b"chio")?;
let signed = sign_projection(&projection, &keypair)?;
let proof = derive_selective_disclosure_proof(
    &signed,
    &projection,
    &keypair,
    &DisclosureSet(vec![4, 8, 9, 10]),
    b"buyer-auditor-proof-package",
)?;
```

Requires the `bbs` feature. `examples/chio_fixture.rs` runs this path end to
end and prints the resulting proof as JSON.

## Feature flags

| Flag | Effect |
|------|--------|
| `bbs` | Enables `affinidi-bbs`-backed key generation, projection signing, and proof derivation/verification, plus the receipt-binding and crypto-context-verification entry points. Off by default; without it only projection, manifest, and transparency-inclusion functions are available. |

## Testing

`cargo test -p chio-selective-disclosure --features bbs`

`tests/bbs_selective_disclosure.rs` is `#![cfg(feature = "bbs")]` and does not
compile without the feature. Several tests validate serialized artifacts
against the JSON Schemas under `spec/schemas/`.

## See also

- `chio-disclosure-lineage` - owns the lineage bundle, leakage ledger, and
  privacy-profile types this crate re-exports; verifies structural and
  Ed25519-signature consistency across a bundle's artifacts, with no BBS logic
  of its own.
- `chio-core-types` - `ChioReceipt`, `ChioReceiptBody`, and
  `ReceiptSigningHandle`, the receipt types this crate projects and signs.
- `chio-workflow` - `WorkflowReceiptBody` and `StepRecord`, the other two
  projectable body types.
- `chio-attest-buyer-core`, `chio-proof-room` - verify disclosed proof
  packages produced by this crate.
