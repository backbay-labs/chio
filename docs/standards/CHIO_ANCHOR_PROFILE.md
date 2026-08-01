# Chio Anchor Profile

## Purpose

This profile freezes the bounded `chio-anchor` runtime, originally tracked
under historical internal milestone `v2.36`, as implemented in the current
pre-release v1 workspace for multi-chain checkpoint anchoring.

> Version posture: this is a pre-release standards profile. Internal `v2.x`
> milestone labels are historical planning labels, not Chio-owned protocol,
> schema, SDK, or runtime versions. The checkpoint-transparency migration uses
> explicit v2 schemas where signed v1 envelopes cannot be extended compatibly.

It covers four connected surfaces:

- direct Base and Arbitrum root-registry publication plus inclusion-proof
  verification
- Bitcoin OpenTimestamps aggregation and imported proof inspection tied to Chio
  super-roots
- Solana memo publication descriptors plus imported memo-record verification
- shared proof-bundle normalization, discovery metadata, and qualification

Production operations for this runtime are frozen separately in
`docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md`, with the anchor-specific
runtime example at `docs/standards/CHIO_ANCHOR_RUNTIME_REPORT_EXAMPLE.json`.

## Shipped Runtime Boundary

`chio-anchor` now claims one bounded multi-lane anchoring runtime only:

- EVM publication requests, publisher-authorization guards, confirmation, and
  on-chain inclusion verification against the official root-registry contract
- OpenTimestamps submission preparation over contiguous Chio checkpoints, plus
  imported `.ots` proof inspection that requires a SHA-256 document digest
  matching the Chio super-root and at least one Bitcoin attestation
- canonical Solana memo publication descriptors and imported memo-anchor
  verification over the built-in Memo program
- one shared proof-bundle normalization lane spanning the primary EVM proof and
  optional Bitcoin or Solana secondary evidence: v1 bundles require a v1
  inclusion proof, and v2 bundles require a chain-committed v2 inclusion proof;
  Bitcoin linkage is validated against the declared super-root digest instead
  of metadata presence alone
- canonical anchor-proof projection only from durable Chio evidence bundles
  that contain the receipt, one kernel-signed checkpoint, and one matching
  inclusion proof

## Machine-Readable Artifacts

- `docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json`
- `docs/standards/CHIO_ANCHOR_DISCOVERY_EXAMPLE.json`
- `docs/standards/CHIO_ANCHOR_OTS_SUBMISSION_EXAMPLE.json`
- `docs/standards/CHIO_ANCHOR_SOLANA_MEMO_EXAMPLE.json`
- `docs/standards/CHIO_ANCHOR_PROOF_BUNDLE_EXAMPLE.json`
- `docs/standards/CHIO_ANCHOR_QUALIFICATION_MATRIX.json`
- `docs/standards/CHIO_ANCHOR_RUNTIME_REPORT_EXAMPLE.json`

## Discovery And Ownership

The shipped discovery and ownership posture is explicit:

- verifier discovery starts with one `did:chio` service entry of type
  `ChioAnchorService`
- every configured EVM lane names one canonical contract address, one operator
  address, and one publisher address
- the operator address remains the owner of anchored checkpoint roots even when
  a delegate publisher is used
- delegate publication is allowed only when the root registry authorizes that
  publisher on-chain

## Bitcoin Lane

The Bitcoin lane is explicitly secondary evidence:

- Chio aggregates one or more contiguous checkpoint roots into one super-root
- Chio prepares one SHA-256 document digest for OpenTimestamps submission
- imported `.ots` payloads must decode, match the expected document digest, and
  include a Bitcoin attestation before Chio treats the lane as anchored
- proof-bundle verification rejects Bitcoin or Solana evidence that is present
  but undeclared, or declared without the cryptographically matching lane data

This keeps the secondary lane tied to canonical Chio checkpoint truth instead of
accepting opaque OTS blobs.

## Solana Lane

The Solana lane stays narrowly defined:

- Chio emits one canonical memo payload format:
  `Chio:{checkpoint_seq}:{merkle_root}:{issued_at}`
- Chio verifies imported memo records only when the memo program id, memo
  payload, checkpoint sequence, and anchored root all match the primary proof
- unsupported programs or mismatched memo payloads fail closed

## Failure Posture

`chio-anchor` is fail closed by default.

Anchoring or verification is denied when:

- the publisher is not authorized for the operator on the target registry
- the checkpoint sequence would replay or regress the latest on-chain sequence
- the imported OTS payload is invalid, pending-only, or tied to the wrong
  document digest
- the Solana memo record does not exactly encode the canonical checkpoint data
- the proof bundle declares a secondary lane that is missing or inconsistent
  with the primary proof
- the imported evidence bundle leaves the receipt uncheckpointed or omits the
  canonical inclusion proof or checkpoint record

## Qualification Closure

The qualification matrix proves the bounded runtime claim across:

- EVM publication readiness and sequencing
- primary proof projection and on-chain verification
- Bitcoin super-root linkage and pending-proof denial
- Solana memo normalization
- shared bundle mismatch rejection
- canonical evidence-bundle completeness and uncheckpointed-receipt denial

## Non-Goals

This profile does not yet claim:

- permissionless operator discovery
- direct Bitcoin transaction construction or block-header validation
- arbitrary Solana program anchoring beyond the Memo program
- Chainlink Automation or other scheduled anchoring infrastructure
- cross-chain settlement release from Bitcoin or Solana evidence alone
