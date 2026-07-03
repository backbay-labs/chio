# Chio Nitro Attested Checkpoint Binding Shape

## Purpose

This note defines one concrete candidate artifact shape for
`chio.nitro.attested_checkpoint_binding.v1`.

It is intentionally bounded:

- it does not change `chio.checkpoint.v1`
- it does not define a new runtime-admission token
- it does not widen trust from Nitro evidence alone
- it stays specific to AWS Nitro rather than inventing a cross-TEE abstraction

## Candidate Contract

`chio.nitro.attested_checkpoint_binding.v1` is a body artifact that proves one
canonical Chio checkpoint was bound to one AWS Nitro attestation document over
one short validity window.

The v1 shape pins one encoding choice so implementations do not need to guess
how Nitro's optional fields are used:

- Nitro `public_key` carries the checkpoint signer's DER-encoded SPKI key
- Nitro `user_data` carries `SHA-256` over the canonical JSON
  `bindingPayload`
- Nitro `nonce` carries the verifier or challenger nonce for freshness

The artifact body should later be carried inside an ordinary Chio-signed
envelope or another explicit transport. That envelope is out of scope here.

## Required Fields

The artifact body must carry these fields:

- `schema`
  Must be `chio.nitro.attested_checkpoint_binding.v1`.
- `bindingId`
  Stable artifact identifier for this binding statement.
- `issuedAt`
  UNIX seconds when the binding body was emitted.
- `expiresAt`
  UNIX seconds after which the binding must fail closed.
  It must be less than or equal to `bindingPayload.notAfter`.
- `checkpoint`
  Must name the bound Chio checkpoint with:
  `schema`, `checkpointId`, `checkpointSeq`, `issuedAt`, `receiptCount`,
  `merkleRootSha256`, and `signerPublicKeySha256`.
- `bindingPayload`
  The canonical payload whose digest is placed into Nitro `user_data`.
  It must carry:
  `checkpointSchema`, `checkpointId`, `checkpointSeq`, `merkleRootSha256`,
  `signerPublicKeySha256`, `sessionAnchor`, `notBefore`, and `notAfter`.
  `notBefore` and `notAfter` are UNIX seconds.
- `bindingPayloadSha256`
  `SHA-256` over the RFC 8785 canonical JSON encoding of `bindingPayload`.
- `nonceB64Url`
  Base64url-encoded freshness nonce that must match Nitro `nonce`.
- `nitro`
  Extracted Nitro evidence metadata with:
  `documentSchema`, `documentSha256`, `moduleId`, `timestampMs`, `digest`,
  `publicKeySha256`, `userDataSha256`, `nonceB64Url`, and `pcrs`.
- `verifier`
  Chio verifier provenance with:
  `descriptorId`, `verifier`, `verifierFamily`, `adapter`,
  `referenceValuesId`, `referenceValuesSha256`, and `requiredPcrs`.

## Verification Order

Consumers should verify in this order and fail closed on any mismatch:

1. Check `schema`, `issuedAt`, and `expiresAt`, and require
   `expiresAt <= bindingPayload.notAfter`.
2. Resolve the referenced `chio.checkpoint.v1` artifact and verify its normal
   checkpoint signature before using any Nitro fields.
3. Confirm the checkpoint's `checkpointId`, `checkpointSeq`,
   `merkleRootSha256`, and signer key digest exactly match the copied
   `checkpoint` fields in the binding artifact.
4. Canonicalize `bindingPayload` with RFC 8785 JSON, hash it with `SHA-256`,
   and require equality with `bindingPayloadSha256`.
5. Verify the raw Nitro attestation document referenced by
   `nitro.documentSha256` against the AWS Nitro root chain and the Chio
   `verifier.descriptorId`.
6. Require Nitro `digest` to be `SHA384`.
7. Require Nitro `public_key` to be present and require its `SHA-256` digest
   to equal both `nitro.publicKeySha256` and
   `checkpoint.signerPublicKeySha256`.
8. Require Nitro `user_data` to be present and require its `SHA-256` digest to
   equal both `nitro.userDataSha256` and `bindingPayloadSha256`.
9. Require Nitro `nonce` to be present and require equality with both
   `nonceB64Url` and `nitro.nonceB64Url`.
10. Resolve `verifier.referenceValuesId`, confirm its digest matches
    `verifier.referenceValuesSha256`, then require every index listed in
    `verifier.requiredPcrs` to be present in `nitro.pcrs` and equal the
    reference values.
11. Deny when Nitro PCRs are all-zero debug values, when required PCRs are
    missing, or when `floor(nitro.timestampMs / 1000)` falls outside
    `bindingPayload.notBefore` through `bindingPayload.notAfter`.
12. Only after all checks pass may a consumer claim:
    `receipt -> checkpoint inclusion -> attested checkpoint`.

## Minimal Example Body

```json
{
  "schema": "chio.nitro.attested_checkpoint_binding.v1",
  "bindingId": "nitro-bind-prod-us-east-1-checkpoint-9184",
  "issuedAt": 1776286500,
  "expiresAt": 1776286800,
  "checkpoint": {
    "schema": "chio.checkpoint.v1",
    "checkpointId": "chk-9184",
    "checkpointSeq": 9184,
    "issuedAt": 1776286500,
    "receiptCount": 128,
    "merkleRootSha256": "0x4b1c7d22f0a6b9138cdb95b29c2f9dfc3220e5f4e5b7708b0cbb1f7fbfc8ef49",
    "signerPublicKeySha256": "0x1111111111111111111111111111111111111111111111111111111111111111"
  },
  "bindingPayload": {
    "checkpointSchema": "chio.checkpoint.v1",
    "checkpointId": "chk-9184",
    "checkpointSeq": 9184,
    "merkleRootSha256": "0x4b1c7d22f0a6b9138cdb95b29c2f9dfc3220e5f4e5b7708b0cbb1f7fbfc8ef49",
    "signerPublicKeySha256": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "sessionAnchor": "sess-7f3c4d9ee8c2f1ab",
    "notBefore": 1776286500,
    "notAfter": 1776286800
  },
  "bindingPayloadSha256": "0x2222222222222222222222222222222222222222222222222222222222222222",
  "nonceB64Url": "yKs6m9Y8Wm6QK8g1o2o7uA",
  "nitro": {
    "documentSchema": "aws.nitro.attestation-document.cose-sign1",
    "documentSha256": "0x3333333333333333333333333333333333333333333333333333333333333333",
    "moduleId": "i-0abc1234def567890-enc019284756",
    "timestampMs": 1776286512123,
    "digest": "SHA384",
    "publicKeySha256": "0x1111111111111111111111111111111111111111111111111111111111111111",
    "userDataSha256": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "nonceB64Url": "yKs6m9Y8Wm6QK8g1o2o7uA",
    "pcrs": {
      "0": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "1": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "2": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "8": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    }
  },
  "verifier": {
    "descriptorId": "vrd-aws-nitro-prod-us-east-1",
    "verifier": "did:chio:9f4f2d8e7c1ab34d56e7890ffedcba1234567890abcdef1234567890abcdef12#aws-nitro-prod",
    "verifierFamily": "aws_nitro",
    "adapter": "chio.aws-nitro-attestation-document",
    "referenceValuesId": "rv-aws-nitro-eif-2026-04-14",
    "referenceValuesSha256": "0x4444444444444444444444444444444444444444444444444444444444444444",
    "requiredPcrs": [
      0,
      1,
      2,
      8
    ]
  }
}
```

## Failure Posture

This candidate shape must fail closed when:

- Nitro `public_key`, `user_data`, or `nonce` is missing
- the checkpoint signer key is not the same key attested by Nitro
- the checkpoint root or sequence differs from the bound payload
- the verifier descriptor or reference-value set cannot be resolved exactly
- the Nitro document is stale, future-dated beyond allowed skew, or debug-zero
- required PCRs are absent or mismatched

## Non-Goals

This note does not define:

- per-receipt Nitro quotes
- a generic cross-vendor TEE binding contract
- a replacement for `chio.runtime-attestation.appraisal-result.v1`
- a kernel admission record or governed-execution policy surface

## Source Notes

- AWS Nitro attestation overview:
  <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html>
- AWS Nitro attestation document structure:
  <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>
