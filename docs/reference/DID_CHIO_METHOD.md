# `did:chio` Method

**Status:** legacy compatibility method for current v1 profile; originally
tracked under an internal portable-trust milestone

**Transition note:** The Chio rename freezes `did:chio` as a legacy
compatibility method for already-issued Chio artifacts. The planned Chio
transition is documented in
`docs/standards/CHIO_IDENTITY_TRANSITION.md`.

---

## Overview

`did:chio` is Chio's currently shipped self-certifying DID method for Ed25519
identities already used by agents, kernels, and capability authorities.

Format:

```text
did:chio:{64-hex-character-ed25519-public-key}
```

Example:

```text
did:chio:80f2b577472e6662f46ac2e029f4b2d1300f889bc767b3de1f7b63a4c562fd8f
```

The DID is self-certifying. Basic resolution requires no registry lookup: the
method-specific identifier is the public key.

## Resolution

The resolver lives in the `chio-did` crate and is exposed in the CLI via:

```text
chio did resolve --did did:chio:...
chio did resolve --public-key <hex>
```

The resolved DID Document always contains:

- `@context: "https://www.w3.org/ns/did/v1"`
- one `verificationMethod` entry at `#key-1`
- `authentication` referencing `#key-1`
- `assertionMethod` referencing `#key-1`

The verification method shape is:

```json
{
  "id": "did:chio:...#key-1",
  "type": "Ed25519VerificationKey2020",
  "controller": "did:chio:...",
  "publicKeyMultibase": "z..."
}
```

`publicKeyMultibase` is the base58btc encoding of the Ed25519 public key with
the standard multicodec prefix `0xed01`.

## Optional Services

Resolvers may attach receipt-log service endpoints when the local environment
knows where a subject's receipt log is published.

Chio currently ships one service type here:

- `ChioReceiptLogService`

CLI example:

```text
chio did resolve \
  --did did:chio:... \
  --receipt-log-url https://trust.example.com/v1/receipts
```

That produces a `service` entry like:

```json
{
  "id": "did:chio:...#receipt-log",
  "type": "ChioReceiptLogService",
  "serviceEndpoint": "https://trust.example.com/v1/receipts"
}
```

Multiple `--receipt-log-url` flags are allowed. They are emitted
deterministically as `#receipt-log`, `#receipt-log-2`, and so on.

## Current Boundary

Shipped now:

- self-certifying DID parsing and canonicalization
- DID document resolution for any Chio Ed25519 public key
- stable `Ed25519VerificationKey2020` verification method output
- optional receipt-log service attachment
- Agent Passport alpha verification on top of `did:chio`

Not shipped yet:

- `did:chio:update` receipt flows
- key rotation receipts
- external DID-method registration work
