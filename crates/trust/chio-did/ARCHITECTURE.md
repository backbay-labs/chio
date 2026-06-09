# chio-did Architecture

## Boundary

`chio-did` owns the self-certifying `did:chio` method. A DID is derived from the Ed25519 public key bytes used elsewhere in Chio, and resolution builds a DID Document without registry lookup.

## Internal Surfaces

The crate boundary is intentionally small: `DidChio` parses and renders canonical identifiers, `DidDocument` and `DidVerificationMethod` describe the resolved document, and `DidService` attaches resolver-provided service metadata such as receipt-log and passport-status endpoints.

## Trust Invariants

The security constraint is that resolver metadata must not weaken the self-certifying identifier. Service URLs are public trust hints, so they must be syntactically valid and transport-safe before entering a DID Document.

## Dependent Surfaces

Credential, federation, governance, and reputation code can treat resolved `did:chio` documents as identity anchors. That makes construction-time validation the compatibility boundary: bad service metadata must be rejected here rather than left for each downstream verifier to interpret differently.

## Verification Focus

Tests should cover canonical identifier round trips, invalid key material, service URL scheme validation, service type validation, and document rendering that preserves the key-derived verification method.

## Improvement Target

Planned improvement: reject non-HTTPS service endpoints at construction time so receipt-log and passport-status services cannot advertise plaintext or local file endpoints.
