# chio-did

Self-certifying `did:chio` identifiers and DID Document resolution. The
method-specific identifier is the lowercase hex form of an Ed25519 public key
already used by Chio agents and operators, so basic resolution needs no
registry lookup. The resolving environment may attach optional receipt-log and
passport-status service endpoints.

## Responsibilities

- Derive a canonical `did:chio:<64-hex>` identifier from an Ed25519
  `PublicKey` and parse it back (`DidChio`, `FromStr`, `Display`).
- Resolve a `DidChio` into a W3C-shaped `DidDocument` with one Ed25519
  verification method, with no network or registry lookups.
- Validate and attach resolver-provided service endpoints (`DidService`),
  rejecting anything that is not a well-formed `https` URL.
- Reject non-Ed25519 key material and malformed method-specific identifiers.

## Public API

- `DidChio` - parses, renders, and resolves a `did:chio` identifier.
  `from_public_key`/`try_from_public_key`, `as_str`, `verification_method_id`,
  `public_key_multibase`, `resolve`, `resolve_with_options`; implements
  `Display`, `FromStr`, `TryFrom<PublicKey>`.
- `DidDocument`, `DidVerificationMethod`, `DidService` - the resolved document
  and its parts (`serde::Serialize`/`Deserialize`, DID-spec field names).
- `DidService::new` / `::receipt_log` / `::passport_status` - validated
  service-endpoint constructors; `RECEIPT_LOG_SERVICE_TYPE` and
  `PASSPORT_STATUS_SERVICE_TYPE` name the two known service types.
- `ResolveOptions` - builder for the services attached during resolution.
- `resolve_did_arc` - parse-and-resolve convenience over a raw
  `did:chio:...` string.
- `DidError` - the crate's fail-closed error enum.

## Usage

```rust
use chio_core::Keypair;
use chio_did::{DidChio, DidService, ResolveOptions};

let keypair = Keypair::from_seed(&[7u8; 32]);
let did = DidChio::from_public_key(keypair.public_key())?;

let options = ResolveOptions::default().with_service(
    DidService::receipt_log(&did, 0, "https://trust.example.com/v1/receipts")?,
);
let document = did.resolve_with_options(&options);
assert_eq!(document.id, did.to_string());
```

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Enables `chio_did::fuzz` (`fuzz_did_resolve`), the libFuzzer entry point. Off by default; pulls in `arbitrary` and `serde_json`. Enabled only by the standalone `fuzz` workspace. |

## Testing

`cargo test -p chio-did`

## See also

- `chio-core` - supplies the `PublicKey` and `SigningAlgorithm` types every `did:chio` identifier wraps.
- `chio-credentials` - anchors credential subjects and issuers to resolved `did:chio` identities.
- `chio-control-plane` - resolves `did:chio` identifiers for reputation and trust-control subjects.
- `chio-cli` - implements the `did resolve` command over `DidChio`, `DidService`, and `ResolveOptions`.
