# Swift API reference: `chio_kernel_mobile`

This document mirrors the UDL interface in
`crates/kernel/chio-kernel-mobile/src/chio_kernel_mobile.udl` one-to-one. It
is the contract `uniffi-bindgen generate --language swift` produces
and the contract the iOS app side should code against.

## Module

```swift
import chio_kernel_mobile
```

Package the module with a `.xcframework` that lipos
`libchio_kernel_mobile.a` across the iOS device and simulator slices
you ship for. See `bindings/README.md` for the full workflow.

## Functions

### `evaluate`

```swift
public func evaluate(requestJson: String) throws -> String
```

Evaluates a tool-call request against a capability token. The input
is a JSON object of shape:

```json
{
  "capability": <CapabilityToken JSON>,
  "trusted_issuers": ["<Ed25519 hex>"],
  "request": {
    "request_id": "req-1",
    "tool_name": "echo",
    "server_id": "srv-a",
    "agent_id": "<Ed25519 hex>",
    "arguments": { "..." }
  },
  "now_secs": 1700000100
}
```

`now_secs` is optional; values `<= 0` fall through to the device
wall-clock (`MobileClock`).

The return value is a JSON string:

```json
{
  "verdict": "allow" | "deny",
  "reason": "...",
  "matched_grant_index": 0
}
```

Errors (see `ChioMobileError` below) are only thrown when the inputs
themselves cannot be parsed; a kernel-core deny is encoded in the
JSON response so callers can render it without an exception path.

### `signReceipt`

```swift
public func signReceipt(
    bodyJson: String,
    canonicalContentHex: String,
    signingSeedHex: String
) throws -> String
```

The public WYSIWYS signer for an `ChioReceiptBody` JSON (fail-closed).
`canonicalContentHex` is the lowercase-hex encoding of the exact byte
preimage `body.content_hash` was derived from; the signer recomputes
`sha256_hex(canonicalContent)` inside the trust boundary and throws
`ChioMobileError.signingFailed(message:)` when it disagrees with
`body.content_hash`. This closes the render-A / sign-B forgery at the
mobile boundary. An empty hex string (or a bare `0x`) is accepted and
decodes to an empty preimage, matching a zero-chunk stream receipt.

The body's `kernel_key` must equal the public key derived from
`signingSeedHex`; otherwise the function throws
`ChioMobileError.kernelKeyMismatch(message:)`. Signs with the 32-byte
Ed25519 seed (lowercase hex, optional `0x` prefix). Returns the signed
`ChioReceipt` as JSON.

Callers that only forward an upstream-minted body and cannot carry the
preimage must use `signReceiptRelayingTrustedBody` instead.

### `signReceiptRelayingTrustedBody`

```swift
public func signReceiptRelayingTrustedBody(
    bodyJson: String,
    signingSeedHex: String
) throws -> String
```

Relay-signs an already-minted, upstream-trusted receipt body. This is
NOT the default public signer: it trusts the caller-supplied
`body.content_hash` and does not recompute it. Use only to forward a
body an upstream trusted producer (the kernel) already minted, where
the WYSIWYS recompute already ran. Content-bearing callers that
construct receipts at the boundary must use `signReceipt` instead so
the recompute gate runs over the canonical content preimage.

The body's `kernel_key` must equal the public key derived from
`signingSeedHex`; otherwise the function throws
`ChioMobileError.kernelKeyMismatch(message:)`.

### `verifyCapability`

```swift
public func verifyCapability(tokenJson: String, authorityPubHex: String) throws -> VerifiedCapability
```

Verifies a capability token against a trusted authority public key.
Uses the device wall-clock for the time-bound check; use
`evaluate()` with `now_secs` populated if you need a pinned clock.

### `verifyCapabilityWithContext`

```swift
public func verifyCapabilityWithContext(requestJson: String) throws -> VerifiedCapability
```

Verifies a capability token with the full portable JSON context.
`requestJson` accepts the same trust-root and parent-budget snapshot
fields as `evaluate` (`capability_trust_roots`,
`parent_budget_snapshots`), letting delegated tokens seed sibling-sum
budget enforcement before verification. Complements `verifyCapability`,
which only takes a token and a single authority key.

### `verifyPassport`

```swift
public func verifyPassport(
    envelopeJson: String,
    issuerPubHex: String,
    nowSecs: Int64
) throws -> PortablePassportMetadata
```

Verifies a portable passport envelope (v1 wire format). Pass
`nowSecs <= 0` to fall back to the device wall-clock.

### `attestAppAttest`

```swift
public func attestAppAttest(keyId: String, challengeHex: String) throws -> String
```

Produces an App Attest challenge envelope bound to `challengeHex`. The
iOS host app still calls DeviceCheck to produce the platform
attestation object; this entry point only returns the server challenge
envelope that object must bind to before `verifyAppAttestEvidence`
accepts it.

### `verifyAppAttestEvidence`

```swift
public func verifyAppAttestEvidence(
    keyId: String,
    challengeHex: String,
    appId: String,
    attestationCborHex: String,
    previousCounter: Int64
) throws -> String
```

Verifies Apple App Attest platform evidence against the issued challenge:
validates the certificate chain to the pinned Apple App Attestation root,
binds the server challenge, checks the app id hash, binds the attestation
leaf key to the credential public key, and enforces counter monotonicity.
Pass `previousCounter = -1` when no prior counter exists, otherwise pass
the last accepted counter; the verifier rejects same-or-lower counters
fail-closed. Throws `ChioMobileError.attestationRejected(message:)` on
any verification failure.

### `attestPlayIntegrity`

```swift
public func attestPlayIntegrity(nonceHex: String) throws -> String
```

Produces a Play Integrity challenge envelope bound to `nonceHex`. The
Android host app still calls the Play Integrity API to produce the JWS;
this entry point only returns the nonce envelope the JWS must bind to
before `verifyPlayIntegrityEvidence` accepts it. Exposed on the Swift
surface for cross-platform parity.

### `verifyPlayIntegrityEvidence`

```swift
public func verifyPlayIntegrityEvidence(
    token: String,
    expectedNonce: String,
    expectedPackageName: String,
    expectedAudience: String,
    jwksJson: String
) throws -> String
```

Verifies a Play Integrity JWS against the pinned Google JWKS: checks
`aud` against `expectedAudience`, `exp` against the current time, the
server-supplied nonce against `expectedNonce` byte-for-byte, the package
name, and the app/device recognition verdicts. `jwksJson` is accepted by
the function signature but is only honoured in non-production builds;
production verification always uses the pinned Google JWKS. Throws
`ChioMobileError.attestationRejected(message:)` on any verification
failure.

### `verifyMobileReceipt`

```swift
public func verifyMobileReceipt(receiptJson: String, evidenceJson: String) throws -> String
```

Shape-checks a mobile receipt against App Attest or Play Integrity
evidence before it is handed to the hosted oracle. This does not
authorize a capability or prove device integrity: the returned JSON
status is explicitly non-authoritative (`"authoritative": false`,
`"authorized": false`) until full receipt-chain verification is wired to
trusted issuer pins and challenge binding. Throws
`ChioMobileError.attestationRejected(message:)` when either envelope
fails to parse or the evidence platform is neither `app_attest` nor
`play_integrity`.

## Records

### `VerifiedCapability`

```swift
public struct VerifiedCapability {
    public let id: String
    public let subjectHex: String
    public let issuerHex: String
    public let scopeJson: String
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let evaluatedAt: UInt64
}
```

`scopeJson` is the canonical JSON encoding of `ChioScope`; decode it
with the app-side Chio SDK to inspect grants, constraints, etc.

### `PortablePassportMetadata`

```swift
public struct PortablePassportMetadata {
    public let subject: String
    public let issuerHex: String
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let evaluatedAt: UInt64
    public let payloadCanonicalHex: String
}
```

`payloadCanonicalHex` is the lowercase-hex encoding of the authenticated
payload blob; decode with `Data(hexEncoded:)`.

## Errors

```swift
public enum ChioMobileError: Error {
    case invalidJson(message: String)
    case invalidHex(message: String)
    case weakEntropy(message: String)
    case invalidCapability(message: String)
    case invalidPassport(message: String)
    case attestationUnavailable(message: String)
    case attestationRejected(message: String)
    case kernelKeyMismatch(message: String)
    case signingFailed(message: String)
    case evaluationDenied(message: String)
    case `internal`(message: String)
}
```

Every variant carries a `message: String` describing the failure.
Render it directly via `error.localizedDescription` or a custom
`LocalizedError` adapter. `weakEntropy` is thrown by `signReceipt` and
`signReceiptRelayingTrustedBody` when the signing seed decodes to all
zero bytes. `attestationUnavailable` and `evaluationDenied` are part of
the error surface but are not thrown by any entry point in this crate
today: `evaluate()` encodes a deny verdict in-band in its JSON response
rather than throwing, and the attestation-evidence verifiers throw
`attestationRejected` on failure.

## Minimal usage

```swift
import chio_kernel_mobile

let requestJson = // ... built by your Chio SDK
let responseJson = try evaluate(requestJson: requestJson)

// Parse responseJson (e.g. with JSONDecoder) to read verdict / reason.
```

## Offline sync

See `bindings/README.md` for the offline evaluate + signReceipt +
queue + sync pattern for offline mobile clients.
The FFI exposes primitives only; the queue, keystore, and sync layer
are owned by the app-side integration.
