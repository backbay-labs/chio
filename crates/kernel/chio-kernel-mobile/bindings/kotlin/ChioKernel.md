# Kotlin API reference: `uniffi.chio_kernel_mobile`

This document mirrors the UDL interface in
`crates/kernel/chio-kernel-mobile/src/chio_kernel_mobile.udl` one-to-one. It
is the contract `uniffi-bindgen generate --language kotlin` produces
and the contract the Android app side should code against.

## Module

```kotlin
import uniffi.chio_kernel_mobile.*
```

The generated Kotlin file lives under
`out/kotlin/uniffi/chio_kernel_mobile/chio_kernel_mobile.kt`; drop it
into the Gradle module's `src/main/java` tree alongside your app
code. Package `libchio_kernel_mobile.so` under
`src/main/jniLibs/<abi>/`. Add `net.java.dev.jna:jna:5.14.0@aar` to
the module's dependencies so UniFFI's Kotlin glue can load the
shared library.

## Functions

### `evaluate`

```kotlin
@Throws(ChioMobileException::class)
fun evaluate(requestJson: String): String
```

Evaluates a tool-call request against a capability token. The input
is a JSON string of shape:

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

Throws `ChioMobileException` only when the inputs cannot be parsed; a
kernel-core deny is encoded in the JSON response so callers can
render it without an exception path.

### `signReceipt`

```kotlin
@Throws(ChioMobileException::class)
fun signReceipt(bodyJson: String, canonicalContentHex: String, signingSeedHex: String): String
```

The public WYSIWYS signer for an `ChioReceiptBody` JSON (fail-closed).
`canonicalContentHex` is the lowercase-hex encoding of the exact byte
preimage `body.content_hash` was derived from; the signer recomputes
`sha256_hex(canonicalContent)` inside the trust boundary and throws
`ChioMobileException.SigningFailed` when it disagrees with
`body.content_hash`. This closes the render-A / sign-B forgery at the
mobile boundary. An empty hex string (or a bare `0x`) is accepted and
decodes to an empty preimage, matching a zero-chunk stream receipt.

The body's `kernel_key` must equal the public key derived from
`signingSeedHex`; otherwise the function throws
`ChioMobileException.KernelKeyMismatch`. Signs with the 32-byte Ed25519
seed (lowercase hex, optional `0x` prefix). Returns the signed
`ChioReceipt` as JSON.

Callers that only forward an upstream-minted body and cannot carry the
preimage must use `signReceiptRelayingTrustedBody` instead.

### `signReceiptRelayingTrustedBody`

```kotlin
@Throws(ChioMobileException::class)
fun signReceiptRelayingTrustedBody(bodyJson: String, signingSeedHex: String): String
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
`ChioMobileException.KernelKeyMismatch`.

### `verifyCapability`

```kotlin
@Throws(ChioMobileException::class)
fun verifyCapability(tokenJson: String, authorityPubHex: String): VerifiedCapability
```

Verifies a capability token against a trusted authority public key.
Uses the device wall-clock for the time-bound check; use
`evaluate()` with `now_secs` populated if you need a pinned clock.

### `verifyCapabilityWithContext`

```kotlin
@Throws(ChioMobileException::class)
fun verifyCapabilityWithContext(requestJson: String): VerifiedCapability
```

Verifies a capability token with the full portable JSON context.
`requestJson` accepts the same trust-root and parent-budget snapshot
fields as `evaluate` (`capability_trust_roots`,
`parent_budget_snapshots`), letting delegated tokens seed sibling-sum
budget enforcement before verification. Complements `verifyCapability`,
which only takes a token and a single authority key.

### `verifyPassport`

```kotlin
@Throws(ChioMobileException::class)
fun verifyPassport(
    envelopeJson: String,
    issuerPubHex: String,
    nowSecs: Long
): PortablePassportMetadata
```

Verifies a portable passport envelope (v1 wire format). Pass
`nowSecs <= 0` to fall back to the device wall-clock.

### `attestAppAttest`

```kotlin
@Throws(ChioMobileException::class)
fun attestAppAttest(keyId: String, challengeHex: String): String
```

Produces an App Attest challenge envelope bound to `challengeHex`. The
iOS host app still calls DeviceCheck to produce the platform attestation
object; this entry point only returns the server challenge envelope
that object must bind to before `verifyAppAttestEvidence` accepts it.
Exposed on the Kotlin surface for cross-platform parity.

### `verifyAppAttestEvidence`

```kotlin
@Throws(ChioMobileException::class)
fun verifyAppAttestEvidence(
    keyId: String,
    challengeHex: String,
    appId: String,
    attestationCborHex: String,
    previousCounter: Long
): String
```

Verifies Apple App Attest platform evidence against the issued challenge:
validates the certificate chain to the pinned Apple App Attestation root,
binds the server challenge, checks the app id hash, binds the
attestation leaf key to the credential public key, and enforces counter
monotonicity. Pass `previousCounter = -1` when no prior counter exists,
otherwise pass the last accepted counter; the verifier rejects
same-or-lower counters fail-closed. Throws
`ChioMobileException.AttestationRejected` on any verification failure.

### `attestPlayIntegrity`

```kotlin
@Throws(ChioMobileException::class)
fun attestPlayIntegrity(nonceHex: String): String
```

Produces a Play Integrity challenge envelope bound to `nonceHex`. The
Android host app still calls the Play Integrity API to produce the JWS;
this entry point only returns the nonce envelope the JWS must bind to
before `verifyPlayIntegrityEvidence` accepts it.

### `verifyPlayIntegrityEvidence`

```kotlin
@Throws(ChioMobileException::class)
fun verifyPlayIntegrityEvidence(
    token: String,
    expectedNonce: String,
    expectedPackageName: String,
    expectedAudience: String,
    jwksJson: String
): String
```

Verifies a Play Integrity JWS against the pinned Google JWKS: checks
`aud` against `expectedAudience`, `exp` against the current time, the
server-supplied nonce against `expectedNonce` byte-for-byte, the package
name, and the app/device recognition verdicts. `jwksJson` is accepted by
the function signature but is only honoured in non-production builds;
production verification always uses the pinned Google JWKS. Throws
`ChioMobileException.AttestationRejected` on any verification failure.

### `verifyMobileReceipt`

```kotlin
@Throws(ChioMobileException::class)
fun verifyMobileReceipt(receiptJson: String, evidenceJson: String): String
```

Shape-checks a mobile receipt against App Attest or Play Integrity
evidence before it is handed to the hosted oracle. This does not
authorize a capability or prove device integrity: the returned JSON
status is explicitly non-authoritative (`"authoritative": false`,
`"authorized": false`) until full receipt-chain verification is wired to
trusted issuer pins and challenge binding. Throws
`ChioMobileException.AttestationRejected` when either envelope fails to
parse or the evidence platform is neither `app_attest` nor
`play_integrity`.

## Records

### `VerifiedCapability`

```kotlin
data class VerifiedCapability(
    val id: String,
    val subjectHex: String,
    val issuerHex: String,
    val scopeJson: String,
    val issuedAt: ULong,
    val expiresAt: ULong,
    val evaluatedAt: ULong,
)
```

`scopeJson` is the canonical JSON encoding of `ChioScope`; decode it
with the app-side Chio SDK to inspect grants, constraints, etc.

### `PortablePassportMetadata`

```kotlin
data class PortablePassportMetadata(
    val subject: String,
    val issuerHex: String,
    val issuedAt: ULong,
    val expiresAt: ULong,
    val evaluatedAt: ULong,
    val payloadCanonicalHex: String,
)
```

`payloadCanonicalHex` is the lowercase-hex encoding of the authenticated
payload blob; decode with `payloadCanonicalHex.hexToByteArray()`.

## Errors

```kotlin
sealed class ChioMobileException(message: String) : kotlin.Exception(message) {
    class InvalidJson(message: String) : ChioMobileException(message)
    class InvalidHex(message: String) : ChioMobileException(message)
    class WeakEntropy(message: String) : ChioMobileException(message)
    class InvalidCapability(message: String) : ChioMobileException(message)
    class InvalidPassport(message: String) : ChioMobileException(message)
    class AttestationUnavailable(message: String) : ChioMobileException(message)
    class AttestationRejected(message: String) : ChioMobileException(message)
    class KernelKeyMismatch(message: String) : ChioMobileException(message)
    class SigningFailed(message: String) : ChioMobileException(message)
    class EvaluationDenied(message: String) : ChioMobileException(message)
    class Internal(message: String) : ChioMobileException(message)
}
```

Every variant carries a `message: String` describing the failure.
Use `exception.message` or a custom `Throwable.toString()` adapter
to surface it to the user. `WeakEntropy` is thrown by `signReceipt` and
`signReceiptRelayingTrustedBody` when the signing seed decodes to all
zero bytes. `AttestationUnavailable` and `EvaluationDenied` are part of
the error surface but are not thrown by any entry point in this crate
today: `evaluate()` encodes a deny verdict in-band in its JSON response
rather than throwing, and the attestation-evidence verifiers throw
`AttestationRejected` on failure.

## Minimal usage

```kotlin
import uniffi.chio_kernel_mobile.*

val requestJson = // ... built by your Chio SDK
val responseJson = evaluate(requestJson = requestJson)

// Parse responseJson (e.g. with kotlinx.serialization) to read
// verdict / reason.
```

## Offline sync

See `bindings/README.md` for the offline evaluate + signReceipt +
queue + sync pattern for offline mobile clients.
The FFI exposes primitives only; the queue, keystore, and sync layer
are owned by the app-side integration.
