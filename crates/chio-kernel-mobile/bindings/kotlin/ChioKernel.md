# Kotlin API reference: `uniffi.chio_kernel_mobile`

This document mirrors the UDL interface in
`crates/chio-kernel-mobile/src/chio_kernel_mobile.udl` one-to-one. It
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
fun signReceipt(bodyJson: String, signingSeedHex: String): String
```

Signs an `ChioReceiptBody` JSON with the 32-byte Ed25519 seed
(lowercase hex, optional `0x` prefix). The body's `kernel_key` must
equal the public key derived from `signingSeedHex`; otherwise the
function throws `ChioMobileException.KernelKeyMismatch`. Returns the
signed `ChioReceipt` as JSON.

### `verifyCapability`

```kotlin
@Throws(ChioMobileException::class)
fun verifyCapability(tokenJson: String, authorityPubHex: String): VerifiedCapability
```

Verifies a capability token against a trusted authority public key.
Uses the device wall-clock for the time-bound check; use
`evaluate()` with `now_secs` populated if you need a pinned clock.

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

Produces the iOS-compatible App Attest evidence shape. The Kotlin surface
keeps the name for cross-platform parity; the function validates
`challengeHex` and returns `ChioMobileException.AttestationUnavailable`; the
platform verifier is not yet wired.

### `attestPlayIntegrity`

```kotlin
@Throws(ChioMobileException::class)
fun attestPlayIntegrity(nonceHex: String): String
```

Produces a Play Integrity evidence envelope bound to an issuer nonce. The
function validates `nonceHex` and returns
`ChioMobileException.AttestationUnavailable`; the platform verifier is not
yet wired.

### `verifyMobileReceipt`

```kotlin
@Throws(ChioMobileException::class)
fun verifyMobileReceipt(receiptJson: String, evidenceJson: String): String
```

Verifies a mobile receipt against App Attest or Play Integrity evidence before
forwarding it to the hosted oracle. The function validates both JSON envelopes
and returns `ChioMobileException.AttestationUnavailable`; the receipt-chain
verifier is not yet wired.

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
    class InvalidCapability(message: String) : ChioMobileException(message)
    class InvalidPassport(message: String) : ChioMobileException(message)
    class AttestationUnavailable(message: String) : ChioMobileException(message)
    class KernelKeyMismatch(message: String) : ChioMobileException(message)
    class SigningFailed(message: String) : ChioMobileException(message)
    class EvaluationDenied(message: String) : ChioMobileException(message)
    class Internal(message: String) : ChioMobileException(message)
}
```

Every variant carries a `message: String` describing the failure.
Use `exception.message` or a custom `Throwable.toString()` adapter
to surface it to the user.

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
