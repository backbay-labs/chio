# M07 Audit: chio-kernel-mobile MVP + Device Attestation

**Trajectory:** trajectory-3
**Milestone:** M07
**Wave:** W2
**Status:** OPEN (P0 fill pending)
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M07 ships an iOS + Android kernel binding with hardware-attested keys
via Apple App Attest and Android Play Integrity (D11). Release-gate
anchor: PROTOCOL.

Concretely the milestone delivers:

- A Swift framework + SPM package at `sdks/swift/` consuming an
  XCFramework built from `crates/chio-kernel-mobile` plus an App
  Attest integration at `Sources/Chio/AppAttest.swift`.
- A Kotlin AAR at `sdks/jvm/chio-kernel-mobile/` plus a Play
  Integrity integration at `PlayIntegrity.kt` and a hardware-backed
  Keystore wrapper at `Keystore.kt`.
- A `crates/chio-custody-hw/src/attestation/` submodule (new) with
  App Attest + Play Integrity verifiers + pinned Apple / Google
  attestation roots + cross-platform receipt-chain validation.
- A thin React Native / Expo Module bridge at
  `sdks/typescript/packages/mobile/` for the Opus mobile patient-app
  demo.
- An extended `chio-kernel-mobile` C-ABI surface (4 -> 7 entries).

The trajectory-2 `chio-custody-hw` WebAuthn passkey path is
**preserved untouched**; mobile attestation is an additive parallel
authn surface, not a replacement.

## 2. Hard counts at P0

[Fill at M07.P0.T1 close.]

- Existing `crates/chio-kernel-mobile/src/` modules:
  - `lib.rs`: 416 LOC
  - `errors.rs`: 76 LOC
  - `clock.rs`: 53 LOC
  - `rng.rs`: 68 LOC
  - Total: ~1226 LOC including UDL + tests + build.rs (verify with
    `find crates/chio-kernel-mobile -name '*.rs' | xargs wc -l`).
- C-ABI surface entries pre-merge: 4 (`evaluate`, `sign_receipt`,
  `verify_capability`, `verify_passport`). Post-merge target: **7**
  (the existing four plus `attest_app_attest`,
  `attest_play_integrity`, `verify_mobile_receipt`).
- Minimum iOS API level pinned: **15.0**.
- Minimum Android API level pinned: **26 (Android 8.0)**, with
  hardware-backed StrongBox Keystore soft-required at API 28+
  (devices on API 26-27 fall back to TEE-backed Keystore with a
  `trust_level: software` capability marker).
- Apple Developer account: <record account id; managed by `@bb-connor`>.
- Google Play Console account: <record account id; managed by `@bb-connor`>.
- Existing `crates/chio-custody-hw/src/` files: 8
  (`capability.rs`, `error.rs`, `issuer.rs`, `lib.rs`, `mint.rs`,
  `nonce_store.rs`, `revocation.rs`, `verifier.rs`).
  `attestation/` directory does not yet exist; M07 P2.T4 / P3.T4
  create it.
- `qualify-mobile-kernel.sh` lanes (4): `host_ffi`, `ios_device`,
  `ios_sim`, `android_arm64`. Baseline status at P0.T2 close:
  <record per-lane outcome>.

## 3. Workspace pin baseline

[Fill at M07.P0.T1 close.]

- `uniffi = "0.28.3"` (held; no minor bumps in trajectory-3).
- `x509-parser = "0.16"` (new pin).
- `der = "0.7"` (new pin).
- `jsonwebtoken = "9"` (new pin).
- `coset = "0.3"` (reused from trajectory-2 M03).
- `base64ct = "1"` (reused from trajectory-2 M10).
- iOS deps: Swift 5.7+, Xcode 15+; Apple frameworks only
  (DeviceCheck, CryptoKit, Security). Zero third-party Swift deps.
- Android deps: Kotlin 1.9+, Gradle 8.4+, AGP 8.2+,
  `com.google.android.play:integrity:1.3.0+`, JNA 5.14.0.
- RN bridge deps: Expo Modules API, Expo SDK 50+. Pin in
  `sdks/typescript/packages/mobile/package.json`.

## 4. Threat-model row introductions

[Fill at M07.P0.T4 close.]

Three new threat IDs land in `spec/security/chio-threat-model.v1.json`
under M07:

- `mobile_attestation_replay` -- replayed App Attest assertion or
  Play Integrity token bypasses freshness check at the issuer.
  Coverage: P5.T4 verifies via fuzz fixture corpus under
  `crates/chio-custody-hw/tests/fixtures/`.
- `device_key_extraction` -- a compromised process on the mobile
  device extracts the kernel signing seed from outside the Secure
  Enclave / StrongBox. Coverage: P2.T3 + P3.T3 deliberately keep
  signing seeds inside hardware enclaves; receipts use ephemeral
  per-call signing assertions, never long-lived exportable keys.
- `play_integrity_token_replay` -- a stale Play Integrity token is
  presented at mint; the issuer's nonce store rejects.
  Coverage: P3.T4 verifier asserts nonce match against the issuer-
  generated value.

Per **D14**, M07 owns these rows; M05 consumes them as coverage-gate
inputs but does not author them.

## 5. C-ABI surface drift evidence

[Fill at M07.P1.T4 close.]

The cross-platform parity test
(`crates/chio-kernel-mobile/tests/cross_ffi_parity.rs`) drives the
same JSON fixture corpus through the mobile UniFFI surface AND
`chio-cpp-kernel-ffi`'s `chio_kernel_evaluate_json`. Asserts byte-
equal verdicts across the seven UDL functions.

Record at P1.T4 close:

- Fixture corpus size (count of canonical JSON inputs): <fill>.
- Parity test result: <green / drift detected with diff>.
- CI lane: <link to GitHub Actions run>.

## 6. App Attest attestation chain documentation

[Fill at M07.P2.T5 close.]

iOS App Attest issuance flow:

1. App calls
   `DCAppAttestService.shared.generateKey { keyId, error in }`.
   Apple's framework provisions an opaque key id; the private key
   lives in the Secure Enclave.
2. App calls `attestKey(keyId, clientDataHash:)` where
   `clientDataHash = SHA-256(server-issued challenge)`. Apple
   returns a CBOR-encoded attestation containing the device's
   anonymous identifier, the hardware-backed public key, and a
   chain of certificates rooted in Apple's App Attest root CA.
3. The Chio issuer (`crates/chio-custody-hw/src/attestation/
   app_attest.rs`) verifies the chain against the pinned Apple
   App Attest root in `apple_root.rs`, asserts the App ID matches
   the expected bundle, and binds the resulting public key to the
   user's tenant.
4. For each subsequent capability mint or sensitive call, the app
   calls `generateAssertion(keyId, clientDataHash:)` and forwards
   the assertion to the issuer; the issuer verifies the signature
   against the previously-attested key.

Apple App Attest root CA fingerprint pin: <record at P2.T4 close>.

Test attestation evidence:

- TestFlight binary build identifier: <fill>.
- CBOR attestation blob fixture path:
  `crates/chio-custody-hw/tests/fixtures/app_attest/<fixture>.cbor`.
- Verifier test result: <link to CI run>.

## 7. Play Integrity attestation chain documentation

[Fill at M07.P3.T5 close.]

Android Play Integrity + Keystore issuance flow:

1. App calls `IntegrityManager.requestIntegrityToken(
   IntegrityTokenRequest.builder().setNonce(serverNonce).build())`.
   Google returns a JWS-signed token containing `appIntegrity`,
   `deviceIntegrity`, and `accountDetails` claims.
2. The Chio issuer verifies the token signature, asserts
   `appIntegrity.appRecognitionVerdict == "PLAY_RECOGNIZED"`,
   `deviceIntegrity.deviceRecognitionVerdict` contains
   `"MEETS_DEVICE_INTEGRITY"`, and the nonce matches the issuer-
   stored value (replay protection via the `chio-custody-hw` nonce
   store).
3. Separately, the app generates a key in the Android Keystore via
   `KeyGenParameterSpec.Builder(...).setIsStrongBoxBacked(true)`
   (API 28+; falls back to TEE on API 26-27 with a degraded
   `trust_level: software` marker). The Keystore exposes a key
   attestation certificate chain rooted in Google's hardware
   attestation root.
4. The issuer's mint endpoint accepts both the Play Integrity
   token (authentication-of-app) AND the keystore attestation
   chain (authentication-of-key) in a single mint request. The
   issued capability is audience-pinned to the StrongBox key id.

Google attestation root fingerprint pin: <record at P3.T4 close>.

Test verdict evidence:

- Internal-track APK build identifier: <fill>.
- JWS payload fixture path:
  `crates/chio-custody-hw/tests/fixtures/play_integrity/<fixture>.jws`.
- Verifier test result: <link to CI run>.

## 8. Mobile receipt round-trip evidence

[Fill at M07.P4.T3 close.]

The mobile-side `sign_receipt()` produces a canonical-JSON receipt
matching the `spec/audit-log/export-schema.v1.json` schema. The
receipt is POSTed to the M01 hosted oracle either immediately or
flushed from the offline queue (iOS Keychain / Android
EncryptedSharedPreferences) on reconnect.

Record:

- M01 hosted-oracle endpoint URL: <fill once M01.P3 closes>.
- iOS-signed receipt round-trip: <green / failed; link to test run>.
- Android-signed receipt round-trip: <green / failed; link to
  test run>.
- Schema acceptance evidence: <link to test that asserts
  `export-schema.v1.json` validates the mobile receipt>.
- Offline-queue flush behavior: <link to test asserting receipts
  queue during airplane mode and flush on reconnect>.

## 9. Opus mobile patient-app demo evidence

[Fill at M07.P5.T4 close.]

Demo flow:

1. Patient opens the Opus mobile patient-app dev-client build (Expo
   SDK pinned per `sdks/typescript/packages/mobile/package.json`).
2. App requests an App Attest key (iOS) or Play Integrity verdict +
   StrongBox key (Android) and forwards the evidence to the Chio
   issuer.
3. Issuer mints a capability audience-pinned to the device-attested
   key.
4. Patient taps "fetch lab result"; the app calls the kernel
   `evaluate(request_json)` which gates the tool call.
5. Kernel returns a verdict; app calls `sign_receipt` and POSTs the
   receipt to the M01 hosted oracle.
6. Oracle records the receipt in the unified audit log.

Record:

- Demo recording (video + log bundle): <link / committed path>.
- Opus cluster repo PR (cross-repo reference): <fill>.
- Patient-app dev-client build identifier: <fill>.
- Round-trip latency envelope (mint -> evaluate -> receipt POST):
  <fill from instrumentation>.

## 10. Closure attestations

- iOS framework + Android AAR build clean (CI run):
  <fill at P5 close>.
- App Attest attestations issued against the iOS TestFlight binary:
  <fill>.
- Play Integrity verdicts issued against the Android internal-track
  APK: <fill>.
- Cross-platform parity test green: <link>.
- Mobile receipt round-trip green: <link>.
- Opus mobile patient-app demo green: <link / video>.
- Threat-model coverage flipped to `covered` for the three new
  IDs: <link to M05 P5.T1 coverage record>.

## 11. Open questions resolved at close

[Fill at P5 close. Reference the questions enumerated in
`.planning/trajectory-3/research/m07/RESEARCH.md` Open Questions
section.]

- Q1 (SPM publication channel): <resolution>.
- Q2 (Maven Central vs GitHub Packages): <resolution>.
- Q3 (trust-level degradation policy on non-StrongBox Android):
  <resolution>.
- Q4 (App Attest assertion replay window): <resolution>.
- Q5 (Play Integrity Standard vs Classic API): <resolution>.
- Q6 (RN module vs Expo module): <resolution>.
- Q7 (account onboarding sequencing): <resolution>.
- Q8 (UniFFI bindgen toolchain in CI): <resolution>.
- Q9 (cross-platform receipt fixture corpus location): <resolution>.
- Q10 (M01 oracle endpoint contract): <resolution>.
