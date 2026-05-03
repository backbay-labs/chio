# Milestone 07: chio-kernel-mobile MVP + Device Attestation

> **TRAJECTORY-3.1 reclassification:** M07 is reclassified as
> **design-only**. The three C-ABI mobile attestation entry points in
> `crates/chio-kernel-mobile/src/lib.rs` (`attest_app_attest` at L430,
> `attest_play_integrity` at L452, `verify_mobile_receipt` at L466) all
> currently return `ChioMobileError::AttestationUnavailable` with
> `pending M07.P2 / P3 / P4 platform wiring` messages (returns at L433,
> L439, L454, L479). Real-device attestation, Apple App Attest verifier
> wiring, Google Play Integrity verifier wiring, and shared
> receipt-chain validation are deferred to **trajectory-4** under the
> `M07-followup` ticket pool. The threat rows
> `mobile_attestation_replay`, `device_key_extraction`, and
> `play_integrity_token_replay` are flipped from `covered` back to
> `pending` with `deferred_to: trajectory-4.M07.real-attestation` in
> both `spec/security/coverage.yaml` and
> `spec/security/chio-threat-model.v1.json`. Any narrative below that
> claims `covered` coverage state, real-device attestation evidence, or
> a wired verifier reflects original trajectory-3 design intent and is
> superseded by this reclassification.

## Lens

Platform-expansion. M07 lifts the Chio kernel onto iOS and Android with
a hardware-attested credential model: Apple App Attest (iOS) plus
Android Play Integrity (D11) plus the device-resident hardware
keystore. The lens is single (mobile platform expansion) and the work
spans Rust kernel C-ABI, Swift framework, Kotlin AAR, the
`chio-custody-hw/src/attestation/` submodule, and a thin RN / Expo
bridge for the M01 design-partner mobile patient-app demo.

This is also the first milestone in the trajectory shaped like the
Chiodome thesis: credentials live in citizen hardware (Secure Enclave
on iOS, StrongBox or TEE on Android), attested by the platform
vendor, audience-pinned by the Chio issuer. The patient's device IS
the authentication factor. The server fleet validates the hardware
attestation but does not custody the key. Future Chiodome milestones
(cross-device sync, social recovery, multi-citizen quorum) build on
this foundation.

Trust-boundary: yes.

## Why this is on the trajectory

**Release-gate anchor:** PROTOCOL.

trajectory-2 closed with `crates/chio-kernel-browser/` (the WASM
browser kernel) plus `@chio-protocol/browser` (the JS receipt verifier
helper) and the `chio-custody-hw` WebAuthn passkey-capability surface,
but no mobile kernel binding. The verdict makes mobile load-bearing
for the M01 design partner: the design-partner mobile patient-app
extension is named explicitly as the M01 P5 hand-off consumer (D09).
Without M07 there is no path for that hand-off to land inside the
trajectory window.

The platform-vendor attestation services (Apple App Attest, Google
Play Integrity) issue the device-attestations directly. Their
issuance IS the third-party evidence per the verdict's per-milestone
external-evidence column, which means M07's external evidence is
procured by Apple and Google rather than by an independent reviewer.
This shapes the audit-doc closure attestations: the audit doc records
the App Attest / Play Integrity verdicts issued against the binaries
plus the kernel-side verifier output that consumes them.

trajectory-2 artifacts the milestone consumes read-only:

- `crates/chio-kernel-browser/` (M08 WASM kernel surface) -- mobile
  inherits the JSON-in / JSON-out kernel call shape; no edits.
- `crates/chio-custody-hw/` (M10 hardware-custody crate) -- M07
  extends the crate with a new `attestation/` submodule for App
  Attest + Play Integrity verification while preserving the
  WebAuthn passkey path. Not a fork; an additive submodule.
- `crates/chio-attest-verify/` (M09 + trajectory-2 M03) -- the
  cosign-bundle + PQ-hybrid signature verifier consumed by the
  mobile-receipt verification path.
- `crates/chio-revocation-oracle/` (trajectory-2 M04) -- mobile
  capabilities reference the device-attested key id; revoking the
  attested key pushes a revocation through the M04 oracle.
- `spec/audit-log/export-schema.v1.json` (M01 P3) -- mobile receipts
  flow into the same export schema so HITRUST i1 (M09) sees a
  unified audit log spanning web and mobile.

What trajectory-2 left exposed that M07 closes:

- No mobile binding at all. `crates/chio-kernel-mobile/` exists on
  `main` (1226 LOC across `lib.rs`, `errors.rs`, `clock.rs`,
  `rng.rs`, plus the UDL and bindings README seeded by trajectory-2
  Phase 14.3) but stops at the Rust-side kernel adapter; there is
  no `sdks/swift/`, no `sdks/jvm/chio-kernel-mobile/`, and no
  `crates/chio-custody-hw/src/attestation/` directory.
- The four existing UDL functions (`evaluate`, `sign_receipt`,
  `verify_capability`, `verify_passport`) cover offline gating but
  have no entry points for App Attest / Play Integrity issuance or
  for hosted-oracle receipt verification.
- `qualify-mobile-kernel.sh` exists but its four lanes
  (`host_ffi`, `ios_device`, `ios_sim`, `android_arm64`) are
  honestly gated on operator toolchains; CI does not yet provision
  them.

## Prior-art reckoning

trajectory-2 shipped, M07 preserves untouched:

- `crates/chio-kernel-browser/` (the M08 wasm-bindgen surface).
  Mobile and browser are sibling adapters around the same
  `chio-kernel-core`; M07 does not edit the browser kernel.
- `crates/chio-custody-hw/` WebAuthn passkey issuer surface
  (M10 P1-P3). M07 extends the crate with mobile attestation chain
  handling but the WebAuthn path stays untouched. Mobile attestation
  is **complementary** to PasskeyCapability, not a replacement: the
  mint pipeline grows two new accepted authn factors (App Attest +
  Play Integrity) alongside the existing WebAuthn factor.
- `@chio/passkey` TypeScript helper (`sdks/typescript/packages/
  passkey/`). The browser-side passkey flow is unrelated to mobile;
  M07 ships its own `sdks/typescript/packages/mobile/` package.
- `crates/chio-bindings-ffi/` and `crates/chio-cpp-kernel-ffi/`
  (the desktop / C++ FFI surfaces). M07 keeps the mobile UniFFI
  surface symmetric with the C++ FFI's JSON-in / JSON-out shape so
  a single behavioral test corpus exercises both. No edits to
  either.

trajectory-2 14.3 (the partial mobile kernel landing) shipped:

- `crates/chio-kernel-mobile/Cargo.toml` with
  `crate-type = ["staticlib", "cdylib", "rlib"]` and UniFFI 0.28.
- `src/lib.rs` (416 LOC) with four exported FFI functions:
  `evaluate(request_json) -> string`,
  `sign_receipt(body_json, signing_seed_hex) -> string`,
  `verify_capability(token_json, authority_pub_hex) -> VerifiedCapability`,
  `verify_passport(envelope_json, issuer_pub_hex, now_secs) -> PortablePassportMetadata`.
- `src/errors.rs` (76 LOC) with the `ChioMobileError` enum.
- `src/clock.rs` (53 LOC) and `src/rng.rs` (68 LOC) delegating to
  `SystemTime::now` and `getrandom` respectively.
- `src/chio_kernel_mobile.udl` (4 fns, 2 records, 1 error enum).
- `tests/ffi_roundtrip.rs` exercising JSON round-trip without a
  simulator.
- `bindings/README.md`, `bindings/swift/ChioKernel.md`,
  `bindings/kotlin/ChioKernel.md` -- hand-authored API references
  for operators wiring the bindings.
- `scripts/qualify-mobile-kernel.sh` recording four qualification
  lanes (host_ffi, ios_device, ios_sim, android_arm64) with honest
  environment-dependent gating.

What M07 changes (deliberately, with discipline):

- Adds three new UDL entries
  (`attest_app_attest`, `attest_play_integrity`,
  `verify_mobile_receipt`) for a total **C-ABI surface count of 7**.
  The four existing entries do not change.
- Creates `sdks/swift/` containing an SPM package with a binary
  XCFramework target plus `Sources/Chio/AppAttest.swift` wrapping
  `DCAppAttestService`.
- Creates `sdks/jvm/chio-kernel-mobile/` (under the existing JVM
  lane to share the trajectory-2 SDK layout) with an AAR module,
  `PlayIntegrity.kt` wrapping `IntegrityManager`, and `Keystore.kt`
  wrapping `AndroidKeystore` + StrongBox.
- Creates `crates/chio-custody-hw/src/attestation/` submodule with
  files `mod.rs`, `app_attest.rs`, `apple_root.rs`,
  `play_integrity.rs`, `google_root.rs`, `receipt_chain.rs`,
  `errors.rs`.
- Creates `sdks/typescript/packages/mobile/` as an Expo Module
  bridge for the design-partner patient-app demo.
- Adds `scripts/build-ios-framework.sh` and
  `scripts/build-android-aar.sh` plus their CI hookup.

Design-partner surface explicitly: the M01 design-partner mobile
patient-app extension (per D09). Trajectory-3 docs do not bind the
partner identity; the selected partner is recorded in the M01 audit
doc evidence log only.

What this milestone deliberately does NOT do:

- Does not replace the trajectory-2 `chio-custody-hw` WebAuthn
  passkey path. That surface stays load-bearing for browser flows;
  mobile attestation is the additive parallel surface.
- Does not ship a custom HSM-backed attestation lane. D11 names App
  Attest + Play Integrity as the only two mobile attestation
  surfaces in trajectory-3.
- Does not ship cross-platform UI. M07 is binding-and-attestation,
  not UX. The design-partner patient-app demo (M07.P5) is a thin
  integration, not a polished consumer product.
- Does not ship App Store / Play Store production listings. TestFlight
  / internal-track only.
- Does not edit `chio-kernel-browser/` or `chio-kernel-core/`.
- Does not extend `@chio/passkey`; the browser passkey package and
  the mobile attestation package have separate distribution
  channels.

## Hard counts (measured 2026-04-30)

Reproduce with the commands in parentheses. Update the date and
numbers if you re-run; do not silently let them drift.

- `crates/chio-kernel-mobile/src/`: **4 modules**
  (`lib.rs` 416 LOC, `errors.rs` 76 LOC, `clock.rs` 53 LOC,
  `rng.rs` 68 LOC); **~1226 LOC total** including UDL + tests +
  build.rs (`find crates/chio-kernel-mobile -name '*.rs' | xargs wc -l`).
- `crates/chio-custody-hw/src/`: **8 files**
  (`capability.rs`, `error.rs`, `issuer.rs`, `lib.rs`, `mint.rs`,
  `nonce_store.rs`, `revocation.rs`, `verifier.rs`).
  `attestation/` does not exist
  (`ls crates/chio-custody-hw/src/ | grep -c '^attestation$'`
  returns `0`). M07 creates the directory.
- `sdks/swift/`: does not exist (`ls sdks/ | grep -c '^swift$'`
  returns `0`). M07 creates it.
- `sdks/jvm/chio-kernel-mobile/`: does not exist
  (`ls sdks/jvm/ | grep -c '^chio-kernel-mobile$'` returns `0`).
  M07 creates it under the existing `sdks/jvm/` lane.
- `sdks/typescript/packages/mobile/`: does not exist
  (`ls sdks/typescript/packages/ | grep -c '^mobile$'` returns `0`).
  M07 creates it.
- C-ABI surface count today: **4** (the four UDL entries listed in
  prior-art reckoning). After M07 P1 closes:
  **7** (the existing four plus `attest_app_attest`,
  `attest_play_integrity`, `verify_mobile_receipt`).
- Minimum iOS API level pinned at P0: **iOS 15.0**. Rationale: App
  Attest requires iOS 14.0+; SPM binary target requires Swift 5.3+;
  iOS 15.0 sits inside Apple's typical 3-version support window
  as of Xcode 15+.
- Minimum Android API level pinned at P0: **API 26 (Android 8.0)**
  for the SDK floor; **API 28 (Pie)** soft-required for
  hardware-backed StrongBox attestation. Devices on API 26-27 fall
  back to TEE-backed Keystore with a `trust_level: software` marker
  on the issued capability.
- Apple Developer + Google Play Console accounts: managed by
  `@bb-connor`. Account IDs to be recorded in the audit doc at
  P0.T1 close.
- `qualify-mobile-kernel.sh` lanes: **4** (`host_ffi`, `ios_device`,
  `ios_sim`, `android_arm64`). At P0 baseline only `host_ffi` runs
  on the trajectory-3 CI host without further provisioning; P2 / P3
  add `ios_sim` and `android_arm64` once toolchains land.

## Workspace dependency state

Reused from trajectory-1 / trajectory-2:

- `chio-kernel-core`, `chio-core-types`, `chio-attest-verify`,
  `chio-custody-hw`, `chio-revocation-oracle` (workspace pins).
- `serde`, `serde_json`, `thiserror`, `chrono`, `getrandom`
  (already pinned workspace level).
- `coset = "0.3"` from trajectory-2 M03 -- used to parse the
  Apple App Attest CBOR attestation blob.
- `base64ct = "1"` from trajectory-2 M10 -- used for the Play
  Integrity nonce / clientDataHash encoding.

Pinned by M07 P0 wave-opener (re-check crates.io for current latest
patch versions before pasting):

- `uniffi = "0.28.3"` (existing pin; M07 holds the line and defers
  any 0.29+ upgrade to a dedicated trajectory-4 ticket because UniFFI
  wire encoding has historically broken across minor bumps).
- `x509-parser = "0.16"` -- pure-Rust X.509 parser used by the
  Apple App Attest root CA verification path and by the Google
  hardware attestation root chain. Pin rationale: `webpki` does not
  expose the App-Attest-specific extension fields we need to verify.
- `der = "0.7"` -- ASN.1 DER decoder shared by both root CA paths.
- `jsonwebtoken = "9"` -- Play Integrity returns a JWS-signed token;
  the kernel-side verifier consumes it via this crate.

Mobile-side platform deps (not in `Cargo.toml`, recorded here for
the audit doc):

- iOS: Swift 5.7+, Xcode 15+, App Attest available iOS 14.0+,
  XCFramework consumed via SPM. Zero third-party Swift deps; only
  Apple frameworks (`DeviceCheck`, `CryptoKit`, `Security`).
- Android: Kotlin 1.9+, Gradle 8.4+, Android Gradle Plugin 8.2+,
  Play Integrity client `com.google.android.play:integrity:1.3.0+`,
  JNA `net.java.dev.jna:jna:5.14.0@aar` (UniFFI Kotlin runtime
  dependency).
- RN bridge: Expo Modules API, Expo SDK 50+. Expo Go is NOT
  supported (custom native code requires a dev-client build).

`Cargo.lock` changes are confined to the P0 wave-opener and the P1
ticket adding the three new UDL entries. Subsequent tickets add no
new direct Rust dependencies; they consume what P0 + P1 pin.

## Scope

### In

- Inventory + audit-doc fill at P0 (NOT a from-zero scaffold;
  `crates/chio-kernel-mobile/` already exists at 1226 LOC).
- C-ABI surface extension: three new UniFFI entries
  (`attest_app_attest`, `attest_play_integrity`,
  `verify_mobile_receipt`); 7 entries total post-merge.
- Cross-platform parity test running the same JSON corpus through
  the mobile UniFFI surface AND `chio-cpp-kernel-ffi`'s C ABI;
  asserts byte-equal verdicts.
- iOS Swift framework binding (XCFramework) + Swift Package
  manifest at `sdks/swift/Package.swift`.
- `Sources/Chio/AppAttest.swift` wrapping `DCAppAttestService`
  generate-key / attest-key / generate-assertion flow plus a
  `Keystore.swift` Keychain + Secure Enclave helper.
- `scripts/build-ios-framework.sh` produces the XCFramework via
  `cargo build --target aarch64-apple-ios* + uniffi-bindgen
  generate --language swift + xcodebuild -create-xcframework`.
- Android Kotlin AAR binding plus Gradle module at
  `sdks/jvm/chio-kernel-mobile/`.
- `PlayIntegrity.kt` wrapping `IntegrityManager` (Standard API,
  per-call verdicts) plus `Keystore.kt` wrapping `AndroidKeystore`
  with `setIsStrongBoxBacked(true)` and TEE fallback.
- `scripts/build-android-aar.sh` produces the AAR via `cargo ndk +
  uniffi-bindgen generate --language kotlin + ./gradlew
  :chio-kernel-mobile:assembleRelease`.
- `crates/chio-custody-hw/src/attestation/` submodule with App
  Attest verifier (`app_attest.rs`) + pinned Apple root CA
  (`apple_root.rs`) + Play Integrity verifier (`play_integrity.rs`)
  + pinned Google attestation root (`google_root.rs`) + cross-
  platform receipt-chain validator (`receipt_chain.rs`) + errors.
- Mobile receipt verification against the M01 hosted-oracle endpoint
  (P4) including offline-queue path: receipts queue locally during
  airplane mode and flush on reconnect.
- RN bridge stub at `sdks/typescript/packages/mobile/` shipped as an
  Expo Module (config plugin `withChio.ts`) consumed by the
  design-partner patient-app demo.
- Design-partner mobile patient-app demo (P5): mints a capability
  via App Attest (iOS) or Play Integrity (Android), gates a sample
  tool call through `evaluate()`, signs a receipt, POSTs to the
  hosted oracle. Demo recording lives outside the Chio repo (in the
  design-partner deployment repo); M07 ships the SDK consumption
  surface.

### Out (and why)

- Custom HSM-backed attestation lane. **D11** defers; App Attest +
  Play Integrity are the only two mobile attestation surfaces in
  trajectory-3.
- Cross-platform UI / production-quality patient-app. M07 is
  binding-and-attestation, not UX. Polished consumer product is
  the design-partner deployment's scope.
- App Store / Play Store production listings. TestFlight + internal-
  track only; production-store listing is out of scope.
- iOS-only or Android-only ship. **D11** binds both.
- Replaceable attestation backends. **D11** locks the surface to
  App Attest + Play Integrity for trajectory-3.
- Public Swift Package Index publication. Default for M07 is private
  GitHub-hosted SPM (Open Question Q1). Same for Maven Central; M07
  publishes to GitHub Packages Maven (private) for the M01
  design-partner consumer.
- React Native versions of the App Attest / Play Integrity flows.
  The patient-app demo calls the native flows directly through the
  Expo bridge; the bridge passes through native attestation results
  without interpretation.
- UniFFI 0.29+ upgrade. Pinned at 0.28.3 for trajectory-3; upgrade
  is a dedicated trajectory-4 ticket.
- Crate consolidation of `chio-bindings-ffi` + `chio-cpp-kernel-ffi`
  + `chio-kernel-mobile`. The three FFI surfaces stay distinct;
  trajectory-4 may revisit consolidation under D05's framing.

## Phases

### P0: Audit doc + chio-kernel-mobile inventory

P0 is **inventory + audit-doc fill**, not a from-zero scaffold. The
crate already exists; P0 records the existing surface and pins the
hard counts.

- M07.P0.T1 -- Fill the audit doc hard counts (C-ABI: 7 post-merge,
  iOS 15.0, Android API 26 with API 28 soft-required, Apple
  Developer / Google Play Console account IDs).
- M07.P0.T2 -- Baseline `qualify-mobile-kernel.sh` run; record
  current lane statuses under
  `target/release-qualification/mobile-kernel/`.
- M07.P0.T3 -- Crate inventory PR (no behaviour change; documentation
  refresh mapping the existing 416-LOC Rust surface to the M07
  contract; updates `bindings/README.md` to anticipate the three
  new UDL entries that P1 lands).
- M07.P0.T4 -- Threat-model rows added to
  `spec/security/chio-threat-model.v1.json`:
  `mobile_attestation_replay`, `device_key_extraction`,
  `play_integrity_token_replay`. Coverage flips to `covered` at
  P5 close per the M05 P5.T1 contract.

### P1: Kernel C-ABI surface (App Attest + Play Integrity + mobile receipt verify)

- M07.P1.T1 -- Add `attest_app_attest(key_id, challenge_hex) ->
  AppAttestEvidence` to `src/chio_kernel_mobile.udl` plus Rust impl
  shell that delegates to the new `chio-custody-hw::attestation`
  surface.
- M07.P1.T2 -- Add `attest_play_integrity(nonce_hex) ->
  PlayIntegrityEvidence` UDL entry plus Rust impl shell.
- M07.P1.T3 -- Add `verify_mobile_receipt(receipt_json,
  evidence_json) -> VerifiedMobileReceipt` UDL entry that delegates
  to `crates/chio-custody-hw/src/attestation/receipt_chain.rs`.
- M07.P1.T4 -- Cross-platform parity test
  (`crates/chio-kernel-mobile/tests/cross_ffi_parity.rs`): drives
  the same JSON fixture corpus through the mobile UniFFI surface
  AND `chio-cpp-kernel-ffi`'s `chio_kernel_evaluate_json`; asserts
  byte-equal verdicts.
- M07.P1.T5 -- Bindings README + Swift / Kotlin reference doc
  refresh under `crates/chio-kernel-mobile/bindings/`.

### P2: iOS Swift framework + App Attest integration

- M07.P2.T1 -- `sdks/swift/` SPM scaffold with binary target
  pointing at `Frameworks/ChioKernel.xcframework` plus
  `Sources/ChioFFI/` UniFFI-generated module map.
- M07.P2.T2 -- `scripts/build-ios-framework.sh` produces the
  XCFramework via `cargo build --target aarch64-apple-ios + cargo
  build --target aarch64-apple-ios-sim + cargo build --target
  x86_64-apple-ios + uniffi-bindgen generate --language swift +
  xcodebuild -create-xcframework`. Output under
  `target/release-qualification/mobile-kernel/ios/`.
- M07.P2.T3 -- `Sources/Chio/AppAttest.swift` wrapping
  `DCAppAttestService.shared` generate-key / attest-key /
  generate-assertion flow. `Sources/Chio/Keystore.swift` Keychain
  + Secure Enclave helper.
- M07.P2.T4 -- `crates/chio-custody-hw/src/attestation/app_attest.rs`
  verifier consuming the App Attest CBOR attestation blob via
  `coset` and `x509-parser`; verifies the chain against the pinned
  Apple App Attest root CA in `apple_root.rs`. Asserts the App ID
  matches the expected bundle.
- M07.P2.T5 -- XCTest harness at `sdks/swift/Tests/ChioTests/` plus
  simulator integration test for the generate-assertion +
  forward-to-kernel round trip. App Attest is sim-supported in
  iOS 17+; older simulator support mocks the service.

### P3: Android Kotlin AAR + Play Integrity integration

- M07.P3.T1 -- `sdks/jvm/chio-kernel-mobile/` Gradle scaffold:
  `build.gradle.kts` for the AAR module, `settings.gradle.kts`,
  `src/main/kotlin/dev/chio/kernel/` package layout.
- M07.P3.T2 -- `scripts/build-android-aar.sh` produces the AAR via
  `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 + uniffi-
  bindgen generate --language kotlin + ./gradlew :chio-kernel-mobile:
  assembleRelease`. Output AAR lands at
  `sdks/jvm/chio-kernel-mobile/build/outputs/aar/`.
- M07.P3.T3 -- `PlayIntegrity.kt` wrapping `IntegrityManager`
  Standard API (per-call verdict; Classic deferred). `Keystore.kt`
  wrapping `AndroidKeystore` + `KeyGenParameterSpec.Builder.
  setIsStrongBoxBacked(true)` with TEE fallback for API 26-27.
- M07.P3.T4 -- `crates/chio-custody-hw/src/attestation/
  play_integrity.rs` verifier consuming the Play Integrity JWS
  token via `jsonwebtoken`; verifies the keystore attestation chain
  via `x509-parser` against the pinned Google attestation root in
  `google_root.rs`. Asserts `appIntegrity.appRecognitionVerdict ==
  "PLAY_RECOGNIZED"` and the nonce matches.
- M07.P3.T5 -- `androidTest/` instrumentation harness exercising the
  full Play Integrity request + keystore-key generate + forward-
  to-kernel round trip on a connected device or emulator.

### P4: Mobile receipt verification against hosted oracle

- M07.P4.T1 -- Mobile-side offline-queue impl. iOS uses Keychain;
  Android uses EncryptedSharedPreferences. Receipts queue locally
  during airplane mode keyed by `(tenant_id, receipt_hash)`.
- M07.P4.T2 -- POST-on-reconnect path with retry policy
  (exponential backoff, max-retry budget per receipt; permanent
  failure surfaces a typed error code matching the
  `urn:chio:error:mobile:*` registry).
- M07.P4.T3 -- Hosted-oracle round-trip test against the M01 fixture
  endpoint (`spec/audit-log/export-schema.v1.json` consumer).
  Asserts schema acceptance for both iOS-signed and Android-signed
  receipts. Soft-blocked on M01.P3 close (the export schema must
  land first).
- M07.P4.T4 -- Audit-doc attestation chain documentation update:
  records the iOS App Attest issuance flow, the Android Play
  Integrity issuance flow, and the hosted-oracle verification path
  with concrete fixture references.

### P5: Design-partner mobile patient-app extension demo

- M07.P5.T1 -- RN bridge stub at `sdks/typescript/packages/mobile/`
  shipped as an Expo Module: `package.json`, `expo-module.config.json`,
  `src/index.ts` exposing the seven-method TurboModule signature
  (`evaluate`, `signReceipt`, `verifyCapability`, `verifyPassport`,
  `attestAppAttest`, `attestPlayIntegrity`).
- M07.P5.T2 -- Expo config plugin (`expo-plugin/withChio.ts`) that
  adds the iOS XCFramework and Android AAR to the Expo prebuild
  output.
- M07.P5.T3 -- Patient-app demo integration in the design-partner
  deployment repo (cross-repo PR; reference only). The demo mints a capability
  via App Attest (iOS) or Play Integrity (Android), gates a sample
  "fetch lab result" tool call through `evaluate()`, signs a
  receipt, POSTs to the M01 hosted oracle, and asserts a green
  round-trip.
- M07.P5.T4 -- Demo recording (video / log bundle) committed under
  `.planning/trajectory-3/audits/M07-mobile-mvp.md` as the closure
  attestation. Threat-model coverage flips to `covered` for the
  three M07 threat IDs.

## Cross-milestone interactions

- **M01 P3 (audit-log export schema v1).** The mobile receipt POST
  endpoint shape consumes `spec/audit-log/export-schema.v1.json`.
  M07.P4.T3 is **soft-blocked** on M01.P3.T1 close; the freeze
  `m01-m09-audit-handoff` (P3-P5) keeps the schema stable while
  M07 P4 builds against it.
- **M01 P5 (design-partner operator runbook).** The freeze
  `m01-m07-audit-handoff` (P5) keeps the M01 audit doc stable while
  M07 P5 builds the patient-app demo. M07.P5 starts only after
  M01.P5.T5 merges.
- **trajectory-2 M10 (chio-custody-hw).** M07 extends
  `crates/chio-custody-hw/src/attestation/` (a new submodule); the
  trajectory-2 m10-custody-issuer-pivot freeze is closed on `main`,
  so M07 is the active owner of the attestation subdirectory under
  the m07-kernel-mobile-pivot freeze.
- **trajectory-2 M03 (HybridBackend).** Mobile-issued capabilities
  sign via the same M03 hybrid-PQ surface as web passkey
  capabilities; mobile receipts are PQ-ready as soon as
  `crypto_floor=allow_hybrid` lands.
- **trajectory-2 M04 (chio-revocation-oracle).** Revoking a mobile
  attested key pushes a revocation through the M04 oracle keyed by
  `(issuer_id, key_id)`; the kernel rejects mobile capabilities
  whose attested key is revoked at the next M04 epoch.
- **M05 (threat-coverage closure).** M07 introduces three new threat
  IDs (`mobile_attestation_replay`, `device_key_extraction`,
  `play_integrity_token_replay`); per **D14** new IDs land under
  the introducing milestone with their own coverage rows. M05
  consumes the rows but does not own them.
- **M09 (HITRUST i1 assessment).** M07 mobile receipts flow into
  the same M01-shaped audit-log export pipeline so HITRUST i1 sees
  a unified audit log spanning web and mobile. The audit doc names
  the mobile-receipt path explicitly.
- **trajectory-2 M08 (WASM browser kernel).** M07 keeps the mobile
  UniFFI surface symmetric with the WASM and C++ surfaces around
  `chio-kernel-core`; cross-platform parity test (P1.T4) asserts
  byte-equal verdicts.

## Risks and mitigations

1. **App Attest / Play Integrity API changes mid-cycle.** Apple and
   Google ship API churn on quarterly cadences. Mitigation: pin SDK
   versions (`com.google.android.play:integrity:1.3.0+`); nightly
   canary against the published API docs; CI fails on signature
   drift. The audit doc records the exact SDK version exercised.
2. **C-ABI surface drift across platforms.** UniFFI Swift and
   Kotlin bindings could diverge from the underlying Rust surface
   under churn. Mitigation: P1.T4 cross-platform parity test runs
   the same JSON corpus through Swift and Kotlin bindings AND the
   C++ FFI; asserts byte-equal verdicts. Lands as a CI gate.
3. **App Store / Play Store review delays the mobile demo.**
   TestFlight / internal-track first; production-store listing is
   out of scope. Mitigation also: M07.P5 demo is recorded against
   the TestFlight build, not a production listing; production-
   store listing slips to a trajectory-4 follow-up without
   affecting M07 closure.
4. **Hardware-attestation availability on older devices.** StrongBox
   requires API 28 + device hardware support; iPhone 8 (iOS 14
   cutoff) is the floor for App Attest. Mitigation: the issuer
   accepts software-attested capabilities with a degraded
   `trust_level: software` marker on the capability; the patient-
   app gates sensitive flows on `trust_level == hardware`. P0
   audit doc records the degradation policy.
5. **Cross-platform receipt format drift.** Mobile receipts must be
   wire-compatible with the M01 hosted-oracle schema. Mitigation:
   the Rust-side `sign_receipt()` already uses
   `chio-kernel-core`'s canonical-JSON pipeline shared with the
   desktop and browser kernels; P4.T3 adds an end-to-end test that
   posts a mobile receipt to a fixture oracle and asserts schema
   acceptance.
6. **UniFFI version churn.** UniFFI 0.28 -> 0.29+ has historically
   changed wire encoding; bumping breaks every consumer.
   Mitigation: pin to `uniffi = "0.28.3"` in the workspace
   `Cargo.toml`; document the upgrade path in
   `bindings/README.md`; defer upgrades to a dedicated trajectory-4
   ticket.
7. **Apple Developer / Google Play Console account onboarding.**
   The bindings require platform-vendor accounts under
   `@bb-connor`'s ownership. Mitigation: P0.T1 captures the
   account IDs; if accounts are not provisioned by week 2 of W2,
   escalate to halt trigger 11 (vendor-blocking).
8. **NDK toolchain on CI.** `cargo ndk` requires Android NDK r25+.
   Mitigation: `qualify-mobile-kernel.sh` records lanes honestly
   (`environment_dependent`); CI runs on a host with the toolchain
   pre-provisioned by P3 close.
9. **Expo dev-client compatibility.** Expo SDK 50 / 51 transitions
   can break native modules. Mitigation: the RN bridge is a stub,
   not a polished package; pin Expo SDK in
   `sdks/typescript/packages/mobile/package.json` and document the
   matrix in the M07 audit doc.

## Success criteria

- iOS framework + Android AAR build clean: `bash
  scripts/build-ios-framework.sh` and `bash
  scripts/build-android-aar.sh` produce signed artifacts under
  `target/release-qualification/mobile-kernel/`.
- C-ABI surface count post-merge equals 7
  (`grep -c '^namespace\|^[[:space:]]*[a-z_]*([^)]*)' crates/chio-
  kernel-mobile/src/chio_kernel_mobile.udl` returns 7 fn entries).
- App Attest attestations issued against a real iOS binary in
  TestFlight; CBOR attestation blob committed under
  `crates/chio-custody-hw/tests/fixtures/app_attest/`.
- Play Integrity verdicts issued against an internal-track APK; JWS
  payload committed under
  `crates/chio-custody-hw/tests/fixtures/play_integrity/`.
- Cross-platform parity test green: `cargo test -p
  chio-kernel-mobile --test cross_ffi_parity` passes; verdicts are
  byte-equal across mobile UniFFI and `chio-cpp-kernel-ffi`.
- Mobile receipt round-trip green against the M01 fixture endpoint;
  the hosted oracle schema-validates the receipt and records it in
  the audit-log export.
- Design-partner mobile patient-app demo green: recorded video / log bundle
  under `.planning/trajectory-3/audits/M07-mobile-mvp.md` shows the
  full flow (App Attest mint -> kernel `evaluate` -> signed receipt
  -> oracle POST) with a green outcome.
- Three new threat-model rows
  (`mobile_attestation_replay`, `device_key_extraction`,
  `play_integrity_token_replay`) carry `coverage_state: covered`
  per M05 P5.T1 contract.
- Audit doc at
  `.planning/trajectory-3/audits/M07-mobile-mvp.md` closes with the
  measured before / after counts plus the App Attest / Play
  Integrity attestation chain documentation.
