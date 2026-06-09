# chio-kernel-mobile: operator bindings guide

This directory documents how to generate the Swift (iOS) and Kotlin
(Android) bindings for `chio-kernel-mobile` and link the static /
shared library into a mobile app. The crate itself ships pure Rust;
all language bindings are emitted at build time by the UniFFI
toolchain from `src/chio_kernel_mobile.udl`.

## Prerequisites

- Rust toolchain matching the workspace `rust-version` (1.93+).
- `uniffi-bindgen` binary. Not a default Cargo install because
  UniFFI publishes its binary under the namespaced crate
  `uniffi_bindgen`. On this repo install with:

  ```bash
  cargo install --git https://github.com/mozilla/uniffi-rs \
      --tag v0.28.3 --bin uniffi-bindgen uniffi_bindgen
  ```

  (Pinning to `v0.28.3` matches the `uniffi = "0.28"` dependency in
  `Cargo.toml`. If the workspace bumps the UniFFI version, bump the
  tag here in lockstep.)

  If your operator host has no Git access, build the binary from the
  workspace itself by adding a `[[bin]] name = "uniffi-bindgen"`
  target to `chio-kernel-mobile/Cargo.toml` (see
  `uniffi/docs/tutorial/foreign_language_bindings.md` upstream).

- iOS target: `rustup target add aarch64-apple-ios aarch64-apple-ios-sim
  x86_64-apple-ios`.
- Android target: `rustup target add aarch64-linux-android
  armv7-linux-androideabi i686-linux-android x86_64-linux-android`, plus
  the Android NDK (r25+) with a `cargo-ndk` wrapper or hand-rolled
  linker config pointing at the NDK-supplied clang.

## One-command verification

Run the repo-local verification suite from the workspace root:

```bash
./scripts/qualify-mobile-kernel.sh
```

It records four lane results under
`target/release-qualification/mobile-kernel/`:

- `host_ffi`: Rust-side JSON-in / JSON-out roundtrip tests
- `ios_device`: `aarch64-apple-ios` static library build
- `ios_sim`: `aarch64-apple-ios-sim` static library build when the target
  is installed
- `android_arm64`: `aarch64-linux-android` shared-library build when a
  real NDK toolchain is provisioned through `cargo-ndk`

Status values are explicit:

- `pass`: the lane ran on this host and succeeded
- `environment_dependent`: the host is missing the required SDK, target, or
  NDK tooling, so the script records that honestly instead of pretending the
  lane was qualified
- `fail`: the host had the required prerequisites and the lane still failed

The overall qualification gate fails unless at least one target-backed iOS or
Android lane runs and passes. The host FFI test is required coverage, but it
does not by itself qualify the mobile target surface.

## Seven-entry mobile surface

The UDL exports seven functions. The first four are the portable kernel
surface: `evaluate`, `sign_receipt`, `verify_capability`, and
`verify_passport`. The remaining three are mobile-attestation entries:

- `attest_app_attest(key_id, challenge_hex)`: produce an App Attest evidence
  envelope bound to a server challenge. Until the platform verifier
  lands, this validates inputs and returns
  `ChioMobileError.AttestationUnavailable`.
- `attest_play_integrity(nonce_hex)`: produce a Play Integrity evidence
  envelope bound to an issuer nonce. Until the platform verifier
  lands, this validates inputs and returns
  `ChioMobileError.AttestationUnavailable`.
- `verify_mobile_receipt(receipt_json, evidence_json)`: verify a mobile
  receipt against device-attestation evidence before it is handed to the
  hosted oracle. Until the receipt-chain verifier lands, this
  validates JSON inputs and returns `ChioMobileError.AttestationUnavailable`.

## Generating the Swift bindings

```bash
# 1. Build the static library for every iOS architecture you ship for.
CARGO_TARGET_DIR=target/mobile cargo build \
    --release --target aarch64-apple-ios -p chio-kernel-mobile
CARGO_TARGET_DIR=target/mobile cargo build \
    --release --target aarch64-apple-ios-sim -p chio-kernel-mobile
CARGO_TARGET_DIR=target/mobile cargo build \
    --release --target x86_64-apple-ios -p chio-kernel-mobile

# 2. Emit the Swift bindings.
mkdir -p out/swift
uniffi-bindgen generate \
    --language swift \
    --out-dir out/swift \
    crates/chio-kernel-mobile/src/chio_kernel_mobile.udl
```

`out/swift/chio_kernel_mobile.swift` is the module file to drop into
Xcode. `out/swift/chio_kernel_mobileFFI.h` is the matching C header;
package it together with a `.xcframework` that lipos the three
static libraries (`libchio_kernel_mobile.a`) from step 1.

### Linking in Xcode

1. Create an xcframework with `xcodebuild -create-xcframework`.
2. Add the framework to your app target's **Frameworks, Libraries,
   and Embedded Content** section.
3. Import the module in Swift: `import chio_kernel_mobile`.
4. Call the entry points directly -- `try evaluate(requestJson:)`,
   `try signReceipt(bodyJson:signingSeedHex:)`,
   `try verifyCapability(tokenJson:authorityPubHex:)`,
   `try verifyPassport(envelopeJson:issuerPubHex:nowSecs:)`. The mobile-attestation entries add
   `try attestAppAttest(keyId:challengeHex:)`,
   `try attestPlayIntegrity(nonceHex:)`, and
   `try verifyMobileReceipt(receiptJson:evidenceJson:)`.

## Generating the Kotlin bindings

```bash
# 1. Build the shared library for every Android ABI you ship for. Use
#    cargo-ndk (`cargo install cargo-ndk`) to hand the correct linker
#    to rustc automatically.
CARGO_TARGET_DIR=target/mobile cargo ndk \
    --target aarch64-linux-android --target armv7-linux-androideabi \
    --target x86_64-linux-android --target i686-linux-android \
    -o android/jniLibs build --release -p chio-kernel-mobile

# 2. Emit the Kotlin bindings.
mkdir -p out/kotlin
uniffi-bindgen generate \
    --language kotlin \
    --out-dir out/kotlin \
    crates/chio-kernel-mobile/src/chio_kernel_mobile.udl
```

`out/kotlin/uniffi/chio_kernel_mobile/chio_kernel_mobile.kt` is the
module file to drop into the `src/main/java` tree of your Android
Gradle module. `android/jniLibs/<abi>/libchio_kernel_mobile.so` goes
into `src/main/jniLibs/<abi>/` alongside the module's resources.

### Linking in Gradle

1. Add `net.java.dev.jna:jna:5.14.0@aar` to the module dependencies
   (UniFFI-generated Kotlin uses JNA to load the shared library).
2. Confirm the JNI libs are packaged under `src/main/jniLibs`.
3. Import the module in Kotlin: `import uniffi.chio_kernel_mobile.*`.
4. Call the entry points directly -- `evaluate(requestJson)`,
   `signReceipt(bodyJson, signingSeedHex)`,
   `verifyCapability(tokenJson, authorityPubHex)`,
   `verifyPassport(envelopeJson, issuerPubHex, nowSecs)`. The mobile-attestation entries add
   `attestAppAttest(keyId, challengeHex)`,
   `attestPlayIntegrity(nonceHex)`, and
   `verifyMobileReceipt(receiptJson, evidenceJson)`.

## Offline receipt sync pattern

The offline-first workflow caches a capability, evaluates tool calls
locally while disconnected, and syncs the resulting receipts to a
backend when connectivity returns. The FFI exposes the primitives for
all three halves:

1. **Cache** a capability token (JSON) to the device keystore
   (`KeychainService` on iOS, `EncryptedSharedPreferences` on Android).
2. **Gate** each tool call with `evaluate()` using the cached token
   and the device wall-clock (`MobileClock` is wired up automatically
   when `now_secs <= 0`).
3. **Sign** a receipt for each gated call with `signReceipt()` and
   append the returned JSON to a local queue (SQLite or the
   platform's durable key-value store).
4. **Sync** on reconnect: drain the queue and POST each receipt to
   the operator's `chio-siem` ingestion endpoint or Merkle-committed
   receipt log. The receipt's signature remains verifiable
   regardless of sync timing.

## Qualification artifacts

`./scripts/qualify-mobile-kernel.sh` emits:

- `target/release-qualification/mobile-kernel/report.md`
- `target/release-qualification/mobile-kernel/summary.json`
- one `*.log` file per lane

That output is the authoritative host-local record of which mobile lanes are
currently qualified versus environment-dependent. A run with only
environment-dependent target lanes is not release-qualified.

## UniFFI bindgen invocation verification

`uniffi-bindgen` is NOT installed on every operator host. To run the
verification step during local development:

```bash
# After cargo install uniffi-bindgen (see Prerequisites):
uniffi-bindgen generate --language swift --out-dir out \
    crates/chio-kernel-mobile/src/chio_kernel_mobile.udl
uniffi-bindgen generate --language kotlin --out-dir out \
    crates/chio-kernel-mobile/src/chio_kernel_mobile.udl
```

The Swift / Kotlin files listed in this directory
(`bindings/swift/ChioKernel.md` and `bindings/kotlin/ChioKernel.md`)
are hand-authored API references that mirror the UDL interface
verbatim. They are the single source of truth for the Swift /
Kotlin surface; the generated files should match them shape-for-shape.
