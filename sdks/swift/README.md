# Chio Swift SDK

The Swift SDK packages `chio-kernel-mobile` for iOS as a private
Swift Package Manager distribution. The package has one source target
(`Chio`) and one binary target (`ChioKernel`) pointing at
`Frameworks/ChioKernel.xcframework`.

## Build

From the repository root:

```bash
bash scripts/build-ios-framework.sh
```

The script builds the Rust static libraries for iOS device and
simulator targets, runs `uniffi-bindgen generate --language swift`,
and creates `target/release-qualification/mobile-kernel/ios/ChioKernel.xcframework`.

## Minimum Platform

The package pins iOS 15.0. App Attest is available on iOS 14+, but
the trajectory-3 support floor is iOS 15.0 so the patient-app demo
stays inside Apple's current supported deployment window.

## App Attest

`Sources/Chio/AppAttest.swift` wraps `DCAppAttestService` for key
generation, attestation, and assertion issuance. The server must
verify freshness and challenge binding through the Rust
`chio-custody-hw::attestation` verifier before minting a mobile
capability.
