# Chio Swift SDK

The Swift SDK packages `chio-kernel-mobile` for iOS as a private
Swift Package Manager distribution.

## TRAJECTORY-3.1 status (design-only)

M07 is reclassified as **design-only** under trajectory-3.1. The
`ChioKernel.xcframework` binary artifact is **not produced** in
trajectory-3 and is a **trajectory-4 deliverable** under the
`M07-followup` ticket pool (see
`.planning/trajectory-3/audits/M07-mobile-mvp.md` reclassification
note).

Concretely:

- `sdks/swift/Package.swift` no longer declares a `binaryTarget` for
  `ChioKernel`, because the xcframework does not exist on disk.
- `Frameworks/` retains its `.gitkeep` so the audit trail of the
  intended path is preserved; the directory is otherwise empty.
- The C-ABI mobile attestation entry points
  (`crates/chio-kernel-mobile/src/lib.rs`) currently return
  `AttestationUnavailable`; until trajectory-4 wires the Apple App
  Attest verifier, the Google Play Integrity verifier, and the shared
  receipt-chain validator, this package cannot evaluate against a
  real device.

## Build (deferred)

The build script `scripts/build-ios-framework.sh` is preserved for
trajectory-4 but is not part of an active CI lane in trajectory-3.

When trajectory-4 produces the artifact, the script will:

1. Build the Rust static libraries for iOS device and simulator
   targets.
2. Run `uniffi-bindgen generate --language swift`.
3. Create
   `target/release-qualification/mobile-kernel/ios/ChioKernel.xcframework`.

At that point the `binaryTarget` reference will be reintroduced into
`Package.swift`.

## Minimum Platform

The package pins iOS 15.0. App Attest is available on iOS 14+, but
the trajectory-3 support floor is iOS 15.0 so the patient-app demo
stays inside Apple's current supported deployment window.

## App Attest

`Sources/Chio/AppAttest.swift` wraps `DCAppAttestService` for key
generation, attestation, and assertion issuance. The server must
verify freshness and challenge binding through the Rust
`chio-custody-hw::attestation` verifier before minting a mobile
capability. **Real-device verification is deferred to trajectory-4.**
