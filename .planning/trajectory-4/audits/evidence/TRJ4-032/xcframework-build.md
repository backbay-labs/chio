# TRJ4-032 Evidence - iOS xcframework build

## Artifact

- Path: `sdks/swift/Frameworks/ChioKernel.xcframework`
- Build command: `bash scripts/build-ios-framework.sh`
- Xcode: 26.4.1 (build 17E202)
- Rust targets present: `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`

## SHA-256

```text
b3b1a39453ea6478ca66da5898cbfa85f721d63320aed095dc41c6dc1c42e647  sdks/swift/Frameworks/ChioKernel.xcframework/Info.plist
0fcae321a5019cd895f5c9b24be9707504b2e4d999ce4e9327c55ff3ced225ee  sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64/libchio_kernel_mobile.a
4d41e7faf831ff19a6648f1b8eb772880d7d6d699dca71633bec1df9a87ba2ea  sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64_x86_64-simulator/libchio_kernel_mobile.a
c775c499058c175e9c97e7df020e45b1332f6c9413819fd1e0d2608614aeecf5  sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64/Headers/chio_kernel_mobileFFI.h
9e8d3227e387388130eb8b9bdab8818d711c1df380d26f0a7cbd848e011fae6c  sdks/swift/Frameworks/ChioKernel.xcframework/ios-arm64/Headers/chio_kernel_mobile.swift
```

## Notes

- `chio-kernel-mobile` now depends on `chio-custody-hw` with default features disabled, so the iOS build no longer pulls the OpenSSL-backed `webauthn-rs` passkey verifier graph.
- The build script combines simulator archives with `lipo` before calling `xcodebuild -create-xcframework`, avoiding duplicate equivalent simulator library definitions.
- Static archives are tracked through Git LFS.
- In-toto style provenance is recorded in `xcframework-build.intoto.jsonl`.
