# Chio Android Kernel Mobile

This module packages `chio-kernel-mobile` as an Android AAR. It is
distributed through GitHub Packages Maven by default.

## Platform

- `minSdk = 26`
- `targetSdk = 34`
- StrongBox is requested on API 28+ and falls back to TEE-backed
  Android Keystore with a degraded `software` trust marker.

## Build

From the repository root:

```bash
bash scripts/build-android-aar.sh
```

The script builds Rust shared libraries through `cargo ndk`, generates
Kotlin UniFFI bindings, and runs Gradle `assembleRelease`. The AAR
lands under `sdks/jvm/chio-kernel-mobile/build/outputs/aar/`.
