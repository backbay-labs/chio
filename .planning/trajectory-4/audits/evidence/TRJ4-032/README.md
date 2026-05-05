# TRJ4-032 Evidence - ChioKernel.xcframework

## PR2 status

Completed for the local trajectory-4 framework artifact.

## Validation attempted

- `bash scripts/build-ios-framework.sh --test-only` passed in PR1.
- `bash scripts/build-ios-framework.sh` passed in PR2.
- `sdks/swift/Frameworks/ChioKernel.xcframework` is present in the tree.
- Static archives are tracked through Git LFS.

## Prior blocker closed

PR1 failed during the aarch64 iOS target build in `openssl-sys`:

```text
Could not find directory of OpenSSL installation
AARCH64_APPLE_IOS_OPENSSL_DIR unset
OPENSSL_DIR unset
pkg-config has not been configured to support cross-compilation
```

PR2 closes this by compiling `chio-kernel-mobile` against `chio-custody-hw` with default features disabled. The mobile target does not need the OpenSSL-backed `webauthn-rs` passkey verifier path.

See `xcframework-build.md` for hashes and build metadata.
