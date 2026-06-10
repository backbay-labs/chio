# chio-binding-helpers Architecture

## Owner

`chio-binding-helpers` owns the Rust facade for deterministic SDK invariant logic. It is a narrow support crate over `chio-core` and `chio-manifest`, used to keep Python, TypeScript, C++, Go, and future bindings aligned on byte-stable checks without duplicating the runtime kernel.

## Module Boundaries

- `canonical` owns raw JSON string parsing plus canonical JSON output.
- `hashing` owns byte and UTF-8 SHA-256 helper output.
- `signing` owns Ed25519 message and canonical JSON signing helpers.
- `capability` owns capability JSON parsing, canonical body output, time status, signature status, and delegation-chain status.
- `receipt` owns receipt JSON parsing, canonical body output, signature status, parameter hash status, content-addressed receipt ID status, semantic decision labels, and trusted-signer authorization status.
- `manifest` owns signed manifest JSON parsing, structural validation, embedded public-key checks, and signature checks.
- `error` owns the stable bindings-oriented error-code taxonomy.

## Design Constraints

- `verify_receipt_with_trusted_signers` takes `PublicKey` values for Rust callers; language bindings carry trusted kernel keys as hex strings, so the facade also exposes a hex-string helper.
- The vector generator and round-trip tests share one large integration test file that serves as the corpus oracle. Public helper changes add focused assertions around the helper boundary.
- `docs/reference/BINDINGS_API.md` is the contract consumers read. Update it when the facade grows.

## Security And API Constraints

- Receipt verification is not authoritative unless the signer is explicitly trusted.
- Invalid trusted-signer material must fail closed. Do not silently ignore malformed keys.
- Canonical JSON and receipt body bytes must remain stable.
- Existing public helpers must remain source-compatible.
- Do not add session, transport, auth discovery, task orchestration, or runtime-kernel behavior here.

## Affected Dependents

SDKs and FFI layers depend on the stable helper shape and vector corpus. The facade exposes a Rust helper that accepts trusted signer hex strings, matching the shape used by the Python and TypeScript SDK invariants.
