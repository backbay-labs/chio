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

## Pain Points

- The public Rust helper `verify_receipt_with_trusted_signers` takes `PublicKey` values, which is useful inside Rust but not enough for language bindings that naturally carry trusted kernel keys as hex strings.
- The vector generator and round-trip tests live in one large integration test file. That file is allowed to remain large because it is a corpus oracle, but public helper changes must add focused assertions around the helper boundary.
- `docs/reference/BINDINGS_API.md` is the contract consumers read. It must be updated when the facade grows.

## Security And API Constraints

- Receipt verification is not authoritative unless the signer is explicitly trusted.
- Invalid trusted-signer material must fail closed. Do not silently ignore malformed keys.
- Canonical JSON and receipt body bytes must remain stable.
- Existing public helpers must remain source-compatible.
- Do not add session, transport, auth discovery, task orchestration, or runtime-kernel behavior here.

## Affected Dependents

SDKs and FFI layers depend on the stable helper shape and vector corpus. This slice keeps the ABI surface unchanged and adds a Rust facade helper that accepts trusted signer hex strings, matching the shape already used by Python and TypeScript SDK invariants. FFI exposure can be added in a separate ABI slice if C/C++ callers need it.

## Planned Improvement

Add a binding-friendly trusted-signer receipt verification path that accepts JSON receipt input plus signer public-key hex strings. This closes the gap between the crate's bindings contract and its Rust-only `PublicKey` trusted-signer helper while preserving the existing API.
