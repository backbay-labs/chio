# chio-kernel-mobile Architecture

`chio-kernel-mobile` is the UniFFI-facing mobile adapter over
`chio-kernel-core`. It exposes synchronous JSON-in and JSON-out entry points for
iOS and Android while keeping verdict evaluation, capability verification,
receipt signing, passport verification, and attestation evidence checks inside
the portable Rust core.

## Boundaries

- `chio-kernel-core` owns capability verification, evaluation semantics,
  sibling-sum budget enforcement, receipt signing, and passport verification.
- `chio-core-types` owns capability, receipt, key, and canonical JSON shapes.
- `chio-custody-hw` owns App Attest, Play Integrity, and mobile receipt evidence
  verification.
- UniFFI scaffolding is generated from `src/chio_kernel_mobile.udl`; this crate
  owns the Rust functions and flat error enum projected to Swift and Kotlin.
- This crate owns JSON envelope parsing, mobile clock and RNG adapters,
  seed-decoding policy, mobile attestation challenge envelopes, and FFI error
  shaping.

## Trust Invariants

- FFI entry points never perform network or filesystem I/O.
- JSON parse failures stop at the FFI boundary with `InvalidJson`.
- Hex keys, seeds, challenges, and nonces are decoded before use and fail with
  `InvalidHex` on malformed input.
- Receipt signing refuses all-zero Ed25519 seeds with `WeakEntropy`.
- Capability verification and evaluation seed delegated-budget snapshots before
  invoking kernel-core sibling-sum checks.
- Mobile attestation challenge helpers bind platform evidence to caller-supplied
  challenge or nonce bytes before verification.

## Testing Focus

Rust-side FFI round-trip tests cover evaluation, signing, capability and
passport verification, attestation challenge envelopes, evidence rejection, and
mobile receipt shape checks. Cross-FFI parity tests compare the UniFFI-facing
mobile JSON output against the C ABI for shared verdict cases. Oracle tests
round-trip iOS and Android receipt fixtures through the hosted-oracle export
schema.
