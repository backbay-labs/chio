# chio-web3-bindings Architecture

## Boundary

`chio-web3-bindings` owns the Rust Alloy binding surface and packaged JSON artifacts for the official Chio web3 contract family.

## Internal Surfaces

The crate is intentionally narrow: `src/interfaces.rs` invokes `alloy::sol!` against compiled interface artifacts and defines the hand-written `ChioMerkleProof` adapter, while `src/lib.rs` re-exports generated contract modules and embeds the implementation, interface, deployment, and local qualification JSON artifacts.

## Trust Invariants

The trust boundary is package integrity. Callers depend on the included artifacts to match the Solidity package under `contracts/`, the standard web3 contract package, and the generated Alloy signatures. Drift must be caught at build or test time before settlement code can prepare calls against stale ABIs or empty implementation bytecode.

## Current Hardening

Current hardening: implementation artifacts are validated separately from interface artifacts, so packaged contracts must carry non-empty implementation bytecode while interface artifacts must not carry implementation bytecode. This crate should remain the first Rust boundary that detects artifact drift, before settlement, anchoring, or CLI tooling builds calls from stale package data.

## Verification Focus

Tests should validate artifact presence, ABI identity, bytecode expectations, deployment metadata, Merkle proof adapter serialization, and drift between Solidity artifacts and generated Rust bindings. Parity tests should compare generated Rust selectors with the packaged JSON artifacts so callers cannot accidentally use an interface-only artifact as a deployable implementation contract.
