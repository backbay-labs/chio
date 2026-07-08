# chio-web3-bindings Architecture

## Boundary

`chio-web3-bindings` owns the Rust Alloy binding surface and packaged JSON artifacts for the official Chio web3 contract family.

## Internal Surfaces

The crate is intentionally narrow: `src/interfaces.rs` invokes `alloy::sol!` against compiled interface artifacts and defines the hand-written `ChioMerkleProof` adapter, while `src/lib.rs` re-exports generated contract modules and embeds the implementation, interface, deployment, and local qualification JSON artifacts.

## Trust Invariants

The trust boundary is package integrity. Callers depend on the included artifacts to match the Solidity package under `contracts/`, the standard web3 contract package, and the generated Alloy signatures. Current tests catch ABI signature drift, empty implementation bytecode, schema registry drift, artifact mirror drift, local deployment fixture drift, and qualification report drift.

## Artifact Validation

Implementation artifacts are validated separately from interface artifacts: packaged contracts must carry non-empty implementation and deployed runtime bytecode plus matching bytecode hashes, while interface artifacts must not carry implementation bytecode. This crate is a Rust compatibility boundary. Release decisions still require independent deployed-address and security review evidence.

## Verification Focus

Tests should validate artifact presence, ABI identity, bytecode expectations, deployment metadata, Merkle proof adapter serialization, and drift between Solidity artifacts and generated Rust bindings. Parity tests should compare generated Rust selectors with the packaged JSON artifacts so callers cannot accidentally use an interface-only artifact as a deployable implementation contract.
