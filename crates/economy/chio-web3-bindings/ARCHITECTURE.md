# chio-web3-bindings architecture

## Overview

`chio-web3-bindings` is the Rust ABI boundary for Chio's official web3
contract family. It holds no protocol logic of its own: it packages compiled
Solidity output (ABI JSON, implementation bytecode) and turns it into typed
Rust bindings via `alloy::sol!`. Trust and settlement semantics for the
contract family live in `chio-web3`; this crate only proves that the Rust
bindings and the packaged artifacts agree with each other and with the
compiled Solidity output.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root (`#![cfg(feature = "web3")]`). Declares `interfaces`, re-exports its public types, and embeds the interface, implementation, deployment, and qualification JSON as `&str` constants via `include_str!`. Its `#[cfg(test)]` module validates artifact shape. |
| `src/interfaces.rs` | Invokes `alloy::sol!` once per contract interface artifact, each inside its own private module (`root_registry_bindings`, `identity_registry_bindings`, `escrow_bindings`, `bond_vault_bindings`, `price_resolver_bindings`). Defines `ChioMerkleProof` and its conversions into the generated Merkle-proof struct. |

## Artifact packaging

1. The Solidity package in `contracts/` compiles to `contracts/artifacts/`,
   `contracts/deployments/`, and `contracts/reports/`.
2. Those directories are mirrored verbatim into this crate's `artifacts/`,
   `deployments/`, and `reports/`; `scripts/check-web3-contract-parity.sh`
   diffs them for drift as part of the workspace's web3 qualification path,
   outside `cargo test`.
3. `src/interfaces.rs` reads the five interface artifacts
   (`artifacts/interfaces/IChio*.json`) at compile time through `alloy::sol!`
   to generate typed bindings. `src/lib.rs` separately embeds those same five
   files, the five matching implementation artifacts (`artifacts/Chio*.json`),
   and the two fixtures under `deployments/` and `reports/` as raw JSON
   constants.
4. The mirrored directories also carry files this crate neither embeds nor
   generates bindings for: the `IAggregatorV3`, `IERC20`, and `IERC20Permit`
   interfaces, the `ChioMerkle` library artifact, and the Foundry mock
   contracts under `mocks/`.

## Invariants and failure modes

- Implementation artifacts must carry non-empty `bytecode` and
  `deployedBytecode` whose keccak256 hashes match `creationBytecodeHash` and
  `deployedRuntimeCodehash`; interface artifacts must carry empty
  `bytecode`/`deployedBytecode` and empty hash fields. Both are checked by
  `src/lib.rs`'s `#[cfg(test)]` module, not by a runtime or compile-time
  guarantee.
- `tests/parity.rs` fails closed on ABI drift: each interface's generated
  call signatures (and, where checked, event signatures) must equal the
  interface artifact's own signature set, and every interface function,
  event, and error signature must remain a subset of the matching
  implementation artifact's signatures.
- `tests/parity.rs` also checks the `docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json`,
  `CHIO_WEB3_CHAIN_CONFIGURATION.json`, and `CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json`
  documents against the bundled artifacts: contract bytecode hashes, the Rust
  binding's crate path and module name, and the Base-mainnet-primary /
  Arbitrum-One-secondary chain roles.
- `ChioMerkleProof` converts into the generated Merkle-proof type only for
  the interfaces whose ABI references one (root registry, escrow, bond
  vault); it has no conversion for the identity registry or price resolver
  interfaces.
- With the `web3` feature disabled, `src/lib.rs`'s
  `#![cfg(feature = "web3")]` compiles the crate to an empty public surface
  rather than failing the build.

## Dependencies

Runtime: `alloy` (`json`, `json-abi`, `sol-types`, `std` features only; no
`provider`, `contract`, `network`, or `rpc` features, so this crate has no
wiring for live RPC calls) generates and encodes the bindings; `serde_json`
backs the crate's own artifact-parsing tests. Dev-only: `chio-core` and
`chio-link` support `tests/parity.rs`. `chio-web3` is also a dev-dependency,
but `tests/parity.rs` reaches its types via `chio_core::web3` (`chio-core`
re-exports `chio-web3` as `web3`) rather than importing `chio-web3` directly.
