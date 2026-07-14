# chio-web3-bindings

Alloy bindings and packaged artifacts for the official Chio web3 contract
family: `ChioRootRegistry`, `ChioIdentityRegistry`, `ChioEscrow`,
`ChioBondVault`, and `ChioPriceResolver`. It is the Rust integration target
for the Solidity package in `contracts/`. `chio-web3` defines the settlement,
anchoring, and chain-configuration types for this contract family; this crate
supplies the generated Rust ABI bindings and the compiled JSON artifacts
themselves.

## Responsibilities

- Generate typed Rust bindings for the five contract interfaces via
  `alloy::sol!`, invoked once per interface inside a private per-contract
  module.
- Embed the compiled interface (ABI-only) and implementation (ABI + bytecode)
  JSON artifacts as `&str` constants.
- Embed a local-devnet deployment fixture and qualification report fixture
  for parser and integration tests.
- Adapt a shared `ChioMerkleProof` type into the `alloy::sol!`-generated
  Merkle-proof struct for the interfaces that reference one (root registry,
  escrow, bond vault).

## Public API

- `IChioRootRegistry`, `IChioIdentityRegistry`, `IChioEscrow`,
  `IChioBondVault`, `IChioPriceResolver` - `alloy::sol!`-generated modules;
  each exposes `<Name>Calls` and `<Name>Events` types with a `SIGNATURES`
  constant, checked against the bundled ABI in `tests/parity.rs`.
- `ChioMerkleProof { audit_path: Vec<B256>, leaf_index: U256, tree_size:
  U256 }` - converts (`From`, `From<&_>`) into the generated
  `ChioMerkle::Proof` type for the root registry, escrow, and bond vault
  interfaces.
- `CHIO_<NAME>_ARTIFACT` (one per contract above, e.g.
  `CHIO_ROOT_REGISTRY_ARTIFACT`) - implementation artifact JSON (ABI +
  bytecode + bytecode hashes).
- `CHIO_<NAME>_INTERFACE_ARTIFACT` (one per contract above, e.g.
  `CHIO_ROOT_REGISTRY_INTERFACE_ARTIFACT`) - interface artifact JSON (ABI
  only, no bytecode).
- `CHIO_LOCAL_DEVNET_DEPLOYMENT`, `CHIO_LOCAL_DEVNET_QUALIFICATION_REPORT` -
  local-devnet deployment and qualification report fixtures.

## Usage

```rust
use chio_web3_bindings::IChioRootRegistry;

// Generated ABI metadata, checked against the bundled artifact in tests/parity.rs.
let call_signatures = IChioRootRegistry::IChioRootRegistryCalls::SIGNATURES;
```

## Feature flags

| Flag | Effect |
|------|--------|
| `web3` (default) | Enables `dep:alloy` and `dep:serde_json`. The crate root is `#![cfg(feature = "web3")]`; with the feature off, the crate exposes no public items. |

## Testing

`cargo test -p chio-web3-bindings` runs the crate's own artifact-parsing
tests. `tests/parity.rs` additionally cross-checks generated ABI signatures,
interface-vs-implementation coverage, and the `docs/standards/CHIO_WEB3_*`
documents against the bundled artifacts.

## See also

- `chio-web3` - defines the settlement, anchoring, and chain-configuration
  types for this contract family; a dev-dependency here, reached in
  `tests/parity.rs` through `chio-core`'s `web3` re-export rather than a
  direct import.
- `chio-core` - re-exports `chio-web3` as `web3`.
- `chio-link` - supplies the CAIP-2 chain identifiers checked against the
  bundled chain configuration in `tests/parity.rs`.
