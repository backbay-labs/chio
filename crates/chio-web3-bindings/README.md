# chio-web3-bindings

`chio-web3-bindings` holds the Alloy bindings and packaged artifacts for Chio's
official web3 contract family. It is the Rust-side integration target for the
Solidity package under `contracts/` and exposes `alloy::sol!` bindings derived
from the compiled interface artifacts, bundled ABI JSON from the local contract
compiler, and bundled deployment and qualification artifacts for the local
devnet harness.

Use this crate to call the Chio web3 contracts from Rust. The contract artifact
type definitions live in `chio-web3`.
