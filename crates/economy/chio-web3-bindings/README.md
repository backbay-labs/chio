# chio-web3-bindings

`chio-web3-bindings` holds the Alloy bindings and packaged artifacts for Chio's
official web3 contract family. It is the Rust-side integration target for the
Solidity package under `contracts/` and exposes `alloy::sol!` bindings derived
from the compiled interface artifacts, bundled ABI JSON from the local contract
compiler, and bundled deployment and qualification artifacts for the local
devnet harness.

The embedded local-devnet qualification JSON is a historical devnet fixture.
It is marked `SUPERSEDED` and is not release approval, mainnet readiness
evidence, or a promotion gate. Artifact parsing and ABI parity tests are narrow
compatibility checks; they prove compiler artifact hash parity, not live
deployed-address codehash parity or release readiness.

Use this crate to call the Chio web3 contracts from Rust. The contract artifact
type definitions live in `chio-web3`.
