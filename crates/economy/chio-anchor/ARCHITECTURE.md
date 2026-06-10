# chio-anchor Architecture

## Boundaries

`chio-anchor` owns checkpoint anchoring and proof normalization for the frozen web3 artifact family. Its public API converts kernel checkpoints and receipt inclusion proofs into anchor proofs, prepares EVM root-registry publication calls, builds DID discovery artifacts, verifies multi-lane proof bundles, and records optional Bitcoin OTS, Solana memo, witness, and Chainlink Functions lanes.

The main internal seams are:

- `evm.rs`: EVM root-registry target configuration, publication preparation, RPC dispatch, guard inspection, and on-chain inclusion verification.
- `discovery.rs`: DID anchor service metadata, publication ownership metadata, runtime freshness, and discovery-backed bundle policy checks.
- `bundle.rs`: fail-closed multi-lane proof bundle verification.
- `batch.rs`, `bitcoin.rs`, `solana.rs`, `witness.rs`, and `functions.rs`: secondary lane preparation and verification.
- `ops.rs` and `metrics.rs`: runtime controls, lane health, incidents, and metrics export.

## Target Validation Boundary

`EvmAnchorTarget` is the authority-bearing configuration object that feeds root publication, delegate registration, guard inspection, chain-anchor records, and discovery artifacts. `evm.rs` owns a single validation boundary, exported as `EvmAnchorTarget::validate`, that runs before EVM publication, delegate registration, guard inspection, on-chain inclusion checks, and discovery artifact construction. It fails closed for malformed CAIP-2 EVM chain IDs, invalid HTTP(S) RPC URLs, missing URL hosts, malformed EVM addresses, and zero contract, operator, or publisher addresses. Invalid contract or publisher data therefore cannot survive into prepared publication requests, DID discovery metadata, or ownership records.

## Security And API Constraints

- Root publication is operator-owned and delegate-authorized.
- Binding validation enforces anchor purpose, covered chain scope, and settlement-address equality.
- RPC egress is mediated by `HttpEgressContract`; target validation does not perform DNS resolution.
- Discovery artifacts must not advertise malformed EVM chain or address data as verifier metadata.

## Dependent Surfaces

Callers are the anchor daemon/control-plane wiring, web3 publication tooling, discovery artifact exporters, and consumers of `build_anchor_discovery_artifact`, `prepare_root_publication`, `prepare_delegate_registration`, `inspect_publication_guard`, `ensure_publication_ready`, and `verify_inclusion_onchain`. Callers that need a syntactic address must supply a full 20-byte EVM address.
