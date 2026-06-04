# chio-anchor Architecture

## Boundaries

`chio-anchor` owns checkpoint anchoring and proof normalization for the frozen web3 artifact family. Its public API converts kernel checkpoints and receipt inclusion proofs into anchor proofs, prepares EVM root-registry publication calls, builds DID discovery artifacts, verifies multi-lane proof bundles, and records optional Bitcoin OTS, Solana memo, witness, and Chainlink Functions lanes.

The main internal seams are:

- `evm.rs`: EVM root-registry target configuration, publication preparation, RPC dispatch, guard inspection, and on-chain inclusion verification.
- `discovery.rs`: DID anchor service metadata, publication ownership metadata, runtime freshness, and discovery-backed bundle policy checks.
- `bundle.rs`: fail-closed multi-lane proof bundle verification.
- `batch.rs`, `bitcoin.rs`, `solana.rs`, `witness.rs`, and `functions.rs`: secondary lane preparation and verification.
- `ops.rs` and `metrics.rs`: runtime controls, lane health, incidents, and metrics export.

## Pain Points

`EvmAnchorTarget` is the authority-bearing configuration object that feeds root publication, delegate registration, guard inspection, chain-anchor records, and discovery artifacts. Today callers can construct targets with malformed chain IDs, RPC URLs, contract addresses, or publisher addresses. Several paths parse the operator address later, but the target is not validated as one coherent boundary before publication or discovery artifacts copy it outward.

That weak boundary lets invalid contract and publisher data survive into prepared publication requests, DID discovery metadata, and ownership records. The failure then appears later as an RPC failure or verifier confusion instead of a fail-closed configuration error at the owning crate boundary.

## Security And API Constraints

- Root publication must remain operator-owned and delegate-authorized.
- Binding validation must keep enforcing anchor purpose, covered chain scope, and settlement-address equality.
- RPC egress remains mediated by `HttpEgressContract`; target validation must not weaken dispatch authorization or perform DNS resolution.
- Public API compatibility should be preserved. Existing public structs remain stable, and validation is added as an explicit boundary rather than replacing the structs.
- Discovery artifacts must not advertise malformed EVM chain or address data as verifier metadata.

## Affected Dependents

Primary callers are the anchor daemon/control-plane wiring, web3 publication tooling, discovery artifact exporters, and tests that consume `build_anchor_discovery_artifact`, `prepare_root_publication`, `prepare_delegate_registration`, `inspect_publication_guard`, `ensure_publication_ready`, and `verify_inclusion_onchain`.

Transitive edits should be limited to tests or call sites that were relying on malformed placeholder EVM addresses. If a downstream test wants a syntactic address, it should use a full 20-byte EVM address.

## Planned Improvement

Add a single EVM target validation boundary owned by `evm.rs`, export it through `EvmAnchorTarget::validate`, and require it before EVM publication, delegate registration, guard inspection, on-chain inclusion checks, and discovery artifact construction. The validation will fail closed for malformed CAIP-2 EVM chain IDs, invalid HTTP(S) RPC URLs, missing URL hosts, malformed EVM addresses, and zero contract, operator, or publisher addresses.
