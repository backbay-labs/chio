# chio-web3 architecture

## Overview

`chio-web3` is a pure data-and-validation crate: in-memory types, schema
constants, and fail-closed validators, with no I/O, no chain RPC client, and
no runtime state (`#![forbid(unsafe_code)]`). It is the source of truth for
Chio's official web3 contract shapes: identity bindings, trust profiles,
contract packages, chain configuration, checkpoint anchoring, and the
settlement dispatch/execution-receipt lifecycle. A second surface,
`settlement_proof`, is a standalone verifier: given a
`PublicSettlementProofBundle` and a caller-supplied
`PublicSettlementVerifierTrust` policy, it re-derives and cross-checks the
full evidence chain behind one settlement offline, without kernel access, and
returns a signed `PublicSettlementVerifierReport`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate facade: re-exports `chio-core-types` primitives and `chio-credit` (as `credit`), declares the public modules. |
| `src/identity.rs` | Signed key-binding certificate (Chio identity to settlement address, chain-scoped, anchor/settle purpose) and its validation and signature verification. |
| `src/trust_profile.rs` | Per-deployment trust profile: settlement paths, dispute policy, chain finality rules, regulated-role assumptions; profile validation. |
| `src/contracts.rs` | Official contract package shape (root registry, escrow, bond vault, identity registry, price resolver) and language binding targets; package validation. |
| `src/chain.rs` | Per-chain deployment configuration (live or template-blocked) and gas profiles; configuration validation. |
| `src/anchors.rs` | Checkpoint statements, Merkle receipt-inclusion proofs, EVM/Bitcoin/super-root anchoring, and oracle FX conversion evidence with signature verification. |
| `src/settlement.rs` | Settlement dispatch and execution-receipt artifacts, lifecycle-state transitions, and their validators. |
| `src/settlement_proof.rs` (+ `settlement_proof_types.rs`, `settlement_proof_event_validation.rs`) | `PublicSettlementProofBundle` types and `verify_public_settlement_proof`, the independent evidence-chain verifier. |
| `src/qualification.rs` | Qualification matrix: pass/fail-closed test cases tied to a trust profile and contract package. |
| `src/error.rs` | `Web3ContractError`, the shared validator error type. |
| `src/validation.rs` | Crate-private field validators (non-empty, EVM address, b256 hex, uniqueness, money) shared across modules. |

## Public settlement proof verification

`verify_public_settlement_proof(bundle, trust)` is the crate's largest
surface by volume. It runs entirely against caller-supplied data; the crate
holds no chain client of its own.

1. Validates the bundle header, receipt/dispatch schema generation (v2
   required), and the bundle's own signature against
   `trust.trusted_bundle_signer_keys`.
2. Re-runs `settlement::validate_web3_settlement_execution_receipt` on the
   embedded receipt, then rejects lifecycle states that are not eligible for
   public finality (failed, reorged, escrow-locked).
3. Checks the capital-instruction signer, anchor checkpoint kernel key, and
   beneficiary identity key against the trust config's allow-lists, and the
   chain id against the allow-list and mainnet block.
4. Cross-checks the order binding and deployment provenance (contract
   addresses, runtime codehashes) against `trust.trusted_runtime_codehashes`,
   then checks escrow, bond, block, identity-registry-operator, and
   beneficiary-identity-binding snapshots against the dispatch and receipt.
5. Verifies an independently observed chain head confirms the same block and
   meets the confirmation threshold, and recomputes the public witness body
   hash to confirm it matches the supplied witness.
6. Validates dispute posture, then checks escrow state: a timed-out
   settlement must show a matching refund event in a trusted event log; other
   settlements match either the release transaction directly in the anchor
   block or a separate release event validated against a trusted event log.
7. Validates any trust-market refs (collateral, guarantee, remedy, slash
   authority) as all-or-nothing against the expected context, assembles
   `verified_claims` incrementally, and returns a
   `PublicSettlementVerifierReport`.

## Invariants and failure modes

- Every validator returns `Result<(), Web3ContractError>` (or a specific
  artifact); there is no constructor that skips validation.
- `validate_web3_settlement_dispatch` and
  `validate_web3_settlement_execution_receipt` accept both the v1 and v2
  dispatch/receipt schema generations, but a receipt's schema generation must
  match its embedded dispatch's; v2 additionally requires a validated
  `settlement_token_address` and a non-zero `operator_key_hash`.
- `Web3TrustProfile` validation fails unless `local_policy_activation_required`
  is `true` and at least one `Web3RegulatedRole::Custodian` role is present;
  trust profiles cannot claim implicit activation or omit a custodian of
  record.
- EVM addresses are validated structurally (`0x` + 40 hex) and rejected if
  they are the zero address, a repeated-byte sentinel, or a low-numbered
  sentinel; two addresses are compared case-insensitively via
  `evm_addresses_match`.
- Monetary amounts require a non-zero unit count and a 3-letter uppercase
  currency code, except escrow-locked and equivalent zero-amount receipt
  states, which still require a well-formed currency code.
- `verify_public_settlement_proof` treats cross-references as mandatory:
  missing deployment provenance, chain-snapshot sub-objects (bond, block,
  beneficiary identity binding), dispute snapshot, independent chain head, or
  public witness each fail closed rather than being treated as not
  applicable.
- Oracle conversion evidence recomputes `converted_cost_units` from
  `rate_numerator`/`rate_denominator` and a fixed currency minor-unit table,
  and rejects evidence whose reported value does not match exactly or whose
  `cache_age_seconds` exceeds `max_age_seconds`.

## Dependencies

Internal: `chio-core-types` supplies canonical JSON, capability
(`MonetaryAmount`), crypto (`PublicKey`, `Signature`, `Keypair`), hashing
(`Hash`), merkle (`MerkleProof`), and receipt (`ChioReceipt`,
`SignedExportEnvelope`) types, re-exported here as
`canonical`/`capability`/`crypto`/`hashing`/`merkle`/`receipt`. `chio-credit`
supplies the capital-execution-instruction and credit-bond types a settlement
dispatch wraps; `lib.rs` re-exports it locally as `credit` (`pub use
chio_credit as credit`, a source-level rename, not a Cargo `package =` alias
- the two crate names match). External: `alloy-primitives` (`keccak256`,
`std` feature only) for EVM-compatible hashing in anchor and witness binding,
`serde`/`serde_json` for artifact (de)serialization, `thiserror` for
`Web3ContractError`.
