# chio-web3

`chio-web3` defines Chio's official web3 settlement, anchoring, and on-chain
contract artifacts: signed identity bindings, trust profiles, contract
packages, chain configuration, checkpoint anchoring proofs, oracle FX
evidence, and the settlement dispatch/execution-receipt lifecycle. It also
carries a standalone verifier, `settlement_proof`, that re-checks a
settlement's full public evidence chain against caller-supplied trust without
needing kernel access.

Use this crate as the source of truth for these artifact shapes and their
validators. Alloy bindings live in `chio-web3-bindings`; execution lives in
`chio-settle` (escrow/bond dispatch) and `chio-anchor` (checkpoint anchoring).

## Responsibilities

- Define signed key-binding certificates linking a Chio identity to an
  on-chain settlement address, scoped by chain and purpose (`identity`).
- Define per-deployment trust profiles: settlement paths, dispute policy,
  per-chain finality rules, and regulated-role assumptions with an explicit
  custody boundary (`trust_profile`).
- Define the official contract package shape (root registry, escrow, bond
  vault, identity registry, price resolver) and its language bindings
  (`contracts`).
- Define per-chain deployment configuration, live or template-blocked, and
  gas profiles (`chain`).
- Define checkpoint statements, Merkle receipt-inclusion proofs, EVM/Bitcoin/
  super-root anchoring, and oracle currency-conversion evidence (`anchors`).
- Define the settlement dispatch and execution-receipt lifecycle across
  schema v1/v2 generations, binding capital-execution instructions, escrow,
  and bonds to observed on-chain outcomes (`settlement`).
- Independently verify a settlement's full public evidence chain against
  caller-supplied trust and emit a signed verifier report (`settlement_proof`).
- Define qualification matrices recording pass/fail-closed test outcomes
  against a trust profile and contract package (`qualification`).

## Public API

- `identity::{Web3IdentityBindingCertificate, SignedWeb3IdentityBinding,
  Web3KeyBindingPurpose, validate_web3_identity_binding,
  verify_web3_identity_binding}` - signed key-binding certificate linking a
  Chio identity to a settlement address, scoped by chain and purpose.
- `trust_profile::{Web3TrustProfile, Web3DisputeWindow,
  Web3ChainFinalityRule, Web3RegulatedRoleAssumption,
  validate_web3_trust_profile}` - per-deployment settlement path, dispute,
  finality, and regulated-role policy.
- `contracts::{Web3ContractPackage, Web3ContractInterface,
  Web3BindingTarget, Web3ContractKind, validate_web3_contract_package}` - the
  official contract family and its language bindings.
- `chain::{Web3ChainConfiguration, Web3ChainDeployment, Web3ChainGasProfile,
  validate_web3_chain_configuration}` - per-chain deployment and gas-profile
  configuration.
- `anchors::{AnchorInclusionProof, Web3CheckpointStatement,
  Web3ChainAnchorRecord, Web3BitcoinAnchor, OracleConversionEvidence,
  validate_anchor_inclusion_proof, verify_anchor_inclusion_proof,
  verify_checkpoint_statement, validate_oracle_conversion_evidence,
  sign_oracle_conversion_evidence, verify_oracle_conversion_evidence_signature}`
  - checkpoint anchoring (EVM, Bitcoin, super-root) and oracle FX evidence.
- `settlement::{Web3SettlementDispatchArtifact, SignedWeb3SettlementDispatch,
  Web3SettlementExecutionReceiptArtifact,
  SignedWeb3SettlementExecutionReceipt, Web3SettlementLifecycleState,
  validate_web3_settlement_dispatch,
  validate_web3_settlement_execution_receipt}` - the settlement dispatch and
  execution-receipt lifecycle.
- `settlement_proof::{PublicSettlementProofBundle,
  PublicSettlementVerifierTrust, PublicSettlementVerifierReport,
  verify_public_settlement_proof}` - independent verification of a
  settlement's full public evidence chain.
- `qualification::{Web3QualificationMatrix, Web3QualificationCase,
  validate_web3_qualification_matrix}` - pass/fail-closed test-outcome
  matrices.
- `error::Web3ContractError` - the error type returned by every validator in
  this crate.

Re-exported for use alongside these types: `canonical`, `capability`,
`crypto`, `hashing`, `merkle`, `receipt` (from `chio-core-types`) and
`credit` (from `chio-credit`).

## Testing

`cargo test -p chio-web3`

## See also

- `chio-core-types` - supplies the capability, crypto, hashing, merkle, and
  receipt types re-exported and built on here.
- `chio-credit` - supplies the capital-execution and credit-bond types a
  settlement dispatch wraps.
- `chio-web3-bindings` - Alloy bindings and packaged artifacts generated from
  these contract shapes.
- `chio-settle` - settlement runtime that dispatches against these artifacts.
- `chio-anchor` - anchoring runtime that produces the proofs these artifacts
  validate.
