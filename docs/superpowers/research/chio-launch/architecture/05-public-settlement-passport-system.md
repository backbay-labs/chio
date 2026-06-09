# Public Runtime And Web3 Settlement Proof

Status: architecture outline
Primary source: `../agent-drafts/05-public-runtime-settlement-passport-web3.md`
Confidence: high for proof-bundle direction, moderate for exact chain integration details.

## Position

The public settlement claim should not rest on a demo transcript. It needs a proof bundle that lets a verifier recompute settlement state from explicit evidence.

`chio.web3-settlement-proof-bundle.v1` is the launch artifact for public settlement context.

## Core Bundle

Fields:

- `bundle_id`
- `transaction_passport_ref`
- `commerce_order_ref`
- `chain_id`
- `registry_root_ref`
- `escrow_state_ref`
- `bond_state_ref`
- `settlement_instruction_ref`
- `tx_refs`
- `block_refs`
- `finality_refs`
- `oracle_conversion_evidence_ref`
- `dispute_posture_ref`
- `identity_binding_refs`
- `verifier_policy_ref`
- `signature`

## Verification Model

The verifier recomputes:

1. Chio transaction id binds the commerce order id.
2. Commerce order id binds the settlement instruction.
3. Settlement instruction binds payee, payer, amount, currency, asset, expiry, and chain id.
4. Registry root contains expected counterparty or service identity.
5. Escrow state has sufficient balance or locked amount.
6. Bond state satisfies policy.
7. Transaction hashes exist in expected blocks.
8. Blocks satisfy configured finality.
9. Oracle conversion evidence binds quote, timestamp, source, and amount.
10. Dispute posture is explicit.
11. Chio identities are distinct from EVM addresses and bound by explicit identity proofs.

## Public Settlement Verifier Report

`chio.public-settlement-verifier-report.v1` contains:

- verdict;
- recomputed settlement state;
- chain context;
- finality decision;
- registry proof result;
- escrow proof result;
- bond proof result;
- oracle conversion result;
- dispute result;
- identity binding result;
- references to Transaction Passport claims.

## Identity Binding

The proof bundle must not collapse Chio subject identity into an EVM address.

Binding options:

- signed Chio identity statement referencing EVM address;
- DID document service entry;
- verifiable credential;
- policy-approved wallet binding receipt.

Verifier rejects:

- missing binding;
- expired binding;
- binding for a different chain id;
- binding for a different address;
- signature from untrusted key.

## Oracle Conversion Evidence

`chio.oracle-conversion-evidence.v1` records:

- source currency;
- target currency or asset;
- amount;
- rate;
- rate source;
- timestamp;
- acceptable staleness;
- quote digest;
- signature or source proof.

Verifier rejects:

- stale rate;
- wrong currency;
- amount mismatch;
- quote digest mismatch;
- untrusted source.

## Dispute And Bond Posture

The public proof must show whether settlement is:

- undisputed;
- challenged;
- bonded;
- slashed;
- refunded;
- appealed;
- closed.

If the dispute posture is unknown, the proof can still exist but the launch claim must say settlement context is incomplete.

## Negative Cases

- settlement proof for wrong order id;
- wrong chain id;
- stale registry root;
- escrow balance below required amount;
- bond missing or below policy;
- tx hash not included in block;
- finality below threshold;
- stale oracle conversion evidence;
- EVM address not bound to Chio identity;
- dispute posture omitted.
