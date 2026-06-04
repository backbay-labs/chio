# chio-web3 Architecture

## Boundary

`chio-web3` owns Chio's official web3 settlement, anchoring, trust-profile, chain-configuration, oracle-evidence, and settlement lifecycle contracts. It is the source of truth for on-chain artifact shapes; generated bindings live in `chio-web3-bindings`, while execution lives in `chio-settle` and anchoring in `chio-anchor`.

## Internal Surfaces

The crate is data-contract heavy. Public structs describe signed key bindings, contract packages, anchor inclusion proofs, settlement dispatches, execution receipts, qualification matrices, and control-state traces. Validator functions enforce schema ids, references, custody boundaries, chain coverage, proof consistency, and terminal settlement state.

## Trust Invariants

The security constraint is live-money exactness. Amounts, currencies, rails, anchor proofs, and oracle evidence must be validated before later crates attempt execution or reconciliation.

## Dependent Surfaces

Generated bindings, `chio-settle`, `chio-anchor`, and Web3 examples consume these structs as the canonical contract vocabulary. Validation must keep on-chain identifiers, chain ids, custody boundaries, and receipt references unambiguous so execution crates do not need to guess at malformed artifact intent.

## Verification Focus

Tests should cover settlement currency canonicalization, chain coverage, proof consistency, custody boundary validation, oracle evidence references, and terminal state validation.

## Improvement Target

Planned improvement: reject non-uppercase settlement currencies in all web3 monetary amounts so dispatch and receipt artifacts cannot carry noncanonical live-money currency codes.
