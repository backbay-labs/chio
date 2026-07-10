# chio-risk-comptroller Design

## D9 Crate Home Decision

`chio-risk-comptroller` stays in `crates/platform` as the verifier for risk comptroller reports and their supporting ledgers. It is used by transaction passport, commerce, enterprise export, and trust-market proof paths.

The default homes considered were `chio-credit`, `chio-underwriting`, and control-plane. Credit and underwriting own economic policy and underwriting primitives; control-plane owns runtime operation. This crate is an offline proof verifier for facility state, coverage, appeals, reserves, sanctions, capital, actuarial evidence, and bounded insurance copy.

## Boundary

This crate verifies risk evidence and emits verified risk claims. It does not price policies, admit capital, execute payouts, or host runtime state.

## Invariants

Required risk claims fail closed unless the comptroller report and supporting evidence verify. Settlement, reserve, sanction, jurisdiction, and authority evidence must be bound by explicit refs and pinned signing authority.
