# chio-disclosure-lineage Design

## D9 Crate Home Decision

`chio-disclosure-lineage` stays in `crates/trust` as the verifier for selective-disclosure lineage evidence. It verifies signed lineage subgraphs, disclosure capsules, leakage ledgers, privacy profiles, hidden predicates, crypto context reports, and transparency state.

The default homes considered were core types and selective-disclosure. Core types would pull trust policy into shared primitives. `chio-selective-disclosure` owns cryptographic proof primitives. This crate owns the Chio-specific lineage and policy evidence around those proofs.

## Boundary

This crate owns disclosure lineage verifier reports and lineage-specific claim emission. It does not generate UI bundles, manage tenant exports, or act as a generic BBS library.

## Invariants

Over-disclosure fails closed. Lineage nodes, redactions, leakage entries, crypto context, and privacy profile evidence must be graph-bound before disclosure claims are verified.
