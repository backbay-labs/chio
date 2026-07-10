# chio-runtime-proof-parity Design

## D9 Crate Home Decision

`chio-runtime-proof-parity` stays in `crates/kernel` as the shared schema and validator for comparing static proof packages with runtime regenerated proof packages. It is consumed by Proof Room and runtime-admission evidence.

The default homes considered were Proof Room and runtime-core. Proof Room would make parity a product-only concept; runtime-core would couple a small schema validator to runtime internals. A kernel support crate keeps the parity contract reusable and small.

## Boundary

This crate owns runtime proof parity artifact shapes and validation. It does not regenerate proofs, read stores, run workflows, or serve proof assets.

## Invariants

Accepted parity reports must bind static and runtime package hashes, verifier report hashes, compared fields, and zero mismatches. Failed reports must carry a stable failure code and mismatch evidence.
