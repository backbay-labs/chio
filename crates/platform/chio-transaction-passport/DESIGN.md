# chio-transaction-passport Design

## D9 Crate Home Decision

`chio-transaction-passport` stays in `crates/platform` as the shared verifier for signed transaction proof roots. It is consumed by CLI, Proof Room, runtime-security verification, commerce, enterprise export, trust-market, and Agent Web verifiers.

The default homes considered were core types, control-plane, and lineage. Core types would make proof verification depend on product schemas; control-plane would make offline proof verification pull runtime wiring; lineage only owns disclosure provenance. A platform crate keeps the signed root verifier reusable without making it a runtime authority.

## Boundary

This crate owns passport signatures, evidence graph integrity, verifier policy shape, claim-set binding, runtime-security evidence checks, and stable transaction verifier reports. It does not collect fixtures, serve UI, execute tools, or decide domain-specific claims that belong to commerce, risk, settlement, swarm, disclosure, or Agent Web verifiers.

## Invariants

Errors reject. Artifact digests are recomputed from bytes. Signatures verify against caller-supplied trusted keys, never keys embedded only in the artifact being checked.
