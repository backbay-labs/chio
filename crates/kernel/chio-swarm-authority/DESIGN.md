# chio-swarm-authority Design

## D9 Crate Home Decision

`chio-swarm-authority` stays in `crates/kernel` because swarm authority is a runtime admission concern and a proof-verifier concern. The same verifier is used by runtime admission and public proof checks to avoid two interpretations of delegation.

The default home considered was protocol adapters. Swarm authority is not MCP, A2A, ACP, or provider transport glue. It binds recursive task graphs, continuations, join receipts, route plans, revocation epochs, witness chains, and budget leases before child work.

## Boundary

This crate owns swarm authority artifact shapes, minting helpers used by tests and fixtures, and fail-closed bundle verification. It does not schedule work, execute child tasks, store nonces, or serve proof-room assets.

## Invariants

Continuation tokens and witness chains are signed. Revocation roots, route plans, parent joins, and budget leases are cross-bound. Runtime callers must enforce verifier success before dispatch.
