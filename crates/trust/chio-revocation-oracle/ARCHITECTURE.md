# chio-revocation-oracle Architecture

## Boundary

`chio-revocation-oracle` owns Chio's signed revocation epoch-root contracts, sparse-Merkle proof generation, freshness windows, passport-bridge revocation application, and root signing/verification traits. It is the primitive used by federation and custody lanes to answer whether a capability or credential subject has been revoked as of an epoch.

## Internal Surfaces

The crate is split into public API types, an in-memory sparse-Merkle oracle, epoch-root signing and broadcast helpers, freshness verification, and passport bridge logic. Feature-gated delegation tests wire signed roots through federation gossip into kernel cache behavior.

## Trust Invariants

The security constraint is revocation-key exactness. Subjects, nonces, roots, signatures, and freshness windows must be unambiguous before proofs are emitted or remote caches merge epoch roots. The oracle boundary rejects empty or padded revocation subject identifiers so sparse-Merkle leaves cannot be minted for noncanonical subjects, keeping revocation lookup keys stable across local oracle state, gossiped epoch roots, and passport bridge projections.

## Verification Focus

Tests should cover empty subjects, padded subjects, sparse-Merkle proof verification, stale epoch roots, bad signatures, passport-bridge subject mapping, and remote-cache merge behavior. Kernel and federation consumers should only see normalized revocation evidence, so tests need to prove malformed subjects are rejected before roots or proofs are signed.

Freshness is the other half of the boundary: a proof or merged epoch root outside its freshness window must read as stale rather than as a negative revocation answer. Coverage exercises window edges across local oracle state, gossiped roots, and passport-bridge projections so a single revocation key resolves identically on every lane.
