# chio-revocation-oracle

`chio-revocation-oracle` provides Chio's revocation oracle primitives: signed
sparse-Merkle epoch roots, freshness windows, and passport-bridge revocation
lookups. It lets a verifier check whether a capability or credential has been
revoked as of a given epoch, with bounded freshness guarantees.

Use this crate to publish or consult revocation state. The hardware custody
issuer (`chio-custody-hw`) consults a revocation cascade before minting
capabilities.
