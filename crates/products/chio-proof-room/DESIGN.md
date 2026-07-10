# chio-proof-room Design

## D9 Crate Home Decision

`chio-proof-room` stays in `crates/products` as the public proof viewing and quickstart server product. It packages the shared verifier crates into a static bundle verifier, fixture catalog, upload verifier, and small HTTP server.

The default homes considered were CLI and control-plane. CLI owns command dispatch; control-plane owns runtime service wiring. Proof Room is a product surface with UI-serving and bundle-verification concerns, so it needs a narrow product crate instead of expanding the CLI binary.

## Boundary

This crate owns Proof Room bundle schemas, source-verifier orchestration, fixture catalog serving, and quickstart HTTP behavior. It does not re-mint domain verdicts, execute runtime work, or bypass the CLI/domain verifier logic.

## Invariants

Bundles are verified before serving configured UI assets. Source verifier reports are recomputed from bundle artifacts. Detached signatures must verify against configured trusted bundle signers.
