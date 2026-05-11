# Chiodos Pheromone Relay Operator Examples

These examples are deployment templates for a static, verifier-owned relay directory. They assume the active peer-directory state is promoted by an operator and stored outside the proof package.

Production profiles require:

- a signed active peer-directory bundle inside `peer-directory-state.json`
- a trusted peer-directory issuer file
- HTTPS relay endpoints with pinned `/v1/chiodos/pheromone/*` paths
- a local signing key readable only by the relay operator
- a single writer for the SQLite relay store

The files in this directory are examples, not a packaged service manager. Operators should adjust paths and users while preserving the security properties above.

See `OBSERVABILITY.md` for the canonical relay observability report, bounded metrics, and alert examples.
