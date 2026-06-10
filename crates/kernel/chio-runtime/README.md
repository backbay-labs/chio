# chio-runtime

`chio-runtime` is the public Chio runtime admission and orchestration boundary.
It is a facade that exposes only the runtime admission, trust-floor,
orchestration, operations, and proof-regeneration APIs that Chio runtime
callers need. The implementation lives in `chio-runtime-core`.

Depend on `chio-runtime` rather than `chio-runtime-core` for the stable runtime
API surface.

## Module Map

- `src/lib.rs`: Chio-owned public facade, schema constants, admission hook, error
  boundary, JSON/signature helpers, orchestration helpers, and validation
  wrappers.
- `src/stores.rs`: public store traits, in-memory/JSON/SQLite store wrappers,
  layered admission/trust-floor routing, and the private adapter into
  `chio-runtime-core`.
