# chio-pheromone-runtime

`chio-pheromone-runtime` is the local Chio pheromone receiver runtime with a
durable store. It receives pheromone signals locally and persists them so they
can be read back across runs.

Use this crate to run a local pheromone receiver. The shared signal and
transit-evidence types live in `chio-pheromone`; the networked relay is
`chio-pheromone-relay`.

## Source Layout

- `src/lib.rs` defines runtime errors, Chio workflow wrappers, signed transit
  policy loading, peer weights, generic receiver traits, and the verified
  workflow resolver.
- `src/store.rs` owns the durable SQLite receiver store, migrations,
  atomic batch receipt persistence, scarcity counters, replay protection, and
  concentration queries.
- `tests/runtime_receiver.rs` exercises runtime policy loading, batch receive,
  store persistence, query behavior, and storage-failure reporting.
