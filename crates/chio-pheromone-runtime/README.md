# chio-pheromone-runtime

`chio-pheromone-runtime` is the local Chio pheromone receiver runtime with a
durable store. It receives pheromone signals locally and persists them so they
can be read back across runs.

Use this crate to run a local pheromone receiver. The shared signal and
transit-evidence types live in `chio-pheromone`; the networked relay is
`chio-pheromone-relay`.
