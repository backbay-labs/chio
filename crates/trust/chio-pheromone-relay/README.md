# chio-pheromone-relay

`chio-pheromone-relay` is the live Chio pheromone relay service with a durable
relay store. It forwards pheromone signals between participants and persists
relay state for durability.

Use this crate to operate a networked pheromone relay. The local receiver
runtime is `chio-pheromone-runtime`; the shared signal types live in
`chio-pheromone`.
