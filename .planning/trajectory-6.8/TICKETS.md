# Chio 6.8 Ticket Closeout

| Ticket | Owner | Status | Notes |
| --- | --- | --- | --- |
| C6.8-001 | Integrator | Complete | Branch and planning docs created from the pinned baseline. |
| C6.8-002 | Peer Directory And Auth | Complete | Peer directory parsing, endpoint pinning, signed HTTP request verification, freshness checks, body hashes, and replay nonce checks are implemented in `chio-pheromone-relay`. |
| C6.8-003 | Relay Store | Complete | SQLite outbox, inbox, attempts, cursors, and nonce tables are implemented with idempotent inbox recording and durable outbox leasing. |
| C6.8-004 | Relay Authorization | Complete | Relay queueing uses accepted batch artifacts and receiver verification preserves signed deposit immutability. |
| C6.8-005 | HTTP Service And Client | Complete | Axum batch receiver and reqwest signed client are covered by loopback HTTP tests. |
| C6.8-006 | Bounded Catch-Up | Complete | Signed catch-up requests verify through the relay envelope, enforce peer-directory frame and byte bounds, and return cursor-eligible outbox batches. |
| C6.8-007 | CLI | Complete | Deterministic receive/query clocks and relay serve, enqueue, tick, catchup, and status commands are wired. |
| C6.8-008 | Metrics And Reports | Complete | Relay report schemas are registered and relay metric descriptors are added to `chio-metrics-spec`. |
| C6.8-009 | Fixtures And Negatives | Complete | Peer directory, relay reports, catch-up artifacts, CI trigger, and negative corpus are committed. |
| C6.8-010 | Assurance | Complete | Final local gates are green; PR review cleanup and merge remain repository operations after publication. |
