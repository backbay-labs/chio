# Chiodos 6.9 Shadow

6.9 should harden production relay operations after 6.8 exits. Candidate work:

- TLS and deployment profile guidance for the signed HTTP relay.
- Long-running relay supervision and operator recovery runbooks.
- Peer discovery hardening beyond static verifier-owned directories.
- Relay observability dashboards and alert thresholds.
- Catch-up replay pressure tests across larger peer sets.

Still deferred: hidden predicates, VC DI BBS, zkVM, FROST, settlement execution, pheromone-driven authority decisions, and dynamic trust.
