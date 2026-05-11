# Chiodos 6.12 Shadow

The next room is relay alert routing and long-horizon operations over the hardened observability surface.

Candidate scope:

- Alert routing packs for PagerDuty, OpsGenie, Slack, and email using the relay observability report as the source of truth.
- Long-horizon trend reports over queue pressure, stale leases, replay conflicts, dead letters, directory expiry, and catch-up load.
- Operator escalation workflows that reference bounded event reports before raw store inspection.
- Alert fatigue controls with bounded code groups and explicit suppression windows.

Non-goals remain dynamic trust, peer crawling, pheromone-driven authority decisions, hidden predicates, VC DI BBS, zkVM, FROST, settlement, new transports, and multi-region HA.
