# Chiodos 6.13 Promotion Note

The 6.13 shadow target is now active as relay alert handoff readiness.

Promoted scope:

- handoff contract examples for existing Alertmanager, PagerDuty, OpsGenie, Slack, email, and webhook consumers
- dry-run reports that prove secrets stay outside Chio artifacts
- alert route, escalation, and runbook evidence over bounded reports
- operator drills for stale reports, duplicate routes, alert floods, and downstream route gaps

Still out of scope:

- credentialed live notification dispatch from Chio
- dynamic sink URLs or inline secrets
- policy mutation from alert state
- dynamic trust or peer discovery
- new transports, settlement, hidden predicates, VC Data Integrity BBS, zkVM, or FROST
