# Chiodos 6.13 Shadow

Candidate focus: relay alert delivery hardening, only if 6.12 routing artifacts prove useful.

Possible scope:

- handoff contract examples for existing Alertmanager, PagerDuty, OpsGenie, Slack, email, and webhook consumers
- delivery dry-run reports that prove secrets stay outside Chio artifacts
- alert retry and escalation evidence over bounded reports
- operator drills for stale suppression state, duplicate routes, alert floods, and downstream outage

Out of scope until explicitly promoted:

- credentialed live notification dispatch from Chio
- dynamic sink URLs or inline secrets
- policy mutation from alert state
- dynamic trust or peer discovery
- new transports, settlement, hidden predicates, VC Data Integrity BBS, zkVM, or FROST
