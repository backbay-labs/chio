# Chiodos 6.14 Shadow

Candidate focus: relay alert delivery hardening only if handoff readiness artifacts prove useful in operator drills.

Possible scope:

- downstream alert delivery replay fixtures that consume Chio handoff reports
- delivery-result import artifacts from Alertmanager or SIEM systems
- escalation acknowledgement evidence with bounded labels
- long-window handoff drift checks across report directories

Out of scope until explicitly promoted:

- credentialed live notification dispatch from Chio
- dynamic sink URLs or inline secrets
- policy mutation from alert state
- dynamic trust or peer discovery
- new transports, settlement, hidden predicates, VC Data Integrity BBS, zkVM, or FROST
