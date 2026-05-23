# Chio 6.18 Shadow

Candidate focus: optional archive packaging and extraction hardening after 6.17 proves report-only archive lifecycle and closeout review are useful.

Possible scope:

- signed archive package manifest over selected export bundle directories
- extraction safety and path traversal hardening
- operator-managed physical archive verification drills
- explicit handoff to external retention systems through local evidence only

Out of scope until explicitly promoted:

- deletion, moving, uploading, or mutating retained evidence
- live notification dispatch from Chio
- downstream credentials or dynamic sink URLs
- policy mutation from alert state
- dynamic trust or peer discovery
- new transports, settlement, hidden predicates, VC Data Integrity BBS, zkVM, or FROST
