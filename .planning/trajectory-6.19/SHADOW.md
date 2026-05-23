# Chiodos 6.19 Shadow

Candidate focus: archive operations hardening after 6.18 ships signed local archive packages and safe extraction.

Possible scope:

- broader archive restore drills across multiple package generations
- reusable safe archive extraction helpers for other Chio package surfaces
- `.arcguard` install hardening against unsafe tar entries
- operator archive runbook pressure tests across large local evidence sets

Out of scope until explicitly promoted:

- deletion, moving, uploading, or mutating retained evidence
- live notification dispatch from Chio
- downstream credentials or dynamic sink URLs
- policy mutation from alert state
- dynamic trust or peer discovery
- new transports, settlement, hidden predicates, VC Data Integrity BBS, zkVM, or FROST
