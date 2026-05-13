# Chiodos 6.21 Shadow

Candidate focus: external-retention custody reconciliation through local evidence only.

Possible scope:

- reconcile multiple external retention review packets across incident windows
- compare local operator evidence against later retention-system exports without calling those systems
- detect custody-claim drift, alias drift, and missing package generations over longer windows
- add dashboard summaries for custody reconciliation packets

Out of scope until explicitly promoted:

- deletion, moving, uploading, or mutating retained evidence
- live notification dispatch from Chio
- downstream credentials or dynamic sink URLs
- policy mutation from alert state
- dynamic trust or peer discovery
- new transports, settlement, hidden predicates, VC Data Integrity BBS, zkVM, or FROST
