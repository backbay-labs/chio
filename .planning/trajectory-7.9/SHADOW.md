# Chiodos 7.9 Shadow

The 7.9 shadow target is buyer review dashboarding and longer-window multi-run
review after the live treaty-to-buyer closure gate is real.

Entry criteria:

- `.planning/trajectory-7.8/GAP_LEDGER.md` shows no blocked 7.6, 7.7, or 7.8
  tickets except explicitly deferred non-goals.
- `bash scripts/check-chiodos-live-treaty-buyer-closure.sh` passes in full,
  not only in schema or fixture modes.
- Dashboarding does not widen Chiodos claims beyond local evidence,
  verifier-owned runtime state, strict DSSE treaty refs, and existing
  proof-verifier acceptance.

Candidate topics:

- Buyer review dashboard cards for accepted, rejected, missing, and drifted
  review packages.
- Multi-run buyer packet search and comparison.
- Long-window replay and downgrade review over buyer review packages.
- Operator-readable provenance drilldowns without policy mutation.

Deferred boundaries remain unchanged: no dynamic trust, peer discovery,
settlement execution, live downstream notification dispatch, hidden predicates,
VC Data Integrity BBS, zkVM, FROST, new transports, or pheromone-driven
authority decisions.
