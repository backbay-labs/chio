# Chio 7.8 Live Treaty To Buyer Closure

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chio-7-8-live-treaty-buyer-closure`

This trajectory closes the unfinished 7.6 and 7.7 hero-loop work instead of
moving to dashboarding. A ticket is not done when the only positive evidence is
fixture-written placeholder hashes, copied static proof packages, or hash-only
self-attestation.

The accepted target is local and bounded:

- A treaty-bound cross-boundary request is denied or admitted before tool
  dispatch and before federation co-signing.
- Treaty, ladder, continuation, lineage, and buyer evidence are loaded from
  verifier-owned runtime state.
- Strict Chio bilateral DSSE carries treaty binding refs over real receipt
  hashes and buyer verification treats compatibility-only predicates as
  non-authoritative.
- Buyer review packages hydrate artifacts by role, path, hash, and byte count.
- Existing Chio proof verification remains the proof package oracle.

## Completion Criteria

7.8 is complete only when the gap ledger closure matrix has no blocked tickets
and every implemented row names a passing gate. A row is only `Implemented`
when the gate validates live or verifier-owned evidence for that ticket. A row
stays `Partially implemented` when the code or artifact path exists but the
proving gate still relies on static fixtures, hash-only self-attestation, or
compatibility-only predicates. A row is `Blocked` when the accepted target
cannot yet be proven by the named gate.

The authoritative closure gates are listed in `FINAL_GATES.md`. Worker-local
status updates may help triage, but gate results win when they conflict with
prose status.

Deferred boundaries remain unchanged: no dynamic trust, peer discovery,
settlement execution, live downstream notification dispatch, hidden predicates,
VC Data Integrity BBS, zkVM, FROST, new transports, or pheromone-driven authority
decisions.

Planning names stay under `.planning` only.
