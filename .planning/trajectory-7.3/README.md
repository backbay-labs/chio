# Chio 7.3: Semantic Runtime Proof Regeneration

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chio-7-3-semantic-runtime-proof-regeneration`

Chio 7.3 closes the `runtime_proof_semantic_regeneration_pending`
gap from 7.2. A local runtime loopback run must now emit verifier-accepted
Chio proof artifacts: package-valid tool receipts, strict bilateral DSSE,
a signed workflow receipt, a `chio.attest.proof-package.v1`, verifier trust
and context inputs, verifier report, semantic parity report, and accepted proof
regeneration metadata.

This lane is local and bounded. It does not add dynamic trust, peer discovery,
settlement execution, live notification dispatch, hidden predicates, VC Data
Integrity BBS, zkVM, FROST, new transports, or pheromone-driven authority
decisions.

Planning names stay only under `.planning`.
