# Chiodos 7.6: Treaty-Bound Cross-Kernel Provenance

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chiodos-7-6-treaty-bound-provenance`

This lane returns to the original Chiodos vision: cross-kernel work should be admitted through verifier-owned treaty semantics, then proven through receipt lineage and buyer-verifiable evidence. The first implementation slice stays local and artifact-first.

## Scope

- Governance ladder manifests for participating kernels.
- Treaty scope with pinned ladder manifest hashes.
- Ladder intersection computation with destructive floors and required evidence.
- Cross-boundary admission reports that fail closed before dispatch.
- Continuation and receipt-lineage statements that preserve evidence class.
- Buyer attestation packet verification that rejects asserted-only lineage.
- CLI and gate coverage for schema, positive, and negative paths.

## Non-Goals

- Dynamic trust or peer discovery.
- Settlement execution or settlement finality claims.
- Live notification dispatch.
- New transports.
- Hidden predicates, VC Data Integrity BBS, zkVM, or FROST.
- Pheromone-driven authority, lease, or governance decisions.

## No-Planning-Metadata Rule

Trajectory and ticket names must remain under `.planning`. Production code, schemas, fixtures, CLI text, and docs use product names only.
