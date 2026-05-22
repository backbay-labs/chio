# Chio 7.7: Treaty-To-Buyer Hero Loop

Baseline SHA: `51cb21735c7d237ccc20f005bbdb7f855adff3c9`

Branch: `codex/chio-7-7-treaty-buyer-hero-loop`

This branch is intentionally stacked on the local Chio 7.6 treaty-bound
provenance work because 7.6 has not been merged in this checkout. The lane
turns treaty-bound artifacts into one buyer-verifiable local review loop.

## Scope

- Buyer review packages that bind the packet and required artifacts by role,
  relative path, byte count, and SHA-256.
- Receipt-lineage bundles that reject asserted-only required edges.
- Buyer verification reports with structured checks and explain output.
- CLI package, verify, and explain commands for local evidence.
- Schema, registry, gate, and docs updates for the buyer loop.

## Non-Goals

- Dynamic trust or peer discovery.
- Settlement execution or settlement finality claims.
- Live notification dispatch.
- New transports.
- Hidden predicates, VC Data Integrity BBS, zkVM, or FROST.
- Pheromone-driven authority, lease, governance, or settlement decisions.

## No-Planning-Metadata Rule

Trajectory and ticket names must remain under `.planning`. Production code,
schemas, fixtures, CLI text, and docs use product names only.
