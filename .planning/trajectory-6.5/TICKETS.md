# Chio 6.5 Tickets

## C6.5-001 Integrator

Create the branch from the pinned baseline SHA, add lane planning docs,
record owner tickets and final gates, and keep planning metadata under
`.planning/trajectory-6.5`.

Acceptance:

- Branch starts from `main@4635d22978376da4134c2ca2874c6b02702a8e91`.
- Planning docs record baseline, scope, tickets, final gates, and the
  no-planning-metadata rule.
- Chio 6.6 shadow planning tracks pheromone transit and workflow context.

## C6.5-002 Schema Registry

Add current runtime authority schemas and mark historical Chio verifier
schemas as deprecated read-compatible where they intentionally share a file.

Acceptance:

- Authority profile, issuance request, issuance bundle, revocation publication
  request, and peer pins have JSON schemas.
- Strict gates use current Chio schemas.
- Historical trust-bundle v2 and report v1 registry entries are explicitly
  deprecated read-compatible.

## C6.5-003 Workflow Classes

Freeze the product-owned workflow reference classes
`workflow.grant_issue` and `workflow.aggregate_publish`.

Acceptance:

- Strict trust bundles must include both reference classes.
- Verifier tests reject missing reference workflow classes.
- Fixture trust-bundle material includes both classes.

## C6.5-004 Authority Profile

Implement public authority profile parsing and validation.

Acceptance:

- Public profiles include BBS issuers, lease authorities, governance
  authorities, and revocation authority metadata.
- Validation rejects empty roots, duplicate roots, missing key ids, missing
  lifecycle windows, and malformed key material.
- Profiles never contain private signing seeds.

## C6.5-005 Lease Issuer

Issue capability leases and lease-scope bindings from workflow step inputs.

Acceptance:

- Issued scope digests are recomputed from the canonical binding preimage.
- Issuance rejects inactive authority, wrong signing key, unsupported action
  class, bad tool args hash, invalid window, and duplicate lease ids.
- Emitted leases verify through the existing Chio verifier.

## C6.5-006 Governance Issuer

Issue governance receipts for destructive steps only.

Acceptance:

- Destructive steps require governance receipt id, step hash, and governance
  window inputs.
- Governance receipts are contained inside the matching lease window.
- Non-destructive steps carrying governance fields fail before signing.

## C6.5-007 Checkpoint Publisher

Publish signed revocation checkpoints from local authority inputs.

Acceptance:

- Checkpoint publication rejects stale windows, duplicate revoked keys,
  malformed fingerprints, wrong signing key, inactive authority, and
  non-monotonic epoch height.
- Produced checkpoints validate through the existing strict trust bundle path.

## C6.5-008 Trust Bundle Assembly

Assemble verifier-owned trust-bundle material from public authority and
verifier input documents.

Acceptance:

- Assembly accepts only external peer pins, workflow intersection, disclosure
  policy, and checkpoint inputs.
- Package-carried material cannot add trust.
- Output validates as `chio.federation.verifier-trust-bundle.v1`.

## C6.5-009 CLI

Add local Chio authority commands.

Acceptance:

- `chio federation authority issue` writes an issuance bundle plus split artifact
  files.
- `chio federation authority checkpoint` writes a signed revocation checkpoint.
- `chio federation authority trust-bundle assemble` writes a strict verifier
  trust bundle.
- Commands require explicit local signing-key input where signatures are
  produced.

## C6.5-010 Fixture Conversion

Regenerate the three-vendor fixture from runtime authority APIs.

Acceptance:

- Fixture leases, lease-scope bindings, governance receipts, context, and trust
  bundle are produced by `chio-federation-authority`.
- Manual construction remains only in focused test mutation helpers.
- Runtime-issued fixture still verifies through `chio attest buyer verify-proof`.

## C6.5-011 Negatives And Gates

Add runtime authority gates and keep the existing proof-package gate strict.

Acceptance:

- `scripts/check-chio-authority-issuance.sh` proves runtime-issued artifacts
  match the committed proof package.
- `scripts/check-chio-proof-package.sh` invokes the authority gate in default
  mode.
- Existing negative corpus still reaches stable verifier failure codes.

## C6.5-012 Integrator

Open the PR, address all review threads, merge to `main`, and rerun the
Chio gates on `main`.

Acceptance:

- PR review threads are queried and resolved before merge.
- Final Chio authority and proof-package gates pass on `main`.

