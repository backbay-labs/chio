# Proof Room And Developer Experience

Status: architecture outline
Primary source: `../agent-drafts/07-proof-room-developer-experience.md`
Confidence: high for product direction.

## Position

If Chio is a proof layer, launch needs a proof room. The proof room is not a marketing page. It is a verifier UI plus fixtures that make the protocol legible.

The CLI is canonical. The UI visualizes the same verifier report.

## CLI Surface

Canonical namespace:

- `chio proof fixture list`
- `chio proof fixture generate`
- `chio proof collect`
- `chio proof verify`
- `chio proof explain`
- `chio proof serve`
- `chio proof export`
- `chio proof doctor`

The CLI should produce:

- machine-readable report JSON;
- compact terminal summary;
- optional bundle for the Proof Room.

## Proof Room Bundle

`chio.proof-room.bundle.v1` contains:

- `bundle_id`
- `created_at`
- `chio_version`
- `fixture_id`
- `transaction_passport_ref`
- `verifier_report_ref`
- `artifact_manifest`
- `artifact_refs`
- `redaction_manifest_ref`
- `source_command`
- `signature`

The bundle should be static-hostable and deterministic.

## UI Views

Required tabs:

1. Overview:
   - verdict;
   - transaction kind;
   - issuer;
   - trust roots;
   - failed claims.
2. Authority:
   - capabilities;
   - policies;
   - guards;
   - receipts.
3. Evidence Graph:
   - nodes;
   - edges;
   - selected claim path.
4. Commerce:
   - order state;
   - quote;
   - mandate;
   - budget;
   - payment;
   - settlement.
5. Swarm:
   - task graph;
   - continuation tokens;
   - route plans;
   - joins;
   - budget pool.
6. Disclosure:
   - privacy profile;
   - disclosed fields;
   - hidden predicates;
   - leakage ledger.
7. Settlement:
   - chain/payment context;
   - tx and finality;
   - registry;
   - escrow;
   - bond;
   - dispute posture.
8. Risk:
   - facility state;
   - coverage;
   - claim;
   - reserve;
   - payout;
   - slashing.
9. External:
   - protocol projections;
   - envelope refs;
   - source protocol object digests.

## Demo Tiers

Tier 0: single governed tool call.

- Should run in a Docker quickstart.
- Must include one valid allow and one denial receipt.

Tier 1: autonomous commerce order.

- Shows order replay, payment/settlement context, and Transaction Passport.

Tier 2: recursive swarm.

- Shows task graph, child authority, join receipt, route-plan receipt, disclosure capsule, and optional risk report.

Tier 3: partner interop envelope.

- Shows MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC/BBS/SD-JWT, Sigstore/SLSA/in-toto/DSSE projections.

Canonical fixture details live in `../indices/proof-room-fixture-catalog.md`. The short version is:

| Stage | Fixture id | Launch role |
| --- | --- | --- |
| 0 | `single-call-authority` | Five-minute proof of one allow and one deny under bounded authority. |
| 1 | `commerce-transaction-passport` | Homepage proof for autonomous commerce. |
| 2 | `recursive-runtime-swarm` | Homepage proof for recursive delegation and multi-swarm coordination. |
| 3 | `disclosure-and-agent-web-envelope` | Homepage proof for selective disclosure and external protocol projection. |

## Release Truth Gate

The proof room must not lie about public availability.

Gate checks should verify:

- CLI binary or package exists where docs say it exists;
- release tag exists where docs say it exists;
- fixture bundle paths are valid;
- Docker quickstart works from a fresh checkout;
- no secret material is required;
- screenshots or hosted demos correspond to current fixture output.

## Negative Fixtures

Every launch demo must include invalid proof:

- invalid signature;
- missing evidence graph node;
- stale capability;
- route-plan mismatch;
- over-disclosed privacy proof;
- settlement finality failure;
- risk reserve mismatch.

Negative fixtures are important. They show that Chio is a proof layer, not just a renderer.
