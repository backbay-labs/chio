# Proof Room Fixture Catalog

Status: second-pass fixture plan
Primary source: `../agent-reviews/11-proof-room-fixture-strategy.md`
Confidence: high for fixture staging, moderate for exact generator commands until `chio proof` exists.

## Position

The Proof Room cannot be a gallery of JSON. It must be a reproducible verifier path with signed roots, sealed manifests, negative fixtures, deterministic reports, and a UI that renders the same verdict as the CLI.

The public fixture catalog should have four stages. Fewer than four does not prove the homepage claim. More can exist, but launch should not depend on a sprawling catalog.

## Staged Public Catalog

| Stage | Fixture id | Public claim covered | Existing source to reuse | Launch bar |
| --- | --- | --- | --- | --- |
| 0 | `single-call-authority` | "Every action" and "verifiable authority" for one governed action | `examples/hello-receipt-verify`, `examples/hello-trust-control`, `examples/docker` | One allow receipt, one denial receipt, capability proof, policy hash, guard result, receipt signature, deterministic verifier report |
| 1 | `commerce-transaction-passport` | "Trust network for autonomous commerce" | `examples/internet-of-agents-web3-network` | Signed Transaction Passport over order, provider selection, quote, budget, payment, settlement, review, receipts, and denials |
| 2 | `recursive-runtime-swarm` | "Recursive delegation" and "multi-swarm coordination" | `examples/chio-3vendor/fixtures/runtime-spine`, `crates/chio-runtime-harness` | Runtime-regenerated proof package, parity report, continuation evidence, route evidence, join evidence, delegated receipts |
| 3 | `disclosure-and-agent-web-envelope` | "Proof layer for the emerging agent web" | `examples/chio-3vendor`, MCP/A2A/OpenAPI edges, proof package scripts | Selective disclosure proof, signed lineage subgraph, external projection manifest, protocol object digests, unsupported-feature denials |

Stage 0 is the five-minute starter. Stages 1 through 3 are the homepage proof. Each stage must be independently verifiable so failures isolate cleanly.

## Bundle Layout

Every stage should emit the same layout:

```text
proof-room-bundle/
  manifest.json
  bundle-signature.dsse.json
  README.md
  claims/
    claim-registry.json
    non-claims.json
  roots/
    transaction-passport.json
    evidence-graph.json
    trust-roots.json
  artifacts/
    authority/
    commerce/
    delegation/
    runtime/
    disclosure/
    settlement/
    risk/
    external/
    receipts/
    lineage/
    release/
  negatives/
    stale-capability/
    policy-hash-mismatch/
    guard-deny/
    bad-receipt-signature/
    order-id-mismatch/
    route-plan-mismatch/
    over-disclosure/
    double-reserve-consumption/
    claim-appeal-open/
    mixed-currency-risk/
    market-slash-facility-reserve/
  verifier/
    report.json
    report.dsse.json
```

`manifest.json` should use schema `chio.proof-room.bundle.v1` and include:

- `bundle_id`;
- `schema`;
- `created_at`;
- `chio_version`;
- `git_commit`;
- `fixture_id`;
- `transaction_passport_ref`;
- `evidence_graph_ref`;
- `verifier_report_ref`;
- `artifact_manifest`;
- `negative_cases[]` with expected and observed failure codes;
- `signature` or detached `bundle-signature.dsse.json`.

The primary verdict must come from `verifier/report.json`, `verifier/report.dsse.json`, or a verifier report hash bound in `bundle-signature.dsse.json`. A UI-generated verdict is not a proof.

## CLI Contract

The public CLI should be discoverable under `chio proof`:

```bash
chio proof fixture list
chio proof fixture generate <fixture-id> --out DIR
chio proof collect --kind <kind> --artifact-dir DIR --out DIR
chio proof verify <bundle-dir|bundle.tar.zst> [--require denials] [--require commerce] [--require delegation] [--require disclosure] [--require external-envelope] [--require runtime-parity] [--json] [--out FILE]
chio proof explain <bundle-dir> --claim <claim-id> [--json]
chio proof serve <bundle-dir> [--listen 127.0.0.1:0]
chio proof export <bundle-dir> --out FILE [--redact PROFILE]
chio proof doctor [--scenario <fixture-id>]
```

Lower-level commands may remain, but launch docs should point to `chio proof`.

## Stage 0: Single Call Authority

Required positive artifacts:

- `roots/transaction-passport.json` with schema `chio.transaction-passport.v1`;
- `roots/evidence-graph.json` with schema `chio.transaction.evidence-graph.v1`;
- one signed allow receipt;
- one signed denial receipt;
- capability proof;
- policy digest;
- guard report;
- trust roots;
- verifier report with verdict `verified`.

Required negative fixtures:

- stale capability;
- policy hash mismatch;
- guard deny;
- bad receipt signature;
- missing receipt node.

Acceptance evidence:

- every negative case fails with a named failure code;
- Proof Room overview shows allow and deny paths;
- CLI and UI verdicts match.

## Stage 1: Commerce Transaction Passport

Required positive artifacts:

- `chio.transaction-passport.v1`;
- `chio.commerce.order-context.v1`;
- `chio.commerce.event-log.v1`;
- provider selection;
- quote;
- mandate or approval;
- budget reservation;
- payment proof;
- settlement packet;
- reconciliation;
- receipts;
- lineage subgraph;
- verifier report.

Required negative fixtures:

- order id mismatch;
- quote replay;
- overspend;
- unauthorized settlement route;
- invoice tampering;
- forged provider passport;
- missing lineage;
- unmediated default path.

Acceptance evidence:

- order replay derives the same terminal state as the passport;
- quote, mandate or approval, budget, payment, settlement, and reconciliation bind the same order id;
- settlement evidence is subordinate to Chio authority unless independently verified and digest-bound;
- all IOA adversarial controls deny and produce verifier-visible denial evidence.

## Stage 2: Recursive Runtime Swarm

Required positive artifacts:

- Transaction Passport;
- runtime evidence manifest;
- runtime proof regeneration input;
- runtime proof regeneration report;
- runtime proof parity report;
- verifier trust bundle;
- verification context;
- delegation witness chain;
- continuation tokens;
- route-plan receipts;
- join receipts.

Required negative fixtures:

- stale continuation token;
- revoked ancestor authority;
- route-plan mismatch;
- join missing parent;
- runtime proof parity drift;
- treaty runtime boundary violation.

Acceptance evidence:

- runtime proof regeneration is deterministic for same scenario, store, and timestamp;
- stale continuation token fails before child authority is accepted;
- fan-in join without required parent receipts fails;
- route metadata is not accepted as authority without a route-plan receipt.

## Stage 3: Disclosure And Agent Web Envelope

Required positive artifacts:

- Transaction Passport;
- `chio.lineage.signed-subgraph.v1`;
- `chio.disclosure.capsule.v1`;
- `chio.disclosure.verifier-privacy-profile.v1`;
- `chio.disclosure.leakage-ledger.v1`;
- `chio.agent-web-proof-envelope.v1`;
- `chio.agent-web.external-projection-manifest.v1`;
- protocol object digests;
- `chio.agent-web.interop-verifier-report.v1`;
- verifier report.

Required negative fixtures:

- over-disclosure;
- hidden predicate unsupported;
- protocol digest mismatch;
- ambiguous `ACP` copy;
- x402 detached from order;
- required transparency proof not verified.

## Risk Fixture Floor

The public risk bundle should include one valid facility claim path and these negative cases:

- missing reserve;
- stale reputation;
- mixed currency;
- claim outside coverage;
- duplicate receipt id;
- payout amount mismatch;
- settlement counterparty mismatch;
- double reserve consumption;
- market slash against facility reserve without sanction/reserve bridge;
- reverse slash without prior enforced penalty;
- closure with open appeal.

Acceptance evidence:

- verifier rejects excess disclosure under selected privacy profile;
- leakage ledger accounts for every disclosed field and hidden predicate;
- each external projection states what Chio proves, what the external protocol proves, and what remains advisory;
- bare `ACP` copy fails the gate.

## Release Truth Gate

The public bundle must not claim a binary, package, Docker image, Homebrew formula, release tag, hosted demo, hosted CI result, Rekor inclusion, Base Sepolia evidence, or GA posture unless the bundle contains current evidence for it.
