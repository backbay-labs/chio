# Agent K: Proof Room Fixture Strategy

Status: launch research refinement
Confidence: high for fixture strategy and gate logic, moderate for final command spelling until `chio proof` exists.

## Position

The Proof Room cannot be a gallery of JSON files. It has to be a reproducible verifier path with signed roots, sealed manifests, negative fixtures, deterministic reports, and a UI that is downstream of the same verifier output as the CLI.

The homepage claim is defensible only if a public reviewer can run one command against a fixture bundle and independently verify these facts:

1. A governed action was authorized by a bounded capability, policy, guard decision, and signed receipt.
2. A commerce transaction joined order, quote, budget, payment, settlement, review, and receipt evidence under one Transaction Passport.
3. Recursive delegation carried parent-to-child authority, attenuation, continuation freshness, route planning, and join evidence.
4. Selective disclosure and lineage were verified as policy-enforced facts, not as redacted screenshots.
5. Negative fixtures failed for specific verifier reasons.
6. The Proof Room UI rendered the verifier report without inventing a stronger verdict.

If any of those are absent, the public claim should be downgraded. The repo has useful ingredients in `examples/hello-receipt-verify`, `examples/hello-trust-control`, `examples/docker`, `examples/chio-3vendor`, `examples/internet-of-agents-web3-network`, `crates/chio-runtime`, and `crates/chio-runtime-harness`. The missing launch move is to normalize them into one proof bundle and one gate suite.

## Minimum Public Fixture Set

The minimum public catalog should have four staged fixtures. Fewer than four is not enough to prove the homepage claim. More can exist, but launch should not depend on a sprawling catalog.

| Stage | Fixture id | Public claim covered | Existing source to reuse | Launch bar |
| --- | --- | --- | --- | --- |
| 0 | `single-call-authority` | "Every action" and "verifiable authority" for one governed action | `examples/hello-receipt-verify`, `examples/hello-trust-control`, `examples/docker` | One allow receipt, one denial receipt, capability proof, policy hash, guard result, receipt signature, deterministic verifier report |
| 1 | `commerce-transaction-passport` | "Trust network for autonomous commerce" | `examples/internet-of-agents-web3-network` | Signed Transaction Passport over order, provider selection, quote, budget, payment, settlement, review, receipts, and denials |
| 2 | `recursive-runtime-swarm` | "Recursive delegation" and "multi-swarm coordination" | `examples/chio-3vendor/fixtures/runtime-spine`, `crates/chio-runtime-harness` | Runtime-regenerated proof package, proof parity report, continuation or treaty evidence, route or admission evidence, delegated receipts |
| 3 | `disclosure-and-agent-web-envelope` | "Proof layer for the emerging agent web" | `examples/chio-3vendor`, proof package scripts, existing MCP/A2A/OpenAPI edges | Selective disclosure proof, signed lineage subgraph, external projection manifest, protocol object digests, unsupported-feature denials |

Stage 0 is the five-minute starter. Stages 1 through 3 are the homepage proof. The Proof Room can present them in one public archive, but each stage must remain independently verifiable so failures isolate cleanly.

## Staged Fixture Catalog

### Stage 0: `single-call-authority`

Purpose: prove that Chio mediates one action and fails closed.

Required positive artifacts:

- `transaction-passport.json` with schema `chio.transaction_passport.v1`.
- `evidence-graph.json` with the action node, capability node, policy node, guard node, receipt node, and trust-root node.
- `receipts/allow.ndjson` with one signed allow receipt.
- `capabilities/allow-capability.json`.
- `policies/policy.yaml` and `policies/policy.sha256`.
- `guards/allow-guard-report.json`.
- `verifier/trust-roots.json`.
- `verifier/report.json` with verdict `pass`.

Required negative artifacts:

- `negative/stale-capability/`.
- `negative/policy-hash-mismatch/`.
- `negative/guard-deny/`.
- `negative/bad-receipt-signature/`.
- `negative/missing-receipt-node/`.

Exact gate:

```bash
chio proof fixture generate single-call-authority --out target/proof-room/single-call-authority
chio proof verify target/proof-room/single-call-authority --require denials --json --out target/proof-room/single-call-authority/verifier/report.json
chio proof explain target/proof-room/single-call-authority --claim authority.capability.valid
```

Acceptance evidence:

- `verifier/report.json` has `verdict: "pass"`.
- Every negative case has `expected_verdict: "fail"` and `observed_verdict: "fail"`.
- The verifier names failure codes, not generic failure text.
- The Proof Room overview shows one allow path and one deny path side by side.

### Stage 1: `commerce-transaction-passport`

Purpose: prove autonomous commerce as a governed state machine, not a narrative transcript.

Required positive artifacts:

- `transaction-passport.json` as the signed root.
- `commerce/order-context.json` with schema `chio.commerce.order-context.v1`.
- `commerce/event-log.ndjson` with monotonic order events.
- `commerce/provider-selection.json`.
- `commerce/quote.json`.
- `commerce/mandate-or-approval.json`.
- `commerce/budget-reservation.json`.
- `settlement/payment-proof.json`.
- `settlement/settlement-packet.json`.
- `settlement/reconciliation.json`.
- `receipts/receipts.ndjson`.
- `lineage/lineage-subgraph.json`.
- `adversarial/summary.json`.
- `verifier/report.json`.

Existing IOA artifacts map cleanly into this stage: RFQ, provider selection, x402-style payment proof, Chio payment proof, settlement packet, web3 evidence, budget reconciliation, provider passport, federation admission, reputation verdict, runtime degradation, SIEM events, and adversarial denials.

Required negative artifacts:

- `negative/order-id-mismatch/`.
- `negative/quote-replay/`.
- `negative/overspend/`.
- `negative/unauthorized-settlement-route/`.
- `negative/invoice-tampering/`.
- `negative/forged-provider-passport/`.
- `negative/missing-lineage/`.
- `negative/unmediated-default-path/`.

Exact gate:

```bash
CHIO_RUN_E2E=1 examples/internet-of-agents-web3-network/smoke.sh --artifact-dir target/proof-room/commerce-transaction-passport
chio proof collect --kind ioa-web3 --artifact-dir target/proof-room/commerce-transaction-passport --out target/proof-room/commerce-transaction-passport/proof-bundle
chio proof verify target/proof-room/commerce-transaction-passport/proof-bundle --require denials --require commerce --json --out target/proof-room/commerce-transaction-passport/proof-bundle/verifier/report.json
```

Acceptance evidence:

- Order replay derives the same terminal order state as the passport.
- Quote, mandate or approval, budget, payment, settlement, and reconciliation all bind the same order id.
- Settlement evidence is subordinate to Chio authority unless independently verified and bound by digest.
- All IOA adversarial controls deny and produce verifier-visible denial evidence.
- `review-result.json` may be displayed as advisory unless sealed into the proof bundle.

### Stage 2: `recursive-runtime-swarm`

Purpose: prove recursive authority and runtime proof regeneration.

Required positive artifacts:

- `transaction-passport.json`.
- `runtime/runtime-evidence-manifest.json`.
- `runtime/runtime-step-evidence.json`.
- `runtime/runtime-proof-regeneration-input.json`.
- `runtime/runtime-proof-regeneration-report.json`.
- `runtime/runtime-proof-parity-report.json`.
- `runtime/verifier-trust-bundle.json`.
- `runtime/verification-context.json`.
- `runtime/verifier-report.json`.
- `delegation/delegation-witness-chain.json`.
- `delegation/continuation-tokens.ndjson`.
- `delegation/route-plan-receipts.ndjson`.
- `delegation/join-receipts.ndjson`.

The runtime harness should be the canonical generator for this stage because it drives live runtime loopback and proof regeneration deterministically.

Required negative artifacts:

- `negative/stale-continuation-token/`.
- `negative/revoked-ancestor-authority/`.
- `negative/route-plan-mismatch/`.
- `negative/join-missing-parent/`.
- `negative/runtime-proof-parity-drift/`.
- `negative/treaty-runtime-boundary/`.

Exact gate:

```bash
chio runtime run-loopback --scenario examples/chio-3vendor/fixtures/runtime-spine/scenario.json --store-dir target/proof-room/recursive-runtime-swarm/store --now-unix-ms 1800000001000 --out-dir target/proof-room/recursive-runtime-swarm/runtime
chio proof collect --kind runtime-spine --artifact-dir target/proof-room/recursive-runtime-swarm/runtime --out target/proof-room/recursive-runtime-swarm/proof-bundle
chio proof verify target/proof-room/recursive-runtime-swarm/proof-bundle --require runtime-parity --require delegation --require denials --json --out target/proof-room/recursive-runtime-swarm/proof-bundle/verifier/report.json
```

Acceptance evidence:

- Runtime proof regeneration is deterministic for the same scenario, store, and timestamp.
- Proof parity report compares workflow claims, step count, step semantics, tool receipt targets, bilateral DSSE semantics, lease scope semantics, governance authorization, destructive flags, and treaty binding where present.
- A stale continuation token fails before child action authority is accepted.
- A fan-in join without the required parent receipt set fails.
- Route metadata is not accepted as authority unless covered by a route-plan receipt.

### Stage 3: `disclosure-and-agent-web-envelope`

Purpose: prove that Chio can publish a verifier-owned proof envelope without claiming that external protocols natively enforce Chio authority.

Required positive artifacts:

- `transaction-passport.json`.
- `lineage/signed-lineage-subgraph.json`.
- `disclosure/disclosure-capsule.json`.
- `disclosure/verifier-privacy-profile.json`.
- `disclosure/leakage-ledger.json`.
- `external/agent-web-proof-envelope.json`.
- `external/projection-manifest.json`.
- `external/protocol-object-digests.json`.
- `external/interop-verifier-report.json`.
- `verifier/report.json`.

Required projections:

- MCP.
- A2A.
- ACP-Client.
- ACP-Commerce.
- AG-UI.
- OpenAPI.
- AP2.
- x402.
- VC or presentation proof.
- BBS or selective disclosure proof.
- SD-JWT if used.
- Sigstore, SLSA, in-toto, or DSSE where the claim is supply-chain related.

Required negative artifacts:

- `negative/over-disclosure/`.
- `negative/hidden-predicate-unsupported/`.
- `negative/protocol-digest-mismatch/`.
- `negative/acp-ambiguous-copy/`.
- `negative/x402-detached-from-order/`.
- `negative/rekor-required-but-not-verified/`.

Exact gate:

```bash
chio proof collect --kind agent-web-envelope --artifact-dir target/proof-room/disclosure-and-agent-web-envelope/source --out target/proof-room/disclosure-and-agent-web-envelope/proof-bundle
chio proof verify target/proof-room/disclosure-and-agent-web-envelope/proof-bundle --require disclosure --require external-envelope --require denials --json --out target/proof-room/disclosure-and-agent-web-envelope/proof-bundle/verifier/report.json
```

Acceptance evidence:

- The verifier rejects excess disclosure under the selected privacy profile.
- The leakage ledger accounts for every disclosed field and hidden predicate.
- Each external projection states what Chio proves, what the external protocol proves, and what remains advisory.
- Bare `ACP` copy fails the gate.
- Unsupported proof systems fail explicitly instead of being silently ignored.

## Proof Room Bundle Layout

Use one static-hostable archive layout for every stage. Do not let each example invent its own terminal report.

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
    quote-replay/
    overspend/
    unauthorized-settlement-route/
    stale-continuation-token/
    route-plan-mismatch/
    over-disclosure/
    protocol-digest-mismatch/
  verifier/
    report.json
    report.dsse.json
    explain-index.json
    tool-versions.json
  ui/
    proof-room-static/
```

`manifest.json` is the authenticated inventory. It must include:

- `schema: "chio.proof_room_bundle.v1"`.
- `bundle_id`.
- `fixture_id`.
- `stage`.
- `created_at`.
- `source_commit`.
- `source_branch`.
- `source_command`.
- `chio_version`.
- `schema_versions`.
- `hash_algorithm`.
- `artifacts[]` with path, sha256, media type, schema, artifact class, sensitivity class, producer, participates in primary verdict, and renderer hint.
- `claims[]` with claim id, required artifacts, checker, result, proof level, caveat, and source refs.
- `negative_cases[]` with expected failure code and observed failure code.
- `advisory_artifacts[]`.
- `excluded_artifacts[]` with reason.
- `signature` or detached `bundle-signature.dsse.json`.

The primary Proof Room verdict must come from `verifier/report.dsse.json` or from a verifier report hash bound in `bundle-signature.dsse.json`. A UI-generated verdict is not a proof.

## CLI Contract

The public CLI should be discoverable under `chio proof`, while lower-level commands remain available for specialists.

Required commands:

```text
chio proof fixture list
chio proof fixture generate <fixture-id> --out DIR
chio proof collect --kind <kind> --artifact-dir DIR --out DIR
chio proof verify <bundle-dir|bundle.tar.zst> [--require denials] [--require commerce] [--require delegation] [--require disclosure] [--require external-envelope] [--require runtime-parity] [--json] [--out FILE]
chio proof explain <bundle-dir> --claim <claim-id> [--json]
chio proof serve <bundle-dir> [--listen 127.0.0.1:0]
chio proof export <bundle-dir> --out FILE [--redact PROFILE]
chio proof doctor [--scenario <fixture-id>]
```

Required adapter mappings:

- `chio proof verify --kind evidence` can call the `chio evidence verify` verifier path.
- `chio proof verify --kind replay` can call `chio replay`.
- `chio proof verify --kind buyer-package` can call `chio attest buyer verify-proof`.
- `chio proof verify --kind runtime-spine` can call `chio runtime run-loopback` output plus runtime parity verification.
- `chio proof verify --kind ioa-web3` can call the IOA offline verifier until commerce gates are promoted into generic checkers.
- `chio proof explain` can reuse receipt, lineage, buyer, runtime, and evidence explainers, but it must return normalized claim ids.

Required exit codes:

| Exit code | Meaning |
| --- | --- |
| 0 | Bundle verified and all required claims passed. |
| 10 | Required proof claim failed. |
| 20 | Signature, digest, or manifest integrity failure. |
| 30 | Parse or schema failure. |
| 40 | Required negative fixture did not fail. |
| 50 | Required proof feature unsupported. |
| 60 | Release or package truth check failed. |

The verifier report must include `checker_provenance[]` so a reviewer can tell whether a claim came from receipt replay, evidence verification, buyer proof verification, runtime parity, IOA verifier logic, Sigstore verification, release qualification, or a manual operator decision.

## Exact Gates

These gates should block launch publication of the homepage claim.

### Gate 1: Bundle Integrity

Command:

```bash
chio proof verify target/proof-room/public-bundle --require denials --json --out target/proof-room/public-bundle/verifier/report.json
```

Pass criteria:

- Every manifest entry exists.
- Every manifest digest recomputes.
- No primary-verdict artifact is unmanifested.
- Advisory artifacts are visible and cannot change the primary verdict.
- The verifier report is signed or hash-bound by the bundle signature.

### Gate 2: Authority

Pass criteria:

- Every governed action has a signed receipt or a declared unsupported-action exclusion.
- Capability issuer, audience, scope, expiry, revocation epoch, policy hash, guard decision, request digest, and response digest verify.
- Stale capability, bad signature, missing receipt, and policy hash mismatch fixtures fail.

### Gate 3: Commerce

Pass criteria:

- Order context replays monotonically.
- Provider selection, quote, mandate or approval, budget reservation, payment, settlement, fulfillment, review, dispute posture, and reconciliation bind the same order id.
- Settlement evidence cannot advance the order without Chio authority and a valid reconciliation transition.
- Quote replay, overspend, unauthorized settlement route, invoice tampering, forged passport, missing lineage, and unmediated path fixtures fail.

### Gate 4: Recursive Delegation

Pass criteria:

- Each child action has a parent witness and attenuation proof.
- Continuation tokens are fresh at evaluation time.
- Revoked ancestors fail descendants.
- Route-plan receipts bind the route used.
- Multi-parent joins require the complete parent receipt set.
- Runtime proof regeneration and proof parity reports pass for the committed runtime-spine scenario.

### Gate 5: Disclosure And Lineage

Pass criteria:

- Signed lineage subgraph root binds to the Transaction Passport.
- Evidence class remains visible as asserted, observed, or verified.
- Verifier privacy profile rejects excess disclosure.
- Leakage ledger covers every disclosed field.
- Unsupported hidden predicates fail as unsupported instead of passing as advisory.

### Gate 6: External Envelope

Pass criteria:

- Every external projection includes source protocol object digest, Chio proof ref, projection schema, checker, and caveat.
- The verifier report separates Chio authority from MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE facts.
- Ambiguous `ACP` copy fails.
- Detached x402 or AP2 evidence cannot satisfy the commerce gate.

### Gate 7: Proof Room UI

Command:

```bash
chio proof serve target/proof-room/public-bundle --listen 127.0.0.1:0
```

Pass criteria:

- The UI can load the bundle offline.
- The overview verdict equals the CLI verifier verdict.
- Failed claims link to exact claim ids, artifact refs, and failure codes.
- Missing file, hash mismatch, schema mismatch, unauthenticated review result, unsupported feature, and negative-control regression each render as failures.
- Raw JSON remains downloadable.

### Gate 8: Release Truth

Pass criteria:

- Public docs do not claim a binary, package, Docker image, Homebrew formula, release tag, hosted demo, hosted CI result, Rekor inclusion, Base Sepolia evidence, or GA posture unless the bundle contains current evidence for it.
- Package owner and namespace are canonical.
- Local-only gates are labeled local-only.
- Any `rekor_inclusion_verified: false` result fails claims that require Rekor inclusion.

## Negative Fixture Floor

The public bundle should include at least these named negatives:

| Negative id | Required failure code | Claim protected |
| --- | --- | --- |
| `stale-capability` | `authority.capability.expired` | Verifiable authority |
| `bad-receipt-signature` | `receipt.signature.invalid` | Signed receipts |
| `policy-hash-mismatch` | `policy.hash.mismatch` | Guarded execution |
| `missing-evidence-node` | `evidence_graph.node.missing` | Transaction Passport |
| `order-id-mismatch` | `commerce.order_binding.mismatch` | Autonomous commerce |
| `quote-replay` | `commerce.quote.replay` | Provider selection |
| `overspend` | `commerce.budget.exceeded` | Budget authority |
| `unauthorized-settlement-route` | `settlement.route.unauthorized` | Settlement context |
| `stale-continuation-token` | `delegation.continuation.stale` | Recursive delegation |
| `route-plan-mismatch` | `delegation.route_plan.mismatch` | Multi-agent routing |
| `join-missing-parent` | `delegation.join.parent_missing` | Swarm fan-in |
| `runtime-proof-parity-drift` | `runtime.parity.drift` | Runtime proof regeneration |
| `over-disclosure` | `disclosure.excess_field` | Selective disclosure |
| `hidden-predicate-unsupported` | `disclosure.predicate.unsupported` | Disclosure honesty |
| `protocol-digest-mismatch` | `external.digest.mismatch` | Agent web envelope |
| `rekor-required-but-not-verified` | `supply_chain.rekor.required_unverified` | Release proof |

Every negative case must include:

- Original valid artifact ref.
- Mutated artifact ref.
- Mutation description.
- Expected verifier failure code.
- Observed verifier failure code.
- Verifier command.
- Verifier report digest.

## Acceptance Evidence Package

The launch evidence packet should be one archive and one public directory:

```text
target/proof-room/public-bundle/
target/proof-room/public-bundle.tar.zst
```

Required contents:

- `manifest.json`.
- `bundle-signature.dsse.json`.
- `claims/claim-registry.json`.
- `claims/non-claims.json`.
- `roots/transaction-passport.json`.
- `roots/evidence-graph.json`.
- `verifier/report.json`.
- `verifier/report.dsse.json`.
- `verifier/tool-versions.json`.
- Four stage directories.
- Negative corpus directories.
- Proof Room static UI export.
- Command transcript with exact commands and exit codes.

Final launch command:

```bash
chio proof verify target/proof-room/public-bundle --require denials --require commerce --require delegation --require disclosure --require external-envelope --require runtime-parity --json --out target/proof-room/public-bundle/verifier/final-report.json
```

Final launch pass criteria:

- `final-report.json` verdict is `pass`.
- All required claims pass.
- All required negative fixtures fail with expected codes.
- The Proof Room UI verdict matches `final-report.json`.
- The bundle can be copied to a clean machine and verified without private credentials.
- Network-dependent claims are either absent, marked advisory, or backed by explicit live evidence included in the bundle.

## Implementation Cut Line

The first implementation pass should not build every tab. It should build the verifier contract first:

1. Define `chio.proof_room_bundle.v1`, `ProofManifest`, `ProofClaim`, `ProofDenial`, and `ProofVerificationReport`.
2. Add fixture generation for `single-call-authority`.
3. Wrap IOA web3 output into `commerce-transaction-passport`.
4. Wrap runtime harness output into `recursive-runtime-swarm`.
5. Wrap buyer proof package and projection artifacts into `disclosure-and-agent-web-envelope`.
6. Add `chio proof verify` and `chio proof explain`.
7. Make the UI read only the normalized report and manifest.

The UI can trail the CLI. The homepage claim cannot trail the CLI. If `chio proof verify` cannot reproduce the public verdict from a clean checkout, Proof Room is not launch proof.
