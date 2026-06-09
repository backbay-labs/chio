# Chio Launch Roadmap

Status: build priority roadmap
Confidence: moderate. Sequencing is strong; effort estimates require owner review.

## Phase 0 - Proof Surface Freeze

Goal: stop proof fragmentation before adding more domain behavior.

Tasks:

1. Register artifact names and versioning rules for the Transaction Passport, evidence graph, commerce order context, swarm authority graph, disclosure capsule, settlement proof bundle, risk comptroller report, Agent Web Proof Envelope, and Proof Room bundle.
2. Add protocol sections for each artifact with canonical JSON rules.
3. Add schema stubs with failing tests for required fields and signature/digest bindings.
4. Define unsupported-action exclusions for the launch "every action" claim.
5. Assign one registry owner for `spec/schemas/registry.json`, `spec/schemas/MANIFEST.sha256`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, `claim-registry.v1.json`, and `proof-manifest.v1.json`.
6. Classify every proposed launch artifact as signed verifier artifact, control-plane export, example-only bundle shape, or future-scope artifact.

Exit criteria:

- schema names are stable;
- the verifier policy shape is stable;
- negative tests exist for missing root, wrong digest, wrong schema version, and unknown artifact type.

## Phase 1 - Minimal Transaction Passport

Goal: one signed root over one governed action.

Tasks:

1. Build the first Transaction Passport verifier slice in existing proof-package, control-plane, lineage, or CLI surfaces before creating any new crate.
2. Bind one kernel receipt, capability proof, guard decision, policy hash, request digest, response digest, and trust root.
3. Add `chio proof collect` and `chio proof verify`.
4. Add a minimal Proof Room fixture.

Exit criteria:

- a fresh checkout can run the verifier against a bundled fixture;
- one negative fixture fails for a real policy digest mismatch;
- verifier output is deterministic.

## Phase 1A - Runtime Enforcement Evidence

Goal: prove runtime authority is online-enforced, not only assembled after execution.

Tasks:

1. Add execution lease, nonce, revocation freshness, policy digest, sandbox attestation, and tool-server acknowledgement evidence for one side-effecting call.
2. Add receipt totality claims for allow, denial, and infrastructure failure paths.
3. Add verifier rejection for advisory evidence wired to authority edges.
4. Add runtime-security negative fixtures for missing lease, reused nonce, stale revocation, policy mismatch, sandbox mismatch, and missing denial receipt.

Exit criteria:

- a side-effecting runtime claim fails without a valid execution lease;
- advisory observations cannot satisfy authorization claims;
- every governed attempt has a terminal receipt or signed incident receipt.

## Phase 1B - First-Run Product Evidence

Goal: make the proof layer reproducible by an outsider.

Tasks:

1. Add `chio proof doctor --scenario single-call-authority --json`.
2. Emit first-run evidence with one allow receipt, one denial receipt, one minimal Transaction Passport, and one verifier report.
3. Add docs command log and release truth report.
4. Add static Proof Room loading evidence bound to the CLI verifier report.

Exit criteria:

- `chio proof doctor` fails if the valid fixture, invalid fixture, denial receipt, command log, or release truth evidence is missing;
- docs cannot claim public release, package, Docker, hosted, chain, or transparency evidence unless current evidence is present.

## Phase 2 - Commerce Order Context

Goal: prove autonomous commerce as a state machine, not a demo transcript.

Tasks:

1. Implement `chio.commerce.order-context.v1` and `chio.commerce.event-log.v1`.
2. Promote provider passport, reputation, federation, quote, mandate, budget, payment, fulfillment, settlement, dispute, and reconciliation into typed order events.
3. Add a replay ledger that derives order state from events.
4. Gate order advancement through a commerce admission verifier.
5. Add payment lifecycle, mandate allowance, dispute recovery, fraud assessment, currency liquidity, and recurring mandate state before adding more rails.

Exit criteria:

- an order cannot advance if quote, mandate, budget, or payment evidence does not bind the same order id;
- the event log replays to the same order state;
- settlement observer evidence cannot mutate state without a valid reconciliation transition.
- payment success alone cannot complete an order while capture, dispute, refund, chargeback, fraud, currency, or recurring-mandate state is unresolved.

## Phase 2A - Workflow Preflight

Goal: reject invalid autonomous plans before authority, budget, route, tool calls, settlement, or approval are consumed.

Tasks:

1. Define read-only preflight plan and report vocabulary.
2. Validate child scope, route plans, budgets, approvals, registry support, and revocation inputs before token minting.
3. Add a first negative fixture for broader child scope.

Exit criteria:

- preflight rejects a child task broader than its parent;
- preflight success is labeled as planning evidence, not live execution proof;
- rehearsal or simulation artifacts cannot satisfy live authority claims.

## Phase 3 - Recursive Swarm Authority

Goal: make multi-swarm coordination verifiable.

Tasks:

1. Add per-hop attenuation witnesses.
2. Add signed swarm task graph and continuation tokens.
3. Add route-plan receipts before cross-protocol dispatch.
4. Add multi-parent join receipts.
5. Add revocation epoch checks and budget pool leases.

Exit criteria:

- stale continuation tokens fail;
- revoked ancestor or leaf authority fails;
- route mismatch fails;
- fan-in join without the correct parent receipt set fails.

## Phase 4 - Lineage And Selective Disclosure

Goal: make cross-boundary review private and verifiable.

Tasks:

1. Reconcile projection v1 spec and implementation truth.
2. Add BBS projection v2 manifests.
3. Add kernel runtime BBS modes.
4. Add verifier privacy profiles with excess-disclosure rejection.
5. Add signed lineage subgraph export and leakage ledger.
6. Add cryptographic verification context for key state, revocation snapshots, nonce, audience, holder binding, algorithm policy, and transparency status.

Exit criteria:

- proof verifies cryptographically and semantically;
- forbidden disclosure fails;
- hidden predicates are policy-declared and typed;
- lineage subgraph signature and root binding verify.
- cryptographic proof fails under stale keys, wrong audience, replayed nonce, forbidden algorithm, or missing status snapshot.

## Phase 5 - Public Settlement Proof

Goal: make web3 and settlement evidence independently reproducible.

Tasks:

1. Define `chio.web3-settlement-proof-bundle.v1`.
2. Promote IOA web3 evidence to include registry roots, escrow state, bond state, tx hashes, block/finality, oracle conversion evidence, and dispute posture.
3. Add verifier recomputation from evidence, not narrative.
4. Bind public settlement report into the Transaction Passport.

Exit criteria:

- verifier recomputes settlement state;
- wrong chain id, stale block, wrong registry root, wrong escrow balance, or mismatched order id fails;
- public proof can be checked offline except for explicitly marked chain lookups.

## Phase 6 - Risk Comptroller And Facility

Goal: make risk, insurance, and reserve claims auditable.

Tasks:

1. Build `chio.risk.comptroller-report.v1`.
2. Define facility lifecycle and transition gates.
3. Reconcile exposure, reserve, bond, capital, coverage, claim, payout, settlement, reputation, and governance state.
4. Separate claim payout, reserve release, reserve slash, and market slash ledgers.
5. Add enterprise evidence export hooks for retention, legal hold, PII classification, data residency, approval, telemetry projection, control mapping, and incident review.
6. Add trust-market context for provider discovery, local scorecards, SLA commitments, collateral positions, guarantees, and adjudication jurisdiction.

Exit criteria:

- no transition can consume the same reserve twice;
- facility state can be replayed and verified;
- insurance copy is limited to what actuarial evidence supports.
- enterprise exports are redacted, approved, retained, and digest-bound to the same Transaction Passport;
- trust-market claims remain bounded and do not imply global scores, liquidity pools, underwriter markets, or slashing courts.

## Phase 7 - Agent Web Proof Envelope

Goal: project Chio proof across the agent web without overclaiming external standards.

Tasks:

1. Define detached envelope and projection manifest.
2. Implement protocol-specific projections for MCP, A2A, ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, VC, BBS, SD-JWT, Sigstore, SLSA, in-toto, and DSSE.
3. Add copy lint for bare `ACP` and overbroad standard claims.
4. Add interop verifier report.
5. Add operational source protocols for Standard Webhooks, CloudEvents, GraphQL, AsyncAPI, browser automation, RPA transcripts, SaaS connectors, OAuth/OIDC, SCIM, SPIFFE/SPIRE, Kubernetes admission, and OCI refs.

Exit criteria:

- each projection names what Chio proves and what the external protocol proves;
- digest bindings verify;
- ambiguous `ACP` copy fails lint.
- external signatures, webhook events, OAuth tokens, SPIFFE identities, Kubernetes admission, or OCI refs never become Chio capability authority by themselves.

## Phase 8 - Proof Room Launch Package

Goal: turn the proof system into a launchable public artifact.

Tasks:

1. Ship `chio proof` CLI path.
2. Ship a static Proof Room with bundle upload and fixture browsing.
3. Include valid and invalid fixtures for single action, commerce, swarm, disclosure, settlement, and risk.
4. Add release/package truth checks.

Exit criteria:

- reviewer can run the Docker quickstart and see the same proof room verdicts;
- public release/package state matches docs;
- proof room explains invalid fixtures without requiring codebase knowledge.
