# Third-Wave Debate Synthesis

Status: integrated feature debate synthesis
Sources: `../agent-debate/15-commerce-payments-debate.md` through `../agent-debate/22-ai-workflow-simulation-debate.md`
Confidence: high for priority order, moderate for exact schema placement.

## Verdict

The strongest additions are not more demos, more rails, or more external standards. The strongest additions are verifier depth around the places where the homepage claim can otherwise be attacked:

1. online runtime enforcement before tool side effects;
2. first-run product evidence and `chio proof doctor`;
3. merchant payment lifecycle replay beyond generic settlement proof;
4. cryptographic verification context for keys, revocation, audience, nonce, and transparency;
5. read-only workflow preflight before recursive execution;
6. enterprise evidence export and control mapping;
7. trust-market context around provider discovery, scorecards, SLAs, collateral, guarantees, and jurisdiction;
8. wider Agent Web projections for webhooks, events, GraphQL, connectors, identity, workload, Kubernetes, browser automation, and OCI refs.

The main rejection is scope bloat. Chio should not become a payment rail, compliance suite, identity provider, RPA standard, liquidity pool, global trust score, certification authority, workflow IDE, or hosted marketplace before the verifier spine proves the claims.

## Promote To P0

| Addition | Why it is P0 | First slice | Negative fixture |
| --- | --- | --- | --- |
| Runtime execution lease | A passport that proves only after-the-fact evidence can still miss online bypass. | One side-effecting call requires kernel allow receipt, execution lease, nonce, revocation freshness proof, policy digest, sandbox attestation, and tool-server ack. | Missing execution lease fails. |
| Receipt totality | "Every action" is false if denied, failed, abandoned, or infrastructure-failed attempts can disappear. | Stage 0 must show allow and denial receipts and a totality report. | Guard denial without terminal receipt fails. |
| Advisory evidence laundering guard | External payment success, traces, supply-chain proof, and UI observations cannot authorize tools. | Transaction Passport verifier rejects `advisory-observation` on authority edges. | Advisory observation wired to `authorizes` fails. |
| `chio proof doctor` and first-run evidence | A proof layer that needs insider setup is not launchable. | `chio proof doctor --scenario single-call-authority --json` validates valid and invalid fixtures, docs command log, and release truth. | First-run evidence without denial fails. |

## Promote To P1

| Addition | Why it matters | First slice |
| --- | --- | --- |
| Merchant payment lifecycle | Autonomous commerce needs capture, refund, dispute, chargeback, fraud, currency, PSP, and recurring mandate state, not only "payment happened". | Offline Stripe-shaped payment lifecycle fixture bound to AP2, ACP-Commerce, and order context. |
| Crypto verification context | BBS, SD-JWT, VC, and external envelopes are unsafe without key state, revocation, nonce, audience, holder binding, algorithm policy, and transparency status. | Disclosure capsule rejects wrong audience, stale key state, or replayed nonce. |
| Workflow preflight | Autonomous commerce should reject impossible or unauthorized plans before minting continuation tokens or spending budget. | Read-only preflight rejects broader child scope before execution. |
| Enterprise evidence export | Enterprise buyers need digest-bound telemetry, retention, legal hold, PII classification, data residency, approval, evidence export, control mapping, and incident review. | One risk-backed commerce fixture emits data governance report, evidence export bundle, telemetry projection, approval case, and control map. |
| Trust-market envelope | A trust network needs provider discovery, selection, local scorecards, SLAs, collateral, guarantees, and adjudication jurisdiction. | Marketplace-mode commerce fixture with three providers, local scorecard, SLA, collateral-backed guarantee, and jurisdiction receipt. |
| Webhook and CloudEvents projection | Real agent systems mutate the world through webhook and event surfaces not covered by MCP/A2A/OpenAPI alone. | Standard Webhooks plus CloudEvents projection through existing Agent Web envelope IDs. |

## Promote To P2

| Addition | Reason to defer | First useful later slice |
| --- | --- | --- |
| GraphQL mutation projection | Important SaaS surface, but lower than webhook/event proof and no new authority model. | One GraphQL mutation with operation name, schema digest, document digest, variables digest, and response digest. |
| Browser automation and RPA transcripts | High-risk mutation surface, but needs careful sandbox and transcript semantics. | WebDriver or WebDriver BiDi command transcript bound to Chio receipt and screenshot/download digests. |
| SIEM/OTel vendor adapters | Enterprise buyers need exports, but vendor-specific integrations should consume stable Chio projections. | Emit stable JSON or OTLP-shaped projection from signed evidence. |
| Conformance Passport | Valuable ecosystem primitive, but needs negative fixtures and verifier hashes first. | Signed conformance report over Stage 0 and Stage 1 fixture matrix. |
| Synthetic transaction generator | Useful for regression and red-team coverage after hand-authored fixture shapes stabilize. | Seeded generator that mutates exactly one invariant and emits expected failure code. |
| Hosted Proof Room and plugins | Useful distribution surfaces, but must consume CLI verifier reports only. | Read-only hosted bundle viewer and plugin shell that delegates to `chio proof verify`. |

## Defer Or Block

- Do not claim Chio is a payment rail, wallet, PSP, acquirer, or facilitator.
- Do not claim autonomous insurer pricing without actuarial backtest and capital adequacy artifacts.
- Do not claim global trust scores, permissionless provider markets, liquidity pools, risk syndication, underwriter markets, guarantee product markets, or slashing courts.
- Do not claim generic ZK, TEE, threshold, VC wallet, W3C BBS Data Integrity, SD-JWT VC, transparency-log, or post-quantum support without exact verifier-backed profiles.
- Do not claim generic RPA standard conformance or browser-standard conformance through Chrome DevTools Protocol.
- Do not let Proof Room, hosted mode, plugins, playgrounds, SIEM exports, or dashboards mint proof verdicts.

## Plan Deltas

### Runtime Security

Add a runtime security follow-on sprint after the minimal Transaction Passport sprint:

- `chio.runtime.execution-lease.v1`
- `chio.runtime.tool-server-ack.v1`
- `chio.runtime.revocation-freshness-proof.v1`
- `chio.runtime.sandbox-attestation.v1`
- `chio.policy.activation-receipt.v1`

The first implementation should stay local and deterministic. Hardware TEE and distributed revocation consensus can wait.

### Commerce Payments

Extend commerce plans with:

- `chio.commerce.payment-lifecycle.v1`
- `chio.commerce.mandate-allowance-ledger.v1`
- `chio.commerce.dispute-recovery-ledger.v1`
- `chio.commerce.fraud-assessment.v1`
- `chio.commerce.currency-liquidity-ledger.v1`
- `chio.commerce.recurring-agent-commerce.v1`

First slice: one Stripe-shaped offline fixture with AP2 mandate hashes, ACP-Commerce delegated token constraints, PSP lifecycle state, fraud assessment, Connect transfer posture, and currency ledger.

### Crypto And Privacy

Add a shared cryptographic verification context consumed by Transaction Passport, disclosure capsules, signed lineage subgraphs, and Agent Web envelopes:

- `chio.crypto.verification-context.v1`
- `chio.trust.key-state.v1`
- `chio.trust.revocation-snapshot.v1`
- `chio.transparency.inclusion-proof.v1`

Do not advertise these as external standard conformance. They are Chio verifier inputs.

### Workflow Simulation

Add read-only preflight and replay vocabulary:

- `chio.workflow.preflight-plan.v1`
- `chio.workflow.preflight-report.v1`
- `chio.workflow.what-if-delta.v1`
- `chio.workflow.rehearsal-run.v1`
- `chio.workflow.replay-capsule.v1`
- `chio.workflow.model-provider-conformance.v1`
- `chio.workflow.approval-gate.v1`

First slice: reject broader child scope before any continuation token or tool invocation exists.

### Enterprise Evidence

Add enterprise projections rooted in the Transaction Passport verifier report:

- `chio.enterprise.telemetry-projection.v1`
- `chio.enterprise.data-governance-report.v1`
- `chio.enterprise.policy-pack-manifest.v1`
- `chio.enterprise.approval-case.v1`
- `chio.enterprise.access-decision-report.v1`
- `chio.enterprise.evidence-export-bundle.v1`
- `chio.enterprise.control-evidence-map.v1`
- `chio.enterprise.incident-review-case.v1`
- `chio.enterprise.regulator-review-bundle.v1`

These are evidence exports and control maps, not a compliance product.

### Trust-Market Context

Add bounded marketplace context:

- `chio.commerce.provider-discovery-snapshot.v1`
- `chio.commerce.provider-selection-report.v1`
- `chio.trust.scorecard-snapshot.v1`
- `chio.trust.reputation-import-report.v1`
- `chio.commerce.sla-commitment.v1`
- `chio.commerce.sla-performance-report.v1`
- `chio.risk.collateral-position-report.v1`
- `chio.risk.capital-commitment-snapshot.v1`
- `chio.risk.guarantee-decision.v1`
- `chio.risk.adjudication-jurisdiction-receipt.v1`

These make provider selection and guarantees inspectable without launching a permissionless market.

### Agent Web Interop

Widen the Agent Web source protocol vocabulary before adding new schema IDs. First slices should use the existing Agent Web envelope, projection manifest, and interop verifier report.

Add source protocol values for:

- Standard Webhooks;
- OpenAPI webhooks and callbacks;
- GraphQL and GraphQL-over-HTTP;
- AsyncAPI;
- CloudEvents;
- WebDriver and WebDriver BiDi;
- browser/vendor automation transcripts;
- desktop RPA transcripts;
- Gmail, Calendar, Slack, Drive, RFC 5322, iCalendar, and JMAP Mail;
- OAuth 2.0 and OpenID Connect;
- SCIM;
- SPIFFE/SPIRE;
- Kubernetes AdmissionReview;
- OCI image, artifact, and distribution referrers.

First slice: Standard Webhooks plus CloudEvents. No artifact-registry update is needed until a verifier trusts Chio-signed automation transcripts directly.

## Revised Near-Term Sequence

1. Finish minimal Transaction Passport and `chio proof verify`.
2. Add runtime security slice 0: execution lease, nonce, revocation freshness, sandbox attestation, tool-server ack, and advisory laundering rejection.
3. Add DX slice 0A: `chio proof doctor`, first-run evidence with allow and denial, command log, and release truth.
4. Add commerce payments slice 0: payment lifecycle and mandate allowance ledger over one offline PSP-shaped fixture.
5. Add workflow preflight slice 0: reject broader child scope before execution.
6. Add crypto context slice 0: key state, revocation snapshot, nonce/audience binding, algorithm policy, and transparency status in disclosure verification.
7. Add enterprise export slice 0: data governance, redacted evidence export, telemetry projection, approval case, and control map.
8. Add Agent Web interop slice 0: Standard Webhooks plus CloudEvents projection.
9. Add trust-market slice 0: provider discovery, selection report, local scorecard, SLA, collateral, guarantee, and jurisdiction receipt.

## Bottom Line

The debate team did not find a need for a giant new product. It found a need for sharper proof contracts around execution, commerce payments, cryptographic context, preflight, enterprise export, marketplace selection, and operational interop. Add those as verifier-backed slices. Block everything that would make Chio look like an unverified marketplace, payment rail, compliance platform, or universal agent protocol.
