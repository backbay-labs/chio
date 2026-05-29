# Full Vision Execution Program

**Date:** 2026-03-23
**Status:** Historical internal milestone narrative
**Scope:** Execute the roadmap through the Q2 2027 trust/economy vision as a dependency-driven multi-track program

> Chio-owned protocol, schema, runtime, SDK, and storage surfaces are current
> v1 only. This document is not active protocol execution guidance unless a
> section is reconciled with accepted ADRs and `spec/PROTOCOL.md`.

---

## Program Rules

1. Treat the roadmap as a dependency graph, not a calendar.
2. Run independent tracks in parallel, but keep one integration lane responsible for merge, contract review, and green CI.
3. Do not claim a track complete until its exit criteria are verified in code, docs, and tests.
4. Design-partner pressure can reorder priority inside a wave, but it does not remove technical dependencies.

---

## Track Map

### Track A: Core Productization

**Goal:** production launch readiness for the trust/control plane.

**Includes:**
- Python SDK release posture
- Go SDK release posture
- dashboard hardening
- deployment docs
- release engineering
- observability, backup/restore, migrations, failover drills

**Primary dependency:** already-shipped Milestone A substrate

### Track B: Economy

**Goal:** truthful economic execution and operator-facing spend/reporting workflows.

**Includes:**
- payment bridge interface
- first payment rail
- receipt-linked settlement
- cost attribution reporting
- pricing and budget-planning examples

**Primary dependency:** canonical settlement semantics and receipt attribution

### Track C: Reputation

**Goal:** deterministic local trust scoring and reputation-gated issuance.

**Includes:**
- `chio-reputation`
- deterministic metric computation
- policy hooks
- graduated issuance controls

**Primary dependency:** local attribution + analytics substrate

### Track D: Portable Trust

**Goal:** portable credentials and cross-org trust verification.

**Includes:**
- `did:chio`
- verifier libraries
- Agent Passport
- cross-org delegation flows

**Primary dependency:** local reputation model and stable verifier semantics

### Track E: Ecosystem

**Goal:** broaden adoption surface and trust portability.

**Includes:**
- A2A adapter
- Chio Certify
- identity federation
- conformance suite release

**Primary dependency:** stable SDKs and integration-grade contracts

### Track F: Compliance and Launch

**Goal:** enterprise-ready evidence, reporting, and operating model.

**Includes:**
- compliance evidence export
- operator reporting
- Colorado/EU mapping maintenance
- launch documentation
- security/threat-model review

**Primary dependency:** receipt/query/analytics substrate

### Track G: Integration Lane

**Goal:** keep the program shippable while all other tracks move in parallel.

**Includes:**
- cross-track merge review
- CI stabilization
- contract drift review
- migration compatibility review
- release-candidate qualification

**Primary dependency:** none; this runs continuously

---

## Release Structure

## Phase 1: Launch Surface Closure

**Objective:** finish the remaining near-term substrate and operator surface so the trust/control plane is deployable without caveats.

**Track focus:**
- Track A
- Track F
- Track G

**Required outcomes:**
- Python SDK moved from scaffold posture to release-ready beta posture
- Go SDK moved from scaffold posture to release-ready beta posture
- dashboard/API boundary hardened and regression-covered
- dashboard packaging/deployment story documented
- compliance evidence export implemented and verified
- release and operations checklist documented

**Phase 1 issue set:**
- `P1-05`
- `P1-06`
- `P1-07`
- `P1-08`
- pulled-forward evidence export foundation from former `P3-06`

**Exit criteria:**
- Rust workspace green
- SDK-specific checks green
- dashboard build and tests green
- no known contract drift between dashboard, SDKs, and trust-control APIs

## Phase 2: Economic Execution

**Objective:** make Chio economically real, not just economically shaped.

**Track focus:**
- Track B
- Track F
- Track G

**Required outcomes:**
- payment bridge interface in code
- one truthful payment rail
- receipt-linked settlement
- delegation-chain cost attribution
- operator-facing reporting

**Phase 2 issue set:**
- Completed: `P2-01`, `P2-02`, `P2-03`, `P2-04`, `P2-05`, `P2-06`

## Phase 3: Local Trust Enforcement

**Objective:** turn receipts into usable local trust and policy decisions.

**Track focus:**
- Track C
- Track F
- Track G

**Required outcomes:**
- `chio-reputation`
- deterministic local scoring
- reputation-gated issuance
- certification skeleton available to trust launch claims

**Phase 3 issue set:**
- Completed: `P3-01`
- Remaining:
- `P3-02`

## Phase 4: Portable Trust

**Objective:** make trust portable across organizations.

**Track focus:**
- Track D
- Track E
- Track G

**Required outcomes:**
- `did:chio`
- verifier libraries
- Agent Passport alpha
- first cross-org trust flow

**Phase 4 issue set:**
- `P3-03`
- `P3-04`

## Phase 5: Ecosystem Expansion

**Objective:** widen the adoption surface without losing contract integrity.

**Track focus:**
- Track E
- Track F
- Track G

**Required outcomes:**
- A2A adapter
- compliance-specific report views and verifier tooling on top of the existing evidence package
- identity federation
- conformance suite/community release

**Phase 5 issue set:**
- `P3-05` completed on 2026-03-23
- identity federation work from roadmap

---

## Historical Work: Phase 5

### Completed In This Session

- Create this execution program and freeze wave boundaries.
- Complete the first dashboard/API hardening slice:
  - move sparkline data onto backend receipt analytics
  - fix detail-panel subject resolution so agent-cost history is keyed by subject rather than capability ID
  - add dashboard API regression tests
  - add dashboard README with deploy/test/build instructions
  - replace the heavyweight chart dependency with a lightweight SVG sparkline
- Complete the first SDK release-posture slice:
  - centralize Python SDK version/client defaults
  - add Python packaging metadata and typed-package marker
  - centralize Go SDK version defaults
  - align Go SDK docs with the actual current release posture
- Ship the first A2A adapter skeleton:
  - add the new `crates/chio-a2a-adapter` workspace crate
  - support A2A Agent Card discovery plus `JSONRPC` and `HTTP+JSON` `SendMessage`
  - expose one Chio tool per A2A skill with explicit `metadata.chio.targetSkillId` routing
  - verify with direct adapter tests, a kernel receipt test, and full `cargo test --workspace`
- Complete the second dashboard hardening slice:
  - add explicit missing-token operator guidance
  - add component tests for token-loss, empty corpus, and lineage failure/empty states
  - align the long-form dashboard guide with the shipped analytics-backed sparkline behavior
- Pull compliance evidence export forward into an implementation-ready plan:
  - define CLI shape
  - define package layout
  - define inclusion-proof generation strategy
  - define kernel/CLI module boundaries
- Implement the local compliance evidence export path:
  - add `chio evidence export` CLI wiring
  - add kernel-side bundle assembly for receipts, child receipts, checkpoints, lineage, and inclusion proofs
  - attach optional policy source + metadata when `--policy-file` is provided
  - add `--require-proofs` enforcement for fully checkpointed exports
  - verify the export with dedicated kernel and CLI tests
- Complete the SDK release-qualification slice:
  - fix Python distribution identity so the published package is `chio-py` while the import remains `chio`
  - move Python and Go SDK docs from alpha posture to release-ready beta posture
  - add package-specific release docs for artifact verification and publication mechanics
- Complete the payment bridge contract slice:
  - add `crates/chio-kernel/src/payment.rs`
  - expose `PaymentAdapter`, `PaymentAuthorization`, `PaymentResult`, and `RailSettlementStatus`
  - centralize canonical receipt-side settlement mapping through `ReceiptSettlement`
  - wire the kernel's monetary allow/deny receipt construction through the new settlement helpers
  - add kernel tests for adapter installation and truthful failed-settlement receipts when a tool overruns the charged amount
  - verify the slice with `cargo test -p chio-kernel` and `cargo test --workspace`
- Harden monetary pre-execution denial semantics:
  - add reversible budget-charge support to the local and remote budget stores
  - release provisional monetary budget charges when a guard denies before tool execution
  - emit deny receipts with truthful attempted-cost metadata after that rollback
  - verify the remote control-service path still passes the workspace and cluster lanes
- Complete the first thin payment rail bridge:
  - add the concrete `X402PaymentAdapter` in `crates/chio-kernel/src/payment.rs`
  - authorize prepaid payment before execution and deny truthfully on auth failure
  - unwind aborted monetary invocations so tool errors do not leak budget or prepaid settlement
  - reconcile provisional internal debits down to actual reported cost when the rail is not prepaid
  - verify the bridge with targeted payment tests, full kernel tests, `cargo test -p chio-cli --bin chio`, and `cargo test --workspace`
- Complete delegation-chain cost attribution reporting:
  - add kernel-side cost-attribution report types and aggregation over matching financial receipts
  - expose `GET /v1/reports/cost-attribution` on the trust-control service
  - persist observed delegated capability snapshots during live tool-call evaluation so leaf receipts gain chain context
  - replicate lineage snapshots across clustered trust-control nodes so follower reports and lineage endpoints converge
  - verify the slice with targeted kernel tests, receipt-query HTTP tests, trust-cluster failover tests, and full `cargo test --workspace`
- Complete operator-facing reporting:
  - add `GET /v1/reports/operator` to compose analytics, cost attribution, budget utilization, and compliance/export readiness
  - derive budget-pressure rows from persisted capability lineage plus grant budgets without fabricating missing joins
  - expose operator-summary cards in the dashboard for activity, spend, budget pressure, and compliance posture
  - verify the slice with kernel compliance tests, receipt-query HTTP tests, dashboard tests/build, and full `cargo test --workspace`
- Complete the local reputation substrate:
  - add the new `chio-reputation` workspace crate with a pure local scoring API over normalized receipts, capability-lineage records, budget-usage records, and optional incident inputs
  - implement deterministic Phase 1 metrics for boundary pressure, resource stewardship, least privilege, history depth, specialization, delegation hygiene, reliability, and incident correlation
  - preserve truthful `unknown` semantics for unavailable metrics and renormalize the composite score across the available metrics only
  - verify the crate with dedicated fixture tests and a full `cargo test --workspace` run
- Complete reputation-gated issuance:
  - extend HushSpec/runtime loading with `extensions.reputation` issuance policy materialization, probation settings, and tier scope ceilings including monetary caps
  - add a shared capability-authority wrapper that computes local scorecards from persisted receipts, lineage snapshots, and budget usage before signing capabilities
  - wire the same enforcement path into local CLI issuance and `chio trust serve --policy ...`, with successful issuance persisting lineage snapshots at the authority boundary
  - add unit coverage for probationary denial/allow paths plus an HTTP integration test proving the trust-control service enforces the same gate
  - verify the slice with `cargo test -p chio-cli` and full `cargo test --workspace`
- Complete `did:chio` identity resolution:
  - add the new `crates/chio-did` workspace crate with self-certifying DID parsing, canonicalization, and DID Document resolution for Chio Ed25519 public keys
  - ship stable `Ed25519VerificationKey2020` verification methods plus validated optional `ChioReceiptLogService` endpoints
  - expose the resolver through `chio did resolve --did ...` and `chio did resolve --public-key ...`
  - verify the slice with crate tests, CLI integration tests, `cargo test -p chio-cli`, and full `cargo test --workspace`
- Complete Agent Passport alpha:
  - add the new `crates/chio-credentials` workspace crate with signed reputation credentials, passport bundling, offline verification, and filtered presentation helpers
  - expose `chio passport create`, `chio passport verify`, and `chio passport present`
  - build credentials directly from the local reputation corpus plus receipt/checkpoint evidence
  - verify the slice with crate tests, CLI passport end-to-end tests, and full `cargo test --workspace`

### Current Phase 4 Focus

- `P3-01` completed on 2026-03-23
  - added the new `chio-reputation` workspace crate without creating a `chio-kernel` dependency cycle
  - shipped deterministic local scorecards over the current unreleased v1 substrate: receipts, lineage, budget usage, and optional incident inputs
  - implemented truthful `unknown` metric handling plus composite-score renormalization for partially available local data
  - verified with crate-specific fixture tests and a full `cargo test --workspace` run
- `P3-02` completed on 2026-03-23
  - shipped policy-backed issuance gating at the shared authority boundary for both local CLI flows and `trust serve`
  - enforced probation/tier ceilings over TTL, operations, invocation caps, required constraints, and monetary grant caps before capability issuance
  - made successful issuance persist lineage snapshots inside the same authority wrapper so local scoring and future joins converge by construction
  - verified with focused policy/issuance tests, a trust-service HTTP integration test, `cargo test -p chio-cli`, and full `cargo test --workspace`
- `P3-03` completed on 2026-03-23
  - shipped the `chio-did` crate with self-certifying `did:chio` parsing plus DID Document resolution for both agent and kernel public keys
  - emitted stable `Ed25519VerificationKey2020` verification methods and optional validated `ChioReceiptLogService` entries
  - added the operator-facing `chio did resolve` command for resolving either a DID or a raw public key
  - verified with crate tests, CLI integration tests, `cargo test -p chio-cli`, and full `cargo test --workspace`
- `P3-04` completed on 2026-03-23
  - shipped the `chio-credentials` crate with signed single-issuer reputation credentials, Agent Passport bundling, offline verification, and filtered presentation helpers
  - added `chio passport create`, `chio passport verify`, and `chio passport present`
  - tied credential issuance to the local reputation corpus plus receipt/checkpoint evidence, with optional checkpoint-required creation
  - verified with crate tests, CLI end-to-end passport tests, and full `cargo test --workspace`
- `P3-18` completed on 2026-03-24
  - widened `chio mcp serve-http` identity federation from Ed25519-only OIDC bootstrap into discovery-backed JWKS verification for `EdDSA`, RSA (`RS*`, `PS*`), and EC (`ES256`, `ES384`) JWTs
  - kept the verifier fail-closed by selecting trusted keys via `kid` plus algorithm compatibility and denying kid-less tokens whenever the issuer exposes multiple compatible keys
  - added end-to-end OIDC discovery coverage for `RS256` and `ES256`, focused verifier coverage for `PS256` and `ES384`, and hardened revocation admin-path tests onto bind-retry startup handling after a workspace flake exposed a readiness race
  - verified with focused `chio-cli` auth tests, targeted `mcp_serve_http` integration tests, and full `cargo test --workspace`
- `P3-19` completed on 2026-03-24
  - added explicit OAuth2 token introspection for opaque bearer admission on `chio mcp serve-http`, including confidential-client auth to the introspection endpoint and reuse of the same stable principal-to-subject derivation path already shipped for JWT-backed federation
  - kept the non-JWT lane fail-closed: inactive introspected tokens deny, issuer/audience/scope checks still apply, the introspection endpoint must be `https` or localhost-only `http`, and only bearer-style token types are accepted when the provider returns one
  - added pure verifier coverage for active/inactive introspected tokens plus an end-to-end `mcp_serve_http` test proving opaque-token sessions converge on one stable federated subject
  - verified with focused `chio-cli` auth tests, targeted `mcp_serve_http` integration tests, `cargo test -p chio-cli`, and full `cargo test --workspace`
- `P3-20` completed on 2026-03-24
  - extended `chio-a2a-adapter` so declared `apiKeySecurityScheme` requirements can now be satisfied for `location: query` and `location: cookie`, not just `location: header`
  - widened the adapter request-auth model into one truthful transport shape carrying headers, query params, cookies, and TLS mode together so all mediated A2A paths apply the same fail-closed auth logic
  - added direct adapter coverage for query and cookie API-key negotiation, a pure fail-closed query-auth denial test, and a kernel end-to-end allow-receipt path for query-authenticated invocation
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, `cargo test --workspace`, and `git diff --check`
- `P3-21` completed on 2026-03-24
  - hardened `chio-a2a-adapter` lifecycle semantics so `historyLength` is only sent on `SendMessage` and `GetTask` when the Agent Card advertises `capabilities.stateTransitionHistory = true`
  - closed the protocol-truth gap where Chio parsed that capability but did not enforce it, making unsupported task-history requests deny locally instead of probing undefined upstream behavior
  - added direct lifecycle-capability tests for unsupported `history_length` usage while preserving supported-path transport and kernel receipt coverage for cards that do advertise state-transition history
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, `cargo test --workspace`, and `git diff --check`
- `P3-22` completed on 2026-03-24
  - hardened `chio-a2a-adapter` task lifecycle validation so `SendMessage` task responses, `GetTask` results, streamed `statusUpdate` events, and streamed `artifactUpdate` events are rejected fail-closed when required lifecycle fields are missing
  - closed the second protocol-truth gap in the A2A lifecycle lane by validating the lifecycle payloads themselves instead of only counting top-level response variants
  - added direct validation tests for malformed task, status-update, and artifact-update payloads while preserving the existing good-path transport and kernel receipt coverage
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, `cargo test --workspace`, and `git diff --check`
- `P3-23` completed on 2026-03-24
  - deepened `chio mcp serve-http` identity federation by propagating canonical enterprise identity metadata into `authContext.method.federatedClaims` instead of discarding it after principal derivation
  - the bearer-authenticated lane now preserves `clientId`, `objectId`, `tenantId`, `organizationId`, `groups`, and `roles` from verified JWT and introspection claims, with normalization and provider-aware client/object claim capture
  - added unit coverage for claim normalization plus end-to-end `mcp_serve_http` coverage proving the admin trust surface exposes federated claim context for direct JWT, Azure-profile OIDC discovery, and opaque-token introspection flows
  - verified with focused `chio-core` and `chio-cli` auth tests plus targeted `mcp_serve_http` federation integration tests
- `P3-24` completed on 2026-03-24
  - extended `chio-a2a-adapter` so declared `httpAuthSecurityScheme: { scheme: \"basic\" }` requirements can now be satisfied truthfully instead of being treated as unsupported
  - added adapter configuration for HTTP Basic auth, fail-closed local denial when required Basic credentials are missing, and a kernel end-to-end allow-receipt path for Basic-authenticated A2A invocation
  - narrowed the remaining A2A auth-matrix gap from “HTTP auth beyond bearer” to custom schemes and deeper federation/partner hardening
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, targeted auth tests, and `git diff --check`
- `P3-25` completed on 2026-03-24
  - added the first challenge-bound passport presentation protocol on top of the shipped single-issuer Agent Passport alpha
  - introduced portable challenge documents carrying verifier identity, nonce, TTL, selective-disclosure hints, and optional embedded verifier policy, plus holder-signed responses bound to the passport subject DID
  - exposed the full loop through `chio passport challenge create`, `chio passport challenge respond`, and `chio passport challenge verify`, with structural verification, exact expected-challenge matching, and optional embedded-policy evaluation
  - verified with new credential-crate presentation tests, expanded CLI passport end-to-end coverage, `cargo test -p chio-credentials`, `cargo test -p chio-cli --test passport`, and full `cargo test --workspace`
- `P3-26` completed on 2026-03-24
  - added the first operator-facing local-versus-portable reputation comparison surface through `chio reputation compare --subject-public-key ... --passport ...`
  - kept the comparison contractually aligned by reusing the existing local inspection path plus the existing passport verification/evaluation path, then computing explicit per-credential metric drift as `local_minus_portable`
  - supported both direct local-db execution and trust-service-backed local inspection via `--control-url`, while keeping portable artifact verification client-side and deterministic
  - verified with new CLI integration coverage for both local and trust-service-backed flows plus full `cargo test --workspace`
- `P3-27` completed on 2026-03-24
  - added signed bilateral receipt-sharing policy documents through `chio evidence federation-policy create`
  - extended `chio evidence export --federation-policy ...` so the final package query is constrained to the signed bilateral scope, proof requirements can be enforced by policy, and the signed policy is embedded for offline exchange
  - extended `chio evidence verify` so it verifies the federation policy signature, export timestamp window, proof requirements, and query containment instead of treating the policy as a passive file
  - verified with new evidence-export integration coverage plus full `cargo test --workspace`
- `P3-28` completed on 2026-03-24
  - extended local-versus-portable comparison from CLI into trust-control with `POST /v1/reputation/compare/:subject_key`
  - moved the CLI `reputation compare --control-url` path onto that shared backend contract so remote comparison logic is single-sourced
  - added a dashboard-side portable comparison panel that uploads a passport JSON artifact, calls the trust-control comparison endpoint, and renders subject match, local score, policy acceptance, and per-credential drift
  - verified with new trust-service HTTP integration coverage, dashboard API/component tests, `npm run build`, and full `cargo test --workspace`
- `P3-29` completed on 2026-03-24
  - extended trust-control with live remote evidence export through `POST /v1/evidence/export`
  - moved `chio evidence export --control-url ...` onto the same prepared-query, signed federation-policy, and proof-requirement contract already used by local evidence export
  - verified with new end-to-end remote `evidence_export` integration coverage plus full `cargo test --workspace`
- `P3-30` completed on 2026-03-24
  - added the first live cross-org portable-trust issuance flow through `chio trust federated-issue` and `POST /v1/federation/capabilities/issue`
  - trust-control now consumes an exact expected passport challenge plus a challenge-bound presentation response, requires an embedded verifier policy, derives the subject key from the presented `did:chio`, and issues exactly one locally signed capability from a supplied capability policy
  - kept the scope boundary honest by supporting one requested default capability per request instead of pretending multi-capability federated issuance is atomic
  - verified with new `federated_issue` integration coverage plus full `cargo test --workspace`
- `P3-31` completed on 2026-03-24
  - added signed federated delegation-policy documents through `chio trust federated-delegation-policy-create`
  - extended `chio trust federated-issue` and `POST /v1/federation/capabilities/issue` so the live portable-trust issuance flow can now enforce a signed scope/TTL ceiling, require a locally trusted signer, and persist a delegation anchor into capability lineage for later chain reconstruction
  - verified with expanded `federated_issue` integration coverage plus full `cargo test --workspace`
- `P3-32` completed on 2026-03-24
  - added bilateral evidence consumption through `chio evidence import` and `POST /v1/evidence/import`, with full package verification before persistence plus imported federated-share indexing for upstream capability lookup
  - extended `chio trust federated-issue` and `POST /v1/federation/capabilities/issue` with parent-bound `--upstream-capability-id` continuation so a new local anchor can bridge to an imported upstream capability and reconstruct a truthful multi-hop cross-org chain
  - kept the cross-org boundary honest by preserving local lineage foreign keys and modeling imported parents through explicit federated lineage bridges rather than pretending they are native local issuers
  - verified with new multi-hop `federated_issue` coverage, `cargo test -p chio-cli --test evidence_export`, and full `cargo test --workspace`

### Release Status

Phase 1 launch-surface closure is complete. Phase 2 economic execution is
complete. Phase 3 local reputation work is complete. Phase 4 portable trust is
now active. The local reputation substrate,
issuance-time enforcement, `did:chio` identity layer, and Agent Passport alpha
are real and verified. The thin A2A adapter skeleton is now also real and
verified against the A2A v1.0.0 discovery plus `SendMessage` surface, and now
also supports truthful `GetTask` follow-up over both bindings without leaving
the normal capability or receipt pipeline. The same adapter now also supports
explicit `SendStreamingMessage` over both bindings, with each upstream A2A
`StreamResponse` captured as one Chio stream chunk and prematurely closed
streams turned into incomplete receipts instead of silent truncation. It now
also negotiates required bearer, HTTP Basic, and API-key
header/query/cookie auth directly from Agent Card metadata, fails closed on unsupported required
schemes such as mTLS, and propagates tenant-scoped request metadata without
leaving those semantics implicit. It now also supports direct `SubscribeToTask` follow-up
streaming over both bindings, and its HTTP tenant shaping matches the current
official A2A proto path semantics instead of a local query-string convention.
It now also supports direct `CancelTask` and task push-notification config
create/get/list/delete over both bindings, while keeping those task-management
operations inside the normal capability and receipt pipeline and validating
remote callback URLs fail closed. It now also enforces
`capabilities.stateTransitionHistory` before sending `historyLength` on
`SendMessage` or `GetTask`, so task-history requests stay truthful to the
advertised upstream capability surface. It now also rejects malformed
upstream task, status-update, and artifact-update lifecycle payloads
fail-closed instead of only validating the top-level response variant shape.
It also now supports real OAuth2
client-credentials and OpenID Connect token acquisition when the Agent Card
declares those bearer schemes, with in-process token caching so repeated
mediated calls do not reissue token requests unnecessarily. It now also
supports truthful mTLS transport when the Agent Card declares
`mtlsSecurityScheme`, including custom trusted root CAs, real client-cert
handshake coverage for both Agent Card discovery and mediated invocation, and
fail-closed denial when a required client identity is missing. Offline evidence verification is now also real, and the
first identity-federation alpha is shipped for bearer-authenticated
`serve-http` sessions via stable principal-to-subject derivation. That lane
now also supports startup-time OIDC discovery, JWKS bootstrap for `EdDSA`,
RSA, and `ES256`/`ES384`, explicit OAuth2 token introspection for opaque
bearer tokens, and provider-aware principal mapping for
Generic/Auth0/Okta/Azure AD claim shapes, with fail-closed startup if the IdP
metadata is insecure or exposes no compatible signing key.
That same lane now also preserves normalized enterprise identity context in
`authContext.method.federatedClaims`, including `clientId`, `objectId`,
`tenantId`, `organizationId`, `groups`, and `roles` when those claims are
present on verified JWT or introspection responses, so operators no longer
lose that context after principal derivation.
Local reputation is now also queryable through both
`chio reputation local` and `GET /v1/reputation/local/:subject_key`, reusing
the exact same corpus, probation, and tier-resolution path as issuance. The
first portable-verifier lane is now also real through `chio passport evaluate`
plus reusable verifier policy logic in `chio-credentials`. That lane now also
supports challenge-bound presentations with holder proof-of-possession tied to
the passport subject DID, selective-disclosure hints, optional embedded
verifier policy, and exact expected-challenge matching. The first bilateral
cross-org receipt-sharing contract is now also real through signed federation
policies plus constrained evidence-export packages, and that bilateral package
exchange can now be generated live over trust-control instead of only from a
local SQLite checkout. The first live portable-presentation-backed issuance
path is now also real through `chio trust federated-issue`, and that lane now
extends through verified `chio evidence import` consumption into a real
multi-hop cross-org delegation chain. Signed federated delegation-policy
documents can now bind to an exact imported upstream capability, and the local
trust-control service preserves that bridge explicitly instead of collapsing it
into a fake local root. The first operator comparison surface is now available
through trust-control and dashboard in addition to CLI. The next coding slice
is cross-org identity surfaces, remaining A2A custom/federated auth hardening,
shared remote evidence references in operator surfaces, and multi-issuer
portable-trust design.

### Next 10 Execution Tasks

1. Extend identity federation beyond the shipped bearer-authenticated plus federated-claims lane into SCIM/SAML, provider-admin integration, and broader cross-org identity surfaces.
2. Scope the remaining A2A auth matrix after bearer, HTTP Basic, API-key header/query/cookie, OAuth/OpenID, and mTLS.
3. Deepen A2A long-running task lifecycle beyond the now-shipped `GetTask` / `SubscribeToTask` / `CancelTask` plus push-notification config CRUD, state-transition-history enforcement, and lifecycle payload validation surface.
4. Add the first certification registry/storage design once multiple signed artifacts exist.
5. Start anomaly-detection primitives once reputation metrics are deterministic.
6. Design per-capability numeric delegation-depth ceilings for portable credentials.
7. Design multi-issuer passport aggregation semantics without weakening verification guarantees.
8. Extend the shipped operator-facing comparison and drift-reporting view with verifier-policy upload and shared remote evidence references.
9. Define portable verifier policy distribution, verifier replay-state management, and wallet transport semantics on top of the shipped local evaluator plus challenge-response lane.
10. Extend the new multi-hop federation lane from imported parent resolution into broader cross-org receipt analytics and downstream operator reporting.

---

## Operating Cadence

### Daily

- Keep `cargo test --workspace` green.
- Keep SDK checks green.
- Keep wave scope explicit.

### Per Merge Window

- Review contract drift across:
  - `chio-core`
  - `chio-kernel`
  - trust-control API
  - dashboard types
  - SDK public types

### Per Wave Exit

- Update this document
- Update [V2_EXECUTION_BACKLOG.md](V2_EXECUTION_BACKLOG.md)
- Update [STRATEGIC_ROADMAP.md](../operations/STRATEGIC_ROADMAP.md) only when shipped reality changes sequencing

---

## Bottom Line

The fastest path to the full vision is:

1. close the remaining launch-surface substrate,
2. make payment and reporting real,
3. enforce local reputation,
4. make trust portable,
5. then expand the ecosystem surface on top of a stable base.
