# Historical Internal Milestone Backlog

> This document is historical pre-release planning. Chio-owned protocol,
> schema, runtime, SDK, and storage surfaces are current v1 only. Do not use
> this backlog as active execution guidance without reconciling it with
> `spec/PROTOCOL.md` and the accepted protocol ADRs.

**Date:** 2026-03-23
**Source:** post-v2 code review, testing pass, and roadmap gap analysis
**Purpose:** turn the current review into an issue-sized execution queue

## Priority Model

- `P0`: correctness, contract, or release-signal blockers
- `P1`: finish the missing substrate required by the roadmap's near-term promises
- `P2`: next product and ecosystem slices already called for in the roadmap
- `P3`: later roadmap work that is real but not on the immediate execution path

## Recommended Order

1. Historical note: close all `P0` items before calling the internal milestone foundation bulletproof.
2. Historical note: finish the `P1` substrate before starting reputation or payment-rail work.
3. Historical note: `P2` was a candidate product roadmap after the foundation stabilized.
4. Historical note: keep `P3` out of the immediate execution wave unless a design partner forced it.

## Verified Completed (2026-03-23)

- `P0-01` Unify `settlement_status` across runtime, spec, guides, and examples.
- `P0-02` Fix multi-grant `budget_remaining` accounting.
- `P0-03` Make `max_spend_per_window` consume planned monetary cost.
- `P0-04` Stabilize trust-control readiness and cluster verification paths.
- `P0-05` Extend retention/archive to cover child receipts.
- `P0-06` Archive capability-lineage snapshots with archived receipts.
- `P1-01` Persist universal per-receipt grant attribution.
- `P1-02` Ship backend receipt analytics API with tests.
- `P1-03` Add tool manifest pricing metadata.
- `P1-04` Harden TypeScript SDK packaging for dist-backed npm publication.
- `P1-05` Move Python SDK from alpha scaffold to release-ready beta.
- `P1-06` Move Go SDK from alpha scaffold to release-ready beta.
- `P3-06` Build the compliance evidence export package.
- `P1-07` Harden the dashboard/API boundary with regression coverage and operator-path tests.
- `P1-08` Harden dashboard production packaging, auth guidance, and deployment docs.
- `P2-01` Define the payment bridge interface and receipt-linked settlement model in code.
- `P2-02` Build one thin payment rail bridge with truthful pre-execution authorization and settlement metadata.

## P0: Correctness And Contract Blockers

No open `P0` items remain. The current exit signal for Milestone A is:

- `cargo test --workspace` green
- canonical receipt/economy contract aligned across code and docs
- archived audit data preserving nested-flow and lineage joins

## P1: Finish The Near-Term Substrate

No open `P1` items remain. The near-term substrate is now complete:

- Python and Go SDKs have release-qualified beta posture with artifact/docs coverage.
- dashboard, analytics, pricing metadata, and evidence export are in place.
- the next critical path is economic execution, not more substrate cleanup.

## P2: Next Product Roadmap Slice

Completed:
- `P2-03` completed on 2026-03-23
  - added `/v1/reports/cost-attribution`
  - shipped kernel-side root/leaf/detail attribution aggregation over delegation chains
  - persist observed delegated capability snapshots on live tool-call evaluation
  - replicate lineage snapshots across clustered trust-control nodes so follower reports stay accurate
  - verified with targeted kernel tests, receipt-query HTTP tests, trust-cluster failover tests, and full `cargo test --workspace`
- `P2-04` completed on 2026-03-23
  - added `/v1/reports/operator` as the composed operator-facing reporting surface
  - shipped backend composition over receipt analytics, cost attribution, budget utilization, and compliance/export readiness
  - added dashboard summary cards backed by the new report endpoint
  - verified with new kernel compliance tests, receipt-query HTTP tests, dashboard unit tests, dashboard production build, and full `cargo test --workspace`
- `P2-05` completed on 2026-03-23
  - added `chio certify check` as the first Chio Certify command surface
  - evaluates explicit fail-closed certification criteria over a conformance scenario/result corpus
  - emits a signed portable pass/fail JSON artifact plus an optional generated markdown report
  - verified with end-to-end CLI integration tests, targeted `chio-cli` unit tests, and full `cargo test --workspace`
- `P2-06` completed on 2026-03-23
  - added priced native-tool authoring helpers so example servers can publish manifest pricing without dropping to raw struct edits
  - updated `examples/hello-tool` to publish a priced manifest and added a dedicated example test for that contract
  - added a pricing and budget-planning guide that explains how advertised manifest pricing informs capability monetary budgets before invocation, without overstating the current YAML policy surface
  - aligned TypeScript signed-manifest types with the shipped pricing metadata contract
  - verified with `npm --prefix packages/sdk/chio-ts test` and full `cargo test --workspace`

| ID | Task | Why it matters | Effort | Depends on | Acceptance |
| --- | --- | --- | --- | --- | --- |

## P3: Later Roadmap Work

Completed:
- `P3-01` completed on 2026-03-23
  - added the new `crates/chio-reputation` workspace crate as a pure local scoring surface with no `chio-kernel` dependency
  - shipped deterministic Phase 1 local metric computation over receipts, capability-lineage records, budget-usage records, and optional incident inputs
  - implemented truthful `unknown` metric handling plus composite-score renormalization across available metrics
  - verified with dedicated crate fixture tests and full `cargo test --workspace`
- `P3-02` completed on 2026-03-23
  - extended HushSpec/runtime policy loading with `extensions.reputation` issuance materialization, probation configuration, and tier scope ceilings including monetary caps
  - added a shared issuance authority wrapper that computes local reputation from persisted receipts, lineage snapshots, and budget usage before signing capabilities
  - wired the same enforcement path into local CLI issuance and `chio trust serve --policy ...`, with successful issuance persisting capability snapshots at the authority boundary
  - verified with policy unit tests, issuance unit tests, a trust-service HTTP integration test, `cargo test -p chio-cli`, and full `cargo test --workspace`
- `P3-03` completed on 2026-03-23
  - added the new `crates/chio-did` workspace crate with self-certifying `did:chio` parsing, canonicalization, and DID Document resolution over Chio Ed25519 public keys
  - shipped stable `Ed25519VerificationKey2020` documents with optional validated `ChioReceiptLogService` endpoints
  - exposed the resolver through `chio did resolve --did ...` and `chio did resolve --public-key ...`
  - verified with crate unit tests, CLI integration tests, `cargo test -p chio-cli`, and full `cargo test --workspace`
- `P3-04` completed on 2026-03-23
  - added the new `crates/chio-credentials` workspace crate with signed reputation credentials, passport bundling, offline verification, and filtered presentation helpers
  - shipped `chio passport create`, `chio passport verify`, and `chio passport present` on top of local reputation scoring and `did:chio`
  - enforced truthful alpha boundaries: single issuer only, optional checkpoint-required issuance, and no fake multi-issuer aggregation
  - verified with credential crate tests, CLI end-to-end passport tests, `cargo test -p chio-cli --test passport`, and full `cargo test --workspace`
- `P3-05` completed on 2026-03-23
  - added the new `crates/chio-a2a-adapter` workspace crate with A2A v1.0.0 Agent Card discovery, preferred-interface selection, and blocking `SendMessage` mediation for both `JSONRPC` and `HTTP+JSON`
  - exposed one Chio tool per advertised A2A skill and kept the protocol boundary honest by routing skill intent through the adapter-specific `metadata.chio.targetSkillId` convention rather than pretending A2A has a native `skillId` field
  - enforced secure transport defaults: HTTPS required in production, localhost HTTP only for local testing, bounded request timeouts, and optional bearer-auth propagation
  - verified with direct adapter tests, an end-to-end kernel receipt test, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-06` completed on 2026-03-23
  - added `chio evidence verify --input <dir>` as an offline verifier for exported receipt/checkpoint/lineage packages
  - verifies manifest hashes, query scope, receipt signatures, checkpoint signatures, lineage integrity, inclusion proofs, and policy attachment consistency without a running trust-control node
  - hardened the flaky `mcp_serve_http_control_service_centralizes_receipts_revocations_and_authority` lane with bind-collision retry logic so full workspace runs are repeatable again
  - verified with `cargo test -p chio-cli --test evidence_export`, the repaired HTTP integration lane, and full `cargo test --workspace`
- `P3-07` completed on 2026-03-23
  - shipped the first identity-federation alpha for JWT-authenticated `chio mcp serve-http`
  - canonicalizes federated principals as `oidc:<issuer>#sub:<sub>` or `oidc:<issuer>#client:<client_id>`
  - adds `--identity-federation-seed-file` so the edge derives a stable Chio subject key from the authenticated enterprise principal instead of minting a random subject per session
  - exposes `authContext` plus per-capability `subjectPublicKey` in the admin session APIs so operators can audit the mapping directly
  - verified with new `remote_mcp` unit tests, a JWT HTTP integration test proving same-principal convergence and different-principal separation, `cargo test -p chio-cli`, `git diff --check`, and full `cargo test --workspace`
- `P3-08` completed on 2026-03-24
  - added `chio reputation local --subject-public-key ...` as the first operator-facing CLI for inspecting local scorecards from persisted receipts, lineage snapshots, and budget state
  - added `GET /v1/reputation/local/:subject_key` to trust-control so operators can query the same scorecard over HTTP using the service's configured issuance-policy scoring context
  - kept the logic single-sourced by reusing the same local corpus assembly, probationary evaluation, and tier resolution path already used for reputation-gated issuance
  - verified with dedicated CLI/HTTP integration tests, `cargo test -p chio-cli`, `git diff --check`, and full `cargo test --workspace`
- `P3-09` completed on 2026-03-24
  - added the first portable relying-party verifier lane on top of shipped single-issuer passports
  - introduced `PassportVerifierPolicy` plus per-credential acceptance evaluation in `chio-credentials` for issuer allowlists, metric thresholds, checkpoint/log-url requirements, and attestation freshness
  - exposed the verifier through `chio passport evaluate --input <passport> --policy <yaml-or-json>`
  - kept the semantics honest by evaluating each credential independently and accepting the passport only when at least one credential satisfies policy, without inventing multi-credential aggregation
  - verified with new credential crate policy tests, expanded CLI passport end-to-end coverage, `cargo test -p chio-credentials`, `cargo test -p chio-cli --test passport`, `cargo test -p chio-cli`, `git diff --check`, and full `cargo test --workspace`
- `P3-10` completed on 2026-03-24
  - extended `chio-a2a-adapter` with adapter-local `get_task` follow-up mode on top of the shipped A2A v1.0.0 `SendMessage` skeleton
  - supports follow-up `GetTask` over both `JSONRPC` and `HTTP+JSON` while keeping one Chio tool per advertised A2A skill and reusing the normal capability/receipt pipeline
  - hardened the public tool contract so the published snake_case manifest surface is actually accepted, while camelCase aliases remain accepted for compatibility
  - rejects mixed send/follow-up invocations fail-closed instead of guessing caller intent
  - verified with new direct transport tests, a kernel end-to-end receipt test for follow-up polling, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-11` completed on 2026-03-24
  - extended `chio-a2a-adapter` with adapter-local `stream: true` opt-in that issues A2A `SendStreamingMessage` over both `JSONRPC` and `HTTP+JSON`
  - the kernel now captures each upstream A2A `StreamResponse` as one streamed tool chunk without inventing a second stream model
  - complete streams produce normal allow receipts, and prematurely closed upstream streams fail closed as incomplete receipts while preserving partial stream output
  - verified with direct streaming tests over both bindings, direct incomplete-stream tests, kernel end-to-end allow/incomplete receipt tests, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-12` completed on 2026-03-24
  - extended `chio-a2a-adapter` with fail-closed auth negotiation from Agent Card `securitySchemes` / `securityRequirements`
  - supports declared bearer-style auth, OAuth/OpenID bearer semantics backed by configured bearer material, and header-based API keys without guessing or silently over-sharing headers
  - denies invocation locally when required credentials are missing or when the Agent Card requires an auth scheme Chio still does not implement
  - propagates interface tenant metadata into `SendMessage` and HTTP `GetTask` follow-up requests and added direct regression coverage for that request shaping
  - verified with direct auth-negotiation tests, tenant-shaping tests, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-13` completed on 2026-03-24
  - extended `chio-a2a-adapter` with adapter-local `subscribe_task` follow-up mode that issues A2A `SubscribeToTask` over both `JSONRPC` and `HTTP+JSON`
  - corrected HTTP tenant propagation to match the official A2A proto by using tenant path segments for `message:send`, `message:stream`, `GetTask`, and `SubscribeToTask` instead of a query-string shim
  - keeps `SubscribeToTask` inside the normal capability/receipt pipeline: terminal streams allow, prematurely closed streams fail closed as incomplete while preserving partial output
  - verified with new direct subscribe tests over both bindings, direct incomplete-subscribe tests, kernel end-to-end allow/incomplete receipt tests, `cargo test -p chio-a2a-adapter`, and full `cargo test --workspace`
- `P3-14` completed on 2026-03-24
  - extended `chio-a2a-adapter` with adapter-local `cancel_task` plus push-notification config create/get/list/delete over both `JSONRPC` and `HTTP+JSON`
  - kept these task-management operations inside the normal capability and receipt pipeline, including a kernel end-to-end allow-receipt test for `CancelTask`
  - added fail-closed callback URL validation so remote push-notification targets must use `https` and localhost-only `http` remains the only plaintext exception
  - verified with new direct cancel tests, push-config CRUD roundtrip tests, URL-shaping tests, insecure-callback validation tests, kernel end-to-end receipt coverage, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-15` completed on 2026-03-24
  - extended `chio-a2a-adapter` with real OAuth2 client-credentials token acquisition and OpenID Connect discovery-backed token acquisition when the Agent Card declares those schemes
  - added in-process bearer-token caching keyed by scheme, endpoint, and scope set so repeated mediated calls do not keep reissuing token requests during a valid token lifetime
  - kept the auth surface fail-closed: missing client credentials still deny locally, remote token/discovery endpoints must use `https` or localhost-only `http`, and unsupported non-bearer token types are rejected
  - verified with direct OAuth2 acquisition/caching tests, direct OpenID discovery tests, a kernel end-to-end allow-receipt test for OAuth-backed invocation, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-16` completed on 2026-03-24
  - extended `chio-a2a-adapter` with real `mtlsSecurityScheme` support using client-certificate auth plus custom trusted root CAs
  - the adapter now uses configured client certificates for Agent Card discovery when needed, selects mTLS only for mediated request paths that actually require it, and keeps other auth flows on their declared transport semantics
  - kept the transport surface fail-closed: missing client identity still denies locally when the Agent Card requires mTLS, malformed PEM material is rejected at adapter construction, and local HTTPS handshake tests prove the real transport path instead of only config parsing
  - verified with direct mTLS discovery/invocation tests, a kernel end-to-end allow-receipt test for mTLS-backed invocation, `cargo test -p chio-a2a-adapter`, `git diff --check`, and full `cargo test --workspace`
- `P3-17` completed on 2026-03-24
  - deepened `chio mcp serve-http` identity federation with startup-time OIDC discovery, Ed25519 JWKS bootstrap, and provider-aware principal mapping for Generic/Auth0/Okta/Azure AD claim shapes
  - added fail-closed enterprise bootstrap semantics: discovery and discovered `jwks_uri` must use `https` or localhost-only `http`, issuer mismatches are rejected, and discovery without a compatible Ed25519 signing key fails at startup instead of silently admitting tokens
  - verified with direct unit coverage for Azure AD principal mapping and provider-profile discovery derivation, a full `mcp_serve_http` integration test for discovery-backed JWT admission plus stable subject derivation, `cargo test -p chio-cli remote_mcp::tests -- --nocapture`, `cargo test -p chio-cli --test mcp_serve_http mcp_serve_http_oidc_discovery_verifies_jwt_and_uses_azure_ad_profile_mapping -- --nocapture`, and full `cargo test --workspace`
- `P3-18` completed on 2026-03-24
  - widened discovery-backed `chio mcp serve-http` JWT federation from Ed25519-only bootstrap into JWKS verification for `EdDSA`, RSA (`RS*`, `PS*`), and EC (`ES256`, `ES384`) signing keys
  - kept the verifier fail-closed by resolving trusted keys through `kid` plus algorithm compatibility, denying tokens without `kid` whenever the JWKS exposes more than one compatible key
  - added end-to-end OIDC discovery coverage for `RS256` and `ES256`, focused verifier coverage for `PS256` and `ES384`, and hardened the revocation admin-path tests onto bind-retry startup handling after the workspace run exposed a readiness flake
  - verified with `cargo test -p chio-cli remote_mcp::tests -- --nocapture`, `cargo test -p chio-cli --test mcp_serve_http mcp_serve_http_oidc_discovery_verifies_rs256_tokens -- --nocapture`, `cargo test -p chio-cli --test mcp_serve_http mcp_serve_http_oidc_discovery_verifies_es256_tokens -- --nocapture`, targeted admin-revocation test reruns, `cargo test --workspace`, and `git diff --check`
- `P3-19` completed on 2026-03-24
  - added explicit OAuth2 token introspection for opaque bearer admission on `chio mcp serve-http`, including confidential-client authentication to the introspection endpoint and the same stable principal-to-subject derivation path used for JWT-backed federation
  - kept the non-JWT lane fail-closed: introspection endpoints must use `https` or localhost-only `http`, inactive tokens deny, issuer/audience/scope checks still apply, and introspection only accepts bearer-style token types when the provider returns one
  - added pure verifier coverage for active/inactive introspected tokens plus an end-to-end `mcp_serve_http` integration test proving opaque tokens map to stable federated subjects across sessions
  - verified with `cargo test -p chio-cli remote_mcp::tests -- --nocapture`, `cargo test -p chio-cli --test mcp_serve_http mcp_serve_http_token_introspection_verifies_opaque_tokens_and_derives_stable_subjects -- --nocapture`, `cargo test -p chio-cli`, `cargo test --workspace`, and `git diff --check`
- `P3-20` completed on 2026-03-24
  - extended `chio-a2a-adapter` so declared `apiKeySecurityScheme` requirements can now be satisfied for `location: query` and `location: cookie`, not just `location: header`
  - widened the adapter request-auth model into one truthful transport shape that carries headers, query params, cookies, and TLS mode together, so every mediated A2A path applies the same fail-closed auth logic
  - kept the auth surface fail-closed: missing query or cookie credentials still deny locally before the upstream call, while adapter-level and kernel end-to-end coverage now prove query-authenticated invocation produces normal allow receipts
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, `cargo test --workspace`, and `git diff --check`
- `P3-21` completed on 2026-03-24
  - hardened `chio-a2a-adapter` lifecycle semantics so `historyLength` is only sent on `SendMessage` and `GetTask` when the Agent Card advertises `capabilities.stateTransitionHistory = true`
  - closed a protocol-truth gap where Chio already parsed the capability but did not enforce it, keeping unsupported task-history requests fail-closed at the adapter boundary instead of probing upstream behavior
  - added direct lifecycle-capability tests for unsupported `history_length` usage while preserving the existing supported-path transport and kernel receipt coverage for cards that do advertise state-transition history
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, `cargo test --workspace`, and `git diff --check`
- `P3-22` completed on 2026-03-24
  - hardened `chio-a2a-adapter` task lifecycle validation so `SendMessage` task responses, `GetTask` results, streamed `statusUpdate` events, and streamed `artifactUpdate` events are rejected fail-closed when required lifecycle fields are missing
  - closed a second protocol-truth gap where Chio previously accepted malformed upstream task objects after only counting top-level response variants instead of validating the lifecycle payloads themselves
  - added direct validation tests for malformed task, status-update, and artifact-update payloads while preserving the existing good-path transport and kernel receipt coverage
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, `cargo test --workspace`, and `git diff --check`
- `P3-23` completed on 2026-03-24
  - deepened `chio mcp serve-http` identity federation by propagating canonical enterprise identity metadata into `authContext.method.federatedClaims` instead of discarding it after principal derivation
  - the bearer-authenticated lane now preserves `clientId`, `objectId`, `tenantId`, `organizationId`, `groups`, and `roles` from verified JWT and introspection claims, with normalization and provider-aware client/object claim capture
  - added unit coverage for claim normalization plus end-to-end `mcp_serve_http` coverage proving the admin trust surface exposes federated claim context for direct JWT, Azure-profile OIDC discovery, and opaque-token introspection flows
  - verified with `cargo test -p chio-core -- --nocapture`, `cargo test -p chio-cli remote_mcp::tests -- --nocapture`, targeted `mcp_serve_http` federation integration tests, and `git diff --check`
- `P3-24` completed on 2026-03-24
  - extended `chio-a2a-adapter` so declared `httpAuthSecurityScheme: { scheme: \"basic\" }` requirements can now be satisfied truthfully instead of being treated as unsupported
  - added adapter configuration for HTTP Basic auth, fail-closed local denial when required Basic credentials are missing, and a kernel end-to-end allow-receipt path for Basic-authenticated A2A invocation
  - narrowed the remaining A2A auth-matrix gap from “HTTP auth beyond bearer” to custom schemes and deeper federation/partner hardening
  - verified with `cargo test -p chio-a2a-adapter -- --nocapture`, targeted `chio-core` and `chio-cli` auth tests, and `git diff --check`
- `P3-25` completed on 2026-03-24
  - added the first challenge-bound Agent Passport presentation protocol on top of the shipped single-issuer passport alpha
  - introduced portable presentation challenge documents with verifier identity, nonce, TTL, selective-disclosure hints, and optional embedded verifier policy, plus holder-signed responses bound to the passport subject DID
  - exposed the full relying-party loop through `chio passport challenge create`, `chio passport challenge respond`, and `chio passport challenge verify`, while keeping the current alpha boundary honest by avoiding fake multi-issuer aggregation or wallet transport claims
  - verified with new `chio-credentials` challenge/presentation tests, expanded CLI passport end-to-end coverage, `cargo test -p chio-credentials`, `cargo test -p chio-cli --test passport`, `cargo test --workspace`, and `git diff --check`
- `P3-26` completed on 2026-03-24
  - added the first operator-facing local-versus-portable reputation comparison surface through `chio reputation compare --subject-public-key ... --passport ...`
  - kept the comparison truthful by reusing the exact existing local inspection path plus the exact existing passport verification/evaluation path, then computing explicit per-credential metric drift as `local_minus_portable` without inventing new scoring semantics
  - supports both direct `--receipt-db` / `--budget-db` operation and `--control-url` for trust-service-backed local inspection while still evaluating the portable artifact client-side
  - verified with new CLI integration coverage for both direct and trust-service-backed comparison flows, `cargo test -p chio-cli --test local_reputation`, full `cargo test --workspace`, and `git diff --check`
- `P3-27` completed on 2026-03-24
  - added signed bilateral receipt-sharing policy documents through `chio evidence federation-policy create`
  - extended `chio evidence export --federation-policy ...` so the export query is constrained to the signed bilateral scope, proof requirements can be enforced by policy, and the resulting package carries the signed policy document for offline handoff
  - extended `chio evidence verify` so it verifies the federation policy signature, package export timestamp, proof requirements, and query containment instead of treating the policy as an inert attachment
  - verified with new `evidence_export` integration coverage for signed-policy roundtrip and out-of-scope denial, `cargo test -p chio-cli --test evidence_export`, full `cargo test --workspace`, and `git diff --check`
- `P3-28` completed on 2026-03-24
  - extended local-versus-portable comparison from CLI into trust-control through `POST /v1/reputation/compare/:subject_key`
  - moved the remote CLI `reputation compare --control-url` path onto that shared backend contract so trust-control and CLI do not drift
  - added a dashboard-side portable comparison panel that uploads a passport JSON artifact, calls the trust-control comparison endpoint, and renders subject match, local score, policy acceptance, and per-credential drift
  - verified with new trust-service HTTP integration coverage, dashboard API and component tests, `npm test`, `npm run build`, `cargo test -p chio-cli --test local_reputation`, full `cargo test --workspace`, and `git diff --check`
- `P3-29` completed on 2026-03-24
  - extended trust-control with live remote evidence export through `POST /v1/evidence/export`
  - moved `chio evidence export --control-url ...` onto the same prepared-query, signed federation-policy, and proof-requirement contract already used by local evidence export
  - verified with new end-to-end remote `evidence_export` integration coverage, `cargo test -p chio-cli --test evidence_export`, full `cargo test --workspace`, and `git diff --check`
- `P3-30` completed on 2026-03-24
  - added the first live cross-org portable-trust issuance flow through `chio trust federated-issue` and `POST /v1/federation/capabilities/issue`
  - trust-control now consumes an exact expected passport challenge plus a challenge-bound presentation response, requires an embedded verifier policy, derives the subject key from the presented `did:chio`, and issues exactly one locally signed capability from a supplied capability policy
  - kept the scope boundary honest by supporting one requested default capability per request instead of pretending multi-capability federated issuance is atomic
  - verified with new `federated_issue` integration coverage, `cargo test -p chio-cli --test federated_issue`, full `cargo test --workspace`, and `git diff --check`
- `P3-31` completed on 2026-03-24
  - added signed federated delegation-policy documents through `chio trust federated-delegation-policy-create`
  - extended `chio trust federated-issue` and `POST /v1/federation/capabilities/issue` with an optional delegation-policy ceiling that enforces scope and TTL attenuation, requires a locally trusted signer, and persists a delegation anchor into capability lineage
  - verified with expanded `federated_issue` integration coverage for successful anchored issuance plus fail-closed ceiling rejection, full `cargo test --workspace`, and `git diff --check`
- `P3-32` completed on 2026-03-24
  - added bilateral evidence consumption through `chio evidence import` and `POST /v1/evidence/import`, with full package verification before persistence plus imported federated-share indexing for upstream capability lookup
  - extended `chio trust federated-issue` and `POST /v1/federation/capabilities/issue` with `--upstream-capability-id` and parent-bound delegation policies so a new local delegation anchor can bridge to an imported upstream capability and reconstruct a truthful multi-hop cross-org chain
  - kept the boundary honest by preserving local lineage foreign keys and modeling the cross-org hop through explicit federated lineage bridges instead of pretending imported parents are native local issuers
  - verified with new multi-hop `federated_issue` integration coverage, `cargo test -p chio-cli --test federated_issue`, `cargo test -p chio-cli --test evidence_export`, full `cargo test --workspace`, and `git diff --check`

| ID | Task | Why it matters | Effort | Depends on | Acceptance |
| --- | --- | --- | --- | --- | --- |
## Suggested Next Issues

1. Design portable multi-issuer passport composition
2. Extend identity federation beyond the shipped bearer-authenticated plus federated-claims lane into SCIM/SAML, provider-admin integration, and broader cross-org identity surfaces
3. Design portable relying-party policy distribution and replay-resistant verifier state on top of the shipped embedded-policy plus challenge-response lane
4. Scope the remaining A2A auth matrix after bearer, HTTP Basic, API-key header/query/cookie, OAuth/OpenID, and mTLS
5. Deepen A2A long-running task lifecycle beyond the now-shipped `GetTask` / `SubscribeToTask` / `CancelTask` plus push-notification config CRUD, state-transition-history enforcement, and lifecycle payload validation surface
6. Extend the new multi-hop federation lane into shared remote evidence references in operator surfaces and analytics

## Suggested Milestone Cut

### Milestone A: Foundation Hardening

- Completed on 2026-03-23
- Exit criteria:
  - `cargo test --workspace` is green repeatedly
  - receipt/economy contract is internally consistent
  - archived audit data preserves the intended trust model

### Milestone B: Q3 Substrate Closure

- Completed on 2026-03-23
- Already completed: `P1-01` through `P1-08`, plus the pulled-forward compliance evidence export substrate
- Exit criteria:
  - reputation and analytics prerequisites are genuinely in place
  - manifest pricing exists
  - SDKs are honestly described at their real maturity levels

### Milestone C: Economic Integrations

- `P2-01` completed on 2026-03-23
- `P2-02` completed on 2026-03-23
- `P2-03` completed on 2026-03-23
- `P2-04` completed on 2026-03-23
- `P2-05` completed on 2026-03-23
- `P2-06` completed on 2026-03-23
- Exit criteria:
  - one payment bridge works truthfully end-to-end
  - operator reporting is usable
  - certification skeleton exists
  - priced example manifests and budget-planning guidance exist

### Milestone D: Portable Trust

- `P3-01` completed on 2026-03-23
- `P3-02` completed on 2026-03-23
- `P3-03` completed on 2026-03-23
- `P3-04` completed on 2026-03-23
- `P3-05` completed on 2026-03-23
- `P3-06` completed on 2026-03-23
- Exit criteria:
  - local reputation is enforced
  - `did:chio` and Agent Passport alpha exist
  - portable trust artifacts build on the already-shipped evidence package
  - at least one non-MCP ecosystem adapter produces truthful Chio receipts

## Bottom Line

The immediate work is no longer contract cleanup. That foundation is now in
place and verified.

The next execution wave is:

1. harden the A2A adapter beyond the current blocking plus streaming plus `GetTask` plus `SubscribeToTask` lifecycle surface with push-notification/task lifecycle depth and non-header auth support,
2. deepen identity federation beyond JWT-backed principal mapping,
3. design portable multi-issuer passport composition without weakening verification,
4. define portable verifier policy distribution and verifier-side replay state on top of the shipped verifier lane,
5. and use the already-shipped evidence export as the compliance substrate for those later products.
