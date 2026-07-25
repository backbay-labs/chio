# Chio Changelog

> Historical internal milestone log. `v2.x` labels in this file are
> pre-release implementation milestones, not Chio-owned protocol, schema, SDK,
> or runtime versions. Current protocol posture is v1-only.

---

## Unreleased (pre-release production candidate closeout)

### Production And Standards

- **Release hygiene and structure** (`chio-cli`, packaging, scripts): generated
  Python cache/build artifacts are now excluded from tracked release inputs,
  release-input guard scripts fail fast when they reappear, and oversized CLI
  admin handling has been split into `crates/products/chio-cli/src/admin.rs`.

- **Qualification and operator runbooks** (`scripts`, workflows, docs): the
  release lane now explicitly qualifies dashboard, TypeScript package, Python
  wheel/sdist, Go module, live conformance waves, and repeat-run trust-cluster
  behavior, while the runbook documents deployment, backup/restore, upgrade,
  and rollback against those same surfaces.

- **Observability contract** (`trust-control`, `remote_mcp`, docs): trust
  service `/health` now reports authority, store, federation, and cluster
  state; hosted MCP edges now expose `/admin/health`; and the new
  `docs/release/OBSERVABILITY.md` defines the supported operator diagnostics
  contract across trust-control, hosted sessions, federation, evidence, and
  A2A task correlation.

- **Protocol posture alignment** (`spec`, docs): `spec/PROTOCOL.md` now describes
  the shipped repository profile instead of the older aspirational draft,
  including the real capability, receipt, trust-control, portable-trust, A2A,
  certification, and compatibility contracts.

- **Standards and launch artifacts** (`docs/release`, `docs/standards`,
  `README`, SDK docs): release-candidate, audit, GA checklist, and risk
  register docs now align to the internal closeout milestone, while new
  receipts and portable-trust standards profiles define the intended
  interoperable submission surface.

## v2.1.0 (2026-03-24)

### Federation and Verifier Completion

- **Enterprise federation administration** (`chio-cli`, `chio-core`,
  `chio-policy`): `chio mcp serve-http` and `chio trust serve` now share an
  explicit `--enterprise-providers-file` registry for provider-admin records.
  Provider records support `oidc_jwks`, `oauth_introspection`, `scim`, and
  `saml` kinds, preserve provenance and trust-boundary metadata, and stay
  operator-visible with `validation_errors` when incomplete or invalid.

- **Provider-admin CLI and HTTP surfaces** (`chio-cli`, trust-control): Added
  `chio trust provider list|get|upsert|delete` plus
  `GET/PUT/DELETE /v1/federation/providers...` on the trust-control service.
  Operators can now inspect or manage enterprise provider records without
  editing ad hoc bearer settings directly.

- **Enterprise identity audit context** (`chio-core`, `remote_mcp`):
  bearer-backed session auth now exposes `enterpriseIdentity` with provider
  id, provider record id, provider kind, federation method, canonical
  principal, stable subject key, tenant, organization, groups, roles,
  `attributeSources`, and `trustMaterialRef`.

- **Enterprise portable-trust admission gating** (`chio-cli`, `chio-policy`):
  federated issue can now evaluate HushSpec origin profiles against enterprise
  provider, tenant, organization, groups, and roles. The enterprise-provider
  lane is explicit: bearer-only observability does not activate it, but once a
  validated provider-admin record is selected, admission fails closed unless
  the richer origin policy matches. Allow and deny outcomes now surface
  `enterprise_audit` / `enterpriseAudit` with matched origin profile and
  decision context.

- **Signed verifier policy artifacts** (`chio-credentials`, `chio-cli`):
  verifier policy is now a signed reusable document with schema
  `chio.passport-verifier-policy.v1`, explicit `policy_id`, verifier binding,
  validity window, and signer public key. Operators can manage these artifacts
  locally or remotely with `chio passport policy create|verify|list|get|upsert|delete`
  and trust-control verifier policy CRUD endpoints.

- **Replay-safe verifier challenge state** (`chio-cli`, trust-control):
  verifier challenges can now be persisted in a SQLite-backed durable store via
  `--verifier-challenge-db`. Stored rows bind `challengeId` to the full
  canonical challenge payload, track `issued` / `consumed` / `expired` state,
  and reject replay after local or remote verifier-side consumption.

- **Local and remote verifier parity** (`chio-cli`, trust-control): local
  `passport challenge create|verify`, remote trust-control challenge create and
  verify, and `trust federated-issue` now all understand stored verifier policy
  references plus shared output fields including `challengeId`, `policyId`,
  `policySource`, `policyEvaluated`, and `replayState`.

- **Multi-issuer passport composition** (`chio-credentials`, `chio-cli`):
  passport verification, evaluation, presentation, and reputation comparison no
  longer reject same-subject bundles signed by more than one issuer. Verification
  now exposes `issuerCount` and `issuers`, while policy evaluation stays
  per-credential, adds issuer identity to each credential result, and reports
  `matchedIssuers` without inventing any cross-issuer aggregate score.

- **Cross-org shared evidence analytics** (`chio-kernel`, `chio-cli`,
  dashboard): imported federated evidence shares now surface through a shared
  `sharedEvidence` report contract used by `GET /v1/federation/evidence-shares`,
  `GET /v1/reports/operator`, `POST /v1/reputation/compare/{subject_key}`, the
  new `chio trust evidence-share list` CLI, and dashboard operator/comparison
  panels. Downstream local receipts now preserve upstream provenance through
  remote share metadata plus `localAnchorCapabilityId`.

- **Historical internal v2.1 boundary**: this milestone did not ship automatic
  local multi-issuer bundle authoring, cluster-wide verifier-state replication,
  or automatic SCIM provisioning lifecycle.

## v2.0.0 (2026-03-23)

### Enforcement

- **Monetary budget enforcement** (`chio-core`, `chio-kernel`): `ToolGrant`
  gains `max_cost_per_invocation: Option<MonetaryAmount>` and
  `max_total_cost: Option<MonetaryAmount>`. The Kernel enforces both limits
  atomically via `BudgetStore::try_charge_cost`. All monetary values use u64
  minor units with an ISO 4217 currency code. Overflow is detected with
  `checked_add` and fails closed.

- **DPoP proof-of-possession** (`chio-kernel`): Added `DpopProof`,
  `DpopProofBody`, `DpopNonceStore`, and `verify_dpop_proof`. The 8-field
  Chio-native DPoP format (`chio.dpop_proof.v1`) binds each invocation to the
  agent's Ed25519 private key. Enabled per-grant via
  `ToolGrant::dpop_required: Option<bool>`. Default TTL 300s, clock skew
  tolerance 30s, LRU nonce cache capacity 8192.

- **Receipt Merkle checkpointing** (`chio-kernel`): Added `build_checkpoint`,
  `build_inclusion_proof`, `verify_checkpoint_signature`,
  `KernelCheckpoint`, `KernelCheckpointBody`, and `ReceiptInclusionProof`.
  Checkpoints are triggered every `checkpoint_batch_size` receipts (default
  100, configurable). Each checkpoint commits a batch of canonical receipt
  bytes to a binary Merkle tree and signs the root with the Kernel's keypair.
  Schema: `chio.checkpoint_statement.v1`.

### Compliance and Audit

- **Financial receipt metadata** (`chio-core`): Added
  `FinancialReceiptMetadata` struct with 11 fields: `grant_index`,
  `cost_charged`, `currency`, `budget_remaining`, `budget_total`,
  `delegation_depth`, `root_budget_holder`, `payment_reference`,
  `settlement_status`, `cost_breakdown`, and `attempted_cost`. Attached under
  the `"financial"` key in `ChioReceipt::metadata` for all monetary
  invocations. Denial receipts carry `attempted_cost` instead of
  `cost_charged`.

- **Receipt attribution metadata** (`chio-core`, `chio-kernel`): Added
  canonical `ReceiptAttributionMetadata` under the `"attribution"` metadata
  key. Receipts now persist `subject_key`, `issuer_key`, `delegation_depth`,
  and `grant_index` when available, giving analytics and reputation systems a
  deterministic local join path.

- **Nested flow receipts** (`chio-core`): Added `ChildRequestReceipt` and
  `ChildRequestReceiptBody`. Signed records for sub-operations spawned within
  a parent tool call (sampling, resource reads, elicitation). Fields:
  `session_id`, `parent_request_id`, `request_id`, `operation_kind`,
  `terminal_state`, `outcome_hash`, `policy_hash`. Terminal states:
  `Completed`, `Cancelled`, `Incomplete`.

### APIs

- **Receipt query API** (`chio-cli`): New `GET /v1/receipts/query` endpoint
  with 9 filter dimensions: `capabilityId`, `toolServer`, `toolName`,
  `outcome`, `since`, `until`, `minCost`, `maxCost`, `costCurrency`,
  `agentSubject`. Cost bounds require a three-letter uppercase currency. Supports
  cursor-based pagination (`cursor` + `limit`). Maximum page size: 200
  receipts. Response includes `totalCount` (full filtered set), `nextCursor`,
  and `receipts` ordered by `seq` ascending.

- **Agent receipts endpoint** (`chio-cli`): New
  `GET /v1/agents/{subject_key}/receipts` endpoint for per-agent receipt
  history lookup via hex-encoded Ed25519 public key.

- **Receipt analytics API** (`chio-cli`, `chio-kernel`): New
  `GET /v1/receipts/analytics` endpoint providing backend-side aggregates by
  agent, tool, and time window, including reliability, compliance, and budget
  utilization metrics.

- **Operator report API** (`chio-cli`, `chio-kernel`, dashboard): New
  `GET /v1/reports/operator` endpoint composing activity, cost attribution,
  budget utilization, and compliance/export readiness into one stable operator
  workflow surface. The receipt dashboard now renders these report cards above
  the receipt table.

- **Capability lineage endpoints** (`chio-cli`): New
  `GET /v1/lineage/{capability_id}` and
  `GET /v1/lineage/{capability_id}/chain` for querying delegation chain
  snapshots.

- **`Chio Certify` alpha CLI** (`chio-cli`, `chio-conformance`): New
  `chio certify check` command evaluates a conformance scenario/result corpus
  against the fail-closed `conformance-all-pass-v1` profile and emits a signed
  `chio.certify.check.v1` pass/fail artifact. Optional markdown report output
  uses the same compatibility report generator as release qualification.

### SDK

- **`MonetaryAmount` type** (`chio-core`): New struct with `units: u64` and
  `currency: String`. Used in `ToolGrant::max_cost_per_invocation` and
  `ToolGrant::max_total_cost`. Forward-compatible with v1.0 tokens via
  `#[serde(default, skip_serializing_if = "Option::is_none")]`.

- **`ToolGrant` attenuation** (`chio-core`): `ToolGrant::is_subset_of` updated
  to respect monetary fields. A child grant is a valid attenuation only if its
  `max_cost_per_invocation` and `max_total_cost` are no greater than the
  parent's corresponding limits.

- **`CapabilityLineage` snapshot** (`chio-kernel`): New
  `CapabilitySnapshot` and `CapabilityLineageError` types. `record_capability_snapshot`
  on `SqliteReceiptStore` captures issuer, subject, and delegation chain at
  token issuance time for the `agentSubject` filter.

- **Manifest pricing authoring and examples** (`chio-mcp-adapter`,
  `examples/hello-tool`, `chio-ts`): `NativeTool` now exposes pricing helpers
  for flat, per-invocation, per-unit, and hybrid quotes. The maintained
  `hello-tool` example publishes manifest pricing, TypeScript manifest types
  preserve the `pricing` field, and `docs/TOOL_PRICING_GUIDE.md` documents how
  advertised tool pricing informs capability monetary budgets before
  invocation.

### Trust and Reputation

- **`chio-reputation` crate**: Added a new pure local-scoring workspace crate
  that computes deterministic Phase 1 reputation scorecards from normalized
  receipts, capability-lineage records, budget-usage records, and optional
  incident inputs. It ships boundary-pressure, stewardship, least-privilege,
  history-depth, specialization, delegation-hygiene, reliability, and incident
  metrics, preserves `unknown` for unavailable metrics, and renormalizes the
  composite score across the available weights only. The crate does not depend
  on `chio-kernel`, keeping later issuance-hook integration cycle-free.

- **Reputation-gated issuance** (`chio-cli`, `chio-policy`): HushSpec
  `extensions.reputation` now materializes into a runtime issuance policy that
  is enforced by a shared capability-authority wrapper. The wrapper computes a
  subject's local scorecard from persisted receipts, capability-lineage
  snapshots, and budget usage before signing capabilities, enforces TTL,
  operation, invocation, required-constraint, and monetary grant ceilings, and
  persists successful issuance into the lineage index at the same boundary.
  `chio trust serve --policy ...` now applies the same gate over HTTP.

- **Local reputation operator surfaces** (`chio-cli`, `trust-control`): Added
  `chio reputation local --subject-public-key ...` for direct CLI inspection of
  local scorecards, plus `GET /v1/reputation/local/:subject_key` on the
  trust-control service. Both surfaces reuse the exact same persisted corpus,
  probationary evaluation, and tier resolution path already used for
  reputation-gated issuance, so operator debugging and issuance enforcement
  stay contractually aligned.

- **OIDC discovery-backed identity federation** (`chio-cli`, `remote_mcp`):
  `chio mcp serve-http` now supports startup-time OIDC discovery, discovery-backed
  JWKS verification for `EdDSA`, RSA (`RS*`, `PS*`), and EC (`ES256`,
  `ES384`) JWTs, and provider-aware principal mapping for
  Generic/Auth0/Okta/Azure AD claim shapes. JWT admission can now bootstrap
  from `--auth-jwt-discovery-url` instead of a manually copied public key,
  discovery mismatches fail closed, insecure remote metadata is rejected unless
  it is localhost-only HTTP for tests, Azure AD style tokens can canonicalize
  user principals from `oid` instead of opaque `sub` values, and trusted JWKS
  key selection is fail-closed on `kid` plus algorithm compatibility.

- **Opaque bearer federation via token introspection** (`chio-cli`,
  `remote_mcp`): `chio mcp serve-http` now also supports OAuth2 token
  introspection for opaque bearer tokens through `--auth-introspection-url`,
  with optional confidential-client auth to the introspection endpoint.
  Introspected tokens feed the same stable principal-to-subject derivation path
  as JWT-backed federation, still enforce issuer/audience/scope checks, and
  fail closed on inactive tokens, unsupported token types, or insecure remote
  introspection endpoints.

- **`did:chio` method + resolver** (`chio-did`, `chio-cli`): Added the new
  `chio-did` workspace crate with self-certifying `did:chio` parsing,
  canonicalization, and DID Document resolution for any Chio Ed25519 public
  key. The resolved document emits a stable `Ed25519VerificationKey2020`
  method, canonical `publicKeyMultibase`, and optional validated
  `ChioReceiptLogService` endpoints. The CLI now exposes this via
  `chio did resolve --did ...` and `chio did resolve --public-key ...`.

- **Agent Passport alpha** (`chio-credentials`, `chio-cli`): Added the new
  `chio-credentials` workspace crate with signed reputation credentials,
  single-issuer Agent Passport bundling, offline verification, and filtered
  presentation helpers. The CLI now exposes `chio passport create`,
  `chio passport verify`, and `chio passport present`. Passport creation is
  grounded in the local reputation corpus plus receipt/checkpoint evidence and
  can fail closed when `--require-checkpoints` is set.

- **Portable verifier policy lane** (`chio-credentials`, `chio-cli`): Added
  `PassportVerifierPolicy` plus per-credential policy evaluation in
  `chio-credentials`, and exposed it through `chio passport evaluate`. A
  relying party can now evaluate a passport against issuer allowlists, metric
  thresholds, checkpoint coverage, receipt-log URL requirements, and
  attestation freshness without custom glue code, while keeping the current
  alpha semantics honest by evaluating credentials independently instead of
  inventing multi-credential aggregation.

- **Challenge-bound passport presentation** (`chio-credentials`, `chio-cli`):
  Added portable presentation challenge documents plus holder-signed passport
  presentation responses. The CLI now exposes `chio passport challenge create`,
  `chio passport challenge respond`, and `chio passport challenge verify`.
  Challenges carry verifier identity, nonce, TTL, selective-disclosure hints,
  and optional embedded verifier policy; responses bind the selected passport
  view to the passport subject DID and support exact expected-challenge
  matching during verification.

- **Local-versus-portable reputation comparison** (`chio-cli`): Added
  `chio reputation compare --subject-public-key ... --passport ...` as the
  first operator-facing drift surface between live local reputation and
  portable passport artifacts. The command reuses the exact local inspection
  path plus the exact passport verification/evaluation path, then emits
  per-credential `local_minus_portable` metric drift without inventing new
  scoring semantics. It also supports trust-service-backed local inspection
  through `--control-url`.

- **A2A adapter skeleton** (`chio-a2a-adapter`): Added the new
  `chio-a2a-adapter` workspace crate with A2A v1.0.0 Agent Card discovery,
  preferred-interface selection, and blocking `SendMessage` mediation for both
  `JSONRPC` and `HTTP+JSON`. The adapter exposes one Chio tool per advertised
  A2A skill, routes skill intent through the explicit
  `metadata.chio.targetSkillId` convention, requires HTTPS except for
  localhost test targets, and is verified by direct adapter tests plus an
  end-to-end kernel receipt test.

- **A2A task follow-up support** (`chio-a2a-adapter`): Extended the A2A
  adapter with adapter-local `get_task` follow-up mode so the same Chio
  skill-scoped tool can poll A2A `GetTask` over both `JSONRPC` and
  `HTTP+JSON` after a non-terminal `SendMessage` response. The public Chio
  tool contract now truthfully exposes snake_case follow-up fields while still
  accepting camelCase aliases for compatibility, rejects mixed send/follow-up
  inputs fail-closed, and is verified by direct transport tests plus a kernel
  end-to-end receipt test for the follow-up path.

- **A2A streaming support** (`chio-a2a-adapter`): Extended the A2A adapter
  with adapter-local `stream: true` opt-in that issues A2A
  `SendStreamingMessage` over both `JSONRPC` and `HTTP+JSON`. The kernel now
  captures each upstream A2A `StreamResponse` as one streamed tool chunk,
  complete streams produce normal allow receipts, and prematurely closed
  upstream streams fail closed as incomplete receipts while preserving partial
  stream output for auditability.

- **A2A auth negotiation hardening** (`chio-a2a-adapter`): Extended the A2A
  adapter with fail-closed request auth negotiation from Agent Card
  `securitySchemes` / `securityRequirements`. The adapter now satisfies
  declared bearer-style and header API-key requirements from configured
  credentials, denies invocation locally when required credentials are missing
  or when unsupported schemes such as mTLS are required, and propagates
  interface tenant metadata into `SendMessage` and HTTP `GetTask` requests.

- **A2A subscribe-task support** (`chio-a2a-adapter`): Extended the A2A
  adapter with adapter-local `subscribe_task` follow-up mode so the same Chio
  tool can reattach to live task updates through A2A `SubscribeToTask` over
  both `JSONRPC` and `HTTP+JSON`. The HTTP transport now follows the current
  A2A proto's tenant path semantics instead of a query-string shim, and
  incomplete subscribe streams fail closed as incomplete receipts while
  preserving partial output.

- **A2A task-management hardening** (`chio-a2a-adapter`): Extended the A2A
  adapter with adapter-local `cancel_task` plus task push-notification config
  create/get/list/delete over both `JSONRPC` and `HTTP+JSON`. These follow-up
  operations stay inside the normal capability and receipt pipeline, remote
  notification callbacks fail closed unless they use `https` or localhost-only
  `http`, and the shipped coverage now includes direct roundtrip tests plus a
  kernel end-to-end allow-receipt test for `CancelTask`.

- **A2A OAuth/OpenID acquisition** (`chio-a2a-adapter`): Extended the A2A
  adapter so required `oauth2SecurityScheme` and
  `openIdConnectSecurityScheme` bearer flows can be satisfied with configured
  client credentials instead of only a preseeded static bearer token. The
  adapter now discovers OpenID token endpoints, acquires bearer tokens through
  client-credentials, caches them in-process for reuse, and still fails closed
  when credentials are missing, token endpoints are unsafe, or token types are
  not bearer-compatible.

- **A2A mTLS transport support** (`chio-a2a-adapter`): Extended the A2A
  adapter so required `mtlsSecurityScheme` flows can be satisfied with a
  configured client certificate plus trusted root CA bundle. The adapter now
  performs real client-certificate authentication for Agent Card discovery and
  mediated upstream calls when needed, keeps mTLS selection fail-closed when a
  required client identity is missing, and preserves the existing rule that
  other auth flows only receive the credentials their declared requirement set
  actually needs.

- **A2A query/cookie API-key support** (`chio-a2a-adapter`): Extended the A2A
  adapter so declared `apiKeySecurityScheme` requirements can now be satisfied
  for `location: query` and `location: cookie`, not just `location: header`.
  The request-auth model now carries headers, query parameters, cookies, and
  TLS mode together so every mediated A2A path uses the same fail-closed auth
  application logic. Missing query/cookie credentials still deny locally, the
  shipped tests now cover both adapter-level negotiation paths plus a kernel
  end-to-end allow-receipt path for query-authenticated invocation.

- **A2A state-transition-history enforcement** (`chio-a2a-adapter`): Hardened
  the A2A lifecycle surface so `historyLength` is only sent on `SendMessage`
  and `GetTask` when the Agent Card explicitly advertises
  `capabilities.stateTransitionHistory = true`. This closes a protocol-truth
  gap where Chio previously parsed the capability but did not enforce it. The
  shipped tests now cover both supported history paths and fail-closed local
  denial when the capability is absent.

- **A2A lifecycle payload validation** (`chio-a2a-adapter`): Hardened the A2A
  adapter so task lifecycle payloads are validated fail-closed instead of only
  being shape-counted. `SendMessage` task responses and `GetTask` results now
  require non-empty `id` plus `status.state`, streamed `statusUpdate` events
  require `taskId` plus `status.state`, and streamed `artifactUpdate` events
  require `taskId` plus object `artifact`. The shipped tests now cover these
  malformed-payload denial paths directly.

- **Offline evidence verification** (`chio-cli`, `chio-kernel`): Added
  `chio evidence verify --input <dir>` so exported evidence bundles can be
  verified without a running trust-control service. The verifier checks the
  manifest, file hashes, query scope, receipt signatures, checkpoint
  signatures, lineage shape, inclusion proofs, and optional policy attachment.
  The workspace HTTP control-plane harness was also hardened with bind-collision
  retry logic so the full verification/test signal is repeatable again.

- **Identity federation alpha** (`chio-cli`): JWT-authenticated
  `chio mcp serve-http` sessions can now derive a stable Chio subject from the
  authenticated enterprise principal when `--identity-federation-seed-file` is
  configured. Principals are canonicalized as `oidc:<issuer>#sub:<sub>` or
  `oidc:<issuer>#client:<client_id>`, the edge derives a deterministic subject
  key from that principal, and the admin session APIs now expose both
  `authContext` and `subjectPublicKey` so the mapping is directly auditable.

- **Identity federation claim propagation** (`chio-cli`, `chio-core`): The
  bearer-authenticated federation lane now preserves normalized enterprise
  identity metadata in `authContext.method.federatedClaims` instead of
  discarding it after principal derivation. Verified JWT and introspection
  claims can now surface `clientId`, `objectId`, `tenantId`,
  `organizationId`, `groups`, and `roles`, with normalization plus
  provider-aware client/object claim capture for the shipped Generic/Auth0/
  Okta/Azure AD profiles.

- **A2A HTTP Basic auth** (`chio-a2a-adapter`): The adapter now supports
  `httpAuthSecurityScheme` with `scheme: basic` in the Agent Card
  `securitySchemes` / `securityRequirements` surface. Operators can configure
  Basic credentials directly, missing required Basic auth fails closed before
  the upstream call, and the shipped tests now include both adapter-level and
  kernel end-to-end allow-receipt coverage for Basic-authenticated A2A
  invocation.

### Infrastructure

- **`chio-siem` crate**: New crate providing an independent SIEM exporter
  pipeline. `ExporterManager` runs a cursor-pull loop reading from the
  Kernel's receipt SQLite database (read-only, no `chio-kernel` dependency).
  Ships with `SplunkExporter` (Splunk HEC) and `ElasticExporter`
  (Elasticsearch `_bulk` API). Includes `DeadLetterQueue` with configurable
  capacity (default 1000) and exponential backoff retry (default 3 attempts,
  base 500ms). Configurable via `SiemConfig`: `poll_interval`,
  `batch_size`, `max_retries`, `base_backoff_ms`, `dlq_capacity`.

- **SQLite budget store** (`chio-kernel`): `SqliteBudgetStore` gains
  `total_cost_charged` column (added via `ALTER TABLE` migration for existing
  databases). LWW merge strategy uses seq-based conflict resolution.

- **Checkpoint persistence** (`chio-kernel`): `SqliteReceiptStore` gains
  `store_checkpoint`, `load_checkpoint_by_seq`, and
  `receipts_canonical_bytes_range` methods for checkpoint storage and
  inclusion proof construction.

- **Retention coverage expansion** (`chio-kernel`): archival rotation now
  copies `chio_child_receipts` and the relevant capability-lineage snapshots,
  preserving nested-flow and agent-centric auditability in archive files.

- **Federation evidence policies** (`chio-cli`): Added
  `chio evidence federation-policy create` plus signed bilateral
  receipt-sharing policy documents. `chio evidence export` can now be
  constrained by `--federation-policy`, and `chio evidence verify` now checks
  the signed policy's signature, validity window, proof requirements, and
  query containment rather than treating the policy as a passive attachment.

- **Remote portable comparison** (`trust-control`, dashboard): Added
  `POST /v1/reputation/compare/:subject_key` so trust-control can compare a
  live local scorecard against a passport artifact using the same contract as
  CLI. The dashboard now includes a portable reputation comparison panel that
  uploads a passport JSON file and renders subject match, local score, policy
  acceptance, and per-credential drift.

- **Remote evidence export** (`trust-control`, `chio-cli`): Added
  `POST /v1/evidence/export` so signed bilateral evidence packages can be
  generated live from a trust-control deployment instead of only from a local
  SQLite checkout. `chio evidence export --control-url ...` now reuses the
  same prepared-query, federation-policy, and proof-requirement contract as
  local export.

- **Federated portable-trust issuance** (`trust-control`, `chio-cli`): Added
  `POST /v1/federation/capabilities/issue` plus `chio trust federated-issue`
  for the first live cross-org portable-trust issuance path. Trust-control now
  consumes an exact expected challenge, requires an embedded verifier policy,
  verifies a challenge-bound passport presentation response, derives the
  subject key from the presented `did:chio`, and issues one locally signed
  capability from a supplied capability policy.

- **Federated delegation-policy attenuation** (`trust-control`, `chio-cli`):
  Added `chio trust federated-delegation-policy-create` plus optional
  `--delegation-policy` support on `chio trust federated-issue` and
  `POST /v1/federation/capabilities/issue`. Trust-control now verifies a
  signed scope/TTL ceiling, requires a locally trusted signer, and persists a
  delegation anchor into capability lineage so the issued capability no longer
  appears as a fresh local root when this path is used.

- **Federated evidence import** (`trust-control`, `chio-cli`, `chio-kernel`):
  Added `chio evidence import` plus `POST /v1/evidence/import` for consuming
  bilateral evidence packages into a trust-control deployment. Imported
  packages are fully re-verified before persistence, then indexed as
  federated shares for later upstream capability lookup without polluting the
  native local receipt tables.

- **Multi-hop cross-org delegation** (`trust-control`, `chio-cli`,
  `chio-kernel`): Extended `chio trust federated-issue` and
  `POST /v1/federation/capabilities/issue` with parent-bound
  `--upstream-capability-id` continuation. A new local delegation anchor can
  now bridge to an imported upstream capability under an exact signed ceiling,
  and combined lineage queries reconstruct the full multi-hop chain without
  weakening local lineage foreign-key guarantees.

### Protocol Specification

- `spec/PROTOCOL.md` Appendix D: Receipt Financial Metadata.
- `spec/PROTOCOL.md` Appendix E: Receipt Query API.
- `spec/PROTOCOL.md` Appendix F: Receipt Checkpointing.
- `spec/PROTOCOL.md` Appendix G: Nested Flow Receipts.
- ADR-0006: Monetary Budget Semantics.
- ADR-0007: DPoP Binding Format.
- ADR-0008: Checkpoint Trigger Strategy.
- ADR-0009: SIEM Isolation Architecture.

---

## v1.0.0

Initial release. Core capability model, receipt signing, revocation store,
MCP adapter, and trust control service.
