# Milestone 01: Opus Cluster Design-Partner Production Pilot

## Lens

Adoption / operational. M01 is the first trajectory-3 milestone that
puts Chio in front of a real production tenant under real workload.
Every other lens (security, formal, perf) is a downstream consumer of
the operational evidence M01 produces. The work here is hardening,
runbook authoring, and sustained 30-day observation, not new
substrate. If a proposal here would also pull in a substrate redesign
(new crate, new state machine), it is out of scope and belongs in
M04, M05, M06, or M07.

Trust-boundary: yes.

## Why this is on the trajectory

**Release-gate anchor:** BOUNDED_OPERATIONAL_PROFILE.

The verdict's per-milestone block names this milestone as the
load-bearing customer-anchor of the 50/30/20 blend (D01).
trajectory-2 closed without a single named external customer
reference on `main`; trajectory-3 cannot ship an externally legible
release without one. The Opus cluster (Backbay's healthcare cluster,
D09) is in-house but real workload run by a separate ops team, which
makes onboarding tractable inside the Wave 1 window while still
satisfying the BOUNDED_OPERATIONAL_PROFILE release gate
(`docs/release/OPERATIONS_RUNBOOK.md` lines 13-26). The 30-day
observation period attests that the bounded profile holds under real
workload.

Three concrete trajectory-2 artifacts created the precondition for
this milestone:

1. The bounded operational profile is documented but un-attested.
   `docs/release/OPERATIONS_RUNBOOK.md` (lines 13-26) names the four
   bounds Chio claims to hold: trust-control single-writer (NOT
   consensus HA), single-node hosted auth with sender-constrained
   tokens, single-node atomic monetary budgets on one SQLite store,
   and signed local audit evidence with checkpoint export (NOT public
   transparency-log semantics). M01 is the first run that observes
   these bounds under real workload for 30 consecutive days.
2. The operator runbook is generic. `docs/release/OPERATIONS_RUNBOOK.md`
   is hundreds of lines on required runtime inputs (`chio trust serve
   --listen --service-token --receipt-db --revocation-db
   --authority-db --budget-db`; `chio mcp serve-http --policy
   --server-id --listen` plus a wrapped command and one of three auth
   modes) but is NOT tenant-shaped: no rotation guidance, no
   PagerDuty integration, no incident classification table, no SLO
   targets. The directory `docs/operator-runbook/` does NOT exist
   yet. M01 P1 creates it.
3. The audit-log export surface ships JSON-shaped exporters but no
   CEF or LEEF. `crates/chio-siem/src/lib.rs` exports
   `OcsfExporter`, `SplunkHecExporter`, `DatadogExporter`,
   `ElasticsearchExporter`, `SumoLogicExporter`, `WebhookExporter`,
   `PagerDutyBackend`, and `OpsGenieBackend`; verified absent:
   `grep -rln 'CEF' crates/chio-siem` returns nothing, and
   `crates/chio-siem/Cargo.toml` carries no `syslog` dependency.
   Healthcare SOC pipelines often default to ArcSight (CEF) or
   QRadar (LEEF). M01 P3 adds the missing CEF emitter (or LEEF if
   the Opus SOC is QRadar-shaped) and pins the
   `spec/audit-log/export-schema.v1.json` field-by-field mapping
   that M09 HITRUST consumes.

The dependency graph in the trajectory-3 README anchors M01 as the
load-bearing input for M07 chio-kernel-mobile MVP (which consumes
the Opus tenant runbook + schema v1 as the design-partner reference)
and M09 HITRUST i1 assessment (which scopes the assessment to the
Opus deployment per D02). Both freezes (`m01-m07-audit-handoff` and
`m01-m09-audit-handoff` in `freezes.yml`) point at this milestone's
audit doc.

## Prior-art reckoning

What trajectory-2 already shipped that overlaps with this milestone:

- **Hardened CLI surface (trajectory-2 M01).** Preserved read-only.
  `chio trust serve`, `chio mcp serve-http`, `chio doctor`, and the
  `urn:chio:error:*` registry at `spec/errors/registry.yaml` ship
  unchanged. M01 consumes them as the surface the operator runbook
  documents.
- **OTEL receipt exporter (trajectory-2 M10).** Preserved. The
  `chio-otel-receipt-exporter` shape is the upstream of any SIEM
  forwarder; M01 documents the OTEL endpoint configuration in the
  operator runbook but does not change the exporter.
- **Replay fixtures (trajectory-2 M07).** Preserved. The fixtures
  feed M01.P2 sustained-load runner as the replay corpus baseline.
- **Inherited operator runbook skeleton.** `docs/release/OPERATIONS_RUNBOOK.md`
  stays as the bounded-profile reference. M01.P1 adds a tenant-shaped
  layer at `docs/operator-runbook/` that imports the bounded-profile
  language and adds rotation, PagerDuty, SLO, and incident
  classification.
- **chio-siem exporters (trajectory-2).** `crates/chio-siem/src/`
  ships `lib.rs`, `ocsf.rs` (OCSF 1.3.0 Authorization-event mapper,
  `OCSF_CLASS_UID = 3002`, `OCSF_CATEGORY_UID = 3`),
  `alerting.rs` (severity derivation `Info / Low / Medium / High /
  Critical` and `PagerDutyBackend` posting Events API v2 to
  `https://events.pagerduty.com/v2/enqueue`), and the
  `exporters/{splunk,elastic,datadog,sumo_logic,webhook}.rs`
  transports. M01 freezes the source surface and adds one new
  exporter file `crates/chio-siem/src/exporters/cef.rs` (P3.T2).

What this milestone changes vs preserves:

- The operator runbook becomes load-bearing under PagerDuty; the
  bounded-profile language is preserved verbatim from
  `docs/release/OPERATIONS_RUNBOOK.md` lines 13-26.
- The log-export schema is new (v1) at
  `spec/audit-log/export-schema.v1.json` and consumed by M09 HITRUST
  scope (`m01-m09-audit-handoff` freeze) and by M07 mobile patient-app
  (`m01-m07-audit-handoff` freeze).
- The quota lane is capacity-tested under real Opus traffic but the
  underlying budget store is NOT re-shaped; the bound stays
  "single-node atomic on one SQLite store" per OPERATIONS_RUNBOOK
  line 23.
- `PagerDutyBackend` source code is not edited; M01 plumbs a real
  routing key through Opus deployment configuration and adds a
  weekly heartbeat workflow at
  `.github/workflows/opus-pagerduty-heartbeat.yml`.

Customer named explicitly: **Opus cluster** (Backbay healthcare;
in-house, real workload). Decision register reference: D09.

What this milestone deliberately does NOT do:

- Does not ship the M07 mobile patient-app extension; M07 owns that
  surface and consumes the M01 runbook + schema v1 as load-bearing
  inputs.
- Does not ship the M09 HITRUST evidence package; M09 consumes the
  M01 audit-log export schema but owns the assessor portal and the
  control mapping.
- Does not promote multi-tenant. M01 is single-tenant per verdict
  and per Opus contract; the runbook declares "single-tenant
  deployment" so the bounded profile claim is honest.
- Does not chase a substitute design partner if Opus withdraws.
  Halt trigger 12 (design-partner withdrawal) fires; the verdict
  accepts single-tenant.
- Does not modify `crates/chio-siem/src/alerting.rs` source. The
  PagerDuty + OpsGenie backends are read-only consumed; severity
  override config is plumbed through deployment configuration
  files.
- Does not promote receipts to a public transparency log. The
  bounded profile says "signed local audit evidence with checkpoint
  export"; M01 honors the bound.
- Does not ship CMIA / CCPA / state-level data-law mappings. Out of
  scope per the verdict; recorded as M09 follow-up if applicable.

## Hard counts (measured 2026-04-30)

These rows are filled at P0.T1 and reproduced from the audit doc at
`.planning/trajectory-3/audits/M01-opus-pilot.md` section 2.

- Opus tenant size at P0: estimated tenants (single tenant per
  D09), daily receipt volume (TBD: collect from Opus ops; gates
  P2 quota lane sizing), current Opus-side SLO targets (TBD: the
  Opus API service `opus_api` runs on port 8103 per
  `clusters/opus/CLAUDE.md` and has internal latency targets but
  Chio mediation-edge SLOs are net-new in M01).
- Operator-runbook line count today: `docs/release/OPERATIONS_RUNBOOK.md`
  is the inherited generic runbook; tenant-shaped operator runbook
  at `docs/operator-runbook/` does not exist (line count = 0).
  PagerDuty integration gaps: routing key un-assigned (config-string
  only), no on-call rotation wired, no escalation policy, no
  severity-override config, no heartbeat alert, no per-alert-type
  runbook entry. Six gaps total per RESEARCH.md "PagerDuty / on-call
  integration plan" section.
- Log-export schema fields the Opus team has named as required:
  TBD at P0.T1 from the Opus SOC interview (P0 question:
  ArcSight/CEF, QRadar/LEEF, Splunk-HEC, Elastic, or generic
  syslog). v1 schema MUST cover JSON canonical (already shipped via
  `OcsfExporter`) plus exactly one of CEF or LEEF; the recommended
  default is CEF per RESEARCH.md.
- 30-day observation start date: pinned at P0.T1; no later than
  week 8 of W1 to fit within the wave per risk 3.

Reproduce these counts via the audit doc commands at
`.planning/trajectory-3/audits/M01-opus-pilot.md`.

## Workspace dependency state

M01 is operational rather than substrate work. New crate pins are
limited to one new file under `crates/chio-siem/src/exporters/` and
do not require workspace dependency edits.

- `crates/chio-siem/Cargo.toml`: P3.T2 may pin a `syslog`
  RFC-5424 framing crate if the Opus SOC requires syslog framing
  rather than newline-delimited CEF. Decision deferred to P3
  schema-negotiation receipt; current presumption is that
  newline-delimited CEF over the existing
  `WebhookExporter`/`SplunkHecExporter` transport suffices and
  no new pin is needed.
- No new workspace pins for P0, P1, P2, P4, P5.

Third-party services M01 contracts with:

- **PagerDuty.** Real service named `chio-opus-pilot-prod` with an
  Events API v2 integration key. Routing-key ownership decision
  (Chio team account vs Opus ops team account) recorded in audit
  doc evidence log at P0.T5.
- **Opus identity provider.** Whatever auth the `opus_api` service
  uses (per `clusters/opus/apps/opus/services/api/`); Chio-side
  hosted auth runs as `chio mcp serve-http --auth-token` or
  `--auth-jwt-public-key` per `OPERATIONS_RUNBOOK.md` lines 41-50.
  P0.T4 topology diagram pins which.
- **Opus log sink.** SIEM endpoint per the Opus SOC pipeline (P0
  interview question; CEF target if ArcSight, LEEF target if
  QRadar, Splunk HEC URL if Splunk, Elasticsearch URL if Elastic).
  Receives audit-log export per the v1 schema landing in P3.

External vendor calendar lead times: none beyond PagerDuty service
provisioning (typically 1-2 days).

## Scope

### In

- Operator runbook hardened to PagerDuty-on-call quality. Six
  files under `docs/operator-runbook/` (P1):
  `index.md`, `bounded-profile.md`, `slo.md`, `incidents.md`,
  `pagerduty.md`, `rotations.md`. 50-150 lines each.
- Tenant-onboarding and topology docs at
  `docs/operator-runbook/onboarding.md` and
  `docs/operator-runbook/topology.md` (P0).
- Real PagerDuty integration with on-call rotation matched to the
  Opus ops team. PagerDuty service named `chio-opus-pilot-prod`
  (P0.T5 contract memo, P1.T4 plumbing). Heartbeat workflow at
  `.github/workflows/opus-pagerduty-heartbeat.yml` (P1.T6).
- Sustained-load runner under `bench/opus-capacity/` (new crate,
  sibling to `bench/ttfrh/`). Runner replays Opus shadow traffic
  at 1x / 2x / 5x and records p50/p95/p99 latency, receipt-write
  throughput, trust-control state-machine convergence time, and
  `chio-siem` exporter backpressure. (P2.T1)
- Capacity test report committed to the audit doc evidence log
  (P2.T3); quota lane sizing doc at
  `docs/operator-runbook/quota.md` (P2.T4).
- Log-export schema v1 negotiated with the Opus team and
  committed under `spec/audit-log/export-schema.v1.json` (P3.T1).
  v1 schema covers JSON canonical (OCSF 1.3.0 Authorization
  shape) plus exactly one of CEF or LEEF. PHI redaction policy
  pinned at `docs/operator-runbook/phi-policy.md` (P3.T3).
- CEF emitter at `crates/chio-siem/src/exporters/cef.rs` (P3.T2).
  Field-by-field mapping documented in the schema doc.
- Schema-linter CI job at
  `.github/workflows/audit-log-schema-lint.yml` (P3.T4) validating
  the schema + a CEF golden file.
- 30-day observation with weekly incident review committed to the
  audit doc (P4.T1..T5). Window starts no later than week 8 of W1.
- Closure: Opus ops sign-off memo, runbook live URL, schema v1
  path, four success-criteria rows green, both freezes closed
  (P5.T1..T5).

### Out (and why)

- M07 mobile patient-app extension. M07 owns mobile.
- M09 HITRUST evidence package. M09 owns the assessor relationship
  and the control mapping.
- Multi-tenant beyond the Opus cluster. Single-tenant pilot is the
  verdict scope; the runbook declares this explicitly so the
  bounded-profile claim is honest.
- LEEF emitter if CEF is shipped (P3 picks one; the other is
  reserved for v1.x).
- Crate consolidation, formal proofs, mutation-gate flips, vendor
  reports. Owned by M04 / M05 / M06 / M08.
- BAA negotiation outside the Backbay-internal posture. P0.T2
  records whether a pre-existing internal BAA covers Opus + Chio
  or whether one must be cut; the engineering effort to author a
  BAA is owned by program-lead and legal, not M01.
- A second design-partner backup. The verdict accepts
  single-tenant; if Opus withdraws, halt trigger 12 fires.
- State-level data laws (CMIA, CCPA / CPRA). Out of scope for
  M01 release gate; recorded as M09 follow-up (the M09 audit doc
  captures these as trajectory-4 carry-forward items).
- `chio-siem` source surface beyond the new CEF exporter. The
  alerting / OCSF / existing exporters are read-only consumed.
- Receipt long-retention storage tier. The Opus deployment retains
  Chio receipts for 6 years on its own audit-store per HIPAA per
  P3 retention contract; Chio does not ship a long-retention path
  in M01.

## Phases

### P0 - Audit doc + Opus contract + tenant onboarding plan

Wave-opener for M01. Goal: open the milestone audit doc with hard
counts, sign a written contract with Opus ops naming the
design-partner relationship under D09 + D15, and stand up the two
operator-runbook stub files that subsequent phases extend.

- M01.P0.T1 - Open audit doc and fill four hard-count rows.
- M01.P0.T2 - Opus design-partner contract memo (BAA posture +
  D09 ratification) recorded in audit doc evidence log.
- M01.P0.T3 - Tenant onboarding plan at
  `docs/operator-runbook/onboarding.md`.
- M01.P0.T4 - Production deployment topology diagram naming the
  Chio mediation edge placement relative to `opus_api` (sidecar
  process / in-process library / wrapped MCP edge) at
  `docs/operator-runbook/topology.md`.
- M01.P0.T5 - PagerDuty service-naming + on-call rotation contract
  memo recorded in audit doc.

### P1 - Operator runbook hardening + PagerDuty integration

Goal: tenant-shaped operator runbook plus a real PagerDuty hookup
against Opus on-call. Six files land under
`docs/operator-runbook/`. Severity-override config plumbs through
the chio-siem consumer config (no chio-siem source change required;
M01 freezes the audit doc only).

- M01.P1.T1 - Runbook index + bounded-profile imports.
- M01.P1.T2 - SLO definition (latency, availability, error budget).
- M01.P1.T3 - Incident classification + MTTR table (P0/P1/P2
  severity).
- M01.P1.T4 - PagerDuty integration doc + severity-mapping override
  config.
- M01.P1.T5 - On-call rotation + escalation policy.
- M01.P1.T6 - Weekly heartbeat-alert workflow at
  `.github/workflows/opus-pagerduty-heartbeat.yml`.

### P2 - Quota under real load: capacity test + tenant onboarding rehearsal

Goal: prove BOUNDED_OPERATIONAL_PROFILE holds at Opus production
load and capture quota lane sizing. New sibling crate
`bench/opus-capacity/`.

- M01.P2.T1 - Sustained-load runner crate scaffold under
  `bench/opus-capacity/`.
- M01.P2.T2 - Shadow-traffic capture script at
  `bench/opus-capacity/scripts/shadow-capture.sh`.
- M01.P2.T3 - Capacity test report (1x / 2x / 5x replay) committed
  to audit doc evidence log.
- M01.P2.T4 - Quota lane sizing doc at
  `docs/operator-runbook/quota.md`.
- M01.P2.T5 - Tenant-onboarding rehearsal log recorded in audit doc.

### P3 - Audit-log export schema v1 negotiated with Opus team

Goal: ship `spec/audit-log/export-schema.v1.json` with field
mapping for OCSF / CEF / LEEF / Splunk-HEC and explicit PHI
redaction policy. **Freeze gate:** `M01.P3.T1` opens
`m01-m09-audit-handoff` on the schema + audit doc; the freeze
closes at `M01.P5.T5`.

- M01.P3.T1 - Open `spec/audit-log/export-schema.v1.json`
  (JSON Schema 2020-12). Triggers `m01-m09-audit-handoff` freeze.
- M01.P3.T2 - CEF emitter at
  `crates/chio-siem/src/exporters/cef.rs` (or LEEF if Opus SOC is
  QRadar-shaped per P0 interview).
- M01.P3.T3 - PHI-redaction policy at
  `docs/operator-runbook/phi-policy.md` pinning
  `ResponseSanitizationGuard` config.
- M01.P3.T4 - Schema-linter CI job at
  `.github/workflows/audit-log-schema-lint.yml` validating schema
  + CEF golden file.
- M01.P3.T5 - Schema-negotiation receipt (Opus team accepted v1)
  recorded in audit doc evidence log.

### P4 - 30-day production observation + week-by-week incident review

Calendar-driven phase. Window starts no later than week 8 of W1
per risk 3. Four weekly incident-review tickets at 0.5 days each;
one rollup ticket compiles the 30-day report.

- M01.P4.T1 - Week 1 incident-review entry.
- M01.P4.T2 - Week 2 incident-review entry.
- M01.P4.T3 - Week 3 incident-review entry.
- M01.P4.T4 - Week 4 incident-review entry.
- M01.P4.T5 - 30-day incident report compiled and committed.
- M01.P4.T6 - MTTR + bounded-profile-hold attestation.

### P5 - Opus tenant ops review attests bounded operational profile

Goal: ops sign-off memo received within 7 days of P5 close (D15
freshness window). Closure of both audit-handoff freezes.

- M01.P5.T1 - Open `m01-m07-audit-handoff` freeze (already pinned
  in `freezes.yml`); audit doc evidence log entry.
- M01.P5.T2 - Opus ops sign-off memo recorded under closure
  attestations (D15: <=7 days from receipt).
- M01.P5.T3 - Operator runbook live URL recorded.
- M01.P5.T4 - Schema v1 path recorded under closure.
- M01.P5.T5 - Closure: all four success-criteria check rows green,
  both freezes closed.

## Cross-milestone interactions

Hard deps on trajectory-3 artifacts (express via `depends_on`):

- M01.P0.T1 (open audit doc) is the wave-opener for everything in
  M01.
- M01.P3.T2 (CEF emitter) depends on M01.P3.T1 (schema open).
- M01.P4.T1..T4 (weekly reviews) depend on M01.P3.T5 (schema
  negotiation receipt) so the export-schema is live before the
  observation window opens.
- M01.P5.T2 (sign-off memo) depends on M01.P4.T5 (30-day report)
  and M01.P4.T6 (attestation).

Soft deps (cross-trajectory or informational):

- M03 hosted CI on the v3.18 release commit. NOT a hard block per
  RESEARCH.md; M01 can run on best-effort CI through P3 and require
  green hosted CI by P4 open. Soft-dep recorded in P3 ticket.
- trajectory-2 OPERATIONS_RUNBOOK.md (lines 13-26 bounded profile,
  lines 28-78 required runtime inputs) is read-only consumed by
  the P1 runbook authoring tickets.
- trajectory-2 `crates/chio-siem/src/{lib.rs,ocsf.rs,alerting.rs,
  exporters/}` is read-only consumed by P1.T4 (PagerDuty
  integration doc) and extended by exactly one new file at P3.T2.
- trajectory-2 `bench/ttfrh/` is the microbench reference for the
  P2 sustained-load runner shape.
- M02 runs in parallel; no shared paths.
- M05 `pii_phi_exposure` advisory closure is a precondition for
  Opus PHI handling confidence; M01 references M05's
  threat-coverage doc but does not block. Cited in P3.T3 PHI
  policy doc.
- M06 SBOM at `supply-chain/sbom/v3.18.cdx.json` is consumed by
  M09 not M01, but the M01 runbook references the SBOM
  publication path.

Forward references (other trajectory-3 milestones consuming M01):

- M07 chio-kernel-mobile MVP consumes the Opus tenant runbook +
  schema v1 as load-bearing inputs (per `freezes.yml`
  `m01-m07-audit-handoff` and README invariants table). The Opus
  mobile patient-app is the M07 design partner per D09
  consequences.
- M09 HITRUST i1 assessment consumes the audit-log export schema
  v1 + operator runbook (per `freezes.yml` `m01-m09-audit-handoff`).
  Schema and audit-doc frozen from M01.P3 through M01.P5.
- M04 mutation-gate priority crates: M01 incident reports inform
  M04's choice of which crates to target first.

## Risks and mitigations

1. **Design-partner withdrawal** (halt trigger 12). Opus ops team
   declines to continue, BAA negotiations stall, or organizational
   reprioritization. Mitigation: Opus ops team contracted in P0.T2
   with a written memo; backup tenant relationship not in scope (the
   verdict accepts single-tenant per D09). If withdrawal happens
   inside the 30-day window, the affected weekly review ticket
   captures the withdrawal date and halt trigger 12 fires;
   orchestrator pauses M01 and surfaces to user.
2. **PagerDuty integration latency.** PagerDuty service provisioning
   typically takes 1-2 days but on-call rotation negotiation with
   the Opus ops team can stretch. Mitigation: P0.T5 names the service
   in the contract memo; P1.T4 plumbs the routing key the same week.
   The heartbeat workflow at P1.T6 verifies the wiring stays warm
   for the duration of the observation window.
3. **30-day observation slips into Wave 2.** Mitigation: P4 starts
   no later than week 8 of W1 to fit within the wave. P3 schema
   negotiation must close by week 7; if it slips, P3.T5 status flips
   to blocked and the orchestrator surfaces to user.
4. **PHI exposure in receipts.** A `ChioReceipt` carries
   `action.parameters` (full request), `action.parameter_hash`,
   `decision.reason`, and guard-evidence text. If Opus passes patient
   identifiers as tool arguments, those land in receipts unless
   `ResponseSanitizationGuard` and parameter-redaction rules are
   correctly configured. Mitigation: P3.T3 PHI policy doc declares
   PHI-bearing fields explicitly; P1 runbook pins guard config; P4
   weekly review includes a PHI-leak audit row (any Critical-severity
   `pii_phi_exposure` deny is reviewed line-by-line).
5. **ePHI in PagerDuty alerts.** PagerDuty payloads must NOT carry
   raw patient identifiers. The `AlertingExporter` payload is
   "minimal summary, dedup key, severity" per
   `crates/chio-siem/src/alerting.rs` line 18. Mitigation: P1.T4
   integration doc verifies the summary string carries no PHI
   expansion; P1.T6 heartbeat workflow asserts payload shape.
6. **BAA timing.** HIPAA Business Associate Agreement between Chio
   team and Opus tenant is a precondition for any deployment that
   processes PHI. Mitigation: P0.T2 records BAA posture (pre-existing
   internal Backbay BAA covering both teams, or a fresh BAA cut for
   M01); engineering work proceeds independently because Chio cannot
   leak PHI in receipts whether or not a BAA exists, but no
   production traffic flips on until BAA posture is documented.
7. **Receipt retention vs HIPAA 6-year retention.** Chio receipts
   are signed local audit evidence with checkpoint export
   (`OPERATIONS_RUNBOOK.md` lines 22-24). Mitigation: P3.T1 schema
   doc names the retention contract; the Opus deployment retains
   Chio receipts for 6 years on its own audit-store. Chio does not
   ship a long-retention path in M01; if Opus cannot retain locally,
   record as M09 follow-up.
8. **Capacity test underestimates production load.** P2 capacity
   sized at 1x / 2x / 5x of shadow-capture baseline; if real
   workload spikes 10x during the observation window, quota lane
   sizing fails. Mitigation: P2.T4 quota doc declares "headroom
   capped at 5x replayed baseline; spikes beyond 5x trigger P1
   incident classification per P1.T3"; the trust-control single-writer
   bound holds because the leader-local truth is unaffected by load
   shape.

## Success criteria

A green light on M01 means all of the following are true:

- Opus cluster ops sign-off memo committed under
  `.planning/trajectory-3/audits/M01-opus-pilot.md` within 7 days of
  P5 close (D15 freshness window).
- 30-day incident report green: zero P0 incidents, documented mean
  time to recovery for any P1 / P2 incident.
- Operator runbook renders clean under `docs/operator-runbook/`
  (six core files plus `onboarding.md`, `topology.md`,
  `quota.md`, `phi-policy.md`).
- Log-export schema v1 at `spec/audit-log/export-schema.v1.json`
  validates against the `audit-log-schema-lint.yml` CI job, has a
  CEF golden file under `crates/chio-siem/src/exporters/`, and is
  referenced by the M09 P0 audit doc.
- PagerDuty service `chio-opus-pilot-prod` is live; the weekly
  heartbeat workflow has fired at least four times without
  payload-shape regression.
- Both audit-handoff freezes (`m01-m07-audit-handoff` and
  `m01-m09-audit-handoff` in `freezes.yml`) closed at M01.P5.T5.
- BOUNDED_OPERATIONAL_PROFILE attestation row in audit doc closure
  attestations: "30-day observation confirms trust-control
  single-writer, single-node hosted auth, single-node atomic
  monetary budgets, and signed local audit evidence held under
  Opus production load."
