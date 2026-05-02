# M01 Research: Opus Cluster Design-Partner Production Pilot

**Trajectory:** trajectory-3 | **Milestone:** M01 | **Research date:** 2026-04-30
**Worktree:** `/Users/connor/Medica/backbay/standalone/arc/.worktrees/trajectory-3/`

IMPLEMENT-phase reference for expanding `.planning/trajectory-3/01-opus-design-partner-pilot.md` and authoring six per-phase ticket YAMLs under `.planning/trajectory-3/tickets/M01/`. All paths are absolute from the worktree root unless prefixed.

---

## Opus cluster reality

Opus is the **healthcare** cluster of Backbay Industries. It lives in the parent multi-repo workspace at `/Users/connor/Medica/backbay/clusters/opus/` (NOT inside the Chio repo). Workspace orchestration is documented in `/Users/connor/Medica/backbay/CLAUDE.md` (Moon + Bun + UV) and the platform reference at `/Users/connor/Medica/backbay/platform/CLAUDE.md`.

What actually runs at Opus today:

- `clusters/opus/apps/opus/clients/web/` - Opus portal (Vite/React, port 3003 per the cluster table in `backbay/CLAUDE.md`).
- `clusters/opus/apps/opus/clients/desktop/` - Tauri desktop wrapper using BackbayOS-style "desktop OS" UX patterns.
- `clusters/opus/apps/opus/services/api/` - Python API service (`opus_api`, default port 8103) backed by `pyproject.toml` + `uv.lock`. This is the economy primitives surface (protocols / exchange / governance per `clusters/opus/CLAUDE.md`).
- `clusters/opus/packages/opus-contracts/` - shared contract package.
- Subdomain `opus.backbay.io`. Reference UX is `platform/apps/backbay/client/web` and `platform/apps/opus/client/docs`.

Production deployment is via Moon (`moon run opus-web:dev`, `moon run dev`, `moon run infra:up`); infra is docker-compose under `backbay/infra/`. **Production deployment topology is NOT documented in the Chio worktree; M01 P0 must capture it from the Opus ops team directly.**

The integration shape is: Chio's `chio-trust-control` and `chio mcp serve-http` edges sit between the Opus API service and any agent / tool calls the Opus product makes. The exact sidecar / wrap / agent-passport-gate placement is the load-bearing P0 design question. Estimated tenant size, receipt volume per day, and SLO targets are unknown today; quota lane sizing depends on P0/P2 numbers.

## v3.18 deployment readiness

Current shipped protocol is **v3.0** per `spec/PROTOCOL.md` line 3 (`Status: Current bounded Chio release profile`). The "v3.18" tag is the **release tag** trajectory-3 will cut for the Opus deployment; cited consistently across:

- `audits/M01-opus-pilot.md` line 12 ("v3.18 to the Opus cluster")
- `audits/M03-ci-restoration.md` lines 36-38 (`supply-chain/checksums/v3.18.txt`)
- `audits/M06-formal-supply-chain.md` line 39 (`supply-chain/sbom/v3.18.cdx.json`)
- `audits/M09-vendor-evidence.md` line 12 (HITRUST scoped to v3.18 + Opus)
- `03-hosted-ci-truth-and-reproducible-builds.md` line 108 (M03 P5 retroactively certifies v3.18)
- `tickets/M01/README.md` line 7

There is no v3.18 closeout artifact in `.planning/audits/` yet (that directory holds trajectory-2 milestone audits M01..M10); v3.18 IS the trajectory-3 release tag.

**BOUNDED_OPERATIONAL_PROFILE gate** (`docs/release/OPERATIONS_RUNBOOK.md` lines 13-26):

- **trust-control:** local or leader-local single-writer truth with deterministic leader selection and eventual repair; NOT consensus-backed HA.
- **hosted auth:** single-node or dedicated-per-session hosted admission with sender-constrained access tokens where available.
- **monetary budgets:** single-node atomic on one SQLite store; clustered mode admits a documented overrun bound and is NOT distributed-linearizable.
- **receipts and checkpoints:** signed local audit evidence with checkpoint export and inclusion-proof material; NOT public transparency-log semantics.

The 30-day Opus observation must show these bounds hold in production. Required runtime inputs (`OPERATIONS_RUNBOOK.md` lines 28-78): `chio trust serve` needs `--listen`, `--service-token`, plus `--receipt-db / --revocation-db / --authority-db / --budget-db`; `chio mcp serve-http` needs `--policy / --server-id / --listen` plus a wrapped command; one auth mode (`--auth-token`, `--auth-jwt-public-key`, or `--auth-introspection-url`).

## Tenant onboarding gap analysis

Existing material:

- `docs/release/OPERATIONS_RUNBOOK.md` - generic single-operator runbook for the bounded release. Hundreds of lines on required inputs and bounded profile. **NOT tenant-shaped:** no rotation guidance, no PagerDuty integration, no incident classification table, no SLO targets.
- `docs/release/CHIO_COMPTROLLER_OPERATOR_RUNBOOK.md` - comptroller surface, narrower scope.
- `docs/release/CHIO_LINK_RUNBOOK.md`, `CHIO_SETTLE_RUNBOOK.md`, `CHIO_ANCHOR_RUNBOOK.md`, `CHIO_WEB3_OPERATIONS_RUNBOOK.md` - web3 rail (out of scope per D09).
- `docs/release/OBSERVABILITY.md`, `docs/release/RISK_REGISTER.md` - generic.

`docs/runbooks/` does NOT exist. The narrative line 145 names `docs/operator-runbook/` as the live URL target; that directory does NOT exist either. **M01 P1 creates it.**

Production-observation gaps cited by trajectory-2 critic and the verdict:

1. No SLO definition (no error-budget, latency, or availability targets).
2. No on-call rotation. PagerDuty wiring is implementation-only (see chio-siem analysis below); no rotation or escalation policy is wired to Opus ops.
3. No incident classification (P0/P1/P2 severity table), no MTTR bookkeeping path.
4. No tenant-onboarding checklist. Today's runbook assumes one self-hosted operator; a separate-team tenant has different trust assumptions.
5. No per-tenant log-export contract. `chio-siem` ships exporters but no negotiated tenant-side schema.

## Capacity / load profile

Existing perf-test infra: `bench/ttfrh/` is a "Time To First Receipt Hash" microbench suite with runners `cloudflare_worker.rs`, `next_ai_sdk_receipts.rs`, `fastapi_langchain.rs`, `network_sentinel.rs`, `budget.rs`. Workspace member at `bench/ttfrh/Cargo.toml`. Microbench harness, NOT a production load profile. No `bench/loadtest/`, `bench/k6/`, `bench/locust/` exist.

M01 P2 should land either an extension of `bench/ttfrh/runners/` with a sustained-load runner OR a sibling crate `bench/opus-capacity/` for the Opus profile. Recommended approach:

1. 24-hour shadow-traffic capture from `opus_api` against a Chio mediation edge (read-only, tee'd traffic) to establish baseline receipt-volume / second.
2. Replay baseline at 1x / 2x / 5x against a staging Chio deployment with production quota lane sizing.
3. Record p50/p95/p99 latency, receipt-write throughput, trust-control state-machine convergence time, and `chio-siem` exporter backpressure.
4. Capture results in the audit doc evidence log (or a separate `audits/m01/capacity-report.md`).

The capacity report is one of the four concrete shipped artifacts in the milestone success criteria.

## Audit-log export schema research

What `chio-siem` already ships (`crates/chio-siem/src/`):

- `lib.rs` exports: `PagerDutyBackend`, `OpsGenieBackend`, `DatadogExporter`, `ElasticsearchExporter`, `OcsfExporter`, `SplunkHecExporter`, `SumoLogicExporter`, `WebhookExporter`.
- `ocsf.rs` - OCSF 1.3.0 Authorization-event mapper (`OCSF_CLASS_UID = 3002`, `OCSF_CATEGORY_UID = 3`). Full `ChioReceipt` -> OCSF field table inline at lines 8-32.
- `alerting.rs` - severity derivation (`Info / Low / Medium / High / Critical`) and `PagerDutyBackend` with Events API v2 wiring (lines 195-274). Module rustdoc at lines 27-36 documents the `AlertingExporter` builder pattern.
- `exporters/{splunk,elastic,datadog,sumo_logic,webhook}.rs` - HTTP transports.

What does NOT ship today (the customer-voice critic's gap):

- **CEF (Common Event Format) emitter.** ArcSight / HP / many-SIEM legacy format. Healthcare SOC pipelines often default to CEF. Verified absent: `grep -rln "CEF" crates/chio-siem` returns nothing.
- **LEEF (Log Event Extended Format) emitter.** QRadar's preferred format. Absent.
- **Syslog RFC 5424 framing.** No `syslog` dependency in `crates/chio-siem/Cargo.toml`.

The two passing CEF/LEEF references in the worktree are `docs/archive/CLAWDSTRIKE_INTEGRATION.md` line 185 (archive) and `docs/guards/11-SIEM-OBSERVABILITY-COMPLETION.md` line 508 (planning doc that named CEF as a target schema but did not ship it).

Schema location target (per freeze + M09 dep): `spec/audit-log/export-schema.v1.json`. This path is named in `freezes.yml` (`m01-m09-audit-handoff` opens at `M01.P3.T1`, closes at `M01.P5.T5`). The directory `spec/audit-log/` does NOT exist; M01 P3 creates it. The schema is consumed read-only by M09 HITRUST evidence and by M07 (per README invariants table).

Recommended P3 negotiation surface:

1. Survey Opus ops on their SOC pipeline: ArcSight (CEF), QRadar (LEEF), Splunk (HEC JSON), Elastic (ECS JSON), or generic (syslog + JSON).
2. v1 schema MUST cover at minimum a JSON canonical form (already ships via `OcsfExporter`) plus exactly one of CEF or LEEF. The verdict-cited critic note ("operators expect CEF/LEEF, we emit JSON") suggests CEF is the higher-leverage addition.
3. The schema doc lists the field-by-field mapping (`ChioReceipt` -> CEF / LEEF / OCSF / Splunk-HEC) so any downstream SIEM can negotiate.
4. PHI redaction policy is part of v1: declares which `ChioReceipt` fields may carry PHI and pins the `ResponseSanitizationGuard` mode required upstream (`spec/SECURITY.md` section 2.8 PII/PHI Exposure).

## PagerDuty / on-call integration plan

State today: `crates/chio-siem/src/alerting.rs` ships `PagerDutyBackend::new(service_routing_key)` (lines 195-274) posting to `https://events.pagerduty.com/v2/enqueue` with Events API v2 schema. Also ships `OpsGenieBackend` and the generic `AlertBackend` trait. Severity derivation is deterministic via `derive_severity(receipt)` (lines 65-68: `Critical` covers "deny on secret leak, policy breach, egress to known-bad").

Missing for an Opus production hookup:

1. **A real PagerDuty service / routing-key assignment.** Today the routing key is a config string; Opus pilot needs an actual PagerDuty service named `chio-opus-pilot-prod` with an integration key.
2. **An on-call rotation matched to the Opus ops team** (P1 contract ticket).
3. **An escalation policy.** P0 -> primary on-call (5 min ack), P1 -> primary on-call (15 min ack), P2 -> ticket queue.
4. **Severity mapping calibration.** Opus may want any `pii_phi_exposure` deny treated as Critical regardless of guard origin.
5. **A runbook entry per alert type** (Critical-deny, High-deny, Medium-deny, exporter-DLQ-overflow, trust-control split-brain). Each PagerDuty alert links to a docs section.
6. **A test alert / weekly heartbeat** so the wiring stays warm.

Minimal P1 scope: wire `PagerDutyBackend` into Opus deployment configuration, name the PagerDuty service, document on-call rotation, add the severity-mapping override config, add a heartbeat test, link each alert type to a `docs/operator-runbook/` section.

## Per-phase research findings (P0-P5)

**P0 - Audit doc + Opus contract + tenant onboarding plan.** Goal: open the milestone audit doc with hard counts; sign a written contract with Opus ops naming the design-partner relationship under D09 + D15. Deliverables: fill the four "Hard counts at P0" rows (`audits/M01-opus-pilot.md`); tenant-onboarding plan at `docs/operator-runbook/onboarding.md`; topology diagram at `docs/operator-runbook/topology.md`; PagerDuty service-naming + rotation contract memo in audit doc evidence log.

**P1 - Operator runbook hardening + PagerDuty.** Goal: tenant-shaped operator runbook + real PagerDuty hookup against Opus on-call. Deliverables: `docs/operator-runbook/{index,bounded-profile,slo,incidents,pagerduty,rotations}.md` (six files, 50-150 lines each); severity-mapping override config plumbed through chio-siem consumer config (no chio-siem source change required - M01 freezes the audit doc only); heartbeat-alert workflow under `.github/workflows/`.

**P2 - Quota under real load.** Goal: prove BOUNDED_OPERATIONAL_PROFILE holds at Opus production load and capture quota lane sizing. Deliverables: sustained-load runner under `bench/opus-capacity/` (new crate) or `bench/ttfrh/runners/`; capacity test report; quota lane config under `docs/operator-runbook/quota.md`; tenant-onboarding rehearsal log.

**P3 - Audit-log export schema v1.** Goal: ship `spec/audit-log/export-schema.v1.json` with field mapping for OCSF / CEF / LEEF / Splunk-HEC and explicit PHI redaction policy. Deliverables: the schema (JSON Schema 2020-12); CEF emitter at `crates/chio-siem/src/exporters/cef.rs` (or LEEF); PHI policy doc at `docs/operator-runbook/phi-policy.md`; schema-linter CI job; schema-negotiation receipt in audit doc. **Freeze gate:** `M01.P3.T1` opens `m01-m09-audit-handoff` on the schema + audit doc; closes at `M01.P5.T5`.

**P4 - 30-day production observation.** Per narrative lines 110-113: four weekly incident-review tickets at 0.5 days each (M01.P4.T1..T4); a 30-day incident report compiled and committed; zero P0 incidents (success criterion); documented MTTR for any P1/P2. P4 window MUST start no later than week 8 of W1 (per risk register risk 3 in `01-opus-design-partner-pilot.md` line 134).

**P5 - Opus tenant ops review.** Goal: ops sign-off memo received within 7 days of P5 close (D15 freshness window). Deliverables: sign-off memo under audit doc closure attestations; operator runbook live URL recorded; schema v1 path recorded; success criteria all checked. M01.P5.T1 opens `m01-m07-audit-handoff` (audit doc only). Closes at M01.P5.T5.

## Cross-milestone dependencies

Hard inputs (M01 consumes):

- M03 hosted CI on the v3.18 release commit (per `audits/M03-ci-restoration.md`). NOT a hard block per the research prompt; M01 can run on best-effort CI through P3 and require green hosted CI by P4 open.
- Trajectory-2 inheritance: hardened CLI surface, OTEL exporter, replay fixtures, the inherited operator runbook skeleton at `docs/release/OPERATIONS_RUNBOOK.md`. All read-only consumed.

Hard outputs (other milestones consume from M01):

- **M07** chio-kernel-mobile MVP: consumes the Opus tenant runbook + schema v1 as load-bearing inputs (per `freezes.yml` `m01-m07-audit-handoff` and README invariants). Triggers freeze on M01 audit doc during M01.P5.
- **M09** HITRUST i1 assessment: consumes the audit-log export schema v1 + operator runbook (per `freezes.yml` `m01-m09-audit-handoff`). Schema and audit-doc frozen from M01.P3 through M01.P5.
- **M04** mutation-gate priority: M01 incident reports inform M04 mutation-gate priority crates (narrative line 124).

Soft deps: M02 runs in parallel (no shared paths). M05 (`pii_phi_exposure` advisory closure) is precondition for Opus PHI handling confidence; M01 references M05's threat-coverage doc but does not block. M06 SBOM at `supply-chain/sbom/v3.18.cdx.json` is consumed by M09 not M01, but the M01 runbook should reference the SBOM publication path.

## Healthcare-deployment risk register

Beyond the four risks already in `01-opus-design-partner-pilot.md` lines 127-136:

1. **PHI exposure in receipts.** A `ChioReceipt` carries `action.parameters` (full request), `action.parameter_hash`, `decision.reason`, and guard-evidence text. If Opus passes patient identifiers as tool arguments, those land in receipts unless `ResponseSanitizationGuard` and parameter-redaction rules are correctly configured. Mitigation: P3 schema declares PHI-bearing fields explicitly; P1 runbook pins guard config; P4 weekly review includes a PHI-leak audit row.
2. **BAA timing.** HIPAA Business Associate Agreements between the Chio team and Opus tenant are pre-condition for any deployment that processes PHI. M01 cannot leak PHI in receipts whether or not a BAA exists, but a signed BAA is a P0 contractual gate. The verdict names M09 (HITRUST i1) as the external-attestation milestone; M01 ships the deployment, M09 ships the certificate. M01 must not silently widen the claim.
3. **HIPAA Security Rule pre-conditions.** The Opus tenant environment must meet technical safeguards (access control, audit controls, integrity, transmission security) independently of Chio. M01's runbook documents Chio's contribution (audit log export, fail-closed deny, signed receipts) without claiming to substitute for them.
4. **ePHI in PagerDuty alerts.** PagerDuty payloads must NOT carry raw patient identifiers. The `AlertingExporter` payload is "minimal summary, dedup key, severity" (`alerting.rs` line 18); verify in P1 that the summary string has no PHI expansion.
5. **Receipt retention vs HIPAA 6-year retention.** Chio receipts are signed local audit evidence (`OPERATIONS_RUNBOOK.md` lines 22-24). The Opus deployment needs a retention policy aligning with HIPAA's 6-year audit log retention. P3 schema doc names the retention contract.
6. **State-level data laws** (CMIA, CCPA / CPRA). Out of scope for M01 release gate; record as M09 follow-up.
7. **Multi-tenant leak.** Out of scope (single-tenant per verdict) but the runbook must declare "this is a single-tenant deployment" so the bounded profile is honest.

## Recommended ticket scaffold

Six phases. Per `STYLE.md`, target 4-6 tickets per phase, 0.5-2 days each. M01 is operational, so vendor-wait tickets are not needed (those are an M08/M09 pattern).

### P0 (5 tickets)

- `M01.P0.T1` (1.0d) - Open audit doc and fill hard counts. owner: `.planning/trajectory-3/audits/M01-opus-pilot.md`
- `M01.P0.T2` (0.5d) - Opus design-partner contract memo recorded in audit doc evidence log. owner: same audit doc
- `M01.P0.T3` (1.5d) - Tenant onboarding plan. owner: `docs/operator-runbook/onboarding.md`
- `M01.P0.T4` (1.0d) - Production deployment topology diagram (Chio sidecar relative to `opus_api`). owner: `docs/operator-runbook/topology.md`
- `M01.P0.T5` (0.5d) - PagerDuty service-naming + on-call rotation contract memo. owner: audit doc

### P1 (6 tickets)

- `M01.P1.T1` (1.5d) - Runbook index + bounded-profile. owner: `docs/operator-runbook/{index,bounded-profile}.md`
- `M01.P1.T2` (1.0d) - SLO definition. owner: `docs/operator-runbook/slo.md`
- `M01.P1.T3` (1.5d) - Incident classification + MTTR table. owner: `docs/operator-runbook/incidents.md`
- `M01.P1.T4` (1.5d) - PagerDuty integration doc + severity override config. owner: `docs/operator-runbook/pagerduty.md`
- `M01.P1.T5` (1.0d) - On-call rotation + escalation policy. owner: `docs/operator-runbook/rotations.md`
- `M01.P1.T6` (1.0d) - Weekly heartbeat-alert workflow. owner: `.github/workflows/opus-pagerduty-heartbeat.yml`

### P2 (5 tickets)

- `M01.P2.T1` (2.0d) - Sustained-load runner. owner: `bench/opus-capacity/**`
- `M01.P2.T2` (1.0d) - Shadow-traffic capture script. owner: `bench/opus-capacity/scripts/shadow-capture.sh`
- `M01.P2.T3` (1.5d) - Capacity test report. owner: audit doc (also `audits/m01/capacity-report.md` if needed)
- `M01.P2.T4` (1.0d) - Quota lane sizing doc. owner: `docs/operator-runbook/quota.md`
- `M01.P2.T5` (1.0d) - Tenant-onboarding rehearsal log. owner: audit doc

### P3 (5 tickets)

- `M01.P3.T1` (1.5d) - Open `spec/audit-log/export-schema.v1.json` (JSON Schema 2020-12). Triggers `m01-m09-audit-handoff` freeze. owner: schema path
- `M01.P3.T2` (1.5d) - CEF emitter (or LEEF if QRadar). owner: `crates/chio-siem/src/exporters/cef.rs`
- `M01.P3.T3` (1.0d) - PHI-redaction policy pinning `ResponseSanitizationGuard` config. owner: `docs/operator-runbook/phi-policy.md`
- `M01.P3.T4` (1.0d) - Schema-linter CI job validating schema + CEF golden file. owner: `.github/workflows/audit-log-schema-lint.yml`
- `M01.P3.T5` (0.5d) - Schema-negotiation receipt (Opus team accepted v1). owner: audit doc

### P4 (6 tickets)

- `M01.P4.T1..T4` (0.5d each) - Weekly incident-review entries (W1..W4). owner: audit doc
- `M01.P4.T5` (1.0d) - 30-day incident report compiled + committed. owner: audit doc
- `M01.P4.T6` (0.5d) - MTTR + bounded-profile-hold attestation. owner: audit doc

### P5 (5 tickets)

- `M01.P5.T1` (0.5d) - Open `m01-m07-audit-handoff` freeze (already pinned in `freezes.yml`). owner: audit doc
- `M01.P5.T2` (1.0d) - Opus ops sign-off memo recorded under closure attestations (D15: <=7 days from receipt). owner: audit doc
- `M01.P5.T3` (0.5d) - Operator runbook live URL recorded. owner: audit doc
- `M01.P5.T4` (0.5d) - Schema v1 path recorded under closure. owner: audit doc
- `M01.P5.T5` (0.5d) - Closure: all four success-criteria check rows green, both freezes closed. owner: audit doc

**Total: ~32 tickets across 6 phases, ~30 effort-days. Sits below the 4/6/9 narrative low/real/high band when measured by clock weeks (because P4 is calendar-driven, not effort-driven).**

## Open questions for IMPLEMENT phase

1. **Where does the Chio sidecar sit relative to `opus_api`?** Sidecar process / in-process library / wrapped MCP edge? Narrative does not specify. P0.T4 names this; the answer shapes P1 and P2.
2. **CEF or LEEF for Opus SOC?** P0 interview question. The customer-voice critic named CEF/LEEF collectively; one is enough for v1. Recommendation: ship one in v1, reserve schema fields for the other in v1.x.
3. **PagerDuty service ownership.** Does the routing key live in the Chio team's PagerDuty account or the Opus ops team's? Determines who pays the seat and who can resolve incidents.
4. **30-day window start date.** P4 starts no later than week 8 of W1, but exact day-1 depends on P3 close. Pin in P0.
5. **PHI redaction default mode.** `ResponseSanitizationGuard` has multiple sensitivity levels (`spec/GUARDS.md` lines 273-296). Safe default is High (definite PII/PHI: SSN, MRN, ICD-10) but P3 must confirm.
6. **Receipt retention horizon.** HIPAA wants 6 years. Does the Opus deployment retain Chio receipts for 6 years on its own audit-store, or does Chio need a long-retention path? Affects P3 retention contract.
7. **BAA owner.** Is there a pre-existing Backbay-internal BAA covering Opus + Chio (since both are in-house) or must M01 P0 secure one? Affects P0.T2.
8. **Should M01 wait on M03 hosted CI (week 1-3) before opening P3?** Research prompt says "not a hard block"; the IMPLEMENT agent should record the soft-dep explicitly in the P3 ticket `soft_deps:` field.
9. **PagerDuty heartbeat cadence.** Weekly is typical default; daily is safer but louder. P1.T6 picks one.
10. **Opus tenant size and receipt volume.** Unknown today; gates P2 quota-lane sizing. P0.T1 collects from Opus ops.
