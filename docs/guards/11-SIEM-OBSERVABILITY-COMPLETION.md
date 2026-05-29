# SIEM and Observability Completion Plan

This document describes the current state of Chio's SIEM integration, the
remaining exporters to port from the upstream guard suite, and the new observability
surfaces needed to complete the picture: OCSF format, cloud audit log
integration, LangSmith/LangFuse bridging, and real-time receipt streaming.

---

## 1. Current State: What chio-siem Has

The `chio-siem` crate (`crates/chio-siem/src/`) provides the foundational
infrastructure for forwarding Chio receipts to external SIEM systems. It
depends on `chio-core` for `ChioReceipt` and `FinancialReceiptMetadata`, and
on `rusqlite` for direct read access to the kernel receipt database. It does
NOT depend on `chio-kernel`, keeping the kernel TCB free of HTTP client
dependencies.

### 1.1 Core Abstractions

| File | Purpose |
|------|---------|
| `exporter.rs` | `Exporter` trait: `export_batch(&self, events: &[SiemEvent]) -> ExportFuture`, plus `ExportError` |
| `event.rs` | `SiemEvent`: wraps `ChioReceipt` with extracted `FinancialReceiptMetadata` |
| `manager.rs` | `ExporterManager`: cursor-pull loop that reads receipts from SQLite and fans out to exporters |
| `dlq.rs` | `DeadLetterQueue`: bounded ring buffer for failed exports, drops oldest on overflow |
| `ratelimit.rs` | `ExportRateLimiter`: per-exporter token bucket rate limiting |

### 1.2 Working Exporters

**Splunk HEC** (`exporters/splunk.rs`). POSTs newline-separated JSON event
envelopes to `/services/collector/event`. Uses `receipt.timestamp` as the
Splunk `time` field and `receipt.id` for dedup. Enforces TLS-only for HEC
token transport. Configurable sourcetype, index, and host.

**Elasticsearch** (`exporters/elastic.rs`). POSTs NDJSON action+document
pairs to `/_bulk`. Uses `receipt.id` as the document `_id` for idempotent
upserts. Detects partial failures by parsing per-item statuses from the bulk
response. Supports API key and HTTP Basic auth (with `Zeroizing<String>` for
credential memory hygiene).

### 1.3 ExporterManager Architecture

The manager opens a single read-only SQLite connection at construction time
(WAL-mode shared-read) and polls for new receipts on a configurable interval
(default: 5s). Each poll cycle:

1. SELECT receipts with `seq > cursor`, ordered ascending, limited to
   `batch_size` (default: 100).
2. Deserialize each row into `ChioReceipt`, build `SiemEvent`.
3. Fan out the batch to every registered exporter.
4. On failure: retry with exponential backoff (configurable base and max
   attempts). Exhausted retries push events to the DLQ.
5. Advance the cursor past the batch regardless of DLQ status.

The cursor is NOT persisted to disk. On restart, the manager re-exports from
seq=0. Both Splunk (timestamp dedup) and Elasticsearch (_id upsert) handle
duplicates idempotently.

---

## 2. Missing Exporters from the upstream guard suite

The upstream `hushd` service has four additional exporters that have not
been ported to `chio-siem`. Each is production-tested in the upstream guard suite and
implements the same exporter trait pattern.

### 2.1 Datadog (`exporters/datadog.rs`)

**What it does.** Dual-channel exporter: sends structured log entries to
Datadog's Log Intake API (`/api/v2/logs`) and simultaneously pushes metrics
to the Series API (`/api/v1/series`). Logs carry full event payload with
Datadog-native status mapping (critical/error/warn/info). Metrics emit
`security.events.total`, `.allowed`, `.denied`, plus breakdowns by severity
and by guard name, enabling Datadog dashboards and monitors out of the box.

**Porting plan.**

- Adapt from the upstream `SecurityEvent` to Chio's `SiemEvent`.
- Replace `async_trait` with `Pin<Box<dyn Future>>` to match chio-siem's
  dyn-compatible `Exporter` trait.
- Change the default service/source to `chio`.
- Map Chio `Decision` (Allow/Deny) and `GuardEvidence` to Datadog tags.
- Metric prefix becomes `chio.siem` instead of the legacy source name.
- Retain configurable DD site, API key, tags, and TLS settings.

### 2.2 Sumo Logic (`exporters/sumo_logic.rs`)

**What it does.** Sends events to a Sumo Logic HTTP Source endpoint with
configurable format (JSON, plaintext, key-value). Supports gzip compression
(enabled by default). Sets `X-Sumo-Category`, `X-Sumo-Name`, and
`X-Sumo-Host` headers for Sumo's metadata enrichment.

**Porting plan.**

- Adapt from `SecurityEvent` to `SiemEvent`.
- Change default source category from `security/legacy` to
  `security/chio`.
- Preserve the three format modes. JSON is the default and should serialize
  the full `ChioReceipt` payload.
- Keep gzip compression. The `flate2` dependency is lightweight and
  significantly reduces egress bandwidth to Sumo Logic collectors.

### 2.3 Webhooks (`exporters/webhooks.rs`)

**What it does.** Notification-oriented exporter targeting Slack, Microsoft
Teams, and generic HTTP webhooks. Supports severity-based filtering
(`min_severity`), guard inclusion/exclusion lists, and per-webhook
authentication (bearer, basic, custom header). Includes a minimal
Handlebars-style template engine for custom payload rendering.

**Porting plan.**

- Adapt from `SecurityEvent` to `SiemEvent`.
- Replace legacy-branded message strings ("legacy security event")
  with Chio-branded equivalents.
- Map Chio `Decision` and `GuardEvidence` into the Slack block and Teams
  MessageCard payloads so analysts see which guard fired and why.
- The generic webhook path works unchanged because it serializes the full
  event as JSON.

### 2.4 Alerting (`exporters/alerting.rs`)

**What it does.** Incident management exporter for PagerDuty (Events API v2)
and OpsGenie (Alerts API v2). Features:

- Severity-to-priority mapping (configurable per backend).
- Dedup key templates to control alert grouping (e.g., by guard+session or
  by guard+resource).
- PagerDuty auto-resolve: background loop that sends `resolve` events after
  a configurable quiet period.
- OpsGenie heartbeat: periodic ping to detect silent failures.
- Shutdown-aware: cancels background tasks cleanly via `watch` channels.

**Porting plan.**

- Adapt from `SecurityEvent` to `SiemEvent`.
- Replace legacy branding in alert summaries and source fields.
- Map Chio `GuardEvidence` into PagerDuty `custom_details` and OpsGenie
  `details` so on-call engineers see the full guard context.
- The background task pattern (auto-resolve, heartbeat) ports directly
  because `chio-siem` already uses `tokio` and `watch` channels.

### 2.5 Porting Strategy (All Four)

All four exporters follow the same structural pattern:

1. Define a `FooConfig` struct with `#[derive(Serialize, Deserialize)]`.
2. Implement a `FooExporter` struct holding `config` and `reqwest::Client`.
3. Implement `Exporter` for `FooExporter`.

The primary adaptation is the event type: The upstream suite uses
`SecurityEvent` (rich structured type with `AgentInfo`, `SessionInfo`,
`ThreatInfo`, `DecisionInfo`, `ResourceInfo`). Chio uses `SiemEvent`
(wrapping `ChioReceipt`).

Two approaches, not mutually exclusive:

**Option A: Direct field mapping.** Each exporter extracts what it needs
from `SiemEvent.receipt` (tool_name, decision, evidence, timestamp) and
serializes in the backend-native format. Simple, no shared abstraction.

**Option B: Enriched SiemEvent.** Extend `SiemEvent` with optional fields
that parallel the upstream `SecurityEvent` structure (severity, guard_name,
resource_type, threat indicators). Populate these from `GuardEvidence` and
receipt metadata at construction time. Exporters work against the enriched
type.

**Recommendation: Option B.** The enrichment logic is written once in
`SiemEvent::from_receipt` and every exporter benefits. It also creates the
natural hook for OCSF mapping (Section 3).

---

## 3. OCSF Receipt Format

### 3.1 What Is OCSF

The Open Cybersecurity Schema Framework (OCSF) is a vendor-neutral schema
for security events, adopted by AWS Security Lake, Splunk OCSF integration,
and CrowdStrike Falcon. It defines event classes (Detection Finding, API
Activity, Authorization, etc.) with normalized fields.

### 3.2 Why It Matters for Chio

Chio receipts are security attestations. They record that a tool call was
evaluated against a guard pipeline and either allowed or denied, with
cryptographic proof. This is exactly what OCSF event classes describe:

- **Authorization (class 3002)**: a principal requested access to a
  resource, and a policy decision was made.
- **Detection Finding (class 2004)**: a security control detected something
  noteworthy (guard deny, secret leak, forbidden path).
- **API Activity (class 6003)**: an API call was made (tool invocation).

Without OCSF, every SOC that ingests Chio receipts must write custom parsing
rules. With OCSF, Chio events slot into existing detection pipelines and
Security Lake queries immediately.

### 3.3 Receipt-to-OCSF Mapping

```
Chio Receipt Field           OCSF Field (Authorization)
-----------                 --------------------------
receipt.id                  metadata.uid
receipt.timestamp           time (epoch ms)
receipt.tool_server         dst_endpoint.name
receipt.tool_name           api.operation
receipt.action.parameters   api.request.data
receipt.decision            activity_id (1=Allow, 2=Deny)
receipt.policy_hash         policy.uid
receipt.content_hash        unmapped_data.content_hash
receipt.evidence[]          finding_info.analytic[]
  .guard_name                 .name
  .verdict                    .type (allowed=1, denied=2)
  .details                    .desc
receipt.kernel_key          actor.authorizations[].id
receipt.capability_id       actor.authorizations[].uid
```

### 3.4 Implementation Plan

Add an `ocsf` module to `chio-siem` that transforms `SiemEvent` into the
OCSF Authorization JSON structure:

```rust
// crates/chio-siem/src/ocsf.rs
pub fn to_ocsf_authorization(event: &SiemEvent) -> serde_json::Value { ... }
pub fn to_ocsf_detection_finding(event: &SiemEvent) -> serde_json::Value { ... }
```

The mapping function is used by any exporter that supports OCSF (Splunk
with `_ocsf` index, Elasticsearch with OCSF-schema index templates, AWS
Security Lake ingestion). The exporter calls the mapper before serialization
rather than building OCSF inline.

The upstream suite already has a `SchemaFormat` enum with an `Ocsf` variant. Port
this concept: let exporters declare their schema preference, and the manager
applies the appropriate transform before calling `export_batch`.

---

## 4. Cloud Audit Log Integration

Enterprise deployments need Chio receipts to appear alongside native cloud
audit events. The three targets:

### 4.1 AWS CloudTrail

CloudTrail supports custom event ingestion via CloudTrail Lake.

- Use the `PutAuditEvents` API to write to a CloudTrail Lake event data
  store.
- Map Chio receipts to CloudTrail's event structure: `eventSource` =
  `chio.kernel`, `eventName` = tool_name, `requestParameters` =
  action.parameters, `responseElements.decision` = Allow/Deny.
- Implementation: new `CloudTrailExporter` implementing the `Exporter`
  trait. Uses `aws-sdk-cloudtrail` with standard credential chain
  resolution.

### 4.2 Google Cloud Audit Logs

Cloud Audit Logs accepts custom audit log entries via the Cloud Logging API.

- Write entries with `logName` =
  `projects/{project}/logs/chio.googleapis.com%2Fguard_audit`.
- Use the `AuditLog` protobuf structure: `service_name` = `chio.kernel`,
  `method_name` = tool_name, `authorization_info[]` maps from guard
  evidence.
- Implementation: new `CloudAuditLogExporter`. Uses `google-cloud-logging`
  crate or raw HTTP with service account credentials.

### 4.3 Azure Activity Log

Azure uses Diagnostic Settings to route to Log Analytics, Event Hubs, or
Storage.

- Chio events are sent as custom log entries to a Log Analytics workspace
  via the Data Collector API (HTTP Data Collector / DCR-based ingestion).
- Table name: `ChioGuardAudit_CL`.
- Implementation: new `AzureLogAnalyticsExporter`. Uses shared key or
  Azure AD (Entra ID) authentication.

### 4.4 Priority

Cloud audit log exporters are lower priority than the four upstream
ports. They require cloud-specific SDK dependencies and IAM configuration
that varies per deployment. Ship as optional features behind Cargo feature
flags (`feature = "cloudtrail"`, `feature = "gcp-audit"`, etc.) to avoid
pulling cloud SDKs into the default build.

---

## 5. LangSmith / LangFuse Observability Bridge

### 5.1 The Gap

Chio receipts are security attestations. LangSmith and LangFuse are agent
observability platforms that track LLM calls as spans in traces. Today,
there is no connection between them: a SOC analyst sees guard decisions in
the SIEM, but the agent developer sees tool calls in LangSmith without any
security context. Neither side has the full picture.

### 5.2 The Bridge

Push Chio receipts as enriched spans into LangSmith/LangFuse so that every
tool call trace includes its guard evaluation result.

**LangSmith bridge.** Use LangSmith's Run API (`POST /runs`) to create a
child run for each receipt:
- `run_type` = `chain`
- `name` = `chio.guard.{tool_name}`
- `inputs` = action.parameters
- `outputs` = `{ decision, evidence[] }`
- `extra.metadata` = `{ capability_id, policy_hash, receipt_id }`
- Parent run ID comes from the agent's trace context (passed as receipt
  metadata).

**LangFuse bridge.** Use LangFuse's Ingestion API (`POST /api/public/ingestion`)
to create a span:
- `type` = `span`
- `name` = `chio.guard.{tool_name}`
- `input` = action.parameters
- `output` = `{ decision, evidence[] }`
- `metadata` = `{ capability_id, policy_hash, receipt_id, guard_names }`
- `traceId` and `parentObservationId` come from agent trace context.

### 5.3 Trace Context Propagation

The agent must pass its LangSmith run ID or LangFuse trace ID to the kernel
so it can be attached to the receipt. This propagates via the `metadata`
field on `ChioReceiptBody`:

```json
{
  "metadata": {
    "trace": {
      "langsmith_run_id": "run_abc123",
      "langfuse_trace_id": "trace_xyz789",
      "langfuse_parent_observation_id": "obs_456"
    }
  }
}
```

If trace metadata is absent, the bridge creates a standalone trace (useful
for receipts generated without agent-side instrumentation).

### 5.4 Implementation

These are new exporters implementing the `Exporter` trait:

```
LangSmithExporter  -- POST /runs with API key auth
LangFuseExporter   -- POST /api/public/ingestion with Basic auth (public/secret key)
```

Both follow the same pattern as Splunk and Elasticsearch: config struct,
reqwest client, batch serialization. They are optional features
(`feature = "langsmith"`, `feature = "langfuse"`).

---

## 6. Receipt-to-Event Streaming

### 6.1 Current Model: Polling

The `ExporterManager` uses a cursor-pull loop with a configurable poll
interval (default: 5s). This is simple and correct but introduces latency
equal to the poll interval in the worst case.

### 6.2 Real-Time Emission

For alerting exporters (PagerDuty, OpsGenie, Slack), 5-second latency may
be unacceptable during active incidents. Two options:

**Option A: Kernel notify channel.** The kernel sends a `tokio::sync::Notify`
(or `watch` channel) after each receipt is committed to SQLite. The manager
awaits the notification instead of sleeping for the full poll interval.
The cursor-pull mechanics remain identical; only the wake trigger changes.

This does NOT require `chio-siem` to depend on `chio-kernel`. The kernel
exposes a `Notify` handle at construction time; the binary that wires
kernel + manager passes it through.

**Option B: SQLite WAL hook.** Register a WAL commit hook on the read-only
connection that wakes the poll loop when the receipts table changes. This
avoids any kernel coupling but requires the `SQLITE_FCNTL_WAL_HOOK`
interface, which is not exposed by rusqlite's safe API.

**Recommendation: Option A.** It is simple, type-safe, and already fits the
async architecture. The poll interval remains as a fallback for missed
notifications.

### 6.3 Batch vs. Single-Event Export

Even with real-time notification, batching remains important:

- SIEM backends (Splunk, ES, Datadog) are optimized for batch ingestion.
- Alerting backends (PagerDuty, OpsGenie) should fire per-event.

The manager should support per-exporter batch policy: SIEM exporters
accumulate a batch (up to `batch_size` or `flush_interval`, whichever comes
first), while alerting exporters flush immediately on notification.

---

## 7. Guard Evidence Enrichment

### 7.1 The Problem

As Chio absorbs more guard types (WASM guards, upstream-adapted guards,
cross-protocol guards), the `GuardEvidence` array on each receipt grows
richer. Each guard produces structured details:

- **Forbidden-path guard:** matched path pattern, attempted path.
- **Egress guard:** destination host, matched deny-list entry.
- **Secret-leak guard:** secret type (API key, JWT, etc.), redacted context.
- **WASM guards:** fuel consumed, execution time, custom output JSON.
- **Financial guards:** transaction amount, currency, limit exceeded.

### 7.2 How Evidence Enriches SIEM Events

Today, `SiemEvent` wraps `ChioReceipt` as a blob. Exporters serialize the
entire receipt, and SIEM analysts must drill into nested JSON to find guard
details.

The enriched model extracts evidence into top-level SIEM fields:

```
SiemEvent {
    receipt: ChioReceipt,
    financial: Option<FinancialReceiptMetadata>,

    // New enrichment fields (populated from evidence[]):
    primary_guard: Option<String>,      // first deny guard, or first guard
    severity: Severity,                 // derived from decision + guard type
    resource_type: ResourceType,        // file, network, tool, process
    resource_name: String,              // tool_name or extracted path/host
    threat_indicators: Vec<Indicator>,  // extracted from guard details
    guard_summary: Vec<GuardSummary>,   // name + verdict + key detail per guard
}
```

This structure is what drives:
- OCSF field mapping (Section 3)
- Datadog tag generation (severity, guard, resource)
- Sumo Logic key-value format
- Webhook notification payloads
- Alerting dedup key rendering

### 7.3 Severity Derivation

Chio receipts carry `Decision::Allow` or `Decision::Deny` but no severity
level. The enrichment layer derives severity from the guard type and
decision:

| Decision | Guard Type | Severity |
|----------|-----------|----------|
| Deny | secret-leak | Critical |
| Deny | egress (to known-bad host) | High |
| Deny | forbidden-path | High |
| Deny | financial-limit-exceeded | High |
| Deny | generic / WASM | Medium |
| Allow | (any, with warnings in evidence) | Low |
| Allow | (clean pass) | Info |

This table is configurable via a severity policy, not hardcoded.

---

## 8. Exporter Trait and Plugin Architecture

### 8.1 The Trait

```rust
pub trait Exporter: Send + Sync {
    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a>;
    fn name(&self) -> &str;
}
```

The trait uses `Pin<Box<dyn Future>>` rather than `async_trait` to remain
dyn-compatible. `ExporterManager` holds `Vec<Box<dyn Exporter>>` and fans
out to all registered exporters on each poll cycle.

### 8.2 How New Exporters Plug In

Adding a new exporter requires:

1. Create `crates/chio-siem/src/exporters/foo.rs`.
2. Define `FooConfig` (with `Serialize`/`Deserialize` for config file
   loading).
3. Implement `Exporter for FooExporter`.
4. Add `pub mod foo;` to `exporters/mod.rs`.
5. Re-export from `lib.rs`.
6. Register with `manager.add_exporter(Box::new(foo))` at startup.

No changes to the manager, DLQ, or rate limiter. The exporter is isolated
behind the trait boundary.

### 8.3 Extensions from the upstream guard suite's Trait

The upstream exporter trait has two additional methods not present in
chio-siem's:

```rust
fn schema(&self) -> SchemaFormat;       // ECS, CEF, OCSF, Native
async fn health_check(&self) -> Result<(), String>;
async fn shutdown(&self) -> Result<(), String>;
```

**`schema()`**: needed for OCSF support (Section 3). The manager uses this
to apply the correct transform before export.

**`health_check()`**: needed for operational readiness probes. The manager
should expose an aggregate health endpoint that calls `health_check()` on
each exporter.

**`shutdown()`**: needed for the alerting exporter's background tasks
(PagerDuty auto-resolve, OpsGenie heartbeat). Without it, the manager
cannot cleanly stop these tasks on process exit.

**Recommendation:** Extend chio-siem's `Exporter` trait with all three
methods, using default implementations so existing exporters do not break:

```rust
pub trait Exporter: Send + Sync {
    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a>;
    fn name(&self) -> &str;

    fn schema(&self) -> SchemaFormat { SchemaFormat::Native }
    fn health_check(&self) -> ExportFuture<'static> {
        Box::pin(async { Ok(0) })
    }
    fn shutdown(&self) -> ExportFuture<'static> {
        Box::pin(async { Ok(0) })
    }
}
```

---

## 9. Implementation Order

| Phase | Work | Depends On |
|-------|------|-----------|
| 1 | Enrich `SiemEvent` with guard evidence fields | None |
| 2 | Port Datadog exporter | Phase 1 |
| 3 | Port Sumo Logic exporter | Phase 1 |
| 4 | Port webhook exporter (Slack, Teams, generic) | Phase 1 |
| 5 | Port alerting exporter (PagerDuty, OpsGenie) | Phase 1, trait extension |
| 6 | Extend `Exporter` trait with `schema()`, `health_check()`, `shutdown()` | Phase 5 |
| 7 | Add OCSF mapping module | Phase 1, Phase 6 |
| 8 | Real-time receipt streaming (kernel notify) | None (parallel) |
| 9 | LangSmith bridge exporter | Phase 1 |
| 10 | LangFuse bridge exporter | Phase 1 |
| 11 | Cloud audit log exporters (CloudTrail, GCP, Azure) | Phase 1 |

Phases 1-5 are the critical path. They bring Chio to feature parity with
The upstream SIEM capabilities. Phases 6-7 add schema normalization.
Phase 8 eliminates polling latency. Phases 9-11 are new capabilities that
extend Chio's reach into agent observability and cloud compliance surfaces.

---

## 10. Open Questions

1. **Event type unification.** Should chio-siem adopt the upstream suite
   `SecurityEvent` type wholesale as an intermediate representation, or
   build a leaner Chio-native enrichment? The former maximizes code reuse;
   the latter avoids importing the upstream audit-event ontology into Chio's
   core abstractions.

2. **Cursor persistence.** The current design re-exports all receipts on
   restart. For deployments with millions of receipts, this is untenable.
   Should the cursor be persisted in a separate SQLite table, in the
   receipt database itself, or in a sidecar file?

3. **Multi-tenant isolation.** If Chio serves multiple tenants (different
   agents, different policies), should each tenant get its own exporter
   pipeline, or should the manager apply tenant-scoped filters before
   fan-out?

4. **Credential management.** The ported exporters carry API keys, routing
   keys, and webhook URLs. These must not appear in plaintext config files.
   Define a credential resolution interface (env vars, secrets manager,
   Vault) before shipping any new exporter to production.
