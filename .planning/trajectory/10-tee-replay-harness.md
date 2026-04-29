# Milestone 10: Live-Traffic Tee + Replay Harness (with OpenTelemetry GenAI fold-in)

Status: proposed
Lens: integrations
Owner: integrations track
Anchors: `RELEASE_AUDIT`, `BOUNDED_OPERATIONAL_PROFILE`, `spec/PROTOCOL.md` (receipt provenance, canonical-JSON capture frames), Milestone 01 (canonical-JSON capture stability), Milestone 04 (deterministic replay infrastructure), Milestone 06 (WASM guard PII redactors), Milestone 07 (provider adapters as upstream traffic source).

## Why this milestone

The single largest adoption blocker the seven-agent debate surfaced was operational, not technical: an SRE who runs production agents cannot drop a verdict-enforcing proxy in front of GPT-5 on day one. Hard enforcement against a closed provider is a stop-the-world risk. Today Chio offers two operating modes (full mediation through `chio-mcp-edge`, `chio-a2a-edge`, `chio-acp-proxy`, and the M07 provider adapters; or no mediation at all). There is no documented path to run Chio in shadow mode, observe the verdicts it would have rendered against real prod traffic, capture the trace, and gain confidence before flipping enforcement on.

This milestone closes that gap. It ships `chio-tee`, a sidecar that taps existing edges and adapters; an NDJSON capture format whose frames are receipt-shaped and canonical-JSON stable; a `chio replay` runner that re-executes captures against new policy versions and diffs verdicts; and an OpenTelemetry GenAI fold-in so every adapter emits `gen_ai.*` spans linkable bidirectionally to receipt ids. The replay corpus produced by a single shadow-mode session becomes a regression test for adapter and policy changes, bridging M07 (integration breadth) with M04 (replay reliability).

## In scope

- `chio-tee` sidecar binary and container image. Taps OpenAI Responses, Anthropic Messages, Bedrock Converse, MCP, and A2A traffic from the existing edges (`crates/chio-mcp-edge/src/runtime.rs`, `crates/chio-a2a-edge/src/lib.rs`, `chio-acp-proxy`) and M07 adapters. Three modes are documented and tested:
  - `verdict-only`: kernel computes a verdict, the tee logs it, and the upstream response is returned unaltered. Never blocks. The kernel runs in dry-eval (no receipt-write side effects beyond an in-memory verdict envelope).
  - `shadow`: the tee logs both the verdict and a `would_have_blocked: bool` annotation alongside the unmediated upstream response. Frames flow to NDJSON for replay graduation. Never enforces.
  - `enforce`: the existing M07 mediation path. Verdicts deny or rewrite as policy dictates.
- An NDJSON capture format (`chio-tee-frame.v1`) whose frames are receipt-shaped and stable against the M01 canonical-JSON `ToolInvocation` schema. Frames are append-only, signed by the tee's tenant key, and concatenated with `\n` separators. Blob bodies live alongside the NDJSON in a content-addressed `blobs/<sha256>` directory (encrypted at rest via `chio-store-sqlite`'s BLOB-encryption hook). Unknown `schema_version` values are rejected by the runner. The exact JSON Schema is locked in [Frame schema lock](#frame-schema-lock-chio-tee-framev1).
- A mandatory privacy redaction guard pass before persistence. The tee invokes the M06 WASM guard pipeline through the `chio-wasm-guards` host with the `redact` policy class on every captured payload; raw payloads stay in zeroize-on-drop buffers and never touch disk before the redactor runs. M06 reserves the `chio:guards/redact@0.1.0` namespace in its Phase 1; M10 ships the concrete redactor world. Default redactor set ships in `crates/chio-data-guards/redactors/default/`: regex secrets (AWS keys, JWTs, Stripe keys, generic `[A-Za-z0-9_]{32,}` high-entropy tokens), basic PII (email, E.164 phone, US SSN, credit-card Luhn), and a Bearer-token stripper. Override path: tenants supply a guard manifest pointing to a signed WASM module under `[tee.redactors]`, which replaces or augments the default set. Frames whose redaction manifest reports zero matches on a payload longer than 256 bytes are quarantined under `--paranoid` (heuristic for misconfigured redactors). The exact WIT and an example regex-secret redactor live in [Redactor host call shape](#redactor-host-call-shape-chioguardsredact010).
- `chio-replay` runner exposed as `chio replay <capture.ndjson> --against <policy-ref>` in `chio-cli`. Re-executes each captured `ToolInvocation` against a named policy version and emits a diff report (verdicts changed, guards added or removed, decision reasons). Exit codes are the **canonical M04 registry** (see `04-deterministic-replay.md` "EXIT CODES" block); M10 consumes M04's registry verbatim and does not define new codes. The codes (0, 10, 20, 30, 40, 50) are summarized here for convenience but normatively owned by M04:
  - `0` clean match (every frame's verdict is bit-identical under the new policy)
  - `10` verdict drift (at least one frame flipped allow -> deny or deny -> allow)
  - `20` signature mismatch (a frame's `tenant_sig` fails verification)
  - `30` parse error (NDJSON unreadable, line-level structural failure)
  - `40` schema mismatch (`schema_version` unknown or `invocation` fails M01 validation)
  - `50` redaction mismatch (the recorded `redaction_pass_id` is unavailable or rerunning produces a different redaction manifest)
- A `chio-replay-corpus` crate that adapts a captured NDJSON session into a fixture suitable for M04's `chio-replay-gate` corpus, so a shadow-mode session graduates into the regression suite with a single `chio replay --bless` step.
- OpenTelemetry GenAI semantic conventions, pinned to `opentelemetry-semantic-conventions` v1.31.0 (the first release marking `gen_ai.*` as stable for tool-call spans; the `gen_ai` namespace is still evolving and a version pin is non-optional). Attribute names are locked in [OTel attribute lock](#otel-attribute-lock).
- An OTel Collector exporter (`chio-otel-receipt-exporter`) that receives spans from a Collector pipeline and sinks them to the receipt store, so an existing OTel-instrumented agent can land its traces alongside Chio receipts without instrumenting the agent twice.
- Loki, Tempo, and Jaeger dashboard JSON committed under `deploy/dashboards/` and importable as a one-command demo.

## Out of scope

- A new on-the-wire protocol. The tee sits on top of existing edges; it does not invent a new MCP-equivalent surface.
- Replacing the M04 receipt-log corpus. The replay harness reuses M04's gate; it adds a capture format and an ingest path.
- Provider-specific telemetry vendor lock (Datadog APM, New Relic, etc.). The OTel Collector exporter is the integration point; vendor pipelines plug in there.
- Live policy hot-reload. Replay diffs against a named policy ref; runtime policy swaps are M11 territory.
- Multi-tenant capture aggregation across kernels. Each tee writes its own NDJSON; cross-kernel aggregation is a future milestone.

## Tee mode precedence and SIGUSR1 hot-toggle

Mode selection precedence (verbatim, highest priority first):

1. Process env `CHIO_TEE_MODE={verdict-only,shadow,enforce}` (default `verdict-only` if unset and lower layers also unset).
2. Sidecar TOML config under `[tee] mode = "..."` in `chio-tee.toml`.
3. Per-tenant manifest default (`tenant.tee.mode`) shipped via `chio-manifest`.

Resolution rule: `env > sidecar TOML > tenant manifest`. The resolved mode is logged at startup as `tee.mode_resolved` with all three layer values for diagnostic clarity.

SIGUSR1 handler:

- The handler reads a single line from `${CHIO_TEE_RUNTIME_DIR}/mode-request` (created mode `0600`, owned by the tee user). The line MUST be one of `verdict-only`, `shadow`, or `enforce`.
- Downgrades follow the lattice `enforce -> shadow -> verdict-only`. Downgrades are unconditional (no capability check) because they reduce blast radius.
- Upgrades (`verdict-only -> shadow`, `shadow -> enforce`, `verdict-only -> enforce`) require a `chio-control-plane` capability `chio:tee/upgrade@1` whose token is read from `${CHIO_TEE_RUNTIME_DIR}/upgrade.cap`. Missing or expired capability rejects the upgrade and logs `tee.upgrade_denied`.
- Every successful transition writes a `tee.mode_changed { from, to, source: "sigusr1", caller_pid }` event to the receipt log via the kernel's `record_event` hook. Failed transitions write `tee.mode_change_failed`.
- Concurrent SIGUSR1 deliveries serialize through a `tokio::sync::Mutex` to avoid torn reads of the request file.

Authenticated control-plane RPC (`chio-control-plane.tee.set_mode`): same lattice, same capability requirement for upgrades. RPC and SIGUSR1 share the receipt-log event format but differ in the `source` field (`rpc` vs `sigusr1`).

Test that proves the precedence: `crates/chio-tee/tests/mode_precedence.rs::env_overrides_toml_overrides_manifest` builds a tenant manifest that requests `enforce`, a TOML config that requests `shadow`, and an env var that sets `verdict-only`. The resolved mode MUST be `verdict-only`. The test then unsets the env var and asserts `shadow`. The test then deletes the TOML and asserts `enforce`. Each transition is checked against `tee.mode_resolved` log output for the recorded layer values.

## Frame schema lock: `chio-tee-frame.v1`

Pin `schema_version: "1"` (the string literal `"1"`, not the symbolic name `chio-tee-frame.v1`; the schema name is the type, the version is the field). The `$id` URI is the type/version composition.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.dev/schemas/chio-tee-frame/v1.json",
  "title": "chio-tee-frame.v1",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "event_id",
    "ts",
    "tee_id",
    "upstream",
    "invocation",
    "provenance",
    "request_blob_sha256",
    "response_blob_sha256",
    "redaction_pass_id",
    "verdict",
    "would_have_blocked",
    "tenant_sig"
  ],
  "properties": {
    "schema_version": {
      "type": "string",
      "const": "1",
      "description": "Frame schema major version. Pinned to \"1\" for chio-tee-frame.v1."
    },
    "event_id": {
      "type": "string",
      "pattern": "^[0-9A-HJKMNP-TV-Z]{26}$",
      "description": "ULID. Crockford base32, 26 chars."
    },
    "ts": {
      "type": "string",
      "format": "date-time",
      "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$",
      "description": "RFC3339 UTC timestamp with millisecond precision and trailing Z."
    },
    "tee_id": {
      "type": "string",
      "minLength": 3,
      "maxLength": 64,
      "pattern": "^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$",
      "description": "Stable tee identifier per deployment."
    },
    "upstream": {
      "type": "object",
      "additionalProperties": false,
      "required": ["system", "operation", "api_version"],
      "properties": {
        "system": {
          "type": "string",
          "enum": ["openai", "anthropic", "aws.bedrock", "mcp", "a2a", "acp"]
        },
        "operation": {
          "type": "string",
          "minLength": 1,
          "maxLength": 128,
          "pattern": "^[a-z][a-z0-9_.]*$",
          "description": "Provider-specific operation, e.g. responses.create, messages.create, tool.call."
        },
        "api_version": {
          "type": "string",
          "minLength": 1,
          "maxLength": 32,
          "description": "Provider API version string, e.g. 2025-10-01."
        }
      }
    },
    "invocation": {
      "type": "object",
      "description": "Canonical-JSON ToolInvocation per the M01 schema. Validated by the M01 validator; opaque here."
    },
    "provenance": {
      "type": "object",
      "additionalProperties": false,
      "required": ["otel"],
      "properties": {
        "otel": {
          "type": "object",
          "additionalProperties": false,
          "required": ["trace_id", "span_id"],
          "properties": {
            "trace_id": {
              "type": "string",
              "pattern": "^[0-9a-f]{32}$",
              "description": "W3C trace-id, 32 lowercase hex."
            },
            "span_id": {
              "type": "string",
              "pattern": "^[0-9a-f]{16}$",
              "description": "W3C span-id, 16 lowercase hex."
            }
          }
        },
        "supply_chain": {
          "type": "object",
          "description": "Optional M09 SBOM-style provenance superset; opaque here."
        }
      }
    },
    "request_blob_sha256": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$",
      "description": "Lowercase hex SHA-256 of the redacted request blob."
    },
    "response_blob_sha256": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$",
      "description": "Lowercase hex SHA-256 of the redacted response blob."
    },
    "redaction_pass_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[a-z0-9][a-z0-9._@+-]*$",
      "description": "Identifier for the redactor pipeline that produced this frame, e.g. m06-redactors@1.4.0+default."
    },
    "verdict": {
      "type": "string",
      "enum": ["allow", "deny", "rewrite"]
    },
    "deny_reason": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256,
      "pattern": "^[a-z][a-z0-9_]*(:[a-z][a-z0-9_.]*)*$",
      "description": "Required iff verdict is deny or rewrite. Namespaced reason code, e.g. guard:pii.email_in_response."
    },
    "would_have_blocked": {
      "type": "boolean",
      "description": "True iff the kernel would have denied or rewritten under the resolved policy. Always present; equals (verdict != allow) in shadow/enforce, always false in verdict-only."
    },
    "tenant_sig": {
      "type": "string",
      "pattern": "^ed25519:[A-Za-z0-9+/=]{86,88}$",
      "description": "Ed25519 signature over the canonical-JSON encoding of all other fields, base64-standard."
    }
  },
  "allOf": [
    {
      "if": { "properties": { "verdict": { "const": "allow" } } },
      "then": { "not": { "required": ["deny_reason"] } }
    },
    {
      "if": { "properties": { "verdict": { "enum": ["deny", "rewrite"] } } },
      "then": { "required": ["deny_reason"] }
    }
  ]
}
```

## Phases

### Phase 1: `chio-tee` sidecar and capture format

Effort: **L, 9 days**.

First commit message (verbatim): `feat(chio-tee): scaffold sidecar crate with TrafficTap trait and v1 frame`.

Task breakdown:

1. Scaffold `crates/chio-tee/` (lib + bin), wire into workspace `Cargo.toml`, add `Dockerfile.tee` derived from `Dockerfile.sidecar`. **(S, 0.5d)**
2. Define `TrafficTap` trait in `crates/chio-tee/src/tap.rs` mirroring the `Exporter` trait at `crates/chio-siem/src/exporter.rs:35`; provide `before_kernel` and `after_kernel` hooks. **(S, 1d)**
3. Implement `chio-tee-frame.v1` types in `crates/chio-tee/src/frame.rs` with canonical-JSON serializer reuse from `chio-core`; add proptest round-trip invariants. **(M, 1.5d)**
4. Implement mode resolver (env > sidecar TOML > tenant manifest) and SIGUSR1 handler in `crates/chio-tee/src/mode.rs`; tests at `tests/mode_precedence.rs`. **(M, 1.5d)**
5. Wire mandatory M06 redactor pass via the `chio:guards/redact@0.1.0` host call before any frame is buffered; raw-payload zeroize-on-drop buffer in `crates/chio-tee/src/redact.rs`. **(M, 2d)**
6. Wire BLOB-encrypted at-rest persistence through `chio-store-sqlite`'s tenant-key hook; integration tests against fixture traffic from M07 conformance corpus. **(M, 1.5d)**
7. Ship container image; CI build + smoke under `examples/tee-sidecar/`. **(S, 1d)**

### Phase 2: `chio-replay` runner and CLI integration

Effort: **M, 5 days**.

First commit message (verbatim): `feat(chio-cli): add replay subcommand with frame validation and exit codes 0/10/20/30/40/50`.

Task breakdown:

1. Add `replay` arm to the `Commands` enum in `crates/chio-cli/src/cli/dispatch.rs`; wire dispatch. **(S, 0.5d)**
2. Implement `crates/chio-cli/src/cli/replay.rs`: NDJSON line iterator, schema-version gate, tenant-sig verifier, M01 invocation validator. **(M, 1.5d)**
3. Implement re-execution against `--against <policy-ref>` (manifest hash, package version, or workspace path); namespaced replay receipt ids `replay:<run_id>:<frame_id>`. **(M, 1.5d)**
4. Implement diff renderer grouped by drift class (allow/deny flip, guard delta, reason delta); `--json` and human formats. **(S, 0.5d)**
5. Integration tests at `crates/chio-cli/tests/replay_traffic.rs`: one test per exit code (0, 10, 20, 30, 40, 50). **(S, 1d)**

### Phase 2.5: Fixture-graduation boundary (shadow-mode capture -> M04 corpus)

Effort: **M, 4 days**.

First commit message (verbatim): `feat(chio-replay-corpus): graduate tee captures into M04 fixtures via --bless`.

Task breakdown:

1. Scaffold `crates/chio-replay-corpus/` and add to workspace; depend on `chio-tee` and `chio-cli`. **(S, 0.5d)**
2. Implement dedupe (canonical-JSON `invocation` hash, last-wins) and re-redaction under the current default redactor set. **(M, 1d)**
3. Implement `chio replay --bless --into <fixture-dir>` writing per-scenario directories matching M04's `tests/replay/goldens/<family>/<name>/` layout (`receipts.ndjson`, `checkpoint.json`, `root.hex`); strip `tenant_sig` and request/response blobs so only canonical `invocation` and verdict survive. **(M, 1.5d)**
4. Audit-log entry on bless, weekly review SLA, 30-day unblessed-capture expiry. See [Bless graduation runbook](#bless-graduation-runbook). **(S, 0.5d)**
5. End-to-end test: capture -> redact -> dedupe -> bless -> M04 gate green. **(S, 0.5d)**

The bless flow MUST match what M04 expects. M04 Phase 1 specifies golden directories under `tests/replay/goldens/<family>/<name>/` containing `receipts.ndjson`, `checkpoint.json`, and `root.hex`; M04 Phase 4 documents `chio replay <log> [--from-tee] [--expect-root <hex>] [--json]`. M10's `--bless` writes into the M04 directory shape and the resulting fixture passes `chio-replay-gate` on subsequent CI runs.

### Phase 3: OpenTelemetry GenAI fold-in

Effort: **L, 8 days**.

First commit message (verbatim): `feat(otel): emit gen_ai.tool.call spans and chio.* attributes pinned to opentelemetry-semantic-conventions v1.31.0`.

Task breakdown:

1. Add `otel` cargo feature to each adapter and the kernel; pin `opentelemetry-semantic-conventions = "=1.31.0"` workspace-wide. **(S, 0.5d)**
2. Emit `gen_ai.tool.call` spans with locked attribute set per [OTel attribute lock](#otel-attribute-lock); enforce cardinality bounds via `cardinality_test` proptest. **(M, 2d)**
3. Extend `crates/chio-kernel/src/receipt_support.rs` `provenance` block with `otel.{trace_id, span_id}`. **(S, 1d)**
4. Land `crates/chio-otel-receipt-exporter/`: OTLP gRPC ingress, receipt-store sink, attribute deny-list filter for high-cardinality keys before Prometheus forwarding. **(L, 2.5d)**
5. Commit `deploy/dashboards/{loki,tempo,jaeger}/*.json`: span timeline keyed on receipt id, verdict drift heatmap, redaction-pass latency. **(S, 1d)**
6. Land `examples/otel-genai/` end-to-end demo with Jaeger + Tempo; bidirectional `receipt-id <-> span-id` lookup test. **(M, 1d)**

## OTel attribute lock

All attributes below are locked against `opentelemetry-semantic-conventions = "=1.31.0"`. Any drift requires a workspace-wide version bump and a `docs/integrations/otel.md` migration entry. Cardinality bounds are enforced by `crates/chio-kernel/tests/otel_cardinality.rs`.

`gen_ai.*` attributes (semantic-convention namespace, lower-snake-case):

| Attribute | Required | Type | Cardinality bound | Notes |
|-----------|----------|------|-------------------|-------|
| `gen_ai.system` | required | enum string | <= 8 (`openai`, `anthropic`, `aws.bedrock`, `mcp`, `a2a`, `acp`, `cohere`, `google.vertex`) | low cardinality, safe as metric label |
| `gen_ai.operation.name` | required | string | <= 32 per system | low cardinality, safe as metric label |
| `gen_ai.request.model` | required | string | <= 64 per system | low cardinality, safe as metric label |
| `gen_ai.tool.call.id` | required | string | unbounded | span attribute only, NEVER metric label |
| `gen_ai.tool.name` | required | string | <= 256 per tenant | low-medium, span attribute only |
| `gen_ai.response.finish_reasons` | optional | string array | <= 8 | enum-like; safe as metric label |
| `gen_ai.usage.input_tokens` | optional | int | n/a (numeric) | span attribute and histogram metric |
| `gen_ai.usage.output_tokens` | optional | int | n/a (numeric) | span attribute and histogram metric |

`chio.*` attributes (Chio-namespaced):

| Attribute | Required | Type | Cardinality bound | Notes |
|-----------|----------|------|-------------------|-------|
| `chio.receipt.id` | required | string | unbounded | span attribute only, NEVER metric label |
| `chio.tenant.id` | required | string | <= 1024 per cluster | safe as metric label up to bound |
| `chio.policy.ref` | required | string | <= 256 per tenant | safe as metric label |
| `chio.verdict` | required | enum string | 3 (`allow`, `deny`, `rewrite`) | safe as metric label |
| `chio.tee.mode` | required | enum string | 3 (`verdict-only`, `shadow`, `enforce`) | safe as metric label |
| `chio.tee.id` | optional | string | <= 256 per cluster | safe as metric label |
| `chio.guard.outcome` | optional | string | <= 64 per policy | safe as metric label |
| `chio.deny.reason` | optional | string | <= 128 per policy | safe as metric label |
| `chio.replay.run_id` | optional | string | unbounded | span attribute only, NEVER metric label, only set by `chio replay` |

The deny-list of attribute keys forbidden from Prometheus-shaped sinks: `gen_ai.tool.call.id`, `chio.receipt.id`, `chio.replay.run_id`. The `chio-otel-receipt-exporter` strips them before forwarding.

## Redactor host call shape: `chio:guards/redact@0.1.0`

M06 Phase 1 reserves the `chio:guards/redact@0.1.0` namespace by committing `wit/chio-guards-redact/world.wit` containing only `package chio:guards@0.1.0;` and a `// reserved for M10` comment. No interface bodies and no `redactor` world ship in M06. M10 replaces that placeholder with the concrete world below. The exact WIT M10 lands:

```wit
package chio:guards@0.1.0;

interface redact {
    /// Classes of content the host wants the guest to redact.
    /// Multiple classes compose; the guest applies all selected redactors.
    flags redact-class {
        secrets,        // API keys, tokens, high-entropy strings
        pii-basic,      // email, phone, SSN, credit-card
        pii-extended,   // addresses, names, DOB
        bearer-tokens,  // Authorization: Bearer <...>
        custom,         // tenant-supplied module
    }

    /// One match the redactor produced.
    record redaction-match {
        class: string,             // e.g. "secrets.aws-key", "pii.email"
        offset: u32,               // byte offset in the original payload
        length: u32,               // byte length of the match
        replacement: string,       // canonical replacement string written into the redacted output
    }

    /// Manifest summarizing a redaction pass; signed into the frame.
    record redaction-manifest {
        pass-id: string,           // e.g. "m06-redactors@1.4.0+default"
        matches: list<redaction-match>,
        elapsed-micros: u64,
    }

    /// Output of the host call.
    record redacted-payload {
        bytes: list<u8>,           // post-redaction bytes (UTF-8 if input was UTF-8)
        manifest: redaction-manifest,
    }

    /// The single host-imported function.
    /// Errors fail closed: an Err return MUST cause the tee to refuse persistence.
    redact-payload: func(payload: list<u8>, classes: redact-class) -> result<redacted-payload, string>;
}

world redactor {
    import redact;
}
```

Example regex-secret redactor implementation (Rust, targets `wasm32-wasip2`):

```rust
// crates/chio-data-guards/redactors/default/src/lib.rs
wit_bindgen::generate!({
    world: "redactor",
    path: "../../../wit",
});

use exports::chio::guards::redact::{
    Guest, RedactClass, RedactedPayload, RedactionManifest, RedactionMatch,
};
use once_cell::sync::Lazy;
use regex::bytes::Regex;
use std::time::Instant;

struct DefaultRedactor;

static AWS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\bAKIA[0-9A-Z]{16}\b").expect("static regex compiles")
});
static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
        .expect("static regex compiles")
});
static STRIPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b").expect("static regex compiles")
});
static HIGH_ENTROPY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?-u)\b[A-Za-z0-9_]{32,}\b").expect("static regex compiles")
});

const PASS_ID: &str = "m06-redactors@1.4.0+default";

impl Guest for DefaultRedactor {
    fn redact_payload(
        payload: Vec<u8>,
        classes: RedactClass,
    ) -> Result<RedactedPayload, String> {
        let started = Instant::now();
        let mut out = payload.clone();
        let mut matches: Vec<RedactionMatch> = Vec::new();

        if classes.contains(RedactClass::SECRETS) {
            for (label, re) in [
                ("secrets.aws-key", &*AWS_KEY),
                ("secrets.jwt", &*JWT),
                ("secrets.stripe", &*STRIPE),
                ("secrets.high-entropy", &*HIGH_ENTROPY),
            ] {
                for m in re.find_iter(&payload) {
                    let replacement = format!("<redacted:{label}>");
                    matches.push(RedactionMatch {
                        class: label.to_string(),
                        offset: u32::try_from(m.start())
                            .map_err(|_| "offset exceeds u32".to_string())?,
                        length: u32::try_from(m.end() - m.start())
                            .map_err(|_| "length exceeds u32".to_string())?,
                        replacement: replacement.clone(),
                    });
                    splice(&mut out, m.start(), m.end(), replacement.as_bytes());
                }
            }
        }
        // pii-basic, pii-extended, bearer-tokens follow the same shape.

        let elapsed_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

        Ok(RedactedPayload {
            bytes: out,
            manifest: RedactionManifest {
                pass_id: PASS_ID.to_string(),
                matches,
                elapsed_micros,
            },
        })
    }
}

fn splice(buf: &mut Vec<u8>, start: usize, end: usize, replacement: &[u8]) {
    buf.splice(start..end, replacement.iter().copied());
}

export!(DefaultRedactor);
```

Errors are fail-closed: a `Err(_)` return from the guest MUST cause the tee to refuse persistence and write `tee.redact_failed` to the receipt log.

## chio-tee-corpus GitHub release artifact

In-tree NDJSON fixtures cap at 5 MB per fixture. Oversize captures land in the `chio-tee-corpus` GitHub release stream and are pulled by sha256 at CI time.

Release-tag pattern: `tee-corpus-YYYY-MM-DD` (e.g. `tee-corpus-2026-04-25`). One release per weekly review cycle. Each release ships:

- One or more `<name>.ndjson.zst` capture artifacts.
- A `MANIFEST.toml` listing artifact name, sha256, byte size, and minimum schema version.
- A `MANIFEST.toml.sig` ed25519 signature over the canonical-JSON encoding of the manifest, signed by the integrations track release key.

Sha256 pin file (in-tree): `tests/replay/corpus_pins.toml`.

```toml
# Pinned chio-tee-corpus artifacts. CI refuses to test against any artifact
# whose computed sha256 differs from the pinned value.
schema_version = "1"

[[artifacts]]
name = "openai-responses-shadow-2026-04-25.ndjson.zst"
release_tag = "tee-corpus-2026-04-25"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size_bytes = 7340032

[[artifacts]]
name = "anthropic-messages-shadow-2026-04-25.ndjson.zst"
release_tag = "tee-corpus-2026-04-25"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
size_bytes = 6291456
```

CI step (in `.github/workflows/chio-replay-gate.yml`, runs before `cargo test -p chio-replay-gate`):

```yaml
- name: Pull and verify chio-tee-corpus artifacts
  shell: bash
  run: |
    set -euo pipefail
    python3 scripts/pull_tee_corpus.py \
      --pins tests/replay/corpus_pins.toml \
      --out target/tee-corpus \
      --verify-sha256 \
      --verify-manifest-sig
    # Refuses to proceed on any mismatch; exits non-zero with the offending artifact.
```

The pull script enforces three checks: (1) GitHub release tag exists, (2) artifact sha256 matches the pin, (3) `MANIFEST.toml.sig` verifies under the integrations release public key checked in at `tests/replay/keys/chio-tee-corpus.pub`. Any failure exits non-zero before tests run.

## Bless graduation runbook

Pipeline: `capture (in-memory) -> redact (M06 WASM pass) -> dedupe (frames keyed on canonical-JSON invocation hash, last-wins) -> review -> graduate via chio replay --bless`.

Steps:

1. **Capture**: shadow-mode tee writes signed NDJSON frames into the local capture spool (`${CHIO_TEE_RUNTIME_DIR}/captures/<run_id>.ndjson`). Raw payloads are pre-redaction in-memory only (zeroize-on-drop), never on disk.
2. **Redact**: every frame passes through the M06 redactor pass before persistence. The `redaction_pass_id` is recorded on each frame.
3. **Dedupe**: the bless tool deduplicates frames keyed on the canonical-JSON hash of `invocation`, last-wins. Dedupe runs after redaction so the dedupe key is stable across captures.
4. **Review**: weekly review SLA. The integrations track reviews capture batches every Tuesday at 14:00 UTC. Unreviewed captures expire from `chio-tee-corpus` after 30 days; the GitHub Actions cron `chio-tee-corpus-expire` deletes expired releases automatically.
5. **Graduate**: `chio replay <capture.ndjson> --bless --into tests/replay/fixtures/<family>/<name>/` re-redacts under the current default redactor set, strips `tenant_sig` and request/response blobs, writes the M04 fixture shape (`receipts.ndjson`, `checkpoint.json`, `root.hex`), and emits an audit-log entry to the receipt store.

Audit-log entry format (canonical JSON, written to the receipt store as a `tee.bless` event):

```json
{
  "event": "tee.bless",
  "ts": "2026-04-25T18:02:11.418Z",
  "operator": {
    "id": "did:web:integrations.chio.dev:alice",
    "git_user": "alice@chio.dev"
  },
  "capture": {
    "path": "captures/01J...ULID.ndjson",
    "frames_in": 1234,
    "frames_after_dedupe": 987,
    "frames_after_redact": 987
  },
  "fixture": {
    "family": "openai_responses_shadow",
    "name": "tool_call_with_pii",
    "path": "tests/replay/fixtures/openai_responses_shadow/tool_call_with_pii/",
    "receipts_root": "a917b3c1..."
  },
  "redaction_pass_id": "m06-redactors@1.4.0+default",
  "control_plane_capability": "chio:tee/bless@1",
  "signature": "ed25519:..."
}
```

Bless is gated behind the `chio:tee/bless@1` capability and refuses to run if the resulting fixture would diverge from the M04 directory shape (smoke gate before the M04 review).

## Exit criteria

- `chio-tee` container image deployable as a sidecar; integration tested against real OpenAI, Anthropic, and MCP fixture traffic from M07's conformance corpus in all three modes (`verdict-only`, `shadow`, `enforce`).
- NDJSON frame schema documented in `docs/tee-format.md` and locked above; runner rejects any frame whose `schema_version` is not `"1"`.
- `chio replay <capture.ndjson> --against <policy-ref>` lands in `chio-cli` with the M04 canonical exit codes (`0/10/20/30/40/50`; see `04-deterministic-replay.md` "EXIT CODES") and integration tests covering one case per code.
- A captured shadow-mode session graduates into M04's `chio-replay-gate` corpus via `chio replay --bless` and the resulting fixture passes the gate on subsequent CI runs.
- `gen_ai.*` semantic-convention spans visible in the Jaeger demo for every adapter; bidirectional `receipt-id <-> span-id` lookup demonstrated by the example.
- Loki, Tempo, and Jaeger dashboard JSON committed under `deploy/dashboards/` and importable in one command per the demo `README.md`.
- `tests/replay/corpus_pins.toml` exists and the CI pull-and-verify step passes against the live `chio-tee-corpus` release stream.
- Mode-precedence test `crates/chio-tee/tests/mode_precedence.rs::env_overrides_toml_overrides_manifest` is green under `cargo test --workspace`.
- (NEW) Tee FIPS-mode build smoke test green: see [New M10-scope sub-tasks](#new-m10-scope-sub-tasks).
- (NEW) Capture-spool disk-pressure backpressure test green.
- (NEW) Cross-frame redaction-determinism property test green.

## Dependencies

- M07 (provider-native adapters) is the upstream traffic source. The tee taps the M07 adapters as well as the existing MCP, A2A, and ACP edges. If M07 lands first, the tee inherits real adapters; if M10 lands first, the tee ships against MCP and A2A only and absorbs M07 adapters as they ship.
- M04 (deterministic replay) shares fixture infrastructure. The tee's NDJSON corpus feeds M04's `chio-replay-gate` via the `--bless` workflow; M04's golden machinery is the regression oracle. The bless flow writes into the M04 directory shape (`receipts.ndjson`, `checkpoint.json`, `root.hex`) verified against M04 Phase 1.
- M01 (canonical-JSON `ToolInvocation` schema) gates capture-format stability. The frame schema versions on the M01 schema; bumps require a documented migration.
- M06 (WASM guard platform) supplies the redactor pipeline the tee runs before persistence. M06 reserves the `chio:guards/redact@0.1.0` namespace in its Phase 1; M10 ships the concrete world (see [Redactor host call shape](#redactor-host-call-shape-chioguardsredact010)). Without M06's namespace reservation, the tee runs in plaintext-disabled mode and refuses to persist frames.

## Risks and mitigations

- PII capture leak before the redactor pass. A tee that records prod traffic without redaction is a regulatory incident waiting to happen. Mitigation: raw payloads are pre-redaction in-memory only (zeroize-on-drop buffers, never written to disk, never logged); the redactor pass is mandatory and fail-closed; tenant keys encrypt redacted frames at rest via `chio-store-sqlite`'s existing BLOB encryption; `chio-tee --paranoid` refuses to persist any frame whose redaction manifest reports zero matches on a payload longer than 256 bytes (heuristic guard against a misconfigured redactor). Release-audit row enumerates the failure modes.
- Upstream API rate limits during replay. Replaying 10K captured OpenAI calls against a new policy without throttle will trigger 429s and a billable surprise. Mitigation: `chio replay` defaults to `--throttle 5/sec` and `--dry-run` (no upstream HTTP, kernel-only verdict diff); `--live` requires explicit confirmation and a per-provider rate-limit budget read from the manifest. The throttle is per-`gen_ai.system` so a multi-provider capture cannot starve one provider on behalf of another.
- Receipt-id collision between live and replayed traffic in a shared store. Mitigation: replay receipts use a namespaced prefix `replay:<run_id>:<frame_id>` and live in a logical partition flagged `replay`; the CLI refuses to write replay receipts into a production-flagged store and refuses to write production receipts into a replay-flagged store. The bidirectional refusal is enforced at the `chio-store-sqlite` layer.
- OTel attribute cardinality blowup (`gen_ai.tool.call.id` and `chio.receipt.id` are unbounded). Mitigation: high-cardinality attributes are emitted as span attributes only, never as metric labels; the OTel Collector exporter strips them before forwarding to Prometheus-shaped sinks; a deny-list of attribute keys is documented in `docs/integrations/otel.md` and enforced by the `chio-otel-receipt-exporter`. Cardinality bounds are codified in [OTel attribute lock](#otel-attribute-lock).
- NDJSON schema drift across releases. Mitigation: every frame carries a mandatory `schema_version` field; the runner rejects unknown versions with exit code `40`; schema bumps require a documented migration in `docs/tee-format.md` and a `chio replay --migrate` adapter shim. Frame schema bumps are blocked unless the M01 canonical-JSON `ToolInvocation` hash is unchanged or migrated in lockstep.
- NDJSON corpus drift from live API surface. Mitigation: the M07 nightly canary diff catches API shape drift; replay frames carry `provenance.api_version` so the runner can refuse to replay against a manifest that targets a different upstream version.
- Oversize captures break the in-tree 5 MB cap. Mitigation: oversize captures land in `chio-tee-corpus` GH release artifacts pulled by sha256 (see [chio-tee-corpus GitHub release artifact](#chio-tee-corpus-github-release-artifact)); the CI pull step refuses any artifact whose sha256 does not match the pin.

## Cross-milestone references

- M01 (canonical-JSON `ToolInvocation` schema) is the gating contract for capture format stability; `chio-tee-frame.v1` re-uses M01's canonical-JSON serializer and signs frames with the M01 receipt-key machinery.
- M07 (`chio-provider-conformance` NDJSON capture). M07 and M10 share one NDJSON schema. M10 owns the canonical `chio-tee-frame.v1` definition; M07's conformance fixture format is the same shape. If M07 ships first, M07 documents the shape as provisional and M10 absorbs it under the same `schema_version`; if M10 ships first, M07 inherits `chio-tee-frame.v1` verbatim. Two NDJSON schemas across the two milestones is a defect.
- M04 (deterministic replay corpus) is the consumer of blessed captures; the `--bless` workflow is the only supported path for landing live traffic into M04. The bless flow writes the M04 directory shape verified against M04 Phase 1.
- M06 (WASM guard platform) supplies the redactor host bridge; M06 reserves the `chio:guards/redact@0.1.0` namespace, M10 ships the concrete world. Without M06 the tee runs in `--persist=disabled` and refuses NDJSON output.
- M07 (provider-native adapters) is the upstream traffic source the tee taps; M07's nightly conformance corpus seeds the tee's integration tests.
- M09 (SBOM and supply-chain provenance) overlaps where capture frames carry `provenance` rooted in signed manifests; the tee's `provenance` block is a strict superset of the M09 SBOM-style provenance shape so a single capture can attest to both the tool invocation and its supply chain.

## Code touchpoints

- `crates/chio-tee/` (new), `Dockerfile.tee` (new, derived from `Dockerfile.sidecar`)
- `crates/chio-tee/src/frame.rs`, `crates/chio-tee/src/tap.rs`, `crates/chio-tee/src/redact.rs`, `crates/chio-tee/src/mode.rs`
- `crates/chio-tee/tests/mode_precedence.rs` (new)
- `crates/chio-cli/src/cli/dispatch.rs` (new arm), `crates/chio-cli/src/cli/replay.rs` (extend M04's replay module with traffic mode), `crates/chio-cli/tests/replay_traffic.rs`
- `crates/chio-otel-receipt-exporter/` (new)
- `crates/chio-replay-corpus/` (new, the bridge between captures and M04 fixtures)
- `crates/chio-mcp-edge/`, `crates/chio-a2a-edge/`, `crates/chio-acp-proxy/`, plus M07's three adapters: add `TrafficTap` hook and `otel` feature
- `crates/chio-kernel/src/receipt_support.rs` (extend `provenance` with `otel.{trace_id, span_id}`)
- `crates/chio-kernel/tests/otel_cardinality.rs` (new)
- `crates/chio-store-sqlite/` (tenant-key BLOB encryption hook for tee frames)
- `crates/chio-data-guards/redactors/default/` (new, ships the M10 concrete redactor world over the M06 namespace)
- `wit/chio-guards-redact/world.wit` (M06 reserved, M10 concrete)
- `tests/replay/corpus_pins.toml` (new), `tests/replay/keys/chio-tee-corpus.pub` (new), `scripts/pull_tee_corpus.py` (new)
- `.github/workflows/chio-replay-gate.yml` (extend with corpus-pull step), `.github/workflows/chio-tee-corpus-expire.yml` (new, weekly cron)
- `deploy/dashboards/{loki,tempo,jaeger}/*.json` (new), `examples/otel-genai/` (new), `examples/tee-sidecar/` (new)
- `docs/tee-format.md`, `docs/replay-cli.md`, `docs/integrations/otel.md` (new)

## Open questions

- Should `chio-tee` be a separate process or compile into each edge as a feature flag? Proposal: separate process for v1 because the deployment story (sidecar in a pod, separate failure domain) is the adoption story; revisit once enforcement-mode operators want to drop a hop.
- Should benign-drift exit code (10) gate CI? Proposal: warn-only by default in PRs, fail-only on `main`, with an opt-in `--strict` flag that treats benign drift as material.
- OTel Collector exporter: Rust crate, or contribute upstream to `opentelemetry-collector-contrib`? Proposal: ship the Rust crate first as the receipt-store sink, evaluate upstream contribution after one release cycle of stable schema.

## New M10-scope sub-tasks

Three sub-tasks that did not exist in the round-1 doc, tagged `(NEW)`:

1. **(NEW) Tee FIPS-mode build smoke test**. The default redactor uses regex over byte slices, but the tenant-sig path uses ed25519 from `ring`. Some regulated tenants run FIPS-locked builds where `ring` falls back to BoringSSL FIPS. Add a `fips` cargo feature on `chio-tee` that swaps in `aws-lc-rs` for ed25519 and a CI smoke test under `.github/workflows/chio-tee-fips.yml` that builds and runs `crates/chio-tee/tests/mode_precedence.rs` under the FIPS feature flag. Owner: integrations track. Effort: **S, 1d**.

2. **(NEW) Capture-spool disk-pressure backpressure test**. The shadow-mode tee writes NDJSON to a local spool before any GH release upload. A misconfigured tee on a small disk can fill the volume and crash the host. Add `crates/chio-tee/tests/spool_backpressure.rs` that mounts a 64 MB tmpfs, runs the tee in shadow mode against a synthetic 256 MB traffic stream, and asserts: (a) the tee never writes past 80% spool fill, (b) frames beyond the threshold are dropped with a `tee.spool_full` event written to the receipt log, (c) the tee process does not crash. Effort: **M, 2d**.

3. **(NEW) Cross-frame redaction-determinism property test**. The redactor MUST be a pure function of `(payload, classes)` so dedupe (last-wins on canonical `invocation` hash) is stable across captures. Add `crates/chio-tee/tests/redact_determinism.rs` using `proptest = "1.10"` (already vendored). Strategy: generate random byte payloads up to 16 KB and random `RedactClass` flag combinations; the test asserts `redact_payload(p, c)` returns byte-identical output across two invocations and that `redaction_pass_id` and `manifest.matches` are byte-stable under canonical-JSON encoding. Bound to 30 seconds in CI; archive seeds on failure under `crates/chio-tee/tests/proptest-regressions/`. Effort: **M, 1.5d**.
