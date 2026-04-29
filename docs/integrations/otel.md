# OpenTelemetry integration

Chio's M10 OpenTelemetry path links GenAI tool-call spans to signed receipts.
The same identifiers let operators move in either direction:

- from a Chio receipt id to the OTel span and trace that produced it
- from an OTel span id to the signed Chio receipt stored by the exporter

## Components

| Component | Role |
|-----------|------|
| `chio-kernel::otel` | Builds the locked `gen_ai.tool.call` span shape used by adapters and edges. |
| `chio-otel-receipt-exporter` | Accepts decoded OTLP trace batches, signs span-derived receipts, and appends them to a receipt store. |
| `examples/otel-genai` | Runs a local OTel collector with Tempo and Jaeger and validates bidirectional lookup with an ignored test. |
| `deploy/dashboards` | Grafana dashboards for Loki, Tempo, and Jaeger receipt investigations. |

## Attribute contract

Adapters that emit `gen_ai.tool.call` spans must use the locked M10 attribute
set below.

| Attribute | Required | Use |
|-----------|----------|-----|
| `gen_ai.system` | yes | Provider or protocol family such as `openai`, `anthropic`, `aws.bedrock`, `mcp`, `a2a`, or `acp`. |
| `gen_ai.operation.name` | yes | Stable operation name, normally `tool.call`. |
| `gen_ai.request.model` | yes | Provider model name when available. |
| `gen_ai.tool.call.id` | yes | Provider tool-call id. Span attribute only. |
| `gen_ai.tool.name` | yes | Tool name. |
| `gen_ai.response.finish_reasons` | optional | Provider finish reasons. |
| `gen_ai.usage.input_tokens` | optional | Input token count. |
| `gen_ai.usage.output_tokens` | optional | Output token count. |
| `chio.receipt.id` | yes | Signed receipt id. Span attribute only. |
| `chio.tenant.id` | yes | Tenant id for filtering. |
| `chio.policy.ref` | yes | Policy ref or hash active for the decision. |
| `chio.verdict` | yes | `allow`, `deny`, or `rewrite`. |
| `chio.tee.mode` | yes | `verdict-only`, `shadow`, or `enforce`. |
| `chio.deny.reason` | optional | Namespaced denial reason. |
| `chio.guard.outcome` | optional | Guard outcome for redaction and policy passes. |
| `chio.replay.run_id` | optional | Replay run id. Span attribute only. |

Receipt provenance stores the W3C OTel identifiers under:

```json
{
  "provenance": {
    "otel": {
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "span_id": "00f067aa0ba902b7"
    }
  }
}
```

Both ids must be lowercase hexadecimal. `trace_id` is 32 characters and
`span_id` is 16 characters.

## Metric safety

These fields are intentionally high-cardinality and must not be promoted to
Prometheus-shaped metric labels:

- `gen_ai.tool.call.id`
- `chio.receipt.id`
- `chio.replay.run_id`

`chio-otel-receipt-exporter` strips the same keys from the metadata attribute
copy before forwarding or appending derived receipt metadata. The collector demo
also removes them from the metrics pipeline in
`examples/otel-genai/otel-collector-config.yaml`.

## Collector flow

The demo collector receives OTLP over gRPC and HTTP, batches spans, and exports
the trace stream to both Tempo and Jaeger:

```text
adapter or edge
  -> OTLP collector
  -> Tempo for TraceQL lookup
  -> Jaeger for trace browsing
  -> chio-otel-receipt-exporter for signed receipt storage
```

The Rust exporter receives the decoded OTLP request as
`OtlpGrpcTraceExport`. Production listeners can decode
`ExportTraceServiceRequest` into that shape before calling
`OtlpGrpcIngress::export`.

## Local validation

Run the bidirectional lookup contract from the repository root:

```bash
cargo test --manifest-path examples/otel-genai/Cargo.toml --test bidirectional_lookup -- --ignored
```

The test proves:

- one decoded `gen_ai.tool.call` span is accepted
- one signed Chio receipt is appended
- `receipt id -> span id` lookup resolves through receipt provenance
- `span id -> receipt id` lookup resolves through the same receipt metadata
- high-cardinality span attributes are absent from the sanitized metadata copy

Start the local Tempo and Jaeger demo with:

```bash
docker compose -f examples/otel-genai/docker-compose.yml up
```

Then import the dashboards from `deploy/dashboards/README.md`.
