# OpenTelemetry GenAI demo

This example wires an OTLP collector to Tempo and Jaeger, then validates the
Chio receipt export path with an ignored Rust integration test. It demonstrates
the M10 requirement that a GenAI tool-call span can be looked up by receipt id
and that a signed receipt can be looked up by span id.

## Files

```text
Cargo.toml
README.md
docker-compose.yml
otel-collector-config.yaml
tests/bidirectional_lookup.rs
```

## Run the collector demo

From this directory:

```bash
docker compose up
```

The compose stack exposes:

| Service | URL or endpoint | Purpose |
|---------|-----------------|---------|
| OTLP gRPC | `127.0.0.1:4317` | Receives GenAI spans from adapters or local test clients. |
| OTLP HTTP | `127.0.0.1:4318` | HTTP OTLP ingest for local tooling. |
| Jaeger | `http://127.0.0.1:16686` | Trace lookup by `trace_id`, receipt id tag, and span id tag. |
| Tempo | `http://127.0.0.1:3200` | TraceQL lookup by `span.chio.receipt.id` and `span.chio.verdict`. |
| Grafana | `http://127.0.0.1:3000` | Dashboard shell for the `deploy/dashboards` imports. |

Import the dashboards from the repository root:

```bash
find deploy/dashboards -name '*.json' -print0 | while IFS= read -r -d '' dashboard; do jq -n --argjson dashboard "$(cat "$dashboard")" '{dashboard: $dashboard, overwrite: true}' | curl -fsS -H 'Content-Type: application/json' -X POST http://admin:admin@127.0.0.1:3000/api/dashboards/db -d @- >/dev/null; done
```

## Run the contract test

From the repository root:

```bash
cargo test --manifest-path examples/otel-genai/Cargo.toml --test bidirectional_lookup -- --ignored
```

The test constructs a decoded OTLP trace export with the locked M10
`gen_ai.tool.call` attributes, exports it through `chio-otel-receipt-exporter`,
verifies the signed receipt, and builds both lookup directions:

- `receipt id -> span id`
- `span id -> receipt id`

It also checks that high-cardinality attributes forbidden from
Prometheus-shaped sinks are stripped from the receipt metadata copy while the
receipt id remains the signed receipt identifier.

## Expected span attributes

The demo expects the same attribute names used by the kernel OTel helpers:

- `gen_ai.system`
- `gen_ai.operation.name`
- `gen_ai.request.model`
- `gen_ai.tool.call.id`
- `gen_ai.tool.name`
- `chio.receipt.id`
- `chio.tenant.id`
- `chio.policy.ref`
- `chio.verdict`
- `chio.tee.mode`
- `provenance.otel.trace_id`
- `provenance.otel.span_id`

Use `docs/integrations/otel.md` for the full attribute and collector contract.
