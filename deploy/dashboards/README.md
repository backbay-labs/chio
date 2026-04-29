# Chio observability dashboards

This directory contains Grafana dashboards for the M10 live-traffic tee and
OpenTelemetry GenAI receipt flow. The dashboards are organized by backend:

| Path | Purpose |
|------|---------|
| `loki/chio-tee.json` | Inspect tee and replay logs by receipt id, tenant, verdict, and OTel trace id. |
| `loki/verdict-drift.json` | Show replay verdict drift by source verdict, target verdict, policy ref, and reason. |
| `tempo/span-timeline.json` | Find the trace timeline for a receipt id and verify the linked span ids. |
| `tempo/redaction-latency.json` | Track redaction pass latency, pass ids, and guard outcome spans. |
| `jaeger/receipt-span-lookup.json` | Look up Jaeger traces by receipt id, trace id, span id, tenant, and tool name. |

## One-command import

Start Grafana with Loki, Tempo, and Jaeger data sources named `Loki`, `Tempo`,
and `Jaeger`, then run this from the repository root:

```bash
find deploy/dashboards -name '*.json' -print0 | while IFS= read -r -d '' dashboard; do jq -n --argjson dashboard "$(cat "$dashboard")" '{dashboard: $dashboard, overwrite: true}' | curl -fsS -H 'Content-Type: application/json' -X POST http://admin:admin@127.0.0.1:3000/api/dashboards/db -d @- >/dev/null; done
```

Each dashboard uses Grafana datasource variables, so the import works when the
data source UIDs differ across local demos and production stacks. Set these
variables after import if Grafana does not select them automatically:

| Variable | Type | Expected backend |
|----------|------|------------------|
| `DS_LOKI` | datasource | Loki |
| `DS_TEMPO` | datasource | Tempo |
| `DS_JAEGER` | datasource | Jaeger |

## Required telemetry fields

The dashboards expect the M10 attribute lock to be present on spans and logs:

- `chio.receipt.id`
- `chio.tenant.id`
- `chio.policy.ref`
- `chio.verdict`
- `chio.tee.mode`
- `chio.deny.reason`
- `chio.guard.outcome`
- `provenance.otel.trace_id`
- `provenance.otel.span_id`
- `redaction_pass_id`
- `redaction_elapsed_micros`

High-cardinality fields such as `gen_ai.tool.call.id`, `chio.receipt.id`, and
`chio.replay.run_id` are used only as span or log filters. They must not be
forwarded as Prometheus metric labels.
