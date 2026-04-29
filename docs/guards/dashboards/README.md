# Guard Platform Dashboards

`guard-platform.json` is the Grafana dashboard for the M06 guard platform telemetry surface.

It expects a Prometheus datasource and the guard metric families exposed by the kernel `/metrics` endpoint:

- `chio_guard_eval_duration_seconds`
- `chio_guard_fuel_consumed_total`
- `chio_guard_verdict_total`
- `chio_guard_deny_total`
- `chio_guard_reload_total`
- `chio_guard_host_call_duration_seconds`
- `chio_guard_module_bytes`

The dashboard uses four rows:

1. Deny rate by `reason_class`, plus p50 and p99 eval latency.
2. Fuel consumption distribution, plus top 10 guards by deny count.
3. Reload outcomes timeline, plus host-call latency by `host_fn`.
4. Verification mode breakdown, plus module size by epoch.

Import the JSON into Grafana and bind `DS_PROMETHEUS` to the Prometheus datasource that scrapes Chio.
