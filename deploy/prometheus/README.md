# Chio Prometheus Rules

This directory contains the T1.5 SRE rule pack.

- `chio-recording-rules.yml` computes the p95 and error-ratio series used by
  the healthcare pilot SLO.
- `chio-alert-rules.yml` defines burn-rate, missing-data, and zero-tolerance
  alerts. Labels `notification_route`, `opsgenie`, and `severity` are the
  handoff contract to the existing `chio-siem` PagerDuty and OpsGenie dispatch
  path.
- `chiodos-pheromone-relay-observability-rules.yml` defines relay operator
  alerts using bounded `status`, `reason`, `notification_route`, `opsgenie`,
  `service`, and `severity` labels only.

The metric names in these files are registered in `chio-metrics-spec`; CI runs
the registry grep gate before workspace tests.
