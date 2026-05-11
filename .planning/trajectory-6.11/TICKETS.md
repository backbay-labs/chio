# Chiodos 6.11 Tickets

## C6.11-001 Integrator

Status: in progress

Create the feature branch, record the baseline SHA, write active planning docs, and keep planning metadata under `.planning`.

## C6.11-002 Report Model

Status: in progress

Add relay observability, metrics snapshot, and event report Rust types, JSON schemas, schema registry entries, and committed golden fixtures.

## C6.11-003 Store Aggregation

Status: in progress

Add read-only store summary helpers for queue statuses, stale leases, inbox/cursor/catch-up counts, dead letters, replay conflicts, and recent bounded failure codes.

## C6.11-004 Relay HTTP

Status: in progress

Add authenticated observability and metrics endpoints, per-request clock handling for long-running serve, and report-dir event emission.

## C6.11-005 CLI

Status: in progress

Add relay observe and relay metrics commands. Production observe requires verified peer-directory state plus trusted issuers.

## C6.11-006 Dashboard

Status: in progress

Add typed relay observability API support and operator cards in the existing dashboard with graceful missing-report behavior.

## C6.11-007 Alerts And Docs

Status: in progress

Add Prometheus/Grafana examples, threshold guidance, and runbook drill summaries for stale directory, removed peer, stale lease, dead letter, replay conflict, and catch-up overload.

## C6.11-008 Fixtures And Negatives

Status: in progress

Add healthy and degraded observability fixtures plus executable negatives for stale directory, removed peer, dead letters, stale leases, replay conflicts, catch-up over-limit, malformed report, mixed local kernel id, and timestamp regression.

## C6.11-009 Assurance

Status: pending

Add the observability gate, wire CI path triggers, open the PR, resolve review threads, merge, and rerun gates on `main`.
