# chio-metrics-spec

`chio-metrics-spec` is the authoritative, workspace-wide registry of Prometheus
metric names for Chio's SRE surfaces. New metric names must be added here
first, then consumed from constants instead of inlining string literals at
emission sites. A snapshot test in this crate is the CI gate against metric
taxonomy drift.

Use this crate as the single source of truth for metric names whenever you add
or rename an emitted metric.
