# otel-genai Architecture Notes

## Module Boundaries

This package owns the local OpenTelemetry GenAI example. The Docker Compose
files own the collector, Tempo, Jaeger, and Grafana demo stack. The Rust
integration test owns the decoded OTLP-to-Chio receipt contract: build one
`gen_ai.tool.call` span, export it through `chio-otel-receipt-exporter`, verify
the signed receipt, and prove lookup in both directions.

## Pain Points

The Rust contract currently lives as a single ignored integration test that
mixes in-memory receipt storage, sink construction, span construction, export
assertions, sanitized metadata checks, and lookup-index construction. Because it
is ignored, `cargo test -p otel-genai` does not gate the example behavior even
though the test does not require Docker or a live collector.

## Security And API Constraints

The Rust gate must stay fully local and must not require the collector stack. It
must preserve signed receipt verification, lower-case W3C trace/span ids,
source receipt correlation, receipt-id-to-span-id and span-id-to-receipt-id
lookup, high-cardinality attribute stripping, and the locked Chio GenAI
attribute names from `chio-kernel::otel`.

## Affected Dependents

The package README and `docs/integrations/otel.md` document how to run the
contract test. They need synchronized command updates when the test becomes a
default gate. No crate API consumers or generated artifacts are affected.

## Completed Material Improvement

The test plumbing now lives in a package-local support module, the contract uses
exported OTel attribute constants instead of duplicated raw strings where
available, and the bidirectional lookup contract now runs in the default `cargo
test -p otel-genai` gate.
