# chio-lineage

`chio-lineage` is Chio's provenance and lineage DAG indexer. It indexes signed
receipts, capability lineage, and signed receipt-lineage statements into a
provenance graph. Its source feeds are the OTEL receipt exporter NDJSON stream
and the deterministic replay corpus.

Use this crate to query how a given receipt, capability, or tool call relates
to the artifacts that produced it.
