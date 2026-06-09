# chio-lineage Architecture

## Boundary

`chio-lineage` owns Chio's in-memory provenance DAG projection. It turns OTEL receipt-export frames and replay-corpus rows into typed nodes and edges that query, diff, and anchor code can consume without reinterpreting raw receipt fields.

## Internal Surfaces

The crate is split into the graph schema in `schema`, OTEL stream ingest in `ingest_otel`, deterministic replay-corpus ingest in `ingest_replay_corpus`, bounded in-memory traversal in `query`, guard-version comparison in `diff`, and frontier hashing plus signed-anchor validation in `anchor`.

## Trust Invariants

The trust boundary is natural-key integrity. Node ids and edge ids are derived from receipt ids, capability ids, span ids, tool names, tenants, and signed receipt-lineage statements. Inputs that would produce blank or whitespace-padded graph identifiers must fail before projection, because downstream query and anchor code treats graph ids as canonical.

## Current Hardening

Current hardening: replay-corpus ingest validates every required and optional string field before constructing the graph, and returns `CorpusIngestError::InvalidField` instead of emitting malformed `rcpt:`, `cap:`, or `tool:*` node ids.

## Verification Focus

Tests should cover raw receipt projection, replay-corpus validation, bounded traversal, duplicate edge handling, frontier hash stability, and signed-anchor rejection for malformed graph identifiers.
