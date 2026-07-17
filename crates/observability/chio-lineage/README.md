# chio-lineage

Chio's provenance and lineage DAG indexer. It projects signed receipts,
capability lineage, and signed receipt-lineage statements into an in-memory
graph, tagging every node and edge with an evidence class (`Asserted`,
`Observed`, `Verified`) so a consumer can tell what is caller-supplied from
what the kernel observed from what is independently signed or proof-checked.

The crate performs no file or network I/O itself: it ingests OTEL NDJSON
frames and replay-corpus rows already read from disk and returns an in-memory
`LineageGraph`. `chio-cli`'s `lineage` command surface and `chio-weights`'s
model-card anchoring are the current consumers.

## Responsibilities

- Define the lineage graph schema (`schema`): `LineageNode`, `LineageEdge`,
  `NodeKind`, `EdgeKind`, `EvidenceClass`, and the bounded-query
  `TruncationMarker`, matching the JSON Schema artifact at
  `schemas/lineage-graph.v1.json`.
- Fold OTEL receipt-exporter NDJSON frames into the graph (`ingest_otel`),
  deduplicating nodes and edges by natural key and rejecting frames with an
  unrecognized schema version or a blank, padded, or control-character id.
- Fold deterministic replay-corpus rows into the same graph shape
  (`ingest_replay_corpus`), upgrading a receipt-lineage edge to `Verified`
  only when the row carries a signed `ReceiptLineageStatement` whose
  endpoints match and whose signature verifies.
- Run bounded forward and reverse traversals over an in-memory graph
  (`query`), emitting a `TruncationMarker` when the depth or row cap is hit.
- Compute a stable, sorted symmetric edge diff between two graphs (`diff`),
  for comparing lineage shape across guard versions.
- Hash a graph's frontier to a stable digest and pin it as a signed or
  explicitly-unsigned `AnchoredFrontier` (`anchor`), verifying signatures
  only against a caller-supplied trusted key.

## Public API

- `schema::{LineageGraph, LineageNode, LineageEdge, NodeKind, EdgeKind,
  EvidenceClass, TruncationMarker}` - the graph types.
- `ingest_otel::{OtelIngest, OtelReceiptFrame, OtelIngestError,
  OTEL_INGEST_SCHEMA}` - stateful NDJSON frame ingest.
- `ingest_replay_corpus::{ingest_corpus, CorpusReceiptRow,
  CorpusIngestError}` - one-shot corpus row projection.
- `query::{forward, reverse, receipt_nodes, QueryBounds, QueryResult,
  DEFAULT_DEPTH_LIMIT}` - bounded graph traversal.
- `diff::{diff, render_text, LineageDiff, DiffEdge, EvidenceChange}` -
  symmetric graph diff and its text summary.
- `anchor::{pin_frontier, pin_frontier_signed, verify_frontier_signature,
  frontier_digest, frontier_bytes, frontier_signature_message,
  AnchoredFrontier, FrontierDigest, SigningState, AnchorError}` - frontier
  hashing and signed pinning.
- `LINEAGE_GRAPH_SCHEMA`, `LineageError` - the schema tag and an aggregate
  error unifying the two ingest paths via `From`.

## Testing

`cargo test -p chio-lineage`

`schema.rs`'s `schema_artifact_exists_and_pins_marker_shape` test cross-checks
the `TruncationMarker` shape against `schemas/lineage-graph.v1.json`.

## See also

- `chio-core-types` - supplies `ReceiptLineageStatement` and
  `ProvenanceEvidenceClass` (checked by `ingest_replay_corpus` to upgrade an
  edge to `Verified`) and `crypto::{PublicKey, Signature}` (used by `anchor`
  to verify frontier signatures against a caller-supplied key).
- `chio-otel-receipt-exporter` - writes the NDJSON stream `ingest_otel` reads.
- `chio-store-sqlite` - `lineage_cte.rs` mirrors this crate's depth bound and
  graph shape for its recursive-CTE persistent backing; the two crates share
  no code dependency.
- `chio-cli` - the `lineage query|diff|roots` command surface built on this
  crate.
- `chio-weights` - anchors published model cards using this crate's `anchor`
  digest and signing-state shapes.
