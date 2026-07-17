# chio-lineage architecture

## Overview

`chio-lineage` is a pure in-memory library: no file or network I/O, no
runtime state beyond what a caller constructs and holds. It projects two
source feeds, OTEL receipt-exporter NDJSON and the deterministic replay
corpus, into one graph shape, and tags every node and edge with an
`EvidenceClass` so a consumer never has to reinterpret raw receipt or span
fields to know how much to trust a fact. The `anchor` module touches
signature verification, but the crate never embeds a trusted key: a caller
must supply the public key it already trusts, so an attacker-supplied key
and signature pair can never satisfy verification on its own.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Declares the six public modules, the `LINEAGE_GRAPH_SCHEMA` tag, and `LineageError` (aggregates `OtelIngestError` and `CorpusIngestError`). |
| `src/schema.rs` | Graph types: `LineageNode`, `LineageEdge`, `NodeKind`, `EdgeKind`, `EvidenceClass`, `TruncationMarker`, `LineageGraph`. Source of truth for `schemas/lineage-graph.v1.json`. |
| `src/ingest_otel.rs` | Folds OTEL receipt-exporter NDJSON frames into the graph. Schema-version gated; dedups by natural key. |
| `src/ingest_replay_corpus.rs` | Folds replay-corpus rows into the same graph shape. Validates every field before construction; verifies signed lineage statements. |
| `src/query.rs` | Bounded forward/reverse BFS traversal with depth and row caps. |
| `src/diff.rs` | Symmetric edge diff between two graphs, sorted for byte-stable output. |
| `src/anchor.rs` | Frontier hashing, signed/unsigned pinning, signature verification against a caller-supplied key. Carries an embedded SHA-256 (FIPS 180-4) to avoid a new crypto dependency for a public, non-secret digest. |

## Projection pipeline

1. A source feed (an OTEL NDJSON line, or a `CorpusReceiptRow` slice) enters
   through `ingest_otel` or `ingest_replay_corpus`.
2. Each ingest path validates required and optional string fields (non-empty,
   unpadded, and for OTEL, control-character-free) before constructing any
   node or edge, so a malformed field never reaches the graph as a blank or
   whitespace-padded id.
3. Nodes and edges get natural-key ids (`rcpt:`, `cap:`, `tool:` prefixes)
   and are deduplicated against a `HashSet` of ids already seen, so
   re-ingesting the same frame or row is a no-op.
4. The resulting `LineageGraph` feeds `query` (bounded traversal), `diff`
   (symmetric comparison against another graph), and `anchor` (frontier
   hashing and pinning). None of the three mutate the graph.

## Invariants and failure modes

- Natural-key integrity is the trust boundary: node and edge ids are derived
  from receipt ids, capability ids, span ids, tool names, and tenant ids.
  `ingest_otel` rejects a blank, whitespace-padded, or control-character id
  with `OtelIngestError::InvalidRequiredField`; `ingest_replay_corpus`
  rejects a blank or padded field with `CorpusIngestError::InvalidField`
  before any node is built.
- `ingest_otel` fails closed on an `otel.schema` value other than
  `OTEL_INGEST_SCHEMA` (`otlp.grpc.trace.v1`) via
  `OtelIngestError::SchemaMismatch`; nothing is ingested from a rejected frame.
- Evidence-class upgrades are one-directional and narrow. OTEL tool-call and
  capability nodes are always `Asserted`; an OTEL receipt is `Observed` only
  when the frame carries `correlation_source_chio_receipt_id` (the kernel
  wrote that receipt itself). Corpus rows default to `Observed`; a
  `ReceiptLineageParent` edge upgrades to `Verified` only when the row's
  `signed_lineage_statement` names the same parent and child receipt ids,
  carries `ProvenanceEvidenceClass::Verified`, and its signature verifies.
- `query::forward`/`reverse` bound traversal with `QueryBounds` (default
  depth 20, matching the recursive-CTE bound in
  `capability_lineage::get_delegation_chain`; default row cap 10,000) and
  emit a `TruncationMarker` on overflow. A cycle back to an already-visited
  node is dropped, not re-queued, so it cannot loop forever.
- `anchor::pin_frontier` never produces `SigningState::Signed`: a signer
  hint without a real signature payload records `UnsignedSignerStubbed` so a
  verifier cannot mistake a stub for a real signature. Only
  `pin_frontier_signed` can produce `Signed`, and only after the signature
  verifies against the caller-supplied `trusted_signer` key.
  `AnchoredFrontier::is_signed()` always returns `false` by design (it has no
  trusted-key context); callers must use `is_signed_by` or
  `verify_frontier_signature` with an explicit key.
- Frontier signatures are domain-separated (`FRONTIER_SIGNATURE_DOMAIN`
  prefix), so a signature over a frontier payload cannot be replayed as a
  signature over another Chio payload shape.
- Every artifact this crate produces records `canonical_source:
  EquivalenceShim`; `CanonicalSource::CanonicalBytes` is defined for
  canonical-bytes-newtype interop but nothing in this crate constructs it.

## Dependencies

Internal: `chio-core-types` supplies
`capability::governance::ProvenanceEvidenceClass` (checked on a signed
lineage statement before an edge upgrades to `Verified`) and
`receipt::lineage::ReceiptLineageStatement` (used by
`ingest_replay_corpus`), plus `crypto::{PublicKey, Signature}` (used by
`anchor`). No dependency is aliased. External: `serde`/`serde_json` for the
graph and artifact types, `thiserror` for the error enums. No async runtime;
nothing in `src/` performs file or network I/O.

`chio-store-sqlite`'s `lineage_cte.rs` documents itself as mirroring this
crate's `DEFAULT_DEPTH_LIMIT` and graph shape for its recursive-CTE
persistent backing, but there is no `Cargo.toml` dependency edge between the
two crates in either direction; the two stay in sync by convention, not by
the compiler.
