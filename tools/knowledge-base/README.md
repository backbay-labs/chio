# Local Chio Knowledge Base

This package runs a local retrieval and knowledge-graph stack for agents working in the Chio repository.

It provides:

- CocoIndex v1 incremental ingestion for code, docs, specs, examples, tests, and selected planning docs.
- Postgres with pgvector for semantic code and docs search.
- Neo4j for a durable Chio property graph.
- Graphiti MCP for temporal memory episodes.
- A small Chio KB MCP gateway on `http://localhost:8111/mcp/`.

The graph is retrieval support only. Repository files, tests, and current CI remain authoritative.

## Setup

```sh
cp tools/knowledge-base/.env.example tools/knowledge-base/.env
$EDITOR tools/knowledge-base/.env
make kb-up
make kb-update
make kb-smoke
```

`OPENAI_API_KEY` enables Graphiti, optional LLM relationship extraction for docs, specs, planning docs, crate READMEs, and OpenAI-compatible embeddings for code/docs chunks.
OpenAI embeddings are the default for this stack. A later local profile can swap the embedding backend to sentence-transformers, but the A-grade profile keeps `CHIO_KB_EMBED_MODEL=text-embedding-3-small`.
CocoIndex owns incremental vector ingestion. The Chio property graph is seeded through an idempotent Neo4j `MERGE` pass because the CocoIndex Neo4j connector can deadlock when thousands of files upsert shared repository nodes.

## Services

| Service | URL | Purpose |
| --- | --- | --- |
| Postgres pgvector | `localhost:55432` | Semantic code and docs vector tables |
| Neo4j | `http://localhost:7474` and `bolt://localhost:7687` | Chio property graph |
| Graphiti MCP | `http://localhost:8000/mcp` | Temporal graph memory |
| Chio KB MCP | `http://localhost:8111/mcp/` | Agent-facing repo search tools |

Docker Compose publishes every service port on `127.0.0.1` only. Keep that
binding unless you are deliberately tunneling the stack. The standalone
`chio-kb-mcp` command also defaults `CHIO_KB_MCP_HOST` to `127.0.0.1`.
If you override the MCP listener to a non-loopback interface, set
`CHIO_KB_MCP_BEARER_TOKEN` and send `Authorization: Bearer <token>` for
`kb_add_episode`; without loopback access or a valid token, that write tool is
denied.

Neo4j defaults are `neo4j` / `demodemo`. Change them in `.env` before first startup if needed.

## Commands

```sh
make kb-up       # Start Postgres, Neo4j, Graphiti MCP, and Chio KB MCP
make kb-down     # Stop the stack
make kb-reset    # Clear KB-owned tables, CocoIndex state, and Chio Neo4j nodes
make kb-reseed   # Reset, index, seed the graph, and seed Graphiti memory
make kb-update   # Catch up CocoIndex from the repo
make kb-live     # Run CocoIndex in live mode with local file watching
make kb-status   # Show compose state and service health
make kb-smoke    # Exercise service health and MCP tool listing
make kb-eval     # Run core and deep dogfood fixtures and enforce A overall
make kb-dogfood  # Regenerate DOGFOOD-REVIEW.md from the full dogfood output
make kb-lock-check  # Verify pyproject.toml matches the checked-in uv.lock
```

`kb-reset` does not remove `.env` or Docker named volumes by default. Set `KB_RESET_VOLUMES=1` only when you explicitly want `docker compose down -v` before the stack is started and reseeded.

You can also run the CocoIndex app directly:

```sh
cd tools/knowledge-base
docker compose exec -T chio-kb-mcp cocoindex -d /app show chio_kb.index --tree
docker compose exec -T chio-kb-mcp cocoindex -d /app update --force chio_kb.index
docker compose exec chio-kb-mcp cocoindex -d /app update --force --live chio_kb.index
```

The KB Python environment is locked by `tools/knowledge-base/uv.lock`; run
`make kb-lock-check` or `cd tools/knowledge-base && uv lock --check` before
building container changes. Runtime images are pinned by digest in
`docker-compose.yml` and `Dockerfile.kb-mcp`; refresh those digests deliberately
when upgrading Postgres, Neo4j, Graphiti MCP, or the uv Python base.

## MCP Tools

The Chio KB MCP gateway exposes:

- `kb_search_code(query, limit, filters)`
- `kb_search_docs(query, limit, filters)`
- `kb_manifest()`
- `kb_find_tests(path_or_symbol, limit)`
- `kb_find_docs(path_or_crate, limit)`
- `kb_neighbors(entity, depth, limit)`
- `kb_subgraph(entity, depth, node_limit, edge_limit)`
- `kb_context(entity, limit)`
- `kb_impact(path_or_crate, limit)`
- `kb_brief_feature(feature_or_task, focus_paths, limit, include_memory, intent)`
- `kb_eval(category, format, suite)`
- `kb_add_episode(name, body, source_description)`

Useful filters for `kb_search_code`: `file_path`, `normalized_path`, `source_root`, `language`, `crate`, `package`, `kind`, `symbol_hint`, `canonicality`, `is_generated`.

Useful filters for `kb_search_docs`: `file_path`, `normalized_path`, `source_root`, `doc_type`, `title`, `section`, `canonicality`, `is_generated`.

Search responses include `normalized_path`, `canonicality`, `validation_command`, `why`, and `rank_components` so agents can explain why a result was returned and immediately choose a focused local validation gate.

## Agent Client Snippets

Codex or another HTTP-capable MCP client:

```json
{
  "mcpServers": {
    "chio-kb": {
      "transport": "http",
      "url": "http://localhost:8111/mcp/"
    },
    "graphiti-memory": {
      "transport": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Cursor:

```json
{
  "mcpServers": {
    "chio-kb": {
      "url": "http://localhost:8111/mcp/"
    },
    "graphiti-memory": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Claude Desktop with `mcp-remote`:

```json
{
  "mcpServers": {
    "chio-kb": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8111/mcp/"]
    },
    "graphiti-memory": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8000/mcp"]
    }
  }
}
```

Direct HTTP smoke call:

```sh
curl -s http://localhost:8111/mcp/ \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq
```

Write-tool call with bearer token when the MCP server is intentionally exposed
beyond loopback:

```sh
curl -s http://localhost:8111/mcp/ \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $CHIO_KB_MCP_BEARER_TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kb_add_episode","arguments":{"name":"Repair summary","body":"Validated locally."}}}' | jq
```

## Indexed Shape

Postgres schema `chio_kb` stores:

- `code_chunks`: code/config chunks with file path, source root, language, crate/package, symbol hints, line ranges, and embeddings.
- `doc_chunks`: docs/spec/planning chunks with title, section, anchor, line ranges, and embeddings.

Neo4j stores `Chio`-prefixed labels such as `ChioEntity`, `ChioFolder`, `ChioFile`, `ChioSymbol`, `ChioSection`, `ChioCrate`, `ChioDoc`, `ChioSpec`, `ChioConcept`, `ChioPolicy`, `ChioGuard`, `ChioReceipt`, `ChioProtocol`, and `ChioStandard`. Relationship types include `CONTAINS`, `CALLS`, `IMPORTS`, `DEPENDS_ON`, `DOCUMENTED_IN`, `IMPLEMENTS`, `TESTED_BY`, `MENTIONS`, `DEFINES`, `GUARDS`, `VALIDATES`, `SUPERSEDES`, `OWNED_BY`, `HAS_DOC`, `HAS_TEST`, `CANONICAL_DOC`, `VALIDATED_BY`, and `USES_CONCEPT`.

Scoped concept nodes such as `capability:kernel-validation`, `receipt:protocol`, `policy:compiler`, and `guard:pipeline` are preferred over generic global concept hubs during traversal. `kb_context`, `kb_neighbors`, and `kb_impact` report hub suppression evidence when broad hubs are skipped.

Graphiti should receive high-value temporal episodes only: architecture summaries, planning decisions, release notes, PR repair summaries, and agent session notes. Do not feed raw source files into Graphiti. Curated seed episodes live under `tools/knowledge-base/seeds/graphiti/` and are loaded with `make kb-seed-memory`.

## Evaluation

The evaluation harness lives in `tools/knowledge-base/eval/queries.yml`. It covers the core retrieval fixtures plus deeper dogfood fixtures for docs/spec retrieval, feature briefs, compound test discovery, graph navigation/impact, and Graphiti memory.

```sh
make kb-eval
make kb-dogfood
cd tools/knowledge-base && docker compose exec -T chio-kb-mcp chio-kb-eval --suite deep --format markdown
```

Grades are based on precision@5, recall@10, MRR@10, p95 latency, canonical path misses, forbidden top-3 hits, graph noise checks, and required Graphiti memory terms. The stack is acceptable when the overall grade is A and every reported category is A.

## Graph Structure Notes

The structure follows three practical lessons from code-graph systems such as GitNexus:

- Keep structural code facts separate from prose knowledge. Files, folders, sections, symbols, imports, and calls are deterministic graph facts; Chio protocol concepts and decisions are higher-level semantic facts.
- Prefer stable node identities over display names. File paths, section anchors, symbol line anchors, and crate/package paths are part of node IDs so incremental updates can reconcile records.
- Give agents context and impact tools over raw graph traversal. `kb_context`, `kb_neighbors`, and `kb_impact` are intended as the first graph tools to call before editing shared code.
