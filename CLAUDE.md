# CLAUDE.md

This file is the entry point for agents working inside this repository.

## Canonical references

- `AGENTS.md` is the canonical agent guide (overview, five components, crate map, conventions, key files). Read it first.
- `spec/PROTOCOL.md` is the normative protocol specification. Wire-level changes must agree with it.
- `docs/README.md` indexes the broader documentation set (architecture notes, runtime boundaries, integration guides).

## Project rename

The project was formerly known as ARC and is being renamed to Chio. Treat the names as synonyms when reading legacy code, commits, or documentation. New code, crates, and prose should use Chio.

## One-liner build and test

```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```

Run this before declaring a change ready. `cargo build --workspace` can take several minutes on a cold cache.

## House rules

- No em dashes (U+2014) anywhere in code, comments, or documentation. Use hyphens (`-`) or parentheses.
- Fail-closed: errors deny access. Invalid policies reject at load time.
- Clippy: `unwrap_used = "deny"` and `expect_used = "deny"` are enforced workspace-wide.
- Commits follow conventional commits (`feat:`, `fix:`, `docs:`, `test:`, etc.).

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
