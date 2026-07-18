from __future__ import annotations

import asyncio

from chio_kb import query


def test_repository_metadata_uses_git_and_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CHIO_KB_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("CHIO_KB_REPOSITORY", "backbay-labs/chio")
    monkeypatch.setenv("CHIO_KB_REPOSITORY_URL", "https://github.com/backbay-labs/chio")
    monkeypatch.setenv("CHIO_KB_GIT_REF", "main")
    monkeypatch.setenv("CHIO_KB_GIT_SHA", "abc123")
    monkeypatch.setenv("CHIO_KB_INDEXED_AT", "2026-07-17T20:00:00Z")

    assert query._repository_metadata() == {
        "repository": "backbay-labs/chio",
        "repositoryUrl": "https://github.com/backbay-labs/chio",
        "ref": "main",
        "sha": "abc123",
        "indexedAt": "2026-07-17T20:00:00Z",
        "indexId": "abc123",
    }


def test_evaluation_summary_reads_dogfood_report(monkeypatch, tmp_path) -> None:
    report = tmp_path / "tools" / "knowledge-base" / "DOGFOOD-REVIEW.md"
    report.parent.mkdir(parents=True)
    report.write_text(
        "# Review\n\n- Overall: A\n- Fixtures: 21 / 21 passing\n"
        "- precision@5: 0.99\n- recall@10: 1.00\n- MRR@10: 0.98\n"
        "- p95 latency: 1295 ms\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CHIO_KB_REPO_ROOT", str(tmp_path))

    summary = query._evaluation_summary()

    assert summary["grade"] == "A"
    assert summary["fixtures"] == {"passing": 21, "total": 21}
    assert summary["precisionAt5"] == 0.99
    assert summary["p95LatencyMs"] == 1295


def test_normalize_subgraph_deduplicates_and_preserves_topology() -> None:
    rows = [
        {
            "distance": 1,
            "nodes": [
                {"id": "file:a", "name": "a.rs", "kind": "file", "path": "crates/a.rs"},
                {"id": "file:b", "name": "b.rs", "kind": "file", "path": "crates/b.rs"},
            ],
            "edges": [
                {"source": "file:a", "target": "file:b", "kind": "CALLS"},
            ],
        },
        {
            "distance": 2,
            "nodes": [
                {"id": "file:a", "name": "a.rs", "kind": "file", "path": "crates/a.rs"},
                {"id": "file:b", "name": "b.rs", "kind": "file", "path": "crates/b.rs"},
                {"id": "test:b", "name": "b_test.rs", "kind": "test", "path": "tests/b.rs"},
            ],
            "edges": [
                {"source": "file:a", "target": "file:b", "kind": "CALLS"},
                {"source": "file:b", "target": "test:b", "kind": "TESTED_BY"},
            ],
        },
    ]

    graph = query._normalize_subgraph("file:a", rows, node_limit=3, edge_limit=3)

    assert graph["seed"] == "file:a"
    assert [node["id"] for node in graph["nodes"]] == ["file:a", "file:b", "test:b"]
    assert graph["nodes"][0]["distance"] == 0
    assert graph["nodes"][2]["distance"] == 2
    assert graph["edges"] == [
        {"source": "file:a", "target": "file:b", "kind": "CALLS"},
        {"source": "file:b", "target": "test:b", "kind": "TESTED_BY"},
    ]
    assert graph["truncated"] is False


def test_filter_clause_supports_generated_boolean_without_string_coercion() -> None:
    clause, values = query._filter_clause(
        {"source_root": "crates", "is_generated": False},
        {"source_root", "is_generated"},
    )

    assert clause == "WHERE source_root ILIKE $1 AND is_generated = $2"
    assert values == ["%crates%", False]


def test_manifest_does_not_advertise_semantic_tools_without_api_key(monkeypatch) -> None:
    async def postgres_counts() -> dict[str, int]:
        return {"files": 1, "docs": 1, "languages": 1, "crates": 1, "packages": 0}

    async def graph_counts() -> dict[str, int]:
        return {"entities": 2, "relations": 1, "tests": 0, "concepts": 0}

    async def memory_ready() -> bool:
        return False

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(query, "_postgres_manifest_counts", postgres_counts)
    monkeypatch.setattr(query, "_neo4j_manifest_counts", graph_counts)
    monkeypatch.setattr(query, "_graphiti_manifest_ready", memory_ready)

    result = asyncio.run(query.manifest())

    assert result["capabilities"] == {
        "search": False,
        "graph": True,
        "impact": False,
        "brief": False,
        "memory": False,
        "signedRetrieval": False,
    }
    assert "semantic search unavailable" in result["warnings"]
