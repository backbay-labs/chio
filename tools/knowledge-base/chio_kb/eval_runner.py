"""Dogfood evaluation harness for the local Chio knowledge base."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import pathlib
import re
import statistics
import time
from collections.abc import Iterable
from typing import Any

import yaml

from chio_kb import query, repo_model

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_FIXTURE_PATH = ROOT / "eval" / "queries.yml"


def fixture_path() -> pathlib.Path:
    repo_path = pathlib.Path(os.environ.get("CHIO_KB_REPO_ROOT", "/workspace")) / "ops" / "knowledge-base" / "eval" / "queries.yml"
    if repo_path.exists():
        return repo_path
    return PACKAGE_FIXTURE_PATH


def _load_fixtures() -> list[dict[str, Any]]:
    path = fixture_path()
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    fixtures = payload.get("fixtures", payload)
    if not isinstance(fixtures, list):
        raise ValueError(f"{path} must contain a fixture list.")
    return [dict(item) for item in fixtures]


def _filter_suite(fixtures: list[dict[str, Any]], suite: str) -> list[dict[str, Any]]:
    suite_name = (suite or "all").lower()
    if suite_name == "all":
        return fixtures
    if suite_name not in {"core", "deep"}:
        raise ValueError("suite must be one of core, deep, or all.")
    return [item for item in fixtures if str(item.get("suite", "core")).lower() == suite_name]


def _norm(path: Any) -> str:
    return repo_model.normalize_path(str(path or ""))


def _term_set(value: str) -> set[str]:
    parsed = {term.lower() for term in re.findall(r"[A-Za-z0-9_.-]+", value)}
    for term in list(parsed):
        if len(term) > 3 and term.endswith("s"):
            parsed.add(term[:-1])
    return parsed


def _path_matches(actual: str, expected: str) -> bool:
    actual_norm = _norm(actual)
    expected_norm = _norm(expected)
    return actual_norm == expected_norm or actual_norm.startswith(expected_norm.rstrip("/") + "/")


def _dedupe_paths(paths: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for path in paths:
        norm = _norm(path)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _extract_paths(value: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key in ("normalized_path", "file_path", "path", "seed_path"):
            raw = value.get(key)
            if isinstance(raw, str) and raw:
                paths.append(raw)
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                paths.extend(_extract_paths(nested))
    elif isinstance(value, list):
        for item in value:
            paths.extend(_extract_paths(item))
    return _dedupe_paths(paths)


def _extract_text(value: Any) -> str:
    parts: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            parts.append(str(key))
            if key in {"content", "text", "summary", "name", "path", "normalized_path", "file_path", "why", "intent"}:
                if isinstance(nested, str):
                    parts.append(nested)
                elif isinstance(nested, list):
                    parts.extend(str(item) for item in nested)
            if isinstance(nested, (dict, list)):
                parts.append(_extract_text(nested))
    elif isinstance(value, list):
        for item in value:
            parts.append(_extract_text(item))
    elif isinstance(value, str):
        parts.append(value)
    return "\n".join(part for part in parts if part)


async def _run_tool(fixture: dict[str, Any]) -> Any:
    tool = fixture["target_tool"]
    limit = int(fixture.get("limit", 10))
    text = str(fixture["query"])
    if tool == "kb_search_code":
        return await query.search_code(text, limit=limit, filters=fixture.get("filters"))
    if tool == "kb_search_docs":
        return await query.search_docs(text, limit=limit, filters=fixture.get("filters"))
    if tool == "kb_find_tests":
        return await query.find_tests(text, limit=limit)
    if tool == "kb_find_docs":
        return await query.find_docs(text, limit=limit)
    if tool == "kb_neighbors":
        return await query.neighbors(text, depth=int(fixture.get("depth", 2)), limit=limit)
    if tool == "kb_context":
        return await query.context(text, limit=limit)
    if tool == "kb_impact":
        return await query.impact(text, limit=limit)
    if tool == "kb_search_memory":
        return await query.search_memory(text, limit=limit)
    if tool == "kb_brief_feature":
        return await query.brief_feature(
            text,
            focus_paths=fixture.get("focus_paths"),
            limit=min(limit, 12),
            include_memory=bool(fixture.get("include_memory", False)),
            intent=fixture.get("intent", "auto"),
        )
    raise ValueError(f"Unsupported eval target_tool: {tool}")


def _first_rank(paths: list[str], expected: list[str]) -> int | None:
    for index, path in enumerate(paths, start=1):
        if any(_path_matches(path, target) for target in expected):
            return index
    return None


def _matched_expected(paths: list[str], expected: list[str], top_n: int) -> list[str]:
    top_paths = paths[:top_n]
    return [
        target
        for target in expected
        if any(_path_matches(path, target) for path in top_paths)
    ]


def _forbidden_hits(paths: list[str], forbidden: list[str], top_n: int = 3) -> list[str]:
    top_paths = paths[:top_n]
    return [
        path
        for path in top_paths
        if any(_path_matches(path, target) for target in forbidden)
    ]


def _score_fixture(fixture: dict[str, Any], paths: list[str], latency_ms: float, raw: Any) -> dict[str, Any]:
    expected_top = [_norm(path) for path in fixture.get("expected_top_paths", [])]
    expected_any = [_norm(path) for path in fixture.get("expected_any_paths", [])]
    relevant = _dedupe_paths([*expected_top, *expected_any])
    forbidden_top = [_norm(path) for path in fixture.get("forbidden_top_paths", [])]
    forbidden_any = [_norm(path) for path in fixture.get("forbidden_any_paths", [])]
    expected_text_terms = [str(term).lower() for term in fixture.get("expected_text_terms", [])]
    forbidden_text_terms = [str(term).lower() for term in fixture.get("forbidden_text_terms", [])]
    p5_matches = _matched_expected(paths, relevant, 5)
    r10_matches = _matched_expected(paths, relevant, 10)
    first_rank = _first_rank(paths, expected_top or relevant)
    forbidden_hits = _forbidden_hits(paths, forbidden_top)
    forbidden_any_hits = _forbidden_hits(paths, forbidden_any, top_n=10)
    text_blob = _extract_text(raw).lower()
    text_terms = _term_set(text_blob)

    def _text_term_matches(term: str) -> bool:
        expected_terms = _term_set(term)
        return term in text_blob or bool(expected_terms & text_terms)

    matched_text_terms = [term for term in expected_text_terms if _text_term_matches(term)]
    forbidden_text_hits = [term for term in forbidden_text_terms if term in text_blob]
    if expected_text_terms and not relevant:
        required_hit = len(matched_text_terms) == len(expected_text_terms)
    else:
        required_hit = first_rank is not None and first_rank <= 10
    critical_misses = []
    if expected_top and not any(target in r10_matches for target in expected_top):
        critical_misses.append("expected canonical path missing from top 10")
    if forbidden_hits:
        critical_misses.append("forbidden path ranked in top 3")
    if forbidden_any_hits:
        critical_misses.append("forbidden path appeared in results")
    if forbidden_text_hits:
        critical_misses.append("forbidden text appeared in results")
    if expected_text_terms and len(matched_text_terms) < len(expected_text_terms):
        critical_misses.append("expected memory/text terms missing")
    max_latency = float(fixture.get("max_latency_ms", 2500))
    if latency_ms > max_latency:
        critical_misses.append(f"latency exceeded {max_latency:.0f} ms")

    if expected_text_terms and not relevant:
        precision_at_5 = len(matched_text_terms) / max(1, len(expected_text_terms))
        recall_at_10 = precision_at_5
        mrr_at_10 = 1.0 if matched_text_terms else 0.0
    else:
        relevant_denominator = max(1, min(5, len(relevant)))
        precision_at_5 = len(p5_matches) / relevant_denominator
        recall_at_10 = len(r10_matches) / max(1, len(relevant))
        mrr_at_10 = 0.0 if first_rank is None or first_rank > 10 else 1.0 / first_rank
    fixture_pass = required_hit and not critical_misses and precision_at_5 >= 0.80 and recall_at_10 >= 0.50
    return {
        "id": fixture.get("id"),
        "category": fixture.get("category", "uncategorized"),
        "query": fixture.get("query"),
        "target_tool": fixture.get("target_tool"),
        "top_paths": paths[:10],
        "expected_top_paths": expected_top,
        "expected_any_paths": expected_any,
        "forbidden_top_hits": forbidden_hits,
        "forbidden_any_hits": forbidden_any_hits,
        "matched_text_terms": matched_text_terms,
        "missing_text_terms": [term for term in expected_text_terms if term not in matched_text_terms],
        "matched_at_5": p5_matches,
        "matched_at_10": r10_matches,
        "precision_at_5": precision_at_5,
        "recall_at_10": recall_at_10,
        "mrr_at_10": mrr_at_10,
        "latency_ms": round(latency_ms, 2),
        "max_latency_ms": max_latency,
        "critical_misses": critical_misses,
        "pass": fixture_pass,
    }


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    sorted_values = sorted(values)
    index = math.ceil(0.95 * len(sorted_values)) - 1
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


def _grade(metrics: dict[str, float], critical_miss_count: int, forbidden_hit_count: int) -> str:
    if (
        metrics["precision_at_5"] >= 0.90
        and metrics["recall_at_10"] >= 0.90
        and metrics["mrr_at_10"] >= 0.75
        and critical_miss_count == 0
    ):
        return "A"
    if (
        metrics["precision_at_5"] >= 0.80
        and metrics["recall_at_10"] >= 0.85
        and metrics["mrr_at_10"] >= 0.75
        and forbidden_hit_count == 0
    ):
        return "A-"
    if critical_miss_count:
        return "B-"
    return "B"


def _aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    precision_values = [float(item["precision_at_5"]) for item in results]
    recall_values = [float(item["recall_at_10"]) for item in results]
    mrr_values = [float(item["mrr_at_10"]) for item in results]
    latency_values = [float(item["latency_ms"]) for item in results]
    critical_miss_count = sum(len(item["critical_misses"]) for item in results)
    forbidden_hit_count = sum(len(item["forbidden_top_hits"]) for item in results)
    metrics = {
        "precision_at_5": statistics.fmean(precision_values) if precision_values else 0.0,
        "recall_at_10": statistics.fmean(recall_values) if recall_values else 0.0,
        "mrr_at_10": statistics.fmean(mrr_values) if mrr_values else 0.0,
        "p95_latency_ms": _p95(latency_values),
    }
    return {
        "metrics": {key: round(value, 4) for key, value in metrics.items()},
        "grade": _grade(metrics, critical_miss_count, forbidden_hit_count),
        "critical_miss_count": critical_miss_count,
        "forbidden_hit_count": forbidden_hit_count,
        "fixture_count": len(results),
        "passed_fixture_count": sum(1 for item in results if item["pass"]),
    }


async def run_evaluation_direct(category: str | None = None, suite: str = "all") -> dict[str, Any]:
    fixtures = _load_fixtures()
    fixtures = _filter_suite(fixtures, suite)
    if category:
        fixtures = [item for item in fixtures if item.get("category") == category]
    results: list[dict[str, Any]] = []
    for fixture in fixtures:
        start = time.perf_counter()
        raw = await _run_tool(fixture)
        latency_ms = (time.perf_counter() - start) * 1000.0
        paths = _extract_paths(raw)
        results.append(_score_fixture(fixture, paths, latency_ms, raw))
    aggregate = _aggregate(results)
    by_category: dict[str, dict[str, Any]] = {}
    for category_name in sorted({item["category"] for item in results}):
        by_category[category_name] = _aggregate(
            [item for item in results if item["category"] == category_name]
        )
    return {
        "grade": aggregate["grade"],
        "metrics": aggregate["metrics"],
        "summary": aggregate,
        "categories": by_category,
        "fixtures": results,
    }


def render_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    metrics = result["metrics"]
    lines = [
        "# Chio KB Dogfood Review",
        "",
        "Generated by `chio-kb-eval` from fixed retrieval fixtures.",
        "",
        "## Grade",
        "",
        f"- Overall: {result['grade']}",
        f"- Fixtures: {summary['passed_fixture_count']} / {summary['fixture_count']} passing",
        f"- precision@5: {metrics['precision_at_5']:.2f}",
        f"- recall@10: {metrics['recall_at_10']:.2f}",
        f"- MRR@10: {metrics['mrr_at_10']:.2f}",
        f"- p95 latency: {metrics['p95_latency_ms']:.0f} ms",
        "",
        "## Categories",
        "",
    ]
    for category, category_result in sorted(result["categories"].items()):
        category_metrics = category_result["metrics"]
        lines.append(
            f"- {category}: {category_result['grade']} "
            f"(p@5 {category_metrics['precision_at_5']:.2f}, "
            f"r@10 {category_metrics['recall_at_10']:.2f}, "
            f"mrr {category_metrics['mrr_at_10']:.2f})"
        )
    lines.extend(["", "## Fixture Detail", ""])
    for fixture in result["fixtures"]:
        status = "PASS" if fixture["pass"] else "FAIL"
        lines.extend(
            [
                f"### {fixture['id']} ({status})",
                "",
                f"- Tool: `{fixture['target_tool']}`",
                f"- Query: {fixture['query']}",
                f"- Latency: {fixture['latency_ms']:.0f} ms",
                f"- Top paths: {', '.join(fixture['top_paths'][:5])}",
            ]
        )
        if fixture["critical_misses"]:
            lines.append(f"- Critical misses: {', '.join(fixture['critical_misses'])}")
        if fixture["forbidden_top_hits"]:
            lines.append(f"- Forbidden top hits: {', '.join(fixture['forbidden_top_hits'])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


async def _main_async(args: argparse.Namespace) -> int:
    result = await run_evaluation_direct(category=args.category, suite=args.suite)
    if args.format == "markdown":
        output = render_markdown(result)
    else:
        output = json.dumps(result, indent=2)
    if args.write_dogfood:
        pathlib.Path(args.write_dogfood).write_text(output, encoding="utf-8")
    else:
        print(output)
    if args.fail_below_a and result["grade"] != "A":
        return 1
    if args.fail_below_a_minus and result["grade"] not in {"A", "A-"}:
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Chio KB dogfood retrieval fixtures.")
    parser.add_argument("--category", help="Run a single fixture category.")
    parser.add_argument("--suite", choices=["core", "deep", "all"], default="all")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--write-dogfood", default="", help="Write output to this path.")
    parser.add_argument("--fail-below-a", action="store_true")
    parser.add_argument("--fail-below-a-minus", action="store_true")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(_main_async(args)))


if __name__ == "__main__":
    main()
