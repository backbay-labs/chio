"""Query helpers for the Chio knowledge-base MCP gateway."""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import asyncpg
import httpx
import litellm
from neo4j import AsyncGraphDatabase
from pgvector.asyncpg import register_vector

from chio_kb import repo_model

PG_SCHEMA_NAME = "chio_kb"
CODE_TABLE_NAME = "code_chunks"
DOC_TABLE_NAME = "doc_chunks"

QUERY_INTENTS = {
    "capability",
    "revocation",
    "receipt",
    "guard-policy",
    "mcp-adapter",
    "sdk-conformance",
    "release-qualification",
    "compliance-certificate",
    "planning-history",
    "generic",
}

QUERY_INTENT_PRIORITY = [
    "planning-history",
    "release-qualification",
    "compliance-certificate",
    "revocation",
    "guard-policy",
    "mcp-adapter",
    "sdk-conformance",
    "receipt",
    "capability",
]

POSTGRES_URL = os.environ.get(
    "POSTGRES_URL", "postgres://cocoindex:cocoindex@localhost:55432/chio_kb"
)
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "demodemo")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")
GRAPHITI_MCP_URL = os.environ.get("GRAPHITI_MCP_URL", "http://localhost:8000/mcp").rstrip("/")
GRAPHITI_MCP_HOST_HEADER = os.environ.get("GRAPHITI_MCP_HOST_HEADER")
GRAPHITI_GROUP_ID = os.environ.get("GRAPHITI_GROUP_ID", "chio-repo")
EMBED_MODEL = os.environ.get("CHIO_KB_EMBED_MODEL", "text-embedding-3-small")

GLOBAL_HUB_IDS = {
    "capability:capability",
    "policy:policy",
    "receipt:receipt",
    "guard:guard",
    "kernel:runtime-kernel",
    "conformance:conformance",
    "sdk:sdk",
    "attestation:attestation",
}
GLOBAL_HUB_KINDS = {"capability", "policy", "receipt", "guard", "kernel", "conformance", "sdk", "attestation"}
PLANNING_TERMS = {"planning", "roadmap", "milestone", "decision", "audit", "history", "phase", "tracker"}
TEST_TERMS = {"test", "tests", "testing", "fixture", "fixtures", "conformance", "replay", "validation"}
GENERATED_TERMS = {"generated", "schema", "schemas", "bindings", "codegen", "wire"}
NOISY_GRAPH_KINDS = {"folder"}
NOISY_GRAPH_PATHS = {"", "."}
NOISY_CONTEXT_DOC_PREFIXES = (
    "docs/archive/",
    "docs/operations/ROADMAP",
    "docs/protocols/ADR-",
    "spec/schemas/",
)

EVIDENCE_EXPORT_PATHS = {
    "crates/products/chio-cli/src/evidence_export.rs",
    "crates/kernel/chio-kernel/src/evidence_export.rs",
    "crates/platform/chio-store-sqlite/src/evidence_export.rs",
}


@dataclass(frozen=True)
class QueryPlan:
    intent: str
    intents: tuple[str, ...]
    code_query: str
    docs_query: str
    tests_query: str
    graph_query: str
    memory_query: str

DOMAIN_CODE_HINTS: list[tuple[set[str], list[str]]] = [
    (
        {"capability", "validation"},
        [
            "crates/kernel/chio-kernel/src/kernel/mod.rs",
            "crates/core/chio-core-types/src/capability.rs",
            "crates/kernel/chio-kernel/src/kernel/delegation.rs",
            "crates/platform/chio-http-core/src/authority.rs",
            "crates/kernel/chio-kernel-core/src/capability_verify.rs",
            "crates/kernel/chio-kernel-core/src/scope.rs",
        ],
    ),
    (
        {"delegated", "capability", "revocation"},
        [
            "crates/kernel/chio-kernel/src/kernel/delegation.rs",
            "crates/kernel/chio-kernel/src/revocation_store.rs",
            "crates/core/chio-core-types/src/capability.rs",
            "crates/kernel/chio-kernel-core/src/capability_verify.rs",
        ],
    ),
    (
        {"guard", "pipeline"},
        [
            "crates/guards/chio-guards/src/pipeline.rs",
            "crates/guards/chio-guards/src/lib.rs",
            "crates/kernel/chio-kernel/src/kernel/evaluator.rs",
            "crates/guards/chio-guards/src/mcp_tool.rs",
        ],
    ),
    (
        {"policy", "compiler"},
        [
            "crates/guards/chio-policy/src/validate.rs",
            "crates/guards/chio-policy/src/evaluate/engine.rs",
            "crates/guards/chio-policy/src/lib.rs",
            "crates/guards/chio-policy/src/models.rs",
            "crates/guards/chio-policy/src/compiler.rs",
        ],
    ),
    (
        {"mcp", "adapter"},
        [
            "crates/protocol/chio-mcp-adapter/src/lib.rs",
            "crates/protocol/chio-mcp-adapter/src/transport.rs",
            "crates/protocol/chio-mcp-adapter/src/native.rs",
            "crates/protocol/chio-mcp-edge/src/runtime.rs",
        ],
    ),
    (
        {"compliance", "certificate"},
        [
            "crates/kernel/chio-kernel/src/compliance_certificate.rs",
            "crates/kernel/chio-kernel/tests/compliance_certificate_hybrid.rs",
            "crates/protocol/chio-acp-proxy/src/compliance.rs",
            "crates/platform/chio-store-sqlite/src/receipt_store/reports.rs",
            "crates/platform/chio-store-sqlite/src/evidence_export.rs",
            "crates/products/chio-cli/src/evidence_export.rs",
            "crates/kernel/chio-kernel/src/evidence_export.rs",
            "crates/core/chio-core-types/src/receipt.rs",
        ],
    ),
    (
        {"evidence", "export"},
        [
            "crates/products/chio-cli/src/evidence_export.rs",
            "crates/kernel/chio-kernel/src/evidence_export.rs",
            "crates/platform/chio-store-sqlite/src/evidence_export.rs",
            "crates/platform/chio-store-sqlite/src/receipt_store/reports.rs",
            "crates/platform/chio-http-core/src/receipt.rs",
        ],
    ),
    (
        {"release", "qualification"},
        [
            "crates/products/chio-cli/src/evidence_export.rs",
            "crates/kernel/chio-kernel/src/evidence_export.rs",
            "crates/platform/chio-store-sqlite/src/evidence_export.rs",
            "crates/tooling/chio-conformance/src/report.rs",
            "crates/tooling/chio-conformance/src/runner.rs",
        ],
    ),
]

DOMAIN_DOC_HINTS: list[tuple[set[str], list[str]]] = [
    (
        {"receipt", "merkle"},
        [
            "spec/PROTOCOL.md",
            "spec/schemas/chio-wire/v1/receipt/README.md",
            "spec/schemas/chio-wire/v1/receipt/inclusion-proof.schema.json",
            "docs/standards/CHIO_RECEIPTS_PROFILE.md",
        ],
    ),
    (
        {"sdk", "conformance"},
        [
            "docs/conformance/verdict-matrix.md",
            "tests/conformance/README.md",
            "tests/conformance/peers/js/README.md",
            "tests/conformance/peers/python/README.md",
        ],
    ),
    (
        {"release", "qualification"},
        [
            "docs/release/RELEASE_AUDIT.md",
            "docs/release/QUALIFICATION.md",
            "docs/conformance/verdict-matrix.md",
            "spec/COMPLIANCE-CERTIFICATE.md",
            "docs/standards/CHIO_WEB3_QUALIFICATION_MATRIX.json",
        ],
    ),
    (
        {"compliance", "certificate"},
        [
            "spec/COMPLIANCE-CERTIFICATE.md",
            "spec/PROTOCOL.md",
            "docs/release/QUALIFICATION.md",
            "docs/release/RELEASE_AUDIT.md",
            "docs/conformance/verdict-matrix.md",
        ],
    ),
    (
        {"security", "revocation"},
        [
            "spec/SECURITY.md",
            "spec/PROTOCOL.md",
            "spec/errors/registry.yaml",
            "docs/standards/CHIO_RECEIPTS_PROFILE.md",
        ],
    ),
    (
        {"capability", "revocation"},
        [
            "spec/PROTOCOL.md",
            "spec/schemas/chio-wire/v1/capability/revocation.schema.json",
            "spec/schemas/chio-wire/v1/capability/README.md",
            "docs/standards/CHIO_RECEIPTS_PROFILE.md",
        ],
    ),
]

DOMAIN_TEST_HINTS: list[tuple[set[str], list[str]]] = [
    (
        {"revocation"},
        [
            "crates/trust/chio-revocation-oracle/tests/swarm_revocation_e2e.rs",
            "crates/trust/chio-revocation-oracle/tests/receipt_chain_proof.rs",
            "crates/trust/chio-revocation-oracle/tests/property_oracle.rs",
            "crates/trust/chio-revocation-oracle/tests/scaffold.rs",
            "crates/kernel/chio-kernel-core/tests/revocation_view_concurrency.rs",
            "crates/products/chio-cli/tests/trust_revocation.rs",
        ],
    ),
    (
        {"delegation", "revocation"},
        [
            "crates/trust/chio-revocation-oracle/tests/swarm_revocation_e2e.rs",
            "crates/trust/chio-revocation-oracle/tests/receipt_chain_proof.rs",
            "crates/tooling/chio-conformance/tests/threats/delegation_chain_abuse.rs",
            "tests/conformance/native/scenarios/delegation-attenuation.json",
            "tests/conformance/native/scenarios/revocation-propagation.json",
        ],
    ),
    (
        {"compliance", "certificate"},
        [
            "crates/kernel/chio-kernel/tests/compliance_certificate_hybrid.rs",
            "crates/products/chio-cli/tests/evidence_export.rs",
            "crates/kernel/chio-kernel/src/kernel/tests/compliance_score.rs",
            "crates/platform/chio-http-core/tests/compliance_score_endpoint.rs",
        ],
    ),
    (
        {"evidence", "export"},
        [
            "crates/products/chio-cli/tests/evidence_export.rs",
            "crates/kernel/chio-kernel/tests/compliance_certificate_hybrid.rs",
            "crates/platform/chio-store-sqlite/src/receipt_store/tests.rs",
        ],
    ),
    (
        {"guard", "pipeline"},
        [
            "crates/guards/chio-guards/tests/integration.rs",
            "crates/guards/chio-guards/tests/output_sanitization.rs",
            "tests/e2e/tests/guard_platform_e2e.rs",
            "tests/conformance/fixtures/guard/tool-gate.yaml",
        ],
    ),
    (
        {"policy", "compiler"},
        [
            "crates/guards/chio-policy/tests/compile_policy.rs",
            "crates/guards/chio-policy/tests/validate_boundary.rs",
            "crates/guards/chio-policy/tests/integration_smoke.rs",
        ],
    ),
    (
        {"mcp", "adapter"},
        [
            "integrations/mcp-adapter/tests/transport_round_trip.rs",
            "integrations/mcp-adapter/tests/conformance_suite.rs",
            "crates/protocol/chio-mcp-adapter/tests/integration_smoke.rs",
            "crates/products/chio-cli/tests/mcp_wrap_e2e.rs",
        ],
    ),
    (
        {"sdk", "conformance"},
        [
            "crates/tooling/chio-conformance/tests/mcp_core_live.rs",
            "crates/tooling/chio-conformance/tests/mcp_core_cpp_live.rs",
            "crates/tooling/chio-conformance/verdict_matrix/tests/verdict_matrix_cross_language.rs",
            "sdks/typescript/packages/conformance/test/verdict_matrix.test.ts",
        ],
    ),
]

_pool: asyncpg.Pool | None = None
_driver: Any | None = None
_embed_lock = asyncio.Lock()
_embed_cache: dict[str, list[float]] = {}
_graphiti_session_id: str | None = None


def _openai_config() -> tuple[str | None, str | None]:
    api_key = os.environ.get("OPENAI_API_KEY")
    api_url = os.environ.get("OPENAI_API_URL")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for Chio KB embeddings.")
    if (api_url is None or "api.openai.com" in api_url) and not api_key.startswith("sk-"):
        raise RuntimeError(
            "OPENAI_API_KEY does not look like an OpenAI API key for api.openai.com. "
            "Update tools/knowledge-base/.env or export a valid shell key before querying."
        )
    return api_key, api_url


def _limit(value: Any, default: int = 8, maximum: int = 50) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(parsed, maximum))


def _terms(value: str) -> set[str]:
    parsed = {term.lower() for term in re.findall(r"[A-Za-z0-9_.-]+", value)}
    for term in list(parsed):
        if len(term) > 3 and term.endswith("s"):
            parsed.add(term[:-1])
        for fragment in re.split(r"[._-]+", term):
            if fragment:
                parsed.add(fragment)
                if len(fragment) > 3 and fragment.endswith("s"):
                    parsed.add(fragment[:-1])
    return parsed


def _contains_term(path: str, terms: set[str]) -> bool:
    lowered = path.lower()
    return any(term and term in lowered for term in terms)


def _wants_tests(query: str) -> bool:
    return bool(_terms(query) & TEST_TERMS)


def _wants_generated(query: str) -> bool:
    return bool(_terms(query) & GENERATED_TERMS)


def _wants_planning(query: str) -> bool:
    return bool(_terms(query) & PLANNING_TERMS)


def _row_dict(row: Mapping[str, Any]) -> dict[str, Any]:
    return dict(row)


def _domain_hint_paths(query: str, hints: list[tuple[set[str], list[str]]]) -> list[str]:
    query_terms = _terms(query)
    paths: list[str] = []
    seen: set[str] = set()
    for required_terms, hint_paths in sorted(hints, key=lambda item: (len(item[0]), len(item[1])), reverse=True):
        if not required_terms.issubset(query_terms):
            continue
        for path in hint_paths:
            normalized = repo_model.normalize_path(path)
            if normalized and normalized not in seen:
                seen.add(normalized)
                paths.append(normalized)
    return paths


def detect_query_intent(query: str, explicit: str | None = "auto") -> str:
    return detect_query_intents(query, explicit=explicit)[0]


def detect_query_intents(query: str, explicit: str | None = "auto") -> list[str]:
    requested = (explicit or "auto").strip().lower()
    if requested in QUERY_INTENTS and requested != "generic":
        return [requested]
    if requested == "generic":
        return ["generic"]
    if requested not in {"", "auto", "generic"}:
        requested_intents = [item.strip() for item in re.split(r"[,;+]", requested) if item.strip() in QUERY_INTENTS]
        if requested_intents:
            return requested_intents
    terms = _terms(query)
    intents: list[str] = []
    if terms & PLANNING_TERMS:
        intents.append("planning-history")
    if "release" in terms and terms & {"qualification", "candidate", "audit", "gate", "gates", "conformance", "evidence", "compliance"}:
        intents.append("release-qualification")
    if {"compliance", "certificate"} <= terms or {"certificate", "signed"} <= terms:
        intents.append("compliance-certificate")
    if "revocation" in terms or "revoked" in terms or "revocation-oracle" in terms:
        intents.append("revocation")
    if ("guard" in terms or "guards" in terms) and (terms & {"policy", "pipeline", "redaction", "redact", "deny", "allow"}):
        intents.append("guard-policy")
    if "mcp" in terms and (terms & {"adapter", "bridge", "transport", "edge"}):
        intents.append("mcp-adapter")
    if (terms & {"sdk", "binding", "bindings", "peer", "peers", "typescript", "python", "swift"}) and "conformance" in terms:
        intents.append("sdk-conformance")
    if "receipt" in terms or "receipts" in terms or "merkle" in terms:
        intents.append("receipt")
    if terms & {"capability", "capabilities", "token", "scope", "grant", "grants"}:
        intents.append("capability")
    ordered: list[str] = []
    for intent in QUERY_INTENT_PRIORITY:
        if intent in intents and intent not in ordered:
            ordered.append(intent)
    return ordered or ["generic"]


def _single_query_plan(intent: str, feature_or_task: str) -> QueryPlan:
    if intent == "revocation":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="delegated capability revocation validation token revoked expiration attenuation kernel core revocation store",
            docs_query="delegation revocation capability token attenuated grants protocol security receipts",
            tests_query="revocation oracle delegation revocation capability receipt chain",
            graph_query="capability:kernel-validation",
            memory_query="capability revocation delegated receipts architecture decision",
        )
    if intent == "receipt":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="receipt signing merkle inclusion proof evidence export receipt store",
            docs_query="receipt log Merkle committed signed decisions inclusion proof checkpoint",
            tests_query="receipt merkle inclusion proof replay evidence",
            graph_query="receipt:protocol",
            memory_query="receipt protocol evidence release truth boundary",
        )
    if intent == "guard-policy":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="guard pipeline input output policy evaluator deny allow redaction",
            docs_query="guard pipeline policy engine fail closed redaction docs",
            tests_query="guard pipeline redaction policy compiler deny allow",
            graph_query="guard:pipeline",
            memory_query="guard policy fail closed workflow constraint",
        )
    if intent == "mcp-adapter":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="MCP adapter transport envelope initialize tools call receipt bridge",
            docs_query="MCP adapter conformance edge protocol bridge docs",
            tests_query="MCP adapter transport conformance suite tools call",
            graph_query="crates/protocol/chio-mcp-adapter/src/lib.rs",
            memory_query="MCP adapter SDK conformance workflow",
        )
    if intent == "sdk-conformance":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="SDK conformance peers binding vectors verdict matrix wire protocol",
            docs_query="SDK conformance peers binding vectors verdict matrix wire protocol",
            tests_query="SDK conformance verdict matrix cross language peers",
            graph_query="capability:conformance",
            memory_query="SDK conformance peers verdict matrix",
        )
    if intent == "release-qualification":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="compliance certificate evidence export signed receipts release qualification store kernel cli",
            docs_query="release qualification audit gates conformance security candidate compliance certificate",
            tests_query="compliance certificate evidence export release qualification conformance",
            graph_query="spec/COMPLIANCE-CERTIFICATE.md",
            memory_query="release qualification truth boundary evidence gate",
        )
    if intent == "compliance-certificate":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="compliance certificate evidence export signed receipts kernel store cli",
            docs_query="compliance certificate signed receipts Merkle checkpoint protocol release qualification",
            tests_query="compliance certificate evidence export signed receipts",
            graph_query="spec/COMPLIANCE-CERTIFICATE.md",
            memory_query="compliance certificate evidence release truth boundary",
        )
    if intent == "capability":
        return QueryPlan(
            intent=intent,
            intents=(intent,),
            code_query="capability validation kernel token scope fail closed grants",
            docs_query="capability token scope grants protocol security",
            tests_query="capability token scope validation kernel core",
            graph_query="capability:kernel-validation",
            memory_query="capability validation kernel protocol",
        )
    return QueryPlan(
        intent=intent,
        intents=(intent,),
        code_query=feature_or_task,
        docs_query=feature_or_task,
        tests_query=feature_or_task,
        graph_query=feature_or_task,
        memory_query=feature_or_task,
    )


def _merge_query_text(values: Iterable[str]) -> str:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        for part in re.split(r"\s+[|]\s+|[;]", value):
            normalized = part.strip()
            key = normalized.lower()
            if normalized and key not in seen:
                seen.add(key)
                out.append(normalized)
    return " | ".join(out)


def _query_plan(feature_or_task: str, explicit_intent: str | None = "auto") -> QueryPlan:
    intents = detect_query_intents(feature_or_task, explicit=explicit_intent)
    plans = [_single_query_plan(intent, feature_or_task) for intent in intents]
    primary = plans[0]
    if len(plans) == 1:
        return primary
    implementation_intents = {
        "revocation",
        "guard-policy",
        "mcp-adapter",
        "sdk-conformance",
        "release-qualification",
        "compliance-certificate",
    }
    code_plans = [plan for plan in plans if plan.intent in implementation_intents]
    if not code_plans:
        code_plans = plans
    return QueryPlan(
        intent=primary.intent,
        intents=tuple(plan.intent for plan in plans),
        code_query=_merge_query_text(plan.code_query for plan in code_plans),
        docs_query=_merge_query_text(plan.docs_query for plan in plans),
        tests_query=_merge_query_text(plan.tests_query for plan in plans),
        graph_query=primary.graph_query,
        memory_query=_merge_query_text(plan.memory_query for plan in plans),
    )


def _dedupe_by_path(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for item in items:
        path = repo_model.normalize_path(item.get("normalized_path") or item.get("file_path") or item.get("path") or "")
        current = selected.get(path)
        if current is None or float(item.get("score", 0.0)) > float(current.get("score", 0.0)):
            selected[path] = item
    return sorted(selected.values(), key=lambda item: float(item.get("score", 0.0)), reverse=True)


async def _get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        async def init_connection(conn: asyncpg.Connection) -> None:
            await register_vector(conn)

        _pool = await asyncpg.create_pool(
            POSTGRES_URL,
            min_size=1,
            max_size=4,
            init=init_connection,
        )
    return _pool


async def _get_driver() -> Any:
    global _driver
    if _driver is None:
        _driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return _driver


async def close() -> None:
    global _pool, _driver
    if _pool is not None:
        await _pool.close()
        _pool = None
    if _driver is not None:
        await _driver.close()
    _driver = None


def _git_value(root: pathlib.Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def _repository_metadata() -> dict[str, str]:
    root = repo_model.repo_root_from_env()
    sha = os.environ.get("CHIO_KB_GIT_SHA") or _git_value(root, "rev-parse", "HEAD")
    ref = os.environ.get("CHIO_KB_GIT_REF") or _git_value(root, "branch", "--show-current") or "HEAD"
    indexed_at = os.environ.get("CHIO_KB_INDEXED_AT") or _git_value(root, "show", "-s", "--format=%cI", "HEAD")
    repository = os.environ.get("CHIO_KB_REPOSITORY", "bb-connor/arc")
    repository_url = os.environ.get(
        "CHIO_KB_REPOSITORY_URL", f"https://github.com/{repository}"
    )
    return {
        "repository": repository,
        "repositoryUrl": repository_url,
        "ref": ref,
        "sha": sha,
        "indexedAt": indexed_at,
        "indexId": os.environ.get("CHIO_KB_INDEX_ID") or sha,
    }


def _evaluation_summary() -> dict[str, Any]:
    report = repo_model.repo_root_from_env() / "tools" / "knowledge-base" / "DOGFOOD-REVIEW.md"
    try:
        text = report.read_text(encoding="utf-8")
    except OSError:
        return {"grade": "unavailable"}

    def match(pattern: str) -> str:
        found = re.search(pattern, text, re.MULTILINE)
        return found.group(1) if found else ""

    passing = match(r"^- Fixtures:\s*(\d+)\s*/")
    total = match(r"^- Fixtures:\s*\d+\s*/\s*(\d+)")
    summary: dict[str, Any] = {
        "grade": match(r"^- Overall:\s*([^\s]+)") or "unavailable",
        "fixtures": {
            "passing": int(passing or 0),
            "total": int(total or 0),
        },
    }
    metrics = {
        "precisionAt5": r"^- precision@5:\s*([0-9.]+)",
        "recallAt10": r"^- recall@10:\s*([0-9.]+)",
        "mrrAt10": r"^- MRR@10:\s*([0-9.]+)",
        "p95LatencyMs": r"^- p95 latency:\s*(\d+)",
    }
    for key, pattern in metrics.items():
        value = match(pattern)
        if value:
            summary[key] = int(value) if key == "p95LatencyMs" else float(value)
    return summary


async def _postgres_manifest_counts() -> dict[str, Any]:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        code = await conn.fetchrow(
            f'''SELECT COUNT(DISTINCT normalized_path) AS files,
                       COUNT(DISTINCT NULLIF(language, '')) AS languages,
                       COUNT(DISTINCT NULLIF(crate, '')) AS crates,
                       COUNT(DISTINCT NULLIF(package, '')) AS packages
                FROM "{PG_SCHEMA_NAME}"."{CODE_TABLE_NAME}"'''
        )
        docs = await conn.fetchval(
            f'''SELECT COUNT(DISTINCT normalized_path)
                FROM "{PG_SCHEMA_NAME}"."{DOC_TABLE_NAME}"'''
        )
    return {
        "files": int(code["files"] or 0),
        "docs": int(docs or 0),
        "languages": int(code["languages"] or 0),
        "crates": int(code["crates"] or 0),
        "packages": int(code["packages"] or 0),
    }


async def _neo4j_manifest_counts() -> dict[str, int]:
    driver = await _get_driver()
    async with driver.session(database=NEO4J_DATABASE) as session:
        result = await session.run(
            """
            MATCH (entity:ChioEntity)
            RETURN count(entity) AS entities,
                   sum(COUNT { (entity)-[]->() }) AS relations,
                   count(CASE WHEN entity.kind = 'test' THEN 1 END) AS tests,
                   count(CASE WHEN entity.kind = 'concept' OR entity.concept_scope = 'scoped' THEN 1 END) AS concepts
            """
        )
        row = await result.single()
    return {
        "entities": int(row["entities"] or 0) if row else 0,
        "relations": int(row["relations"] or 0) if row else 0,
        "tests": int(row["tests"] or 0) if row else 0,
        "concepts": int(row["concepts"] or 0) if row else 0,
    }


async def _graphiti_manifest_ready() -> bool:
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.get(GRAPHITI_MCP_URL.removesuffix("/mcp") + "/health")
    return response.is_success


async def manifest() -> dict[str, Any]:
    postgres_result, neo4j_result, graphiti_result = await asyncio.gather(
        _postgres_manifest_counts(),
        _neo4j_manifest_counts(),
        _graphiti_manifest_ready(),
        return_exceptions=True,
    )
    warnings: list[str] = []
    counts: dict[str, int] = {
        "files": 0,
        "docs": 0,
        "languages": 0,
        "crates": 0,
        "packages": 0,
        "entities": 0,
        "relations": 0,
        "tests": 0,
        "concepts": 0,
    }
    if isinstance(postgres_result, Exception):
        warnings.append("postgres index counts unavailable")
    else:
        counts.update(postgres_result)
    if isinstance(neo4j_result, Exception):
        warnings.append("graph index counts unavailable")
    else:
        counts.update(neo4j_result)
    if isinstance(graphiti_result, Exception) or not graphiti_result:
        warnings.append("temporal memory unavailable")
    semantic_ready = not isinstance(postgres_result, Exception) and bool(
        os.environ.get("OPENAI_API_KEY")
    )
    graph_ready = not isinstance(neo4j_result, Exception)
    if not semantic_ready:
        warnings.append("semantic search unavailable")
    metadata = _repository_metadata()
    return {
        "schemaVersion": "chio.kb.manifest.v1",
        **metadata,
        "status": "ready" if not warnings else "degraded",
        "counts": counts,
        "evaluation": _evaluation_summary(),
        "capabilities": {
            "search": semantic_ready,
            "graph": graph_ready,
            "impact": graph_ready and semantic_ready,
            "brief": graph_ready and semantic_ready,
            "memory": not isinstance(graphiti_result, Exception) and graphiti_result,
            "signedRetrieval": False,
        },
        "receipt": {"state": "unsupported"},
        "warnings": warnings,
    }


async def _embed(query: str) -> list[float]:
    cache_key = f"{EMBED_MODEL}:{query}"
    cached = _embed_cache.get(cache_key)
    if cached is not None:
        return cached
    openai_api_key, openai_api_url = _openai_config()
    async with _embed_lock:
        cached = _embed_cache.get(cache_key)
        if cached is not None:
            return cached
        response = await litellm.aembedding(
            model=EMBED_MODEL,
            input=[query],
            api_key=openai_api_key,
            api_base=openai_api_url,
        )
    vector = response["data"][0]["embedding"]
    parsed = [float(value) for value in vector]
    _embed_cache[cache_key] = parsed
    if len(_embed_cache) > 512:
        first_key = next(iter(_embed_cache))
        _embed_cache.pop(first_key, None)
    return parsed


def _filter_clause(filters: Mapping[str, Any] | None, allowed: set[str]) -> tuple[str, list[Any]]:
    if not filters:
        return "", []
    clauses: list[str] = []
    values: list[Any] = []
    for key, raw in filters.items():
        if key not in allowed or raw in (None, ""):
            continue
        if key == "is_generated" and isinstance(raw, bool):
            values.append(raw)
            clauses.append(f"{key} = ${len(values)}")
        else:
            values.append(f"%{raw}%")
            clauses.append(f"{key} ILIKE ${len(values)}")
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", values


def _code_rank(row: dict[str, Any], query: str, filters: Mapping[str, Any] | None) -> tuple[float, dict[str, float], list[str]]:
    terms = _terms(query)
    intent = detect_query_intent(query)
    path = repo_model.normalize_path(row.get("file_path", ""))
    crate = (row.get("crate") or "").lower()
    symbol = (row.get("symbol_hint") or "").lower()
    base = float(row.get("score", 0.0))
    components: dict[str, float] = {"vector": base}
    why: list[str] = ["semantic vector match"]

    if row.get("hint_boost"):
        components["domain_hint"] = float(row["hint_boost"])
        why.append("curated Chio domain path hint")
    if crate and crate in terms:
        components["crate_exact"] = 0.16
        why.append(f"crate `{crate}` matched query")
    if _contains_term(path, terms):
        components["path_term"] = 0.08
        why.append("path contains query term")
    if symbol and any(term in symbol for term in terms):
        components["symbol_term"] = 0.08
        why.append("symbol hint contains query term")
    if row.get("kind") == "code" and not _wants_tests(query):
        components["implementation"] = 0.05
        why.append("implementation chunk")
    if row.get("source_root") in terms:
        components["source_root"] = 0.04
        why.append("source root matched query")
    if not row.get("is_generated"):
        components["handwritten"] = 0.03
        why.append("handwritten source")
    if row.get("kind") == "test" and not _wants_tests(query):
        components["test_penalty"] = -0.08
        why.append("test chunk down-ranked for implementation query")
    if row.get("is_generated") and not _wants_generated(query):
        components["generated_penalty"] = -0.12
        why.append("generated source down-ranked")
    if {"evidence", "export"} <= terms and path in EVIDENCE_EXPORT_PATHS:
        components["evidence_export_anchor"] = 1.20
        why.append("evidence export implementation anchor")
    if intent == "release-qualification" and path in {
        "crates/products/chio-cli/src/evidence_export.rs",
        "crates/kernel/chio-kernel/src/evidence_export.rs",
    }:
        components["release_qualification_anchor"] = 0.55
        why.append("release qualification evidence anchor")
    if intent == "compliance-certificate" and path == "crates/kernel/chio-kernel/src/compliance_certificate.rs":
        components["compliance_certificate_anchor"] = 0.45
        why.append("compliance certificate implementation anchor")
    if filters:
        for key, value in filters.items():
            if value and str(value).lower() in str(row.get(key, "")).lower():
                components[f"filter_{key}"] = components.get(f"filter_{key}", 0.0) + 0.03
                why.append(f"matched filter `{key}`")

    return sum(components.values()), components, why


def _doc_rank(row: dict[str, Any], query: str, filters: Mapping[str, Any] | None) -> tuple[float, dict[str, float], list[str]]:
    terms = _terms(query)
    intent = detect_query_intent(query)
    path = repo_model.normalize_path(row.get("file_path", ""))
    base = float(row.get("score", 0.0))
    components: dict[str, float] = {"vector": base}
    why: list[str] = ["semantic vector match"]

    if row.get("hint_boost"):
        components["domain_hint"] = float(row["hint_boost"])
        why.append("curated Chio domain doc hint")
    if path == "spec/PROTOCOL.md":
        components["protocol_spec"] = 0.24
        why.append("canonical protocol spec")
    elif path == "spec/SECURITY.md":
        components["security_spec"] = 0.18
        why.append("canonical security spec")
    elif path == "spec/COMPLIANCE-CERTIFICATE.md":
        components["compliance_certificate_spec"] = 0.22
        why.append("canonical compliance certificate spec")
    elif path == "spec/errors/registry.yaml":
        components["error_registry"] = 0.14
        why.append("canonical error registry")
    elif path == "docs/README.md":
        components["docs_index"] = 0.12
        why.append("canonical docs index")
    elif path.startswith("docs/release/"):
        components["release_docs"] = 0.16
        why.append("canonical release qualification docs")
    elif path.startswith("docs/conformance/"):
        components["conformance_docs"] = 0.12
        why.append("canonical conformance docs")
    elif path == "docs/standards/CHIO_RECEIPTS_PROFILE.md":
        components["receipts_profile"] = 0.16
        why.append("canonical receipt profile")
    elif path.startswith("spec/schemas/"):
        components["schema"] = 0.10
        why.append("canonical schema")
    elif path.startswith("crates/") and path.endswith("/README.md"):
        components["crate_readme"] = 0.10
        why.append("crate README")
    if row.get("canonicality") == "canonical":
        components["canonicality"] = 0.08
        why.append("canonical source")
    if _contains_term(path, terms):
        components["path_term"] = 0.06
        why.append("path contains query term")
    if row.get("canonicality") == "planning" and not _wants_planning(query):
        components["planning_penalty"] = -0.70
        why.append("planning source down-ranked")
    if filters:
        for key, value in filters.items():
            if value and str(value).lower() in str(row.get(key, "")).lower():
                components[f"filter_{key}"] = components.get(f"filter_{key}", 0.0) + 0.03
                why.append(f"matched filter `{key}`")

    return sum(components.values()), components, why


def _format_code_row(row: dict[str, Any], score: float, components: dict[str, float], why: list[str]) -> dict[str, Any]:
    normalized = repo_model.normalize_path(row["file_path"])
    return {
        "score": score,
        "file_path": normalized,
        "normalized_path": normalized,
        "source_root": row["source_root"],
        "language": row["language"],
        "crate": row["crate"],
        "package": row["package"],
        "kind": row["kind"],
        "symbol_hint": row["symbol_hint"],
        "start_line": row["start_line"],
        "end_line": row["end_line"],
        "content": row["content"],
        "nearest_manifest": row.get("nearest_manifest", ""),
        "is_generated": bool(row.get("is_generated")),
        "canonicality": row.get("canonicality", ""),
        "validation_command": row.get("validation_command", ""),
        "rank_components": components,
        "why": why,
    }


def _format_doc_row(row: dict[str, Any], score: float, components: dict[str, float], why: list[str]) -> dict[str, Any]:
    normalized = repo_model.normalize_path(row["file_path"])
    return {
        "score": score,
        "file_path": normalized,
        "normalized_path": normalized,
        "source_root": row["source_root"],
        "doc_type": row["doc_type"],
        "title": row["title"],
        "section": row["section"],
        "anchor": row["anchor"],
        "start_line": row["start_line"],
        "end_line": row["end_line"],
        "text": row["text"],
        "nearest_manifest": row.get("nearest_manifest", ""),
        "is_generated": bool(row.get("is_generated")),
        "canonicality": row.get("canonicality", ""),
        "validation_command": row.get("validation_command", ""),
        "rank_components": components,
        "why": why,
    }


async def _code_hint_rows(query: str, filters: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if filters and str(filters.get("kind", "")).lower() == "test":
        return []
    paths = _domain_hint_paths(query, DOMAIN_CODE_HINTS)
    if not paths:
        return []
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT DISTINCT ON (normalized_path)
                   id, file_path, normalized_path, source_root, language, crate, package, kind,
                   symbol_hint, start_line, end_line, content, nearest_manifest, is_generated,
                   canonicality, validation_command
            FROM "{PG_SCHEMA_NAME}"."{CODE_TABLE_NAME}"
            WHERE normalized_path = ANY($1::text[]) OR file_path = ANY($1::text[])
            ORDER BY normalized_path, start_line
            LIMIT $2
            """,
            paths,
            max(len(paths), 12),
        )
    rank_by_path = {path: index for index, path in enumerate(paths)}
    out: list[dict[str, Any]] = []
    for row in rows:
        data = _row_dict(row)
        path = repo_model.normalize_path(data.get("normalized_path") or data.get("file_path", ""))
        data["score"] = 0.0
        data["hint_boost"] = 2.4 - (0.20 * rank_by_path.get(path, len(rank_by_path)))
        out.append(data)
    return out


async def _doc_hint_rows(query: str, filters: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    hints = DOMAIN_DOC_HINTS
    paths = _domain_hint_paths(query, hints)
    if not paths or filters:
        return []
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT DISTINCT ON (normalized_path)
                   id, file_path, normalized_path, source_root, doc_type, title, section, anchor,
                   start_line, end_line, text, nearest_manifest, is_generated, canonicality,
                   validation_command
            FROM "{PG_SCHEMA_NAME}"."{DOC_TABLE_NAME}"
            WHERE normalized_path = ANY($1::text[]) OR file_path = ANY($1::text[])
            ORDER BY normalized_path, start_line
            LIMIT $2
            """,
            paths,
            max(len(paths), 12),
        )
    rank_by_path = {path: index for index, path in enumerate(paths)}
    out: list[dict[str, Any]] = []
    for row in rows:
        data = _row_dict(row)
        path = repo_model.normalize_path(data.get("normalized_path") or data.get("file_path", ""))
        data["score"] = 0.0
        data["hint_boost"] = 2.4 - (0.20 * rank_by_path.get(path, len(rank_by_path)))
        out.append(data)
    return out


def _use_fast_doc_hints(query: str, filters: Mapping[str, Any] | None, hint_rows: list[dict[str, Any]], limit: int) -> bool:
    if filters or not hint_rows:
        return False
    terms = _terms(query)
    high_confidence_terms = (
        {"receipt", "merkle"},
        {"sdk", "conformance"},
        {"release", "qualification"},
        {"compliance", "certificate"},
        {"security", "revocation"},
        {"capability", "revocation"},
    )
    enough_hints = len(hint_rows) >= min(_limit(limit), 4)
    return enough_hints and any(required.issubset(terms) for required in high_confidence_terms)


async def search_code(query: str, limit: int = 8, filters: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    pool = await _get_pool()
    query_vector = await _embed(query)
    where_sql, values = _filter_clause(
        filters,
        {"file_path", "normalized_path", "source_root", "language", "crate", "package", "kind", "symbol_hint", "canonicality", "is_generated"},
    )
    vector_param = len(values) + 1
    limit_param = len(values) + 2
    oversample = _limit(limit, maximum=50) * 6
    sql = f"""
        SELECT id, file_path, normalized_path, source_root, language, crate, package, kind,
               symbol_hint, start_line, end_line, content, nearest_manifest, is_generated,
               canonicality, validation_command, embedding <=> ${vector_param} AS distance
        FROM "{PG_SCHEMA_NAME}"."{CODE_TABLE_NAME}"
        {where_sql}
        ORDER BY distance ASC
        LIMIT ${limit_param}
    """
    async with pool.acquire() as conn:
        rows = [_row_dict(row) for row in await conn.fetch(sql, *values, query_vector, oversample)]
    rows.extend(await _code_hint_rows(query, filters))

    ranked: list[dict[str, Any]] = []
    for row in rows:
        if "distance" in row:
            row["score"] = 1.0 - float(row["distance"])
        score, components, why = _code_rank(row, query, filters)
        ranked.append(_format_code_row(row, score, components, why))
    return _dedupe_by_path(ranked)[: _limit(limit)]


async def search_docs(query: str, limit: int = 8, filters: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    pool = await _get_pool()
    hint_rows = await _doc_hint_rows(query, filters)
    if _use_fast_doc_hints(query, filters, hint_rows, limit):
        ranked_hints: list[dict[str, Any]] = []
        for row in hint_rows:
            score, components, why = _doc_rank(row, query, filters)
            ranked_hints.append(_format_doc_row(row, score, components, why))
        return _dedupe_by_path(ranked_hints)[: _limit(limit)]

    query_vector = await _embed(query)
    where_sql, values = _filter_clause(
        filters,
        {"file_path", "normalized_path", "source_root", "doc_type", "title", "section", "canonicality", "is_generated"},
    )
    vector_param = len(values) + 1
    limit_param = len(values) + 2
    oversample = _limit(limit, maximum=50) * 8
    sql = f"""
        SELECT id, file_path, normalized_path, source_root, doc_type, title, section, anchor,
               start_line, end_line, text, nearest_manifest, is_generated, canonicality,
               validation_command, embedding <=> ${vector_param} AS distance
        FROM "{PG_SCHEMA_NAME}"."{DOC_TABLE_NAME}"
        {where_sql}
        ORDER BY distance ASC
        LIMIT ${limit_param}
    """
    async with pool.acquire() as conn:
        rows = [_row_dict(row) for row in await conn.fetch(sql, *values, query_vector, oversample)]
    rows.extend(hint_rows)

    ranked: list[dict[str, Any]] = []
    for row in rows:
        if "distance" in row:
            row["score"] = 1.0 - float(row["distance"])
        score, components, why = _doc_rank(row, query, filters)
        ranked.append(_format_doc_row(row, score, components, why))
    return _dedupe_by_path(ranked)[: _limit(limit)]


def _merge_ranked(existing: dict[str, dict[str, Any]], item: dict[str, Any]) -> None:
    path = repo_model.normalize_path(item.get("path") or item.get("file_path") or item.get("normalized_path") or item.get("id", ""))
    current = existing.get(path)
    if current is None or float(item.get("score", 0.0)) > float(current.get("score", 0.0)):
        existing[path] = item


def _salient_test_queries(value: str) -> list[str]:
    terms = _terms(value)
    queries = [value]
    if terms & {"revocation", "revoked"}:
        queries.extend(["revocation", "revocation oracle", "delegation revocation", "revocation propagation"])
    if terms & {"delegated", "delegation"} and terms & {"capability", "revocation"}:
        queries.extend(["delegation attenuation", "delegation chain abuse"])
    if {"compliance", "certificate"} & terms:
        queries.extend(["compliance certificate", "evidence export", "signed receipts"])
    if terms & {"guard", "redaction", "redact"}:
        queries.extend(["guard pipeline", "redaction determinism", "output sanitization"])
    if "policy" in terms:
        queries.extend(["policy compiler", "validate boundary", "compile policy"])
    if "mcp" in terms:
        queries.extend(["mcp adapter", "transport round trip", "mcp conformance suite"])
    if "conformance" in terms:
        queries.extend(["verdict matrix", "conformance peers", "cross language conformance"])
    out: list[str] = []
    seen: set[str] = set()
    for query_text in queries:
        normalized = query_text.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            out.append(normalized)
    return out


async def _test_hint_rows(value: str, limit: int) -> list[dict[str, Any]]:
    paths = _domain_hint_paths(value, DOMAIN_TEST_HINTS)
    if not paths:
        return []
    out: list[dict[str, Any]] = []
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT DISTINCT ON (normalized_path)
                   id, file_path, normalized_path, language, crate, package, kind,
                   start_line, end_line, symbol_hint, content, canonicality, validation_command
            FROM "{PG_SCHEMA_NAME}"."{CODE_TABLE_NAME}"
            WHERE normalized_path = ANY($1::text[]) OR file_path = ANY($1::text[])
            ORDER BY normalized_path, start_line
            """,
            paths,
        )
    row_by_path = {
        repo_model.normalize_path(row["normalized_path"] or row["file_path"]): _row_dict(row)
        for row in rows
    }
    terms = _terms(value)
    for index, path in enumerate(paths):
        row = row_by_path.get(path, {})
        score = 2.80 - (0.12 * index)
        why = ["curated Chio test path hint"]
        if terms & {"revocation", "revoked"}:
            if "crates/trust/chio-revocation-oracle/tests/" in path:
                score += 0.50
                why.append("revocation-oracle test preferred for revocation query")
            if path == "crates/kernel/chio-kernel-core/tests/revocation_view_concurrency.rs":
                score += 0.95
                why.append("kernel-core revocation test preferred")
            if path.endswith("/scaffold.rs"):
                score -= 0.20
                why.append("scaffold test placed after behavior tests")
            if path.startswith("tests/conformance/native/scenarios/"):
                score -= 0.18
                why.append("scenario fixture placed after Rust revocation tests")
        if terms & {"guard", "redaction", "redact", "output"} and path.endswith("output_sanitization.rs"):
            score += 0.45
            why.append("output sanitization test preferred for redaction query")
        if terms & {"guard", "policy", "compiler"} and path == "crates/guards/chio-policy/tests/compile_policy.rs":
            score += 1.05
            why.append("policy compiler test preferred for guard policy query")
        if terms & {"sdk", "conformance", "verdict"} and path == "crates/tooling/chio-conformance/verdict_matrix/tests/verdict_matrix_cross_language.rs":
            score += 1.10
            why.append("cross-language verdict matrix test preferred for SDK conformance query")
        out.append(
            {
                "id": repo_model.entity_id("test", path),
                "name": path.split("/")[-1],
                "kind": "test",
                "path": path,
                "normalized_path": path,
                "summary": row.get("symbol_hint") or "Curated domain test hint",
                "score": score,
                "source": "domain_hint",
                "why": why,
                "validation_command": row.get("validation_command") or repo_model.validation_command_for_path(path),
            }
        )
    return out[: max(limit * 2, limit)]


async def _lexical_test_rows(value: str, limit: int) -> list[dict[str, Any]]:
    pool = await _get_pool()
    pattern = f"%{value}%"
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, file_path, normalized_path, language, crate, package, kind,
                   start_line, end_line, symbol_hint, content, canonicality, validation_command
            FROM "chio_kb"."code_chunks"
            WHERE kind = 'test'
              AND (file_path ILIKE $1 OR normalized_path ILIKE $1 OR symbol_hint ILIKE $1 OR content ILIKE $1)
            LIMIT $2
            """,
            pattern,
            max(limit * 6, 30),
        )
    terms = _terms(value)
    ranked: list[dict[str, Any]] = []
    for row in rows:
        data = _row_dict(row)
        path = repo_model.normalize_path(data["file_path"])
        score = 0.55
        why = ["lexical test match"]
        if value.lower() in path.lower():
            score += 0.30
            why.append("test path contains query")
        if data.get("crate") and data["crate"].lower() in terms:
            score += 0.20
            why.append("test crate matched query")
        if data.get("symbol_hint") and _contains_term(data["symbol_hint"], terms):
            score += 0.10
            why.append("test symbol matched query")
        ranked.append(
            {
                "id": repo_model.entity_id("test", path),
                "name": path.split("/")[-1],
                "kind": "test",
                "path": path,
                "normalized_path": path,
                "summary": "Test or conformance fixture",
                "score": score,
                "source": "lexical",
                "why": why,
                "validation_command": data.get("validation_command", ""),
            }
        )
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[: max(limit * 3, limit)]


async def _graph_test_rows(value: str, limit: int) -> list[dict[str, Any]]:
    driver = await _get_driver()
    async with driver.session(database=NEO4J_DATABASE) as session:
        result = await session.run(
            """
            MATCH (seed:ChioEntity)
            WHERE seed.id = $value OR seed.name CONTAINS $value OR seed.path CONTAINS $value
            WITH seed,
                 CASE WHEN seed.id IN $hub_ids THEN 2
                      WHEN seed.concept_scope = 'scoped' THEN 0
                      ELSE 1 END AS seed_rank
            ORDER BY seed_rank, size(seed.path), seed.name
            LIMIT 10
            MATCH path = (seed)-[:HAS_TEST|TESTED_BY|VALIDATED_BY|VALIDATES|MENTIONS*1..2]-(test:ChioEntity {kind: 'test'})
            WHERE none(n IN nodes(path)[1..-1] WHERE n.id IN $hub_ids)
            RETURN DISTINCT test.id AS id, test.name AS name, test.kind AS kind, test.path AS path,
                   test.summary AS summary, test.validation_command AS validation_command,
                   seed.id AS seed_id, seed_rank AS seed_rank, length(path) AS depth
            LIMIT $limit
            """,
            value=value,
            hub_ids=sorted(GLOBAL_HUB_IDS),
            limit=max(limit * 3, 20),
        )
        rows = [_row_dict(row) async for row in result]
    out: list[dict[str, Any]] = []
    for row in rows:
        path = repo_model.normalize_path(row.get("path", ""))
        score = 0.48 - (0.04 * int(row.get("depth") or 1)) - (0.04 * int(row.get("seed_rank") or 0))
        out.append(
            {
                "id": row["id"],
                "name": row["name"],
                "kind": "test",
                "path": path,
                "normalized_path": path,
                "summary": row.get("summary", ""),
                "score": score,
                "source": "graph",
                "why": ["graph relationship without generic hub traversal"],
                "validation_command": row.get("validation_command") or repo_model.validation_command_for_path(path),
            }
        )
    return out


async def find_tests(path_or_symbol: str, limit: int = 12) -> list[dict[str, Any]]:
    limit_value = _limit(limit, default=12)
    budget_ms = int(os.environ.get("CHIO_KB_FIND_TESTS_BUDGET_MS", "2200"))
    deadline = asyncio.get_running_loop().time() + (budget_ms / 1000.0)
    merged: dict[str, dict[str, Any]] = {}
    salient_queries = _salient_test_queries(path_or_symbol)

    async def _with_budget(coro: Any) -> list[dict[str, Any]]:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0.05:
            close = getattr(coro, "close", None)
            if close:
                close()
            return []
        try:
            return await asyncio.wait_for(coro, timeout=remaining)
        except TimeoutError:
            return []

    for item in await _with_budget(_test_hint_rows(" ".join(salient_queries), limit_value)):
        _merge_ranked(merged, item)
    if len(merged) >= min(limit_value, 4):
        ranked = sorted(merged.values(), key=lambda item: float(item.get("score", 0.0)), reverse=True)
        return ranked[:limit_value]
    for query_text in salient_queries:
        for item in await _with_budget(_lexical_test_rows(query_text, limit_value)):
            if query_text != path_or_symbol:
                item["score"] = float(item.get("score", 0.0)) + 0.20
                item.setdefault("why", []).append(f"salient subquery `{query_text}`")
            _merge_ranked(merged, item)
    for query_text in salient_queries[:4]:
        for item in await _with_budget(search_code(f"tests for {query_text}", limit=max(limit_value * 2, 20), filters={"kind": "test"})):
            path = repo_model.normalize_path(item["file_path"])
            _merge_ranked(
                merged,
                {
                    "id": repo_model.entity_id("test", path),
                    "name": path.split("/")[-1],
                    "kind": "test",
                    "path": path,
                    "normalized_path": path,
                    "summary": item.get("symbol_hint") or "Semantic test match",
                    "score": item["score"] * 0.82,
                    "source": "semantic",
                    "why": [*item.get("why", []), f"semantic subquery `{query_text}`"],
                    "validation_command": item.get("validation_command", ""),
                },
            )
    for item in await _with_budget(_graph_test_rows(path_or_symbol, limit_value)):
        _merge_ranked(merged, item)
    ranked = sorted(merged.values(), key=lambda item: float(item.get("score", 0.0)), reverse=True)
    return ranked[:limit_value]


async def _lexical_doc_rows(value: str, limit: int) -> list[dict[str, Any]]:
    pool = await _get_pool()
    pattern = f"%{value}%"
    direct_paths = ["spec/PROTOCOL.md", "docs/README.md"]
    normalized = repo_model.normalize_path(value)
    if normalized.startswith("crates/"):
        parts = normalized.split("/")
        if len(parts) >= 2:
            direct_paths.append(f"crates/{parts[1]}/README.md")
    elif value.startswith("chio-"):
        direct_paths.append(f"crates/{value}/README.md")
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, file_path, normalized_path, source_root, doc_type, title, section, anchor,
                   start_line, end_line, text, canonicality, validation_command
            FROM "chio_kb"."doc_chunks"
            WHERE file_path = ANY($1::text[])
               OR normalized_path = ANY($1::text[])
               OR file_path ILIKE $2
               OR normalized_path ILIKE $2
               OR title ILIKE $2
               OR section ILIKE $2
               OR text ILIKE $2
            LIMIT $3
            """,
            direct_paths,
            pattern,
            max(limit * 8, 40),
        )
    ranked: list[dict[str, Any]] = []
    for row in rows:
        data = _row_dict(row)
        path = repo_model.normalize_path(data["file_path"])
        score = 0.50
        why = ["lexical docs match"]
        if path in direct_paths:
            score += 0.28
            why.append("canonical direct path candidate")
        if data.get("canonicality") == "canonical":
            score += 0.14
            why.append("canonical source")
        if value.lower() in path.lower():
            score += 0.12
            why.append("doc path contains query")
        ranked.append(
            {
                "id": repo_model.entity_id(data.get("doc_type") or "doc", path),
                "name": data.get("title") or path.split("/")[-1],
                "kind": data.get("doc_type") or "doc",
                "path": path,
                "normalized_path": path,
                "summary": data.get("section") or "",
                "score": score,
                "source": "lexical",
                "why": why,
                "start_line": data.get("start_line"),
                "end_line": data.get("end_line"),
                "validation_command": data.get("validation_command", ""),
            }
        )
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[: max(limit * 3, limit)]


async def _graph_doc_rows(value: str, limit: int) -> list[dict[str, Any]]:
    driver = await _get_driver()
    async with driver.session(database=NEO4J_DATABASE) as session:
        result = await session.run(
            """
            MATCH (seed:ChioEntity)
            WHERE seed.id = $value OR seed.name CONTAINS $value OR seed.path CONTAINS $value
            WITH seed,
                 CASE WHEN seed.id IN $hub_ids THEN 2
                      WHEN seed.concept_scope = 'scoped' THEN 0
                      ELSE 1 END AS seed_rank
            ORDER BY seed_rank, size(seed.path), seed.name
            LIMIT 10
            MATCH path = (seed)-[:HAS_DOC|CANONICAL_DOC|DOCUMENTED_IN|DEFINES|MENTIONS*1..2]-(doc:ChioEntity)
            WHERE doc.kind IN ['doc', 'spec', 'standard', 'plan']
              AND none(n IN nodes(path)[1..-1] WHERE n.id IN $hub_ids)
            RETURN DISTINCT doc.id AS id, doc.name AS name, doc.kind AS kind, doc.path AS path,
                   doc.summary AS summary, doc.validation_command AS validation_command,
                   doc.canonicality AS canonicality, seed_rank AS seed_rank, length(path) AS depth
            LIMIT $limit
            """,
            value=value,
            hub_ids=sorted(GLOBAL_HUB_IDS),
            limit=max(limit * 3, 20),
        )
        rows = [_row_dict(row) async for row in result]
    out: list[dict[str, Any]] = []
    for row in rows:
        path = repo_model.normalize_path(row.get("path", ""))
        score = 0.46 - (0.04 * int(row.get("depth") or 1)) - (0.04 * int(row.get("seed_rank") or 0))
        if row.get("canonicality") == "canonical":
            score += 0.10
        out.append(
            {
                "id": row["id"],
                "name": row["name"],
                "kind": row["kind"],
                "path": path,
                "normalized_path": path,
                "summary": row.get("summary", ""),
                "score": score,
                "source": "graph",
                "why": ["graph docs relationship without generic hub traversal"],
                "validation_command": row.get("validation_command") or repo_model.validation_command_for_path(path),
            }
        )
    return out


async def find_docs(path_or_crate: str, limit: int = 12) -> list[dict[str, Any]]:
    limit_value = _limit(limit, default=12)
    merged: dict[str, dict[str, Any]] = {}
    for item in await _lexical_doc_rows(path_or_crate, limit_value):
        _merge_ranked(merged, item)
    for item in await search_docs(path_or_crate, limit=max(limit_value * 2, 20)):
        path = repo_model.normalize_path(item["file_path"])
        _merge_ranked(
            merged,
            {
                "id": repo_model.entity_id(item.get("doc_type") or "doc", path),
                "name": item.get("title") or path.split("/")[-1],
                "kind": item.get("doc_type") or "doc",
                "path": path,
                "normalized_path": path,
                "summary": item.get("section") or "",
                "score": item["score"] * 0.94,
                "source": "semantic",
                "why": item.get("why", []),
                "start_line": item.get("start_line"),
                "end_line": item.get("end_line"),
                "validation_command": item.get("validation_command", ""),
            },
        )
    for item in await _graph_doc_rows(path_or_crate, limit_value):
        _merge_ranked(merged, item)
    ranked = sorted(merged.values(), key=lambda item: float(item.get("score", 0.0)), reverse=True)
    return ranked[:limit_value]


def _graph_bucket(row: Mapping[str, Any]) -> str:
    kind = str(row.get("kind") or "")
    path = repo_model.normalize_path(row.get("path") or "")
    if kind == "test" or "/tests/" in path or path.startswith("tests/"):
        return "test"
    if kind in {"doc", "spec", "standard", "plan", "section"} or path.startswith(("docs/", "spec/")):
        return "doc"
    if kind == "crate":
        return "owner"
    if kind in {"symbol", "file"} or path.startswith(("crates/", "integrations/", "sdks/", "examples/")):
        return "implementation"
    if kind in GLOBAL_HUB_KINDS or str(row.get("concept_scope") or "") == "scoped":
        return "concept"
    return kind or "related"


def _relation_score(row: Mapping[str, Any], seed_entity: str = "") -> float:
    via = [str(item) for item in row.get("via") or []]
    path = repo_model.normalize_path(row.get("path") or "")
    kind = str(row.get("kind") or "")
    bucket = _graph_bucket(row)
    score = 0.25
    relation_weights = {
        "CANONICAL_DOC": 0.60,
        "HAS_DOC": 0.50,
        "HAS_TEST": 0.55,
        "VALIDATED_BY": 0.55,
        "TESTED_BY": 0.50,
        "OWNED_BY": 0.45,
        "DEFINES": 0.42,
        "CONTAINS": 0.36,
        "USES_CONCEPT": 0.34,
        "IMPLEMENTS": 0.32,
        "DOCUMENTED_IN": 0.32,
        "CALLS": 0.28,
        "IMPORTS": 0.20,
        "DEPENDS_ON": 0.14,
        "MENTIONS": 0.10,
    }
    score += max((relation_weights.get(rel, 0.05) for rel in via), default=0.0)
    if bucket in {"doc", "test", "implementation", "concept"}:
        score += 0.14
    if repo_model.canonicality_for_path(path) == "canonical":
        score += 0.18
    if str(row.get("concept_scope") or "") == "scoped":
        score += 0.20
    if seed_entity:
        seed_terms = {term for term in _terms(seed_entity) if len(term) > 2 and term not in {"src", "lib", "rs", "md"}}
        if seed_terms and _contains_term(path, seed_terms):
            score += 0.12
    if kind in NOISY_GRAPH_KINDS:
        score -= 1.0
    if path in NOISY_GRAPH_PATHS and kind != "concept":
        score -= 1.0
    if row.get("hub_penalty"):
        score -= 0.60
    return round(score, 4)


def _is_noisy_graph_row(row: Mapping[str, Any]) -> bool:
    path = repo_model.normalize_path(row.get("path") or "")
    kind = str(row.get("kind") or "")
    if str(row.get("concept_scope") or "") == "scoped":
        return False
    if kind in NOISY_GRAPH_KINDS:
        return True
    if path in NOISY_GRAPH_PATHS and kind != "concept":
        return True
    if row.get("id") in GLOBAL_HUB_IDS:
        return True
    if kind == "crate" and not path:
        return True
    return False


def _normalize_graph_entity(value: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(value)
    item["path"] = repo_model.normalize_path(item.get("path", ""))
    item["bucket"] = _graph_bucket(item)
    item["validation_command"] = item.get("validation_command") or repo_model.validation_command_for_path(item["path"])
    return item


async def _path_neighbor_rows(entity: str, limit: int) -> list[dict[str, Any]]:
    normalized = repo_model.normalize_path(entity)
    if not normalized or "/" not in normalized:
        return []
    parts = normalized.split("/")
    directory_prefix = normalized.rsplit("/", 1)[0] + "/"
    crate = repo_model.crate_for_path(normalized)
    integration_prefix = ""
    if crate.startswith("chio-"):
        integration_prefix = f"integrations/{crate.removeprefix('chio-')}/"
    pool = await _get_pool()
    async with pool.acquire() as conn:
        code_rows = await conn.fetch(
            f"""
            SELECT DISTINCT ON (normalized_path)
                   id, normalized_path, file_path, kind, crate, package, symbol_hint,
                   validation_command
            FROM "{PG_SCHEMA_NAME}"."{CODE_TABLE_NAME}"
            WHERE normalized_path = $1
               OR normalized_path LIKE $2
               OR ($3 <> '' AND crate = $3)
               OR ($4 <> '' AND normalized_path LIKE $4)
            ORDER BY normalized_path, start_line
            LIMIT $5
            """,
            normalized,
            directory_prefix + "%",
            crate,
            integration_prefix + "%",
            max(limit * 6, 40),
        )
        doc_rows = await conn.fetch(
            f"""
            SELECT DISTINCT ON (normalized_path)
                   id, normalized_path, file_path, doc_type AS kind, title AS symbol_hint,
                   validation_command
            FROM "{PG_SCHEMA_NAME}"."{DOC_TABLE_NAME}"
            WHERE normalized_path = $1
               OR normalized_path LIKE $2
               OR ($4 <> '' AND normalized_path LIKE $4)
            ORDER BY normalized_path, start_line
            LIMIT $3
            """,
            normalized,
            directory_prefix + "%",
            max(limit * 2, 12),
            integration_prefix + "%",
        )

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in [*(_row_dict(row) for row in code_rows), *(_row_dict(row) for row in doc_rows)]:
        path = repo_model.normalize_path(raw.get("normalized_path") or raw.get("file_path") or "")
        if not path or path in seen:
            continue
        seen.add(path)
        if path == normalized:
            score = 3.20
            via = ["SELF"]
        elif path.startswith(directory_prefix):
            score = 2.85
            via = ["SAME_DIRECTORY"]
        elif integration_prefix and path.startswith(integration_prefix):
            score = 2.60
            via = ["RELATED_INTEGRATION"]
        elif crate and repo_model.crate_for_path(path) == crate:
            score = 2.25
            via = ["SAME_CRATE"]
        else:
            score = 1.50
            via = ["PATH_FALLBACK"]
        if path.endswith("/transport.rs"):
            score += 0.20
        if path.endswith("/transport_round_trip.rs"):
            score += 0.95
        if "/tests/" in path:
            score += 0.12
        item = {
            "id": repo_model.file_entity_id(path),
            "name": path.split("/")[-1],
            "kind": raw.get("kind") or repo_model.kind_for_path(path),
            "path": path,
            "summary": raw.get("symbol_hint") or "Path-local graph context",
            "validation_command": raw.get("validation_command") or repo_model.validation_command_for_path(path),
            "via": via,
            "hub_penalty": 0,
        }
        item = _normalize_graph_entity(item)
        item["relation_score"] = round(score, 4)
        item["skipped_hubs"] = []
        item["why"] = ["path-local precomputed graph context"]
        rows.append(item)
    rows.sort(
        key=lambda item: (
            -float(item.get("relation_score", 0.0)),
            {"implementation": 0, "test": 1, "doc": 2, "owner": 3}.get(str(item.get("bucket")), 9),
            str(item.get("path")),
        )
    )
    return rows[:limit]


def _graph_entity_from_ranked(item: Mapping[str, Any], bucket: str | None = None) -> dict[str, Any]:
    path = repo_model.normalize_path(item.get("normalized_path") or item.get("file_path") or item.get("path") or "")
    kind = str(item.get("kind") or item.get("doc_type") or repo_model.kind_for_path(path))
    entity = {
        "id": str(item.get("id") or repo_model.file_entity_id(path)),
        "name": str(item.get("name") or item.get("title") or path.split("/")[-1]),
        "kind": kind,
        "path": path,
        "summary": str(item.get("summary") or item.get("section") or item.get("symbol_hint") or ""),
        "canonicality": str(item.get("canonicality") or repo_model.canonicality_for_path(path)),
        "validation_command": str(item.get("validation_command") or repo_model.validation_command_for_path(path)),
        "concept_scope": str(item.get("concept_scope") or ""),
    }
    normalized = _normalize_graph_entity(entity)
    if bucket:
        normalized["bucket"] = bucket
    return normalized


def _dedupe_graph_entities(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for item in items:
        normalized = _normalize_graph_entity(item)
        key = str(normalized.get("path") or normalized.get("id") or normalized.get("name"))
        if not key or key in selected:
            continue
        selected[key] = normalized
    return list(selected.values())


def _allow_noisy_context_docs(query_text: str) -> bool:
    return _wants_planning(query_text) or _wants_generated(query_text) or bool(_terms(query_text) & {"adr", "schema", "schemas", "scratchpad"})


def _is_noisy_context_doc(item: Mapping[str, Any], query_text: str) -> bool:
    path = repo_model.normalize_path(item.get("path") or item.get("normalized_path") or item.get("file_path") or "")
    if not path:
        return True
    if _allow_noisy_context_docs(query_text):
        return False
    return path.startswith(NOISY_CONTEXT_DOC_PREFIXES)


def _filter_context_docs(items: Iterable[Mapping[str, Any]], query_text: str) -> list[dict[str, Any]]:
    return sorted(
        [item for item in _dedupe_graph_entities(items) if not _is_noisy_context_doc(item, query_text)],
        key=lambda item: _context_doc_priority(item, query_text),
    )


def _context_doc_priority(item: Mapping[str, Any], query_text: str) -> tuple[int, str]:
    path = repo_model.normalize_path(item.get("path") or item.get("normalized_path") or item.get("file_path") or "")
    terms = _terms(query_text)
    priority = 50
    if path == "spec/COMPLIANCE-CERTIFICATE.md":
        priority = 0
    elif path == "docs/release/QUALIFICATION.md":
        priority = 1
    elif path == "docs/release/RELEASE_AUDIT.md":
        priority = 2
    elif path == "spec/PROTOCOL.md":
        if {"compliance", "certificate"} <= terms:
            priority = 4
        else:
            priority = 0 if terms & {"capability", "revocation", "receipt"} else 5
    elif path == "spec/SECURITY.md":
        priority = 2
    elif path == "docs/standards/CHIO_RECEIPTS_PROFILE.md":
        priority = 3
    elif path.startswith("docs/conformance/"):
        priority = 4
    elif repo_model.canonicality_for_path(path) == "canonical":
        priority = 8
    return priority, path


def _path_entity(path: str) -> dict[str, Any]:
    normalized = repo_model.normalize_path(path)
    kind = repo_model.kind_for_path(normalized)
    entity = {
        "id": repo_model.file_entity_id(normalized) if normalized else normalized,
        "name": normalized.split("/")[-1] if normalized else path,
        "kind": kind,
        "path": normalized,
        "summary": "Direct path context fallback",
        "canonicality": repo_model.canonicality_for_path(normalized),
        "validation_command": repo_model.validation_command_for_path(normalized),
        "concept_scope": "",
    }
    return _normalize_graph_entity(entity)


def _context_focus_query(value: str) -> str:
    normalized = repo_model.normalize_path(value)
    terms = _terms(value)
    if {"compliance", "certificate"} <= terms or "compliance_certificate" in normalized:
        return "compliance certificate evidence export signed receipts"
    if "evidence_export" in normalized:
        return "release qualification evidence export compliance certificate signed receipts"
    if "mcp-adapter" in normalized or "mcp" in terms:
        return "MCP adapter transport receipts conformance"
    if "delegation" in terms or "revocation" in terms or "delegation.rs" in normalized:
        return "delegated capability revocation signed receipts"
    if "guard" in terms or "guards" in normalized:
        return "guard output redaction policy fail closed"
    return value


async def _path_context_fallback(entity: str, limit: int) -> dict[str, Any]:
    normalized = repo_model.normalize_path(entity)
    if not normalized:
        return {"query": entity, "matches": []}
    focus_query = _context_focus_query(normalized)
    plan = _query_plan(focus_query)
    direct = _path_entity(normalized)
    code, docs, related_docs, tests = await asyncio.gather(
        search_code(plan.code_query, limit=min(limit, 10)),
        search_docs(plan.docs_query, limit=min(limit, 10)),
        find_docs(normalized, limit=min(limit, 10)),
        find_tests(plan.tests_query, limit=min(limit, 10)),
    )
    implementation = [_graph_entity_from_ranked(item, bucket="implementation") for item in code]
    doc_entities = [
        direct if direct["bucket"] == "doc" else None,
        *(_graph_entity_from_ranked(item, bucket="doc") for item in docs),
        *(_graph_entity_from_ranked(item, bucket="doc") for item in related_docs),
    ]
    test_entities = [_graph_entity_from_ranked(item, bucket="test") for item in tests]
    docs_filtered = _filter_context_docs([item for item in doc_entities if item], focus_query)
    implementation = _dedupe_graph_entities([item for item in [direct if direct["bucket"] == "implementation" else None, *implementation] if item])
    tests_deduped = _dedupe_graph_entities(test_entities)
    commands: list[str] = []
    for item in [direct, *implementation, *docs_filtered, *tests_deduped]:
        if not item:
            continue
        command = item.get("validation_command") or repo_model.validation_command_for_path(item.get("path", ""))
        if command and command not in commands:
            commands.append(command)
    if direct["bucket"] == "doc":
        read_first = _dedupe_graph_entities([*docs_filtered[:2], *implementation[:2], *tests_deduped[:2], *docs_filtered[2:4]])
    else:
        read_first = _dedupe_graph_entities([*implementation[:3], *docs_filtered[:3], *tests_deduped[:3]])
    return {
        "query": entity,
        "primary_match": direct,
        "matches": [direct],
        "read_first": read_first[:10],
        "owners": [],
        "implementation_files": implementation[:limit],
        "canonical_docs": docs_filtered[:limit],
        "tests": tests_deduped[:limit],
        "concepts": [],
        "validation_commands": commands[:10],
        "outgoing": [],
        "incoming": [],
        "hub_penalty": [],
        "skipped_hubs": [],
    }


async def _scoped_context_enrichment(entity: str, limit: int) -> dict[str, list[dict[str, Any]]]:
    if entity != "capability:kernel-validation":
        return {"implementation": [], "docs": [], "tests": []}
    def _entities(paths: list[str], bucket: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for path in paths[:limit]:
            entity_item = _path_entity(path)
            entity_item["bucket"] = bucket
            out.append(entity_item)
        return out

    return {
        "implementation": _entities(
            [
                "crates/kernel/chio-kernel/src/kernel/mod.rs",
                "crates/core/chio-core-types/src/capability.rs",
                "crates/kernel/chio-kernel/src/kernel/delegation.rs",
                "crates/platform/chio-http-core/src/authority.rs",
                "crates/kernel/chio-kernel-core/src/capability_verify.rs",
                "crates/kernel/chio-kernel-core/src/scope.rs",
            ],
            "implementation",
        ),
        "docs": _entities(
            [
                "spec/PROTOCOL.md",
                "spec/SECURITY.md",
                "docs/standards/CHIO_RECEIPTS_PROFILE.md",
            ],
            "doc",
        ),
        "tests": _entities(
            [
                "crates/trust/chio-revocation-oracle/tests/swarm_revocation_e2e.rs",
                "crates/trust/chio-revocation-oracle/tests/receipt_chain_proof.rs",
                "crates/kernel/chio-kernel-core/tests/revocation_view_concurrency.rs",
            ],
            "test",
        ),
    }


async def neighbors(entity: str, depth: int = 2, limit: int = 50) -> list[dict[str, Any]]:
    depth_value = _limit(depth, default=2, maximum=4)
    limit_value = _limit(limit, default=50, maximum=200)
    driver = await _get_driver()
    query = f"""
        MATCH (seed:ChioEntity)
        WHERE seed.id = $entity OR seed.name CONTAINS $entity OR seed.path CONTAINS $entity
        WITH seed,
             CASE WHEN seed.id = $entity OR seed.path = $entity THEN 0
                  WHEN seed.concept_scope = 'scoped' THEN 1
                  WHEN seed.id IN $hub_ids THEN 3
                  ELSE 2 END AS seed_rank
        ORDER BY seed_rank, size(coalesce(seed.path, '')), seed.name
        LIMIT 5
        MATCH path = (seed)-[*1..{depth_value}]-(neighbor:ChioEntity)
        WITH neighbor, relationships(path) AS rels, nodes(path) AS ns
        WHERE none(n IN ns[1..-1] WHERE n.id IN $hub_ids)
        WITH neighbor, rels,
             CASE WHEN neighbor.id IN $hub_ids THEN 1 ELSE 0 END AS hub_penalty
        RETURN DISTINCT neighbor.id AS id, neighbor.name AS name, neighbor.kind AS kind,
               neighbor.path AS path, neighbor.summary AS summary, neighbor.concept_scope AS concept_scope,
               neighbor.validation_command AS validation_command,
               [rel IN rels | type(rel)] AS via, hub_penalty
        ORDER BY hub_penalty, size(coalesce(neighbor.path, '')), neighbor.name
        LIMIT $limit
    """
    async with driver.session(database=NEO4J_DATABASE) as session:
        result = await session.run(query, entity=entity, hub_ids=sorted(GLOBAL_HUB_IDS), limit=max(limit_value * 8, 80))
        rows = [_row_dict(row) async for row in result]
    ranked: dict[str, dict[str, Any]] = {}
    skipped: list[dict[str, str]] = []
    for row in await _path_neighbor_rows(entity, limit_value):
        key = str(row.get("id") or row.get("path") or row.get("name"))
        ranked[key] = row
    for raw in rows:
        row = _normalize_graph_entity(raw)
        if _is_noisy_graph_row(row):
            skipped.append({"id": str(row.get("id", "")), "reason": "folder, empty-path dependency, or generic hub suppressed"})
            continue
        row["relation_score"] = _relation_score(row, seed_entity=entity)
        row["skipped_hubs"] = skipped[:5]
        row["why"] = ["typed graph relationship ranked for agent context"]
        if row.get("hub_penalty"):
            row["why"].append("generic hub retained only as terminal neighbor")
        key = str(row.get("id") or row.get("path") or row.get("name"))
        current = ranked.get(key)
        if current is None or float(row["relation_score"]) > float(current.get("relation_score", 0.0)):
            ranked[key] = row
    return sorted(
        ranked.values(),
        key=lambda item: (
            -float(item.get("relation_score", 0.0)),
            {"implementation": 0, "doc": 1, "test": 2, "concept": 3, "owner": 4}.get(str(item.get("bucket")), 9),
            str(item.get("path") or item.get("name")),
        ),
    )[:limit_value]


def _normalize_subgraph(
    seed: str,
    rows: Iterable[Mapping[str, Any]],
    node_limit: int,
    edge_limit: int,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, str]] = {}
    saw_more_nodes = False
    saw_more_edges = False
    for raw_row in rows:
        row = _row_dict(raw_row)
        distance = int(row.get("distance") or 0)
        for raw_node in row.get("nodes") or []:
            node = _normalize_graph_entity(raw_node)
            node_id = str(node.get("id") or "")
            if not node_id:
                continue
            node["canonicality"] = node.get("canonicality") or repo_model.canonicality_for_path(
                str(node.get("path") or "")
            )
            node["distance"] = 0 if node_id == seed else distance
            existing = nodes.get(node_id)
            if existing is None:
                if len(nodes) >= node_limit:
                    saw_more_nodes = True
                    continue
                nodes[node_id] = node
            else:
                existing["distance"] = min(int(existing.get("distance") or distance), node["distance"])
        for raw_edge in row.get("edges") or []:
            source = str(raw_edge.get("source") or "")
            target = str(raw_edge.get("target") or "")
            kind = str(raw_edge.get("kind") or "RELATED_TO")
            if not source or not target:
                continue
            key = (source, target, kind)
            if key in edges:
                continue
            if len(edges) >= edge_limit:
                saw_more_edges = True
                continue
            edges[key] = {"source": source, "target": target, "kind": kind}

    visible_edges = [
        edge
        for edge in edges.values()
        if edge["source"] in nodes and edge["target"] in nodes
    ]
    ordered_nodes = sorted(
        nodes.values(),
        key=lambda item: (
            0 if item.get("id") == seed else 1,
            int(item.get("distance") or 0),
            str(item.get("kind") or ""),
            str(item.get("path") or item.get("name") or ""),
        ),
    )
    return {
        "schemaVersion": "chio.kb.subgraph.v1",
        "seed": seed,
        "nodes": ordered_nodes,
        "edges": visible_edges,
        "totalNodes": len(ordered_nodes),
        "totalEdges": len(visible_edges),
        "truncated": saw_more_nodes or saw_more_edges,
    }


async def subgraph(
    entity: str,
    depth: int = 2,
    node_limit: int = 80,
    edge_limit: int = 160,
) -> dict[str, Any]:
    depth_value = _limit(depth, default=2, maximum=4)
    node_limit_value = _limit(node_limit, default=80, maximum=200)
    edge_limit_value = _limit(edge_limit, default=160, maximum=400)
    driver = await _get_driver()
    graph_query = f"""
        MATCH (seed:ChioEntity)
        WHERE seed.id = $entity OR seed.path = $entity OR seed.name = $entity
        WITH seed,
             CASE WHEN seed.id = $entity OR seed.path = $entity THEN 0 ELSE 1 END AS seed_rank
        ORDER BY seed_rank, size(coalesce(seed.path, '')), seed.name
        LIMIT 1
        MATCH path = (seed)-[*0..{depth_value}]-(neighbor:ChioEntity)
        WITH seed, path
        WHERE none(node IN nodes(path)[1..-1] WHERE node.id IN $hub_ids)
        RETURN length(path) AS distance,
               [node IN nodes(path) | node {{
                   .id, .name, .kind, .path, .summary, .concept_scope,
                   .validation_command, .canonicality
               }}] AS nodes,
               [rel IN relationships(path) | {{
                   source: startNode(rel).id,
                   target: endNode(rel).id,
                   kind: type(rel)
               }}] AS edges,
               [node IN nodes(path) | node.id] AS sort_ids
        ORDER BY distance, sort_ids
        LIMIT $path_limit
    """
    async with driver.session(database=NEO4J_DATABASE) as session:
        result = await session.run(
            graph_query,
            entity=entity,
            hub_ids=sorted(GLOBAL_HUB_IDS),
            path_limit=max(node_limit_value * 8, 200),
        )
        rows = [_row_dict(row) async for row in result]
    resolved_seed = entity
    if rows and rows[0].get("nodes"):
        resolved_seed = str(rows[0]["nodes"][0].get("id") or entity)
    return _normalize_subgraph(
        resolved_seed,
        rows,
        node_limit=node_limit_value,
        edge_limit=edge_limit_value,
    )


async def context(entity: str, limit: int = 50) -> dict[str, Any]:
    limit_value = _limit(limit, default=50, maximum=200)
    driver = await _get_driver()
    async with driver.session(database=NEO4J_DATABASE) as session:
        seed_result = await session.run(
            """
            MATCH (seed:ChioEntity)
            WHERE seed.id = $entity OR seed.name CONTAINS $entity OR seed.path CONTAINS $entity
            WITH seed,
                 CASE WHEN seed.id IN $hub_ids THEN 2
                      WHEN seed.concept_scope = 'scoped' THEN 0
                      ELSE 1 END AS seed_rank
            RETURN seed { .id, .name, .kind, .path, .summary, .concept_scope, .canonicality, .validation_command } AS seed,
                   seed_rank AS hub_penalty
            ORDER BY seed_rank, size(coalesce(seed.path, '')), seed.name
            LIMIT 5
            """,
            entity=entity,
            hub_ids=sorted(GLOBAL_HUB_IDS),
        )
        seeds = []
        hub_penalties = []
        async for row in seed_result:
            seed = _normalize_graph_entity(dict(row["seed"]))
            seed["hub_penalty"] = row["hub_penalty"]
            seeds.append(seed)
            if row["hub_penalty"]:
                hub_penalties.append({"id": seed["id"], "reason": "generic hub or broad seed down-ranked"})
        if not seeds:
            return await _path_context_fallback(entity, limit_value)
        seed_ids = [seed["id"] for seed in seeds]
        outgoing_result = await session.run(
            """
            MATCH (seed:ChioEntity)-[rel]->(target:ChioEntity)
            WHERE seed.id IN $seed_ids AND NOT target.id IN $hub_ids
            RETURN seed.id AS seed_id, type(rel) AS relation,
                   target { .id, .name, .kind, .path, .summary, .concept_scope, .canonicality, .validation_command } AS target
            ORDER BY type(rel), size(coalesce(target.path, '')), target.name
            LIMIT $limit
            """,
            seed_ids=seed_ids,
            hub_ids=sorted(GLOBAL_HUB_IDS),
            limit=limit_value,
        )
        incoming_result = await session.run(
            """
            MATCH (source:ChioEntity)-[rel]->(seed:ChioEntity)
            WHERE seed.id IN $seed_ids AND NOT source.id IN $hub_ids
            RETURN seed.id AS seed_id, type(rel) AS relation,
                   source { .id, .name, .kind, .path, .summary, .concept_scope, .canonicality, .validation_command } AS source
            ORDER BY type(rel), size(coalesce(source.path, '')), source.name
            LIMIT $limit
            """,
            seed_ids=seed_ids,
            hub_ids=sorted(GLOBAL_HUB_IDS),
            limit=limit_value,
        )
        outgoing = [_row_dict(row) async for row in outgoing_result]
        incoming = [_row_dict(row) async for row in incoming_result]
    for row in outgoing:
        row["target"] = _normalize_graph_entity(row["target"])
    for row in incoming:
        row["source"] = _normalize_graph_entity(row["source"])

    related = [row["target"] for row in outgoing] + [row["source"] for row in incoming]
    filtered = [item for item in related if not _is_noisy_graph_row(item)]
    docs = _filter_context_docs([item for item in filtered if item["bucket"] == "doc"], entity)
    tests = [item for item in filtered if item["bucket"] == "test"]
    implementation = [item for item in filtered if item["bucket"] == "implementation"]
    concepts = [item for item in filtered if item["bucket"] == "concept"]
    owners = [item for item in filtered if item["bucket"] == "owner"]
    enrichment = await _scoped_context_enrichment(entity, limit_value)
    implementation = _dedupe_graph_entities([*enrichment["implementation"], *implementation])
    docs = _filter_context_docs([*enrichment["docs"], *docs], entity)
    tests = _dedupe_graph_entities([*enrichment["tests"], *tests])
    commands: list[str] = []
    for item in [*seeds, *filtered]:
        command = item.get("validation_command") or repo_model.validation_command_for_path(item.get("path", ""))
        if command and command not in commands:
            commands.append(command)
    read_first = _dedupe_graph_entities([*implementation[:3], *docs[:2], *tests[:2], *concepts[:1]])
    return {
        "query": entity,
        "primary_match": seeds[0] if seeds else None,
        "matches": seeds,
        "read_first": read_first[:10],
        "owners": owners[:limit_value],
        "implementation_files": implementation[:limit_value],
        "canonical_docs": sorted(docs, key=lambda item: repo_model.canonicality_for_path(item.get("path", "")) != "canonical")[:limit_value],
        "tests": tests[:limit_value],
        "concepts": concepts[:limit_value],
        "validation_commands": commands[:10],
        "outgoing": outgoing,
        "incoming": incoming,
        "hub_penalty": hub_penalties,
        "skipped_hubs": [{"id": item.get("id", ""), "reason": "noisy graph row suppressed"} for item in related if _is_noisy_graph_row(item)][:10],
    }


async def impact(path_or_crate: str, limit: int = 50) -> dict[str, Any]:
    limit_value = _limit(limit, default=50, maximum=200)
    normalized_query_path = repo_model.normalize_path(path_or_crate)
    focus_query = _context_focus_query(path_or_crate)
    plan = _query_plan(focus_query)
    driver = await _get_driver()
    async with driver.session(database=NEO4J_DATABASE) as session:
        result = await session.run(
            """
            MATCH (seed:ChioEntity)
            WHERE seed.id = $value OR seed.name CONTAINS $value OR seed.path CONTAINS $value
            WITH seed,
                 CASE WHEN seed.id IN $hub_ids THEN 2
                      WHEN seed.concept_scope = 'scoped' THEN 0
                      ELSE 1 END AS seed_rank
            ORDER BY seed_rank, size(coalesce(seed.path, '')), seed.name
            LIMIT 5
            CALL (seed) {
                MATCH (seed)-[:OWNED_BY|DEPENDS_ON|IMPLEMENTS|DEFINES|IMPORTS|CALLS|CONTAINS|USES_CONCEPT]-(component:ChioEntity)
                WHERE NOT component.id IN $hub_ids
                WITH DISTINCT component
                ORDER BY size(coalesce(component.path, '')), component.name
                LIMIT $limit
                RETURN collect(component { .id, .name, .kind, .path, .summary, .concept_scope, .canonicality, .validation_command }) AS related
            }
            CALL (seed) {
                MATCH (seed)-[:OWNED_BY|DEPENDS_ON|IMPLEMENTS|DEFINES|IMPORTS|CALLS|CONTAINS|USES_CONCEPT]-(component:ChioEntity)
                WHERE NOT component.id IN $hub_ids
                WITH DISTINCT component
                LIMIT $limit
                OPTIONAL MATCH (component)-[:HAS_TEST|TESTED_BY|VALIDATED_BY|HAS_DOC|CANONICAL_DOC|DOCUMENTED_IN]-(evidence:ChioEntity)
                WITH DISTINCT evidence
                WHERE evidence IS NOT NULL AND NOT evidence.id IN $hub_ids
                LIMIT $limit
                RETURN collect(evidence { .id, .name, .kind, .path, .summary, .concept_scope, .canonicality, .validation_command }) AS evidence
            }
            RETURN DISTINCT seed.id AS seed_id, seed.name AS seed_name, seed.path AS seed_path,
                   seed_rank AS hub_penalty, related, evidence
            """,
            value=path_or_crate,
            hub_ids=sorted(GLOBAL_HUB_IDS),
            limit=limit_value,
        )
        rows = [_row_dict(row) async for row in result]
    seed_entities: list[dict[str, Any]] = []
    for row in rows:
        row["seed_path"] = repo_model.normalize_path(row.get("seed_path", ""))
        seed_entity = {
            "id": row.get("seed_id", ""),
            "name": row.get("seed_name", ""),
            "kind": repo_model.kind_for_path(row.get("seed_path", "")),
            "path": row.get("seed_path", ""),
            "summary": "",
            "canonicality": repo_model.canonicality_for_path(row.get("seed_path", "")),
            "validation_command": repo_model.validation_command_for_path(row.get("seed_path", "")),
            "concept_scope": "",
        }
        seed_entities.append(_normalize_graph_entity(seed_entity))
        for key in ("related", "evidence"):
            normalized_items = []
            for item in row.get(key, []):
                normalized = _normalize_graph_entity(item)
                if not _is_noisy_graph_row(normalized):
                    normalized_items.append(normalized)
            row[key] = normalized_items
    all_items = [item for row in rows for item in [*row.get("related", []), *row.get("evidence", [])]]
    code_hits, doc_hits, related_docs, test_hits = await asyncio.gather(
        search_code(plan.code_query, limit=min(limit_value, 10)),
        search_docs(plan.docs_query, limit=min(limit_value, 10)),
        find_docs(path_or_crate, limit=min(limit_value, 10)),
        find_tests(plan.tests_query, limit=min(limit_value, 10)),
    )
    docs = _filter_context_docs(
        [
            *[_graph_entity_from_ranked(item, bucket="doc") for item in doc_hits],
            *[_graph_entity_from_ranked(item, bucket="doc") for item in related_docs],
            *[item for item in all_items if item["bucket"] == "doc"],
        ],
        focus_query,
    )
    tests = _dedupe_graph_entities(
        [
            *[item for item in all_items if item["bucket"] == "test"],
            *[_graph_entity_from_ranked(item, bucket="test") for item in test_hits],
        ]
    )
    direct = _path_entity(normalized_query_path) if normalized_query_path else None
    implementation = _dedupe_graph_entities(
        [
            *([direct] if direct and direct["bucket"] == "implementation" else []),
            *[item for item in all_items if item["bucket"] == "implementation"],
            *[_graph_entity_from_ranked(item, bucket="implementation") for item in code_hits],
        ]
    )
    concepts = _dedupe_graph_entities([item for item in all_items if item["bucket"] == "concept"])
    owners = _dedupe_graph_entities([item for item in all_items if item["bucket"] == "owner"])
    commands: list[str] = []
    for row in rows:
        command = repo_model.validation_command_for_path(row.get("seed_path", ""))
        if command and command not in commands:
            commands.append(command)
    for item in [*seed_entities, *owners, *implementation, *docs, *tests, *concepts]:
        command = item.get("validation_command") or repo_model.validation_command_for_path(item.get("path", ""))
        if command and command not in commands:
            commands.append(command)
    read_first = [
        item
        for item in _dedupe_graph_entities([*implementation[:1], *docs[:1], *tests[:3], *docs[1:2], *implementation[1:3], *concepts[:1]])
        if item.get("path")
    ]
    skipped_docs = [
        item
        for item in [item for item in all_items if item["bucket"] == "doc"]
        if _is_noisy_context_doc(item, focus_query)
    ]
    return {
        "query": path_or_crate,
        "primary_match": (direct or seed_entities[0]) if (direct or seed_entities) else None,
        "matches": _dedupe_graph_entities([*seed_entities, *([direct] if direct else [])]),
        "read_first": read_first[:10],
        "owners": owners[:limit_value],
        "implementation_files": implementation[:limit_value],
        "canonical_docs": sorted(docs, key=lambda item: repo_model.canonicality_for_path(item.get("path", "")) != "canonical")[:limit_value],
        "tests": tests[:limit_value],
        "concepts": concepts[:limit_value],
        "validation_commands": commands[:10],
        "hub_penalty": "generic concept hubs, folders, and empty-path dependencies excluded from expansion",
        "skipped_hubs": [{"id": item.get("id", ""), "path": item.get("path", ""), "reason": "noisy context doc suppressed"} for item in skipped_docs[:10]],
    }


def _parse_mcp_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("event:"):
        for line in text.splitlines():
            if line.startswith("data:"):
                return dict(json.loads(line.removeprefix("data:").strip()))
        raise RuntimeError("Graphiti MCP stream did not contain a data event.")
    return dict(json.loads(text))


def _parse_jsonish(value: str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return {"text": value}


def _graphiti_result_payload(response: dict[str, Any]) -> Any:
    result = response.get("result", response)
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and isinstance(first.get("text"), str):
                return _parse_jsonish(first["text"])
    return result


def _graphiti_items(payload: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


def _count_graphiti_items(payload: Any, keys: tuple[str, ...]) -> int:
    return len(_graphiti_items(payload, keys))


def _graphiti_names(payload: Any, keys: tuple[str, ...]) -> list[str]:
    values = _graphiti_items(payload, keys)
    names: list[str] = []
    for item in values[:5]:
        if isinstance(item, dict):
            name = item.get("name") or item.get("title") or item.get("fact") or item.get("summary")
            if name:
                names.append(str(name)[:160])
    return names


def _memory_summary(facts: Any, nodes: Any, episodes: Any) -> dict[str, Any]:
    return {
        "facts_count": _count_graphiti_items(facts, ("facts", "edges", "results")),
        "nodes_count": _count_graphiti_items(nodes, ("nodes", "results")),
        "episodes_count": _count_graphiti_items(episodes, ("episodes", "results")),
        "top_facts": _graphiti_names(facts, ("facts", "edges", "results")),
        "top_nodes": _graphiti_names(nodes, ("nodes", "results")),
        "top_episodes": _graphiti_names(episodes, ("episodes", "results")),
    }


def _graphiti_item_text(item: Any) -> str:
    try:
        return json.dumps(item, sort_keys=True, default=str)
    except Exception:
        return str(item)


def _sanitize_memory_for_plan(memory: dict[str, Any] | None, plan: QueryPlan) -> dict[str, Any] | None:
    if not isinstance(memory, dict) or memory.get("error"):
        return memory
    if not ({"release-qualification", "compliance-certificate"} & set(plan.intents)):
        return memory
    return memory


async def _graphiti_mcp_call(payload: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
    global _graphiti_session_id

    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if GRAPHITI_MCP_HOST_HEADER:
        headers["Host"] = GRAPHITI_MCP_HOST_HEADER
    async with httpx.AsyncClient(timeout=timeout) as client:
        if _graphiti_session_id is None:
            init_payload = {
                "jsonrpc": "2.0",
                "id": "chio-kb-graphiti-init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "chio-kb-mcp", "version": "0.1.0"},
                },
            }
            init_response = await client.post(GRAPHITI_MCP_URL, json=init_payload, headers=headers)
            init_response.raise_for_status()
            _parse_mcp_response(init_response.text)
            _graphiti_session_id = init_response.headers.get("mcp-session-id")
            if not _graphiti_session_id:
                raise RuntimeError("Graphiti MCP initialize response did not include mcp-session-id.")
            await client.post(
                GRAPHITI_MCP_URL,
                json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                headers={**headers, "Mcp-Session-Id": _graphiti_session_id},
            )

        response = await client.post(
            GRAPHITI_MCP_URL,
            json=payload,
            headers={**headers, "Mcp-Session-Id": _graphiti_session_id},
        )
        response.raise_for_status()
        parsed = _parse_mcp_response(response.text)
        if "error" in parsed:
            raise RuntimeError(parsed["error"])
        return parsed


async def _graphiti_tool_call(tool_names: list[str], arguments: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
    last_error: Exception | None = None
    for tool_name in tool_names:
        payload = {
            "jsonrpc": "2.0",
            "id": f"chio-kb-{tool_name}",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        try:
            return await _graphiti_mcp_call(payload, timeout=timeout)
        except Exception as exc:
            last_error = exc
            if "Unknown tool" not in str(exc) and "not found" not in str(exc).lower():
                raise
    raise RuntimeError(last_error or "Graphiti tool call failed.")


async def add_memory(
    name: str,
    body: str,
    source_description: str = "Chio KB user episode",
    source: str = "text",
) -> dict[str, Any]:
    return await _graphiti_tool_call(
        ["add_memory", "add_episode"],
        {
            "name": name,
            "episode_body": body,
            "group_id": GRAPHITI_GROUP_ID,
            "source": source,
            "source_description": source_description,
        },
    )


async def add_episode(name: str, body: str, source_description: str = "Chio KB user episode") -> dict[str, Any]:
    return await add_memory(name, body, source_description=source_description, source="text")


async def get_episodes(limit: int = 10) -> dict[str, Any]:
    response = await _graphiti_tool_call(
        ["get_episodes"],
        {"group_id": GRAPHITI_GROUP_ID, "last_n": _limit(limit, default=10)},
        timeout=60.0,
    )
    payload = _graphiti_result_payload(response)
    return payload if isinstance(payload, dict) else {"episodes": payload}


async def delete_episode(uuid: str) -> dict[str, Any]:
    last_error: Exception | None = None
    for arguments in ({"uuid": uuid}, {"episode_uuid": uuid}, {"episode_id": uuid}):
        try:
            response = await _graphiti_tool_call(["delete_episode"], arguments, timeout=60.0)
            payload = _graphiti_result_payload(response)
            return payload if isinstance(payload, dict) else {"result": payload}
        except Exception as exc:
            last_error = exc
    raise RuntimeError(last_error or "Graphiti delete_episode failed.")


async def search_memory(query: str, limit: int = 5) -> dict[str, Any]:
    facts_response = await _graphiti_tool_call(
        ["search_memory_facts", "search_facts"],
        {"query": query, "group_ids": [GRAPHITI_GROUP_ID], "max_facts": _limit(limit, default=5)},
        timeout=90.0,
    )
    nodes_response = await _graphiti_tool_call(
        ["search_nodes"],
        {"query": query, "group_ids": [GRAPHITI_GROUP_ID], "max_nodes": _limit(limit, default=5)},
        timeout=90.0,
    )
    try:
        episodes = await get_episodes(limit=limit)
    except Exception as exc:
        episodes = {"error": str(exc), "episodes": []}
    facts = _graphiti_result_payload(facts_response)
    nodes = _graphiti_result_payload(nodes_response)
    fact_items = _graphiti_items(facts, ("facts", "edges", "results"))
    node_items = _graphiti_items(nodes, ("nodes", "results"))
    episode_items = _graphiti_items(episodes, ("episodes", "results"))
    return {
        "facts": fact_items,
        "nodes": node_items,
        "episodes": episode_items,
        "summary": _memory_summary(fact_items, node_items, episode_items),
    }


async def brief_feature(
    feature_or_task: str,
    focus_paths: list[str] | None = None,
    limit: int = 8,
    include_memory: bool = True,
    intent: str = "auto",
) -> dict[str, Any]:
    limit_value = _limit(limit, default=8, maximum=20)
    plan = _query_plan(feature_or_task, explicit_intent=intent)
    focus = [repo_model.normalize_path(path) for path in (focus_paths or []) if path]
    impact_query = focus[0] if focus else plan.graph_query

    async def _memory_or_error() -> dict[str, Any] | None:
        if not include_memory:
            return None
        try:
            timeout_ms = int(os.environ.get("CHIO_KB_BRIEF_MEMORY_TIMEOUT_MS", "3500"))
            return await asyncio.wait_for(search_memory(plan.memory_query, limit=5), timeout=timeout_ms / 1000.0)
        except Exception as exc:
            return {"error": str(exc)}

    code, docs, tests, related_docs, graph_impact, memory = await asyncio.gather(
        search_code(plan.code_query, limit=limit_value),
        search_docs(plan.docs_query, limit=limit_value),
        find_tests(plan.tests_query, limit=max(limit_value * 2, limit_value)),
        find_docs(plan.docs_query, limit=limit_value),
        impact(impact_query, limit=limit_value),
        _memory_or_error(),
    )
    memory = _sanitize_memory_for_plan(memory, plan)

    commands: list[str] = []
    for item in [*code, *docs, *tests, *related_docs]:
        command = item.get("validation_command")
        if command and command not in commands:
            commands.append(command)
    impacted_crates = sorted({item.get("crate") for item in code if item.get("crate")})
    required_buckets = {
        "implementation_files": bool(code),
        "canonical_docs": any(
            item.get("canonicality") == "canonical"
            for item in docs
        ),
        "related_tests": bool(tests),
        "graph_impact": bool(graph_impact.get("matches") or graph_impact.get("implementation_files")),
        "memory": bool(memory and not memory.get("error") and memory.get("summary", {}).get("episodes_count", 0) >= 1),
    }
    coverage_gaps = [name for name, present in required_buckets.items() if not present]
    memory_summary = memory.get("summary") if isinstance(memory, dict) else None
    read_first: list[dict[str, Any]] = []
    seen_read_first: set[str] = set()

    def _doc_priority(item: Mapping[str, Any]) -> tuple[int, str]:
        path = repo_model.normalize_path(item.get("normalized_path") or item.get("file_path") or item.get("path") or "")
        intent_priorities = {
            "revocation": {
                "spec/PROTOCOL.md": 0,
                "spec/SECURITY.md": 1,
                "docs/standards/CHIO_RECEIPTS_PROFILE.md": 2,
            },
            "release-qualification": {
                "spec/COMPLIANCE-CERTIFICATE.md": 0,
                "docs/release/QUALIFICATION.md": 1,
                "docs/release/RELEASE_AUDIT.md": 2,
                "docs/conformance/verdict-matrix.md": 3,
            },
            "compliance-certificate": {
                "spec/COMPLIANCE-CERTIFICATE.md": 0,
                "docs/release/QUALIFICATION.md": 1,
                "spec/PROTOCOL.md": 2,
            },
        }
        priority = intent_priorities.get(plan.intent, {}).get(path, 20)
        if item.get("canonicality") == "canonical":
            priority -= 1
        return priority, path

    def _prioritize_paths(items: list[dict[str, Any]], paths: list[str]) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for wanted in paths:
            for item in items:
                path = repo_model.normalize_path(item.get("normalized_path") or item.get("file_path") or item.get("path") or "")
                if path == wanted and path not in seen_paths:
                    selected.append(item)
                    seen_paths.add(path)
                    break
        for item in items:
            path = repo_model.normalize_path(item.get("normalized_path") or item.get("file_path") or item.get("path") or "")
            if path and path not in seen_paths:
                selected.append(item)
                seen_paths.add(path)
        return selected

    preferred_docs = sorted([*docs, *related_docs], key=_doc_priority)
    intent_set = set(plan.intents)
    if {"guard-policy", "receipt"} <= intent_set:
        guard_code = _prioritize_paths(
            code,
            [
                "crates/guards/chio-guards/src/pipeline.rs",
                "crates/kernel/chio-kernel/src/kernel/evaluator.rs",
            ],
        )
        guard_tests = _prioritize_paths(
            tests,
            [
                "crates/guards/chio-guards/tests/output_sanitization.rs",
                "crates/guards/chio-policy/tests/compile_policy.rs",
            ],
        )
        read_candidates = [*guard_code[:2], *preferred_docs[:1], *guard_tests[:2], *guard_code[2:5], *preferred_docs[1:3]]
    elif {"mcp-adapter", "sdk-conformance"} <= intent_set:
        mcp_tests = _prioritize_paths(
            tests,
            [
                "integrations/mcp-adapter/tests/transport_round_trip.rs",
                "crates/tooling/chio-conformance/verdict_matrix/tests/verdict_matrix_cross_language.rs",
            ],
        )
        mcp_docs = _prioritize_paths(preferred_docs, ["docs/conformance/verdict-matrix.md"])
        read_candidates = [*code[:2], *mcp_docs[:1], *mcp_tests[:2], *code[2:5], *mcp_docs[1:3]]
    elif plan.intent in {"release-qualification", "compliance-certificate"}:
        read_candidates = [*code[:3], *preferred_docs[:2], *tests[:2], *code[3:5], *preferred_docs[2:4]]
    elif plan.intent == "revocation":
        read_candidates = [*code[:3], *preferred_docs[:1], *tests[:2], *preferred_docs[1:3], *code[3:5]]
    elif plan.intent in {"guard-policy", "mcp-adapter", "sdk-conformance"}:
        read_candidates = [*code[:3], *preferred_docs[:1], *tests[:2], *code[3:5], *preferred_docs[1:3]]
    else:
        read_candidates = [*code[:3], *preferred_docs[:2], *tests[:2], *related_docs[:1]]

    for item in read_candidates:
        path = repo_model.normalize_path(item.get("normalized_path") or item.get("file_path") or item.get("path") or "")
        if not path or path in seen_read_first:
            continue
        seen_read_first.add(path)
        read_first.append(
            {
                "normalized_path": path,
                "path": path,
                "kind": item.get("kind") or item.get("doc_type") or "related",
                "source": item.get("source", "ranked"),
                "why": item.get("why", []),
                "validation_command": item.get("validation_command") or repo_model.validation_command_for_path(path),
            }
        )
    return {
        "feature_or_task": feature_or_task,
        "intent": plan.intent,
        "intents": list(plan.intents),
        "subqueries": {
            "code": plan.code_query,
            "docs": plan.docs_query,
            "tests": plan.tests_query,
            "graph": plan.graph_query,
            "memory": plan.memory_query,
        },
        "read_first": read_first,
        "implementation_files": code,
        "canonical_docs": docs,
        "related_tests": tests,
        "related_docs": related_docs,
        "impacted_crates": impacted_crates,
        "graph_impact": graph_impact,
        "memory": memory,
        "memory_summary": memory_summary,
        "coverage_summary": required_buckets,
        "coverage_gaps": coverage_gaps,
        "suggested_validation": commands[:8],
    }


async def eval_knowledge_base(category: str | None = None, output_format: str = "json", suite: str = "all") -> dict[str, Any] | str:
    from chio_kb import eval_runner

    result = await eval_runner.run_evaluation_direct(category=category, suite=suite)
    if output_format == "markdown":
        return eval_runner.render_markdown(result)
    return result


async def health() -> dict[str, Any]:
    status: dict[str, Any] = {}
    try:
        pool = await _get_pool()
        async with pool.acquire() as conn:
            status["postgres"] = await conn.fetchval("SELECT 1")
    except Exception as exc:
        status["postgres_error"] = str(exc)
    try:
        driver = await _get_driver()
        async with driver.session(database=NEO4J_DATABASE) as session:
            result = await session.run("RETURN 1 AS ok")
            record = await result.single()
            status["neo4j"] = record["ok"] if record else None
    except Exception as exc:
        status["neo4j_error"] = str(exc)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            base_url = GRAPHITI_MCP_URL.removesuffix("/mcp")
            response = await client.get(base_url + "/health")
            status["graphiti"] = response.status_code
    except Exception as exc:
        status["graphiti_error"] = str(exc)
    return status
