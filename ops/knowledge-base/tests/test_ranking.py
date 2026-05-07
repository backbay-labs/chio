from __future__ import annotations

from chio_kb import query


def test_doc_rank_boosts_canonical_docs() -> None:
    row = {
        "file_path": "spec/PROTOCOL.md",
        "score": 0.50,
        "canonicality": "canonical",
    }
    score, components, why = query._doc_rank(row, "receipt merkle proof protocol", None)
    assert score > 0.75
    assert components["protocol_spec"] > 0
    assert "canonical protocol spec" in why


def test_doc_rank_penalizes_planning_unless_requested() -> None:
    row = {
        "file_path": ".planning/v3.14-MILESTONE-AUDIT.md",
        "score": 0.80,
        "canonicality": "planning",
    }
    generic_score, generic_components, _ = query._doc_rank(row, "receipt merkle proof", None)
    planning_score, planning_components, _ = query._doc_rank(row, "planning audit receipt merkle proof", None)
    assert generic_components["planning_penalty"] < 0
    assert "planning_penalty" not in planning_components
    assert planning_score > generic_score


def test_code_rank_penalizes_generated_and_unrequested_tests() -> None:
    row = {
        "file_path": "crates/chio-core-types/src/_generated/chio_wire_v1.rs",
        "score": 0.90,
        "crate": "chio-core-types",
        "symbol_hint": "",
        "kind": "test",
        "source_root": "crates",
        "is_generated": True,
    }
    score, components, _ = query._code_rank(row, "capability token", None)
    assert score < 0.90
    assert components["generated_penalty"] < 0
    assert components["test_penalty"] < 0


def test_global_hubs_are_marked_for_suppression() -> None:
    assert "capability:capability" in query.GLOBAL_HUB_IDS
    assert "policy:policy" in query.GLOBAL_HUB_IDS
    assert "receipt:receipt" in query.GLOBAL_HUB_IDS
    assert "guard:guard" in query.GLOBAL_HUB_IDS


def test_intent_classification_separates_release_and_mercury() -> None:
    assert query.detect_query_intent("release qualification evidence export compliance certificate") == "release-qualification"
    assert query.detect_query_intent("Mercury assurance release renewal qualification") == "mercury-product"


def test_multi_intent_classification_keeps_guard_and_receipt() -> None:
    intents = query.detect_query_intents("guard policy fail closed redaction pipeline signed receipts")
    assert intents[:2] == ["guard-policy", "receipt"]


def test_multi_intent_classification_keeps_mcp_sdk_and_receipt() -> None:
    intents = query.detect_query_intents("MCP adapter capability token receipt propagation with SDK conformance")
    assert "mcp-adapter" in intents
    assert "sdk-conformance" in intents
    assert "receipt" in intents


def test_feature_query_plan_decomposes_revocation() -> None:
    plan = query._query_plan("delegated capability revocation with signed receipts")
    assert plan.intent == "revocation"
    assert plan.intents == ("revocation", "receipt", "capability")
    assert "revocation oracle" in plan.tests_query
    assert plan.code_query != plan.docs_query
    assert plan.memory_query != plan.code_query


def test_feature_query_plan_combines_mixed_intents() -> None:
    plan = query._query_plan("MCP adapter capability token receipt propagation with SDK conformance")
    assert plan.intent == "mcp-adapter"
    assert set(plan.intents) >= {"mcp-adapter", "sdk-conformance", "receipt", "capability"}
    assert "MCP adapter" in plan.code_query
    assert "SDK conformance" in plan.docs_query
    assert "receipt" in plan.memory_query


def test_salient_test_queries_preserve_revocation_anchor() -> None:
    queries = query._salient_test_queries("delegated capability revocation")
    assert "revocation" in queries
    assert "revocation oracle" in queries
    assert "delegation revocation" in queries


def test_graph_noise_suppression_allows_scoped_concepts() -> None:
    assert query._is_noisy_graph_row({"kind": "folder", "path": "docs"}) is True
    assert query._is_noisy_graph_row({"kind": "crate", "path": ""}) is True
    assert query._is_noisy_graph_row({"kind": "capability", "path": "", "concept_scope": "scoped"}) is False


def test_context_doc_noise_filter_blocks_planning_by_default() -> None:
    assert query._is_noisy_context_doc({"path": ".planning/phases/example.md"}, "delegation revocation") is True
    assert query._is_noisy_context_doc({"path": ".planning/phases/example.md"}, "planning history revocation") is False
    assert query._is_noisy_context_doc({"path": "spec/schemas/chio-wire/v1/receipt/record.schema.json"}, "delegation revocation") is True


def test_graphiti_result_payload_unwraps_mcp_content() -> None:
    response = {
        "jsonrpc": "2.0",
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": "{\"episodes\":[{\"name\":\"release truth boundary\"}]}",
                }
            ]
        },
    }
    assert query._graphiti_result_payload(response) == {"episodes": [{"name": "release truth boundary"}]}


def test_graphiti_items_unwraps_facts_nodes_and_episodes() -> None:
    assert query._graphiti_items({"facts": [{"fact": "release truth boundary"}]}, ("facts",)) == [
        {"fact": "release truth boundary"}
    ]
    assert query._memory_summary([{"fact": "release truth boundary"}], [{"name": "Release"}], [{"name": "Episode"}])[
        "facts_count"
    ] == 1
