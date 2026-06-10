"""Direct Neo4j graph seeder for the local Chio knowledge base."""

from __future__ import annotations

import os
import pathlib
from collections import defaultdict
from typing import Any

from neo4j import GraphDatabase

from chio_kb import repo_model

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "demodemo")
NEO4J_DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")

RELATION_TYPES = {
    "CONTAINS",
    "CALLS",
    "IMPORTS",
    "DEPENDS_ON",
    "DOCUMENTED_IN",
    "OWNED_BY",
    "HAS_DOC",
    "HAS_TEST",
    "CANONICAL_DOC",
    "VALIDATED_BY",
    "USES_CONCEPT",
    "IMPLEMENTS",
    "TESTED_BY",
    "MENTIONS",
    "DEFINES",
    "GUARDS",
    "VALIDATES",
    "SUPERSEDES",
}


def _concept_labels(kind: str) -> set[str]:
    labels = {"ChioConcept"}
    if kind == "policy":
        labels.add("ChioPolicy")
    elif kind == "guard":
        labels.add("ChioGuard")
    elif kind == "receipt":
        labels.add("ChioReceipt")
    elif kind in {"mcp", "a2a", "acp", "openapi", "protocol"}:
        labels.add("ChioProtocol")
    elif kind == "standard":
        labels.add("ChioStandard")
    return labels


def _merge_props(existing: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    for key, value in new.items():
        if value not in ("", None) or key not in merged:
            merged[key] = value
    return merged


def _build_catalog(root: pathlib.Path) -> tuple[dict[str, dict[str, Any]], set[tuple[str, str, str]]]:
    nodes: dict[str, dict[str, Any]] = {}
    rels: set[tuple[str, str, str]] = set()

    def node(entity_id: str, labels: set[str], **props: Any) -> None:
        all_labels = {"ChioEntity", *labels}
        base = {
            "id": entity_id,
            "name": props.get("name", entity_id),
            "kind": props.get("kind", ""),
            "path": props.get("path", ""),
            "summary": props.get("summary", ""),
        }
        base.update(props)
        current = nodes.get(entity_id)
        if current is None:
            nodes[entity_id] = {"labels": all_labels, "props": base}
        else:
            current["labels"].update(all_labels)
            current["props"] = _merge_props(current["props"], base)

    def rel(rel_type: str, source: str, target: str) -> None:
        if rel_type not in RELATION_TYPES or not source or not target:
            return
        rels.add((rel_type, source, target))

    files = repo_model.iter_indexed_files(root)
    for info, text in files:
        file_id = repo_model.file_entity_id(info.path)
        node(
            file_id,
            {"ChioFile"},
            name=info.path,
            kind="file",
            path=info.path,
            summary=f"{info.kind} file",
            source_root=info.source_root,
            language=info.language,
            crate=info.crate,
            package=info.package,
            file_kind=info.kind,
            nearest_manifest=info.nearest_manifest,
            is_generated=info.is_generated,
            canonicality=info.canonicality,
            validation_command=info.validation_command,
        )

        parts = pathlib.PurePath(info.path).parts
        parent_id = ""
        for index in range(1, len(parts)):
            folder_path = "/".join(parts[:index])
            folder_id = repo_model.entity_id("folder", folder_path)
            node(
                folder_id,
                {"ChioFolder"},
                name=parts[index - 1],
                kind="folder",
                path=folder_path,
                summary="Repository folder",
                source_root=info.source_root,
            )
            if parent_id:
                rel("CONTAINS", parent_id, folder_id)
            parent_id = folder_id
        if parent_id:
            rel("CONTAINS", parent_id, file_id)

        doc_entity_id = ""
        if repo_model.is_docs_path(info.path):
            doc_entity_id = repo_model.entity_id(info.kind, info.path)
            title = info.title or pathlib.PurePath(info.path).stem
            labels = {"ChioDoc"}
            if info.kind == "spec":
                labels.add("ChioSpec")
            if info.kind == "standard":
                labels.add("ChioStandard")
            node(
                doc_entity_id,
                labels,
                name=title,
                kind=info.kind,
                path=info.path,
                summary=f"{info.kind} document",
                canonicality=info.canonicality,
                validation_command=info.validation_command,
            )
            rel("DEFINES", file_id, doc_entity_id)

        crate_name = repo_model.cargo_package_name(info.path, text) or info.crate
        crate_entity_id = ""
        if crate_name:
            crate_entity_id = repo_model.entity_id("crate", crate_name)
            node(crate_entity_id, {"ChioCrate"}, name=crate_name, kind="crate", path=info.path if info.path.endswith("Cargo.toml") else "", summary="Rust workspace crate")
            rel("DEFINES", file_id, crate_entity_id)
            rel("OWNED_BY", file_id, crate_entity_id)
            if info.path.endswith("Cargo.toml"):
                for dep_name in repo_model.cargo_dependency_names(text):
                    dep_id = repo_model.entity_id("crate", dep_name)
                    node(
                        dep_id,
                        {"ChioCrate"},
                        name=dep_name,
                        kind="crate",
                        path="",
                        summary="Rust workspace dependency",
                        graph_role="external_dependency",
                    )
                    rel("DEPENDS_ON", crate_entity_id, dep_id)

        if info.package:
            package_id = repo_model.entity_id("package", info.package)
            node(package_id, {"ChioPackage"}, name=info.package, kind="package", path=info.path, summary="SDK or package surface")
            rel("DEFINES", file_id, package_id)

        if info.kind == "example":
            example_name = "/".join(parts[:2])
            example_id = repo_model.entity_id("example", example_name)
            node(example_id, {"ChioExample"}, name=example_name, kind="example", path=info.path, summary="Runnable example")
            rel("DEFINES", file_id, example_id)

        if info.kind == "test":
            test_id = repo_model.entity_id("test", info.path)
            node(
                test_id,
                {"ChioTest"},
                name=pathlib.PurePath(info.path).name,
                kind="test",
                path=info.path,
                summary="Test or conformance fixture",
                validation_command=info.validation_command,
            )
            rel("DEFINES", file_id, test_id)
            if info.crate:
                rel("TESTED_BY", repo_model.entity_id("crate", info.crate), test_id)
                rel("HAS_TEST", repo_model.entity_id("crate", info.crate), test_id)
                rel("VALIDATED_BY", repo_model.entity_id("crate", info.crate), test_id)

        symbols = repo_model.rust_symbol_records(info.path, text)
        for symbol in symbols:
            node(
                symbol.id,
                {"ChioSymbol", "ChioModule"},
                name=symbol.name,
                kind="symbol",
                path=info.path,
                summary=f"Rust {symbol.symbol_kind}",
                symbol_kind=symbol.symbol_kind,
                language=info.language,
                start_line=symbol.start_line,
                end_line=symbol.end_line,
                signature=symbol.signature,
                source_hash=repo_model.content_hash(symbol.body),
            )
            rel("DEFINES", file_id, symbol.id)
            rel("CONTAINS", file_id, symbol.id)
            if crate_entity_id:
                rel("DEFINES", crate_entity_id, symbol.id)
                rel("OWNED_BY", symbol.id, crate_entity_id)
        for source_id, target_id in repo_model.rust_symbol_calls(symbols):
            rel("CALLS", source_id, target_id)

        for import_root in repo_model.rust_import_roots(text):
            import_id = repo_model.entity_id("crate", import_root)
            node(
                import_id,
                {"ChioCrate"},
                name=import_root,
                kind="crate",
                path="",
                summary="Imported Rust workspace crate",
                graph_role="external_dependency",
            )
            rel("IMPORTS", file_id, import_id)

        for section in repo_model.markdown_sections(info.path, text):
            node(
                section.id,
                {"ChioSection"},
                name=section.title,
                kind="section",
                path=info.path,
                summary="Markdown section",
                level=section.level,
                start_line=section.start_line,
                end_line=section.end_line,
                anchor=section.anchor,
                source_hash=repo_model.content_hash(section.content),
            )
            rel("CONTAINS", doc_entity_id or file_id, section.id)

        for command in repo_model.extract_commands(text):
            command_id = repo_model.entity_id("command", command)
            node(command_id, {"ChioCommand"}, name=command, kind="command", path=info.path, summary="Chio CLI command mention")
            rel("DEFINES", doc_entity_id or file_id, command_id)

        concepts = repo_model.deterministic_concepts(text)
        scoped_concepts = repo_model.scoped_concepts(info.path, text)
        for concept in concepts:
            node(
                concept.id,
                _concept_labels(concept.kind),
                name=concept.name,
                kind=concept.kind,
                path="",
                summary=concept.summary,
                concept_scope="global",
                graph_role="global_hub",
            )
            rel("MENTIONS", doc_entity_id or file_id, concept.id)
            if info.kind == "test":
                rel("VALIDATES", repo_model.entity_id("test", info.path), concept.id)
                rel("VALIDATED_BY", concept.id, repo_model.entity_id("test", info.path))

        for concept in scoped_concepts:
            node(
                concept.id,
                _concept_labels(concept.kind),
                name=concept.name,
                kind=concept.kind,
                path="",
                summary=concept.summary,
                concept_scope="scoped",
                graph_role="scoped_concept",
            )
            rel("USES_CONCEPT", doc_entity_id or file_id, concept.id)
            rel("MENTIONS", concept.id, repo_model.entity_id(concept.kind, concept.kind.title() if concept.kind != "kernel" else "Runtime Kernel"))
            if info.kind == "test":
                rel("VALIDATED_BY", concept.id, repo_model.entity_id("test", info.path))

        if any(concept.kind == "guard" for concept in concepts) and any(concept.kind == "policy" for concept in concepts):
            rel("GUARDS", repo_model.entity_id("guard", "Guard"), repo_model.entity_id("policy", "Policy"))

        if doc_entity_id:
            if info.canonicality == "canonical":
                for concept in [*concepts, *scoped_concepts]:
                    rel("CANONICAL_DOC", concept.id, doc_entity_id)
            for match_name in repo_model.mentioned_crate_names(text):
                crate_id = repo_model.entity_id("crate", match_name)
                node(
                    crate_id,
                    {"ChioCrate"},
                    name=match_name,
                    kind="crate",
                    path="",
                    summary="Mentioned Rust workspace crate",
                    graph_role="mentioned_dependency",
                )
                rel("DOCUMENTED_IN", crate_id, doc_entity_id)
                rel("HAS_DOC", crate_id, doc_entity_id)
                if info.canonicality == "canonical":
                    rel("CANONICAL_DOC", crate_id, doc_entity_id)
            for target in repo_model.superseded_targets(text):
                target_id = repo_model.entity_id("doc", target)
                node(target_id, {"ChioDoc"}, name=target, kind="doc", path=target, summary="Superseded document reference")
                rel("SUPERSEDES", doc_entity_id, target_id)

    return nodes, rels


def _seed() -> dict[str, int]:
    root = repo_model.repo_root_from_env()
    nodes, rels = _build_catalog(root)
    grouped_nodes: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in nodes.values():
        grouped_nodes[tuple(sorted(record["labels"]))].append(record["props"])

    grouped_rels: dict[str, list[dict[str, str]]] = defaultdict(list)
    for rel_type, source, target in rels:
        grouped_rels[rel_type].append({"source": source, "target": target})

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver:
        with driver.session(database=NEO4J_DATABASE) as session:
            session.run('MATCH (n) WHERE any(label IN labels(n) WHERE label STARTS WITH "Chio") DETACH DELETE n').consume()
            session.run("CREATE CONSTRAINT chio_entity_id IF NOT EXISTS FOR (n:ChioEntity) REQUIRE n.id IS UNIQUE").consume()
            for labels, rows in grouped_nodes.items():
                label_clause = ":".join(labels)
                session.run(
                    f"UNWIND $rows AS row MERGE (n:{label_clause} {{id: row.id}}) SET n += row",
                    rows=rows,
                ).consume()
            for rel_type, rows in grouped_rels.items():
                session.run(
                    f"""
                    UNWIND $rows AS row
                    MATCH (source:ChioEntity {{id: row.source}})
                    MATCH (target:ChioEntity {{id: row.target}})
                    MERGE (source)-[:{rel_type}]->(target)
                    """,
                    rows=rows,
                ).consume()
    return {"nodes": len(nodes), "relationships": len(rels)}


def main() -> None:
    print(_seed())


if __name__ == "__main__":
    main()
