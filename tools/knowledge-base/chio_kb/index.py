"""CocoIndex v1 app for the local Chio knowledge base."""

from __future__ import annotations

import asyncio
import os
import pathlib
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

import asyncpg
import pydantic
from numpy.typing import NDArray

import cocoindex as coco
from cocoindex.connectors import localfs, neo4j, postgres
from cocoindex.ops.litellm import LiteLLMEmbedder
from cocoindex.ops.text import RecursiveSplitter, detect_code_language
from cocoindex.resources.chunk import Chunk
from cocoindex.resources.file import FileLike, PatternFilePathMatcher

from chio_kb import repo_model

PG_SCHEMA_NAME = "chio_kb"
CODE_TABLE_NAME = "code_chunks"
DOC_TABLE_NAME = "doc_chunks"
EMBED_MODEL = os.environ.get(
    "CHIO_KB_EMBED_MODEL", "text-embedding-3-small"
)
POSTGRES_URL = os.environ.get("POSTGRES_URL") or os.environ.get("DATABASE_URL") or (
    "postgres://cocoindex:cocoindex@localhost:55432/chio_kb"
)
REPO_ROOT = repo_model.repo_root_from_env()
MAX_FILE_CHARS = int(os.environ.get("CHIO_KB_MAX_FILE_CHARS", "1000000"))

PG_DB = coco.ContextKey[asyncpg.Pool]("chio_kb_postgres")
KG_DB = coco.ContextKey[neo4j.ConnectionFactory]("chio_kb_neo4j")
EMBEDDER = coco.ContextKey[LiteLLMEmbedder]("chio_kb_embedder", detect_change=True)
LLM_MODEL = coco.ContextKey[str]("chio_kb_llm_model", detect_change=True)

_splitter = RecursiveSplitter()


def _openai_config() -> tuple[str | None, str | None]:
    api_key = os.environ.get("OPENAI_API_KEY")
    api_url = os.environ.get("OPENAI_API_URL")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is required for Chio KB embeddings.")
    if (api_url is None or "api.openai.com" in api_url) and not api_key.startswith("sk-"):
        raise RuntimeError(
            "OPENAI_API_KEY does not look like an OpenAI API key for api.openai.com. "
            "Update tools/knowledge-base/.env or export a valid shell key before kb-update."
        )
    return api_key, api_url


@dataclass
class CodeChunk:
    id: str
    file_path: str
    normalized_path: str
    source_root: str
    language: str
    crate: str
    package: str
    kind: str
    symbol_hint: str
    content: str
    embedding: Annotated[NDArray, EMBEDDER]
    start_line: int
    end_line: int
    source_hash: str
    nearest_manifest: str
    is_generated: bool
    canonicality: str
    validation_command: str


@dataclass
class DocChunk:
    id: str
    file_path: str
    normalized_path: str
    source_root: str
    doc_type: str
    title: str
    section: str
    anchor: str
    text: str
    embedding: Annotated[NDArray, EMBEDDER]
    start_line: int
    end_line: int
    source_hash: str
    nearest_manifest: str
    is_generated: bool
    canonicality: str
    validation_command: str


@dataclass
class ChioEntity:
    id: str
    name: str
    kind: str
    path: str
    summary: str


@dataclass
class ChioFile:
    id: str
    path: str
    source_root: str
    kind: str
    language: str
    crate: str
    package: str


@dataclass
class ChioFolder:
    id: str
    name: str
    path: str
    source_root: str


@dataclass
class ChioCrate:
    id: str
    name: str
    path: str
    category: str


@dataclass
class ChioPackage:
    id: str
    name: str
    path: str
    category: str


@dataclass
class ChioDoc:
    id: str
    title: str
    path: str
    doc_type: str


@dataclass
class ChioSpec:
    id: str
    title: str
    path: str


@dataclass
class ChioExample:
    id: str
    name: str
    path: str


@dataclass
class ChioTest:
    id: str
    name: str
    path: str


@dataclass
class ChioModule:
    id: str
    name: str
    path: str
    language: str


@dataclass
class ChioSymbol:
    id: str
    name: str
    symbol_kind: str
    path: str
    language: str
    start_line: int
    end_line: int
    signature: str
    source_hash: str


@dataclass
class ChioSection:
    id: str
    title: str
    path: str
    level: int
    start_line: int
    end_line: int
    anchor: str
    source_hash: str


@dataclass
class ChioCommand:
    id: str
    name: str
    path: str
    summary: str


@dataclass
class ChioConcept:
    id: str
    name: str
    concept_type: str
    summary: str


@dataclass
class ChioPolicy:
    id: str
    name: str
    path: str
    summary: str


@dataclass
class ChioGuard:
    id: str
    name: str
    path: str
    summary: str


@dataclass
class ChioReceipt:
    id: str
    name: str
    path: str
    summary: str


@dataclass
class ChioProtocol:
    id: str
    name: str
    path: str
    summary: str


@dataclass
class ChioStandard:
    id: str
    name: str
    path: str
    summary: str


class LlmConcept(pydantic.BaseModel):
    name: str = pydantic.Field(description="Short canonical entity name.")
    kind: str = pydantic.Field(
        description="One of capability, guard, policy, receipt, protocol, command, crate, standard, risk, decision, procedure, topic."
    )
    summary: str = pydantic.Field(description="One sentence source-grounded summary.")


class LlmRelation(pydantic.BaseModel):
    source: str = pydantic.Field(description="Source concept name.")
    relation: str = pydantic.Field(
        description="One of IMPLEMENTS, MENTIONS, DEFINES, GUARDS, VALIDATES, SUPERSEDES, DOCUMENTED_IN."
    )
    target: str = pydantic.Field(description="Target concept name.")
    evidence: str = pydantic.Field(description="Brief evidence from the source text.")


class LlmExtraction(pydantic.BaseModel):
    concepts: list[LlmConcept] = pydantic.Field(default_factory=list)
    relations: list[LlmRelation] = pydantic.Field(default_factory=list)


@coco.lifespan
async def coco_lifespan(builder: coco.EnvironmentBuilder) -> AsyncIterator[None]:
    openai_api_key, openai_api_url = _openai_config()
    async with await asyncpg.create_pool(POSTGRES_URL) as pool:
        builder.provide(PG_DB, pool)
        builder.provide(
            KG_DB,
            neo4j.ConnectionFactory(
                uri=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
                auth=(
                    os.environ.get("NEO4J_USER", "neo4j"),
                    os.environ.get("NEO4J_PASSWORD", "demodemo"),
                ),
                database=os.environ.get("NEO4J_DATABASE", "neo4j"),
            ),
        )
        builder.provide(
            EMBEDDER,
            LiteLLMEmbedder(
                EMBED_MODEL,
                api_key=openai_api_key,
                api_base=openai_api_url,
            ),
        )
        builder.provide(LLM_MODEL, os.environ.get("CHIO_KB_LLM_MODEL", "openai/gpt-4o-mini"))
        yield


def _declare_entity(table: object, entity_id: str, name: str, kind: str, path: str = "", summary: str = "") -> None:
    table.declare_record(row=ChioEntity(id=entity_id, name=name, kind=kind, path=path, summary=summary))


def _declare_concept(
    entity_table: object,
    concept_table: object,
    policy_table: object,
    guard_table: object,
    receipt_table: object,
    protocol_table: object,
    concept: repo_model.Concept,
    path: str,
) -> None:
    _declare_entity(entity_table, concept.id, concept.name, concept.kind, path, concept.summary)
    concept_table.declare_record(
        row=ChioConcept(
            id=concept.id,
            name=concept.name,
            concept_type=concept.kind,
            summary=concept.summary,
        )
    )
    if concept.kind == "policy":
        policy_table.declare_record(row=ChioPolicy(concept.id, concept.name, path, concept.summary))
    elif concept.kind == "guard":
        guard_table.declare_record(row=ChioGuard(concept.id, concept.name, path, concept.summary))
    elif concept.kind == "receipt":
        receipt_table.declare_record(row=ChioReceipt(concept.id, concept.name, path, concept.summary))
    elif concept.kind in {"mcp", "a2a", "acp", "openapi", "protocol"}:
        protocol_table.declare_record(row=ChioProtocol(concept.id, concept.name, path, concept.summary))


def _as_concept(model: LlmConcept) -> repo_model.Concept:
    kind = repo_model.slug(model.kind)
    name = model.name.strip()
    return repo_model.Concept(
        id=repo_model.entity_id(kind, name),
        name=name,
        kind=kind,
        summary=model.summary.strip(),
    )


def _declare_folder_chain(
    info: repo_model.FileInfo,
    entity_table: neo4j.TableTarget[ChioEntity],
    folder_table: neo4j.TableTarget[ChioFolder],
    contains_rel: neo4j.RelationTarget[object],
    file_id: str,
) -> None:
    parts = pathlib.PurePath(info.path).parts[:-1]
    parent_id = ""
    for index in range(1, len(parts) + 1):
        folder_path = "/".join(parts[:index])
        folder_id = repo_model.entity_id("folder", folder_path)
        folder_name = parts[index - 1]
        _declare_entity(entity_table, folder_id, folder_name, "folder", folder_path, "Repository folder")
        folder_table.declare_record(
            row=ChioFolder(
                id=folder_id,
                name=folder_name,
                path=folder_path,
                source_root=info.source_root,
            )
        )
        if parent_id:
            contains_rel.declare_relation(from_id=parent_id, to_id=folder_id)
        parent_id = folder_id
    if parent_id:
        contains_rel.declare_relation(from_id=parent_id, to_id=file_id)


def _path_scoped_concept(concept: repo_model.Concept, path: str) -> repo_model.Concept:
    return repo_model.Concept(
        id=f"{concept.kind}:{repo_model.slug(concept.name)}@{repo_model.stable_id(path, concept.name)}",
        name=concept.name,
        kind=concept.kind,
        summary=concept.summary,
    )


def _declare_shared_graph_catalog(
    files: list[tuple[repo_model.FileInfo, str]],
    entity_table: neo4j.TableTarget[ChioEntity],
    folder_table: neo4j.TableTarget[ChioFolder],
    crate_table: neo4j.TableTarget[ChioCrate],
    package_table: neo4j.TableTarget[ChioPackage],
    example_table: neo4j.TableTarget[ChioExample],
    command_table: neo4j.TableTarget[ChioCommand],
    concept_table: neo4j.TableTarget[ChioConcept],
    policy_table: neo4j.TableTarget[ChioPolicy],
    guard_table: neo4j.TableTarget[ChioGuard],
    receipt_table: neo4j.TableTarget[ChioReceipt],
    protocol_table: neo4j.TableTarget[ChioProtocol],
    contains_rel: neo4j.RelationTarget[object],
    depends_on_rel: neo4j.RelationTarget[object],
) -> None:
    declared_entities: set[str] = set()
    declared_folders: set[str] = set()
    declared_crates: set[str] = set()
    declared_packages: set[str] = set()
    declared_examples: set[str] = set()
    declared_commands: set[str] = set()
    declared_concepts: set[str] = set()
    declared_relations: set[tuple[str, str, str]] = set()

    def declare_entity_once(entity_id: str, name: str, kind: str, path: str = "", summary: str = "") -> None:
        if entity_id in declared_entities:
            return
        declared_entities.add(entity_id)
        _declare_entity(entity_table, entity_id, name, kind, path, summary)

    def declare_relation_once(rel_name: str, from_id: str, to_id: str, rel: neo4j.RelationTarget[object]) -> None:
        key = (rel_name, from_id, to_id)
        if key in declared_relations:
            return
        declared_relations.add(key)
        rel.declare_relation(from_id=from_id, to_id=to_id)

    def declare_crate_once(crate_id: str, name: str, path: str, category: str) -> None:
        if crate_id in declared_crates:
            return
        declared_crates.add(crate_id)
        declare_entity_once(crate_id, name, "crate", path, "Rust workspace crate")
        crate_table.declare_record(row=ChioCrate(crate_id, name, path, category))

    for info, text in files:
        parts = pathlib.PurePath(info.path).parts
        parent_id = ""
        for index in range(1, len(parts)):
            folder_path = "/".join(parts[:index])
            folder_id = repo_model.entity_id("folder", folder_path)
            folder_name = parts[index - 1]
            if folder_id not in declared_folders:
                declared_folders.add(folder_id)
                declare_entity_once(folder_id, folder_name, "folder", folder_path, "Repository folder")
                folder_table.declare_record(
                    row=ChioFolder(folder_id, folder_name, folder_path, info.source_root)
                )
            if parent_id:
                declare_relation_once("CONTAINS", parent_id, folder_id, contains_rel)
            parent_id = folder_id

        crate_name = repo_model.cargo_package_name(info.path, text) or info.crate
        if crate_name:
            crate_id = repo_model.entity_id("crate", crate_name)
            declare_crate_once(crate_id, crate_name, info.path if info.path.endswith("Cargo.toml") else "", info.source_root)
            if info.path.endswith("Cargo.toml"):
                for dep_name in repo_model.cargo_dependency_names(text):
                    dep_id = repo_model.entity_id("crate", dep_name)
                    declare_crate_once(dep_id, dep_name, "", "dependency")
                    declare_relation_once("DEPENDS_ON", crate_id, dep_id, depends_on_rel)

        for import_root in repo_model.rust_import_roots(text):
            import_id = repo_model.entity_id("crate", import_root)
            declare_crate_once(import_id, import_root, "", "imported")

        for mentioned_name in repo_model.mentioned_crate_names(text):
            mentioned_id = repo_model.entity_id("crate", mentioned_name)
            declare_crate_once(mentioned_id, mentioned_name, "", "mentioned")

        if info.package:
            package_id = repo_model.entity_id("package", info.package)
            if package_id not in declared_packages:
                declared_packages.add(package_id)
                declare_entity_once(package_id, info.package, "package", info.path, "SDK or package surface")
                package_table.declare_record(row=ChioPackage(package_id, info.package, info.path, info.source_root))

        if info.kind == "example":
            example_name = "/".join(pathlib.PurePath(info.path).parts[:2])
            example_id = repo_model.entity_id("example", example_name)
            if example_id not in declared_examples:
                declared_examples.add(example_id)
                declare_entity_once(example_id, example_name, "example", info.path, "Runnable example")
                example_table.declare_record(row=ChioExample(example_id, example_name, info.path))

        for command in repo_model.extract_commands(text):
            command_id = repo_model.entity_id("command", command)
            if command_id not in declared_commands:
                declared_commands.add(command_id)
                declare_entity_once(command_id, command, "command", info.path, "Chio CLI command")
                command_table.declare_record(row=ChioCommand(command_id, command, info.path, "Chio CLI command mention"))

        for concept in repo_model.deterministic_concepts(text):
            if concept.id in declared_concepts:
                continue
            declared_concepts.add(concept.id)
            _declare_concept(
                entity_table,
                concept_table,
                policy_table,
                guard_table,
                receipt_table,
                protocol_table,
                concept,
                info.path,
            )


@coco.fn(memo=True)
async def extract_llm_graph(path: str, text: str) -> LlmExtraction:
    enabled = os.environ.get("CHIO_KB_LLM_EXTRACT", "1").lower() in {"1", "true", "yes"}
    if not enabled or not os.environ.get("OPENAI_API_KEY"):
        return LlmExtraction()

    import instructor
    import litellm

    litellm.drop_params = True
    client = instructor.from_litellm(litellm.acompletion, mode=instructor.Mode.JSON)
    prompt = (
        "Extract only source-supported Chio repository knowledge. "
        "Prefer protocol concepts, architecture decisions, guard and policy behavior, "
        "receipt and attestation facts, commands, standards, risks, and procedures. "
        "Do not infer facts that are not present in the text. "
        "Return compact names that will deduplicate well across docs."
    )
    result = await client.chat.completions.create(
        model=coco.use_context(LLM_MODEL),
        response_model=LlmExtraction,
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Path: {path}\n\n{text[:12000]}"},
        ],
    )
    return LlmExtraction.model_validate(result.model_dump())


@coco.fn
async def process_code_chunk(
    chunk: Chunk,
    info: repo_model.FileInfo,
    table: postgres.TableTarget[CodeChunk],
) -> None:
    symbols = repo_model.extract_symbols(info.path, chunk.text, limit=3)
    embedding = await coco.use_context(EMBEDDER).embed(chunk.text)
    table.declare_row(
        row=CodeChunk(
            id=repo_model.stable_id("code", info.path, str(chunk.start.line), chunk.text),
            file_path=info.path,
            normalized_path=info.path,
            source_root=info.source_root,
            language=info.language,
            crate=info.crate,
            package=info.package,
            kind=info.kind,
            symbol_hint=", ".join(symbols),
            content=chunk.text,
            embedding=embedding,
            start_line=chunk.start.line,
            end_line=chunk.end.line,
            source_hash=repo_model.content_hash(chunk.text),
            nearest_manifest=info.nearest_manifest,
            is_generated=info.is_generated,
            canonicality=info.canonicality,
            validation_command=info.validation_command,
        )
    )


@coco.fn
async def process_doc_chunk(
    chunk: Chunk,
    info: repo_model.FileInfo,
    table: postgres.TableTarget[DocChunk],
) -> None:
    section = repo_model.first_markdown_title(chunk.text, info.title or info.path)
    embedding = await coco.use_context(EMBEDDER).embed(chunk.text)
    table.declare_row(
        row=DocChunk(
            id=repo_model.stable_id("doc", info.path, str(chunk.start.line), chunk.text),
            file_path=info.path,
            normalized_path=info.path,
            source_root=info.source_root,
            doc_type=info.kind,
            title=info.title or section,
            section=section,
            anchor=repo_model.slug(section),
            text=chunk.text,
            embedding=embedding,
            start_line=chunk.start.line,
            end_line=chunk.end.line,
            source_hash=repo_model.content_hash(chunk.text),
            nearest_manifest=info.nearest_manifest,
            is_generated=info.is_generated,
            canonicality=info.canonicality,
            validation_command=info.validation_command,
        )
    )


@coco.fn(memo=True)
async def process_file_vectors(
    file: FileLike,
    code_table: postgres.TableTarget[CodeChunk],
    doc_table: postgres.TableTarget[DocChunk],
) -> None:
    path = repo_model.normalize_path(file.file_path.path)
    text = await file.read_text()
    info = repo_model.file_info(path, text)
    if len(text) > MAX_FILE_CHARS:
        return

    if repo_model.is_code_path(info.path):
        language = detect_code_language(filename=pathlib.PurePath(info.path).name)
        chunks = _splitter.split(
            text,
            chunk_size=1100,
            min_chunk_size=250,
            chunk_overlap=250,
            language=language,
        )
        await coco.map(process_code_chunk, chunks, info, code_table)

    if repo_model.is_docs_path(info.path):
        chunks = _splitter.split(
            text,
            chunk_size=1800,
            min_chunk_size=300,
            chunk_overlap=300,
            language="markdown",
        )
        await coco.map(process_doc_chunk, chunks, info, doc_table)


@coco.fn(memo=True)
async def process_file(
    file: FileLike,
    code_table: postgres.TableTarget[CodeChunk],
    doc_table: postgres.TableTarget[DocChunk],
    entity_table: neo4j.TableTarget[ChioEntity],
    file_table: neo4j.TableTarget[ChioFile],
    folder_table: neo4j.TableTarget[ChioFolder],
    crate_table: neo4j.TableTarget[ChioCrate],
    package_table: neo4j.TableTarget[ChioPackage],
    doc_node_table: neo4j.TableTarget[ChioDoc],
    spec_table: neo4j.TableTarget[ChioSpec],
    example_table: neo4j.TableTarget[ChioExample],
    test_table: neo4j.TableTarget[ChioTest],
    module_table: neo4j.TableTarget[ChioModule],
    symbol_table: neo4j.TableTarget[ChioSymbol],
    section_table: neo4j.TableTarget[ChioSection],
    command_table: neo4j.TableTarget[ChioCommand],
    concept_table: neo4j.TableTarget[ChioConcept],
    policy_table: neo4j.TableTarget[ChioPolicy],
    guard_table: neo4j.TableTarget[ChioGuard],
    receipt_table: neo4j.TableTarget[ChioReceipt],
    protocol_table: neo4j.TableTarget[ChioProtocol],
    standard_table: neo4j.TableTarget[ChioStandard],
    depends_on_rel: neo4j.RelationTarget[object],
    documented_in_rel: neo4j.RelationTarget[object],
    implements_rel: neo4j.RelationTarget[object],
    tested_by_rel: neo4j.RelationTarget[object],
    mentions_rel: neo4j.RelationTarget[object],
    defines_rel: neo4j.RelationTarget[object],
    guards_rel: neo4j.RelationTarget[object],
    validates_rel: neo4j.RelationTarget[object],
    supersedes_rel: neo4j.RelationTarget[object],
    contains_rel: neo4j.RelationTarget[object],
    imports_rel: neo4j.RelationTarget[object],
    calls_rel: neo4j.RelationTarget[object],
) -> None:
    path = repo_model.normalize_path(file.file_path.path)
    text = await file.read_text()
    info = repo_model.file_info(path, text)
    file_id = repo_model.file_entity_id(info.path)

    _declare_entity(entity_table, file_id, info.path, "file", info.path, f"{info.kind} file")
    file_table.declare_record(
        row=ChioFile(
            id=file_id,
            path=info.path,
            source_root=info.source_root,
            kind=info.kind,
            language=info.language,
            crate=info.crate,
            package=info.package,
        )
    )
    parent_parts = pathlib.PurePath(info.path).parts[:-1]
    if parent_parts:
        contains_rel.declare_relation(from_id=repo_model.entity_id("folder", "/".join(parent_parts)), to_id=file_id)

    doc_entity_id = ""
    if repo_model.is_docs_path(info.path):
        doc_entity_id = repo_model.entity_id(info.kind, info.path)
        title = info.title or pathlib.PurePath(info.path).stem
        _declare_entity(entity_table, doc_entity_id, title, info.kind, info.path, f"{info.kind} document")
        doc_node_table.declare_record(row=ChioDoc(doc_entity_id, title, info.path, info.kind))
        if info.kind == "spec":
            spec_table.declare_record(row=ChioSpec(doc_entity_id, title, info.path))
        if info.kind == "standard":
            standard_table.declare_record(row=ChioStandard(doc_entity_id, title, info.path, "Chio standard document"))
        defines_rel.declare_relation(from_id=file_id, to_id=doc_entity_id)

    crate_name = repo_model.cargo_package_name(info.path, text) or info.crate
    crate_entity_id = ""
    if crate_name:
        crate_entity_id = repo_model.entity_id("crate", crate_name)
        defines_rel.declare_relation(from_id=file_id, to_id=crate_entity_id)

    if info.package:
        package_id = repo_model.entity_id("package", info.package)
        defines_rel.declare_relation(from_id=file_id, to_id=package_id)

    if info.kind == "example":
        example_id = repo_model.entity_id("example", "/".join(pathlib.PurePath(info.path).parts[:2]))
        defines_rel.declare_relation(from_id=file_id, to_id=example_id)

    if info.kind == "test":
        test_id = repo_model.entity_id("test", info.path)
        _declare_entity(entity_table, test_id, info.path, "test", info.path, "Test or conformance fixture")
        test_table.declare_record(row=ChioTest(test_id, pathlib.PurePath(info.path).name, info.path))
        defines_rel.declare_relation(from_id=file_id, to_id=test_id)
        if info.crate:
            tested_by_rel.declare_relation(from_id=repo_model.entity_id("crate", info.crate), to_id=test_id)

    if len(text) <= MAX_FILE_CHARS:
        if repo_model.is_code_path(info.path):
            language = detect_code_language(filename=pathlib.PurePath(info.path).name)
            chunks = _splitter.split(
                text,
                chunk_size=1100,
                min_chunk_size=250,
                chunk_overlap=250,
                language=language,
            )
            await coco.map(process_code_chunk, chunks, info, code_table)

        if repo_model.is_docs_path(info.path):
            chunks = _splitter.split(
                text,
                chunk_size=1800,
                min_chunk_size=300,
                chunk_overlap=300,
                language="markdown",
            )
            await coco.map(process_doc_chunk, chunks, info, doc_table)

    parsed_symbols = repo_model.rust_symbol_records(info.path, text)
    for symbol in parsed_symbols:
        _declare_entity(
            entity_table,
            symbol.id,
            symbol.name,
            "symbol",
            info.path,
            f"Rust {symbol.symbol_kind}",
        )
        symbol_table.declare_record(
            row=ChioSymbol(
                id=symbol.id,
                name=symbol.name,
                symbol_kind=symbol.symbol_kind,
                path=info.path,
                language=info.language,
                start_line=symbol.start_line,
                end_line=symbol.end_line,
                signature=symbol.signature,
                source_hash=repo_model.content_hash(symbol.body),
            )
        )
        module_table.declare_record(row=ChioModule(symbol.id, symbol.name, info.path, info.language))
        defines_rel.declare_relation(from_id=file_id, to_id=symbol.id)
        contains_rel.declare_relation(from_id=file_id, to_id=symbol.id)
        if crate_entity_id:
            defines_rel.declare_relation(from_id=crate_entity_id, to_id=symbol.id)

    for source_id, target_id in repo_model.rust_symbol_calls(parsed_symbols):
        calls_rel.declare_relation(from_id=source_id, to_id=target_id)

    for import_root in repo_model.rust_import_roots(text):
        target_id = repo_model.entity_id("crate", import_root)
        imports_rel.declare_relation(from_id=file_id, to_id=target_id)

    for section in repo_model.markdown_sections(info.path, text):
        _declare_entity(entity_table, section.id, section.title, "section", info.path, "Markdown section")
        section_table.declare_record(
            row=ChioSection(
                id=section.id,
                title=section.title,
                path=info.path,
                level=section.level,
                start_line=section.start_line,
                end_line=section.end_line,
                anchor=section.anchor,
                source_hash=repo_model.content_hash(section.content),
            )
        )
        contains_rel.declare_relation(from_id=doc_entity_id or file_id, to_id=section.id)

    commands = repo_model.extract_commands(text)
    for command in commands:
        command_id = repo_model.entity_id("command", command)
        defines_rel.declare_relation(from_id=doc_entity_id or file_id, to_id=command_id)

    concepts = repo_model.deterministic_concepts(text)
    if repo_model.should_llm_extract(info.path):
        extracted = await extract_llm_graph(info.path, text)
        concepts.extend(_path_scoped_concept(_as_concept(concept), info.path) for concept in extracted.concepts)
    else:
        extracted = LlmExtraction()

    seen_concepts: set[str] = set()
    concept_ids: dict[str, str] = {}
    for concept in concepts:
        if concept.id in seen_concepts:
            continue
        seen_concepts.add(concept.id)
        concept_ids[concept.name.lower()] = concept.id
        if "@" in concept.id:
            _declare_concept(
                entity_table,
                concept_table,
                policy_table,
                guard_table,
                receipt_table,
                protocol_table,
                concept,
                info.path,
            )
        mentions_rel.declare_relation(from_id=doc_entity_id or file_id, to_id=concept.id)
        if info.kind == "test":
            validates_rel.declare_relation(from_id=repo_model.entity_id("test", info.path), to_id=concept.id)

    if "guard:guard" in seen_concepts and "policy:policy" in seen_concepts:
        guards_rel.declare_relation(from_id=repo_model.entity_id("guard", "Guard"), to_id=repo_model.entity_id("policy", "Policy"))

    if doc_entity_id:
        for concept in concepts:
            if concept.kind == "sdk" and info.path.startswith("docs/sdk/"):
                documented_in_rel.declare_relation(from_id=concept.id, to_id=doc_entity_id)
        for match_name in repo_model.mentioned_crate_names(text):
            crate_id = repo_model.entity_id("crate", match_name)
            documented_in_rel.declare_relation(from_id=repo_model.entity_id("crate", match_name), to_id=doc_entity_id)
        for target in repo_model.superseded_targets(text):
            supersedes_rel.declare_relation(from_id=doc_entity_id, to_id=repo_model.entity_id("doc", target))

    for relation in extracted.relations:
        source_id = concept_ids.get(relation.source.lower()) or f"topic:{repo_model.slug(relation.source)}@{repo_model.stable_id(info.path, relation.source)}"
        target_id = concept_ids.get(relation.target.lower()) or f"topic:{repo_model.slug(relation.target)}@{repo_model.stable_id(info.path, relation.target)}"
        if "@" in source_id and source_id not in seen_concepts:
            _declare_entity(entity_table, source_id, relation.source, "topic", info.path, relation.evidence)
        if "@" in target_id and target_id not in seen_concepts:
            _declare_entity(entity_table, target_id, relation.target, "topic", info.path, relation.evidence)
        rel = relation.relation.upper()
        if rel == "IMPLEMENTS":
            implements_rel.declare_relation(from_id=source_id, to_id=target_id)
        elif rel == "MENTIONS":
            mentions_rel.declare_relation(from_id=source_id, to_id=target_id)
        elif rel == "DEFINES":
            defines_rel.declare_relation(from_id=source_id, to_id=target_id)
        elif rel == "GUARDS":
            guards_rel.declare_relation(from_id=source_id, to_id=target_id)
        elif rel == "VALIDATES":
            validates_rel.declare_relation(from_id=source_id, to_id=target_id)
        elif rel == "SUPERSEDES":
            supersedes_rel.declare_relation(from_id=source_id, to_id=target_id)
        elif rel == "DOCUMENTED_IN":
            documented_in_rel.declare_relation(from_id=source_id, to_id=target_id)


async def _mount_node(label: str, row_type: type, primary_key: str = "id") -> neo4j.TableTarget[object]:
    return await neo4j.mount_table_target(
        KG_DB,
        label,
        await neo4j.TableSchema.from_class(row_type, primary_key=primary_key),
        primary_key=primary_key,
    )


@coco.fn
async def app_main(sourcedir: pathlib.Path) -> None:
    code_table = await postgres.mount_table_target(
        PG_DB,
        table_name=CODE_TABLE_NAME,
        table_schema=await postgres.TableSchema.from_class(CodeChunk, primary_key=["id"]),
        pg_schema_name=PG_SCHEMA_NAME,
    )
    code_table.declare_vector_index(column="embedding")

    doc_table = await postgres.mount_table_target(
        PG_DB,
        table_name=DOC_TABLE_NAME,
        table_schema=await postgres.TableSchema.from_class(DocChunk, primary_key=["id"]),
        pg_schema_name=PG_SCHEMA_NAME,
    )
    doc_table.declare_vector_index(column="embedding")

    matcher = PatternFilePathMatcher(
        included_patterns=repo_model.INCLUDED_PATTERNS,
        excluded_patterns=repo_model.EXCLUDED_PATTERNS,
    )
    files = localfs.walk_dir(
        sourcedir,
        recursive=True,
        live=os.environ.get("CHIO_KB_LIVE", "0") == "1",
        path_matcher=matcher,
    )
    await coco.mount_each(process_file_vectors, files.items(), code_table, doc_table)

    entity_table = await _mount_node("ChioEntity", ChioEntity)
    file_table = await _mount_node("ChioFile", ChioFile)
    folder_table = await _mount_node("ChioFolder", ChioFolder)
    crate_table = await _mount_node("ChioCrate", ChioCrate)
    package_table = await _mount_node("ChioPackage", ChioPackage)
    doc_node_table = await _mount_node("ChioDoc", ChioDoc)
    spec_table = await _mount_node("ChioSpec", ChioSpec)
    example_table = await _mount_node("ChioExample", ChioExample)
    test_table = await _mount_node("ChioTest", ChioTest)
    module_table = await _mount_node("ChioModule", ChioModule)
    symbol_table = await _mount_node("ChioSymbol", ChioSymbol)
    section_table = await _mount_node("ChioSection", ChioSection)
    command_table = await _mount_node("ChioCommand", ChioCommand)
    concept_table = await _mount_node("ChioConcept", ChioConcept)
    policy_table = await _mount_node("ChioPolicy", ChioPolicy)
    guard_table = await _mount_node("ChioGuard", ChioGuard)
    receipt_table = await _mount_node("ChioReceipt", ChioReceipt)
    protocol_table = await _mount_node("ChioProtocol", ChioProtocol)
    standard_table = await _mount_node("ChioStandard", ChioStandard)

    depends_on_rel = await neo4j.mount_relation_target(KG_DB, "DEPENDS_ON", entity_table, entity_table)
    documented_in_rel = await neo4j.mount_relation_target(KG_DB, "DOCUMENTED_IN", entity_table, entity_table)
    implements_rel = await neo4j.mount_relation_target(KG_DB, "IMPLEMENTS", entity_table, entity_table)
    tested_by_rel = await neo4j.mount_relation_target(KG_DB, "TESTED_BY", entity_table, entity_table)
    mentions_rel = await neo4j.mount_relation_target(KG_DB, "MENTIONS", entity_table, entity_table)
    defines_rel = await neo4j.mount_relation_target(KG_DB, "DEFINES", entity_table, entity_table)
    guards_rel = await neo4j.mount_relation_target(KG_DB, "GUARDS", entity_table, entity_table)
    validates_rel = await neo4j.mount_relation_target(KG_DB, "VALIDATES", entity_table, entity_table)
    supersedes_rel = await neo4j.mount_relation_target(KG_DB, "SUPERSEDES", entity_table, entity_table)
    contains_rel = await neo4j.mount_relation_target(KG_DB, "CONTAINS", entity_table, entity_table)
    imports_rel = await neo4j.mount_relation_target(KG_DB, "IMPORTS", entity_table, entity_table)
    calls_rel = await neo4j.mount_relation_target(KG_DB, "CALLS", entity_table, entity_table)

    indexed_files = repo_model.iter_indexed_files(sourcedir)
    _declare_shared_graph_catalog(
        indexed_files,
        entity_table,
        folder_table,
        crate_table,
        package_table,
        example_table,
        command_table,
        concept_table,
        policy_table,
        guard_table,
        receipt_table,
        protocol_table,
        contains_rel,
        depends_on_rel,
    )

    matcher = PatternFilePathMatcher(
        included_patterns=repo_model.INCLUDED_PATTERNS,
        excluded_patterns=repo_model.EXCLUDED_PATTERNS,
    )
    files = localfs.walk_dir(
        sourcedir,
        recursive=True,
        live=os.environ.get("CHIO_KB_LIVE", "0") == "1",
        path_matcher=matcher,
    )
    await coco.mount_each(
        process_file,
        files.items(),
        code_table,
        doc_table,
        entity_table,
        file_table,
        folder_table,
        crate_table,
        package_table,
        doc_node_table,
        spec_table,
        example_table,
        test_table,
        module_table,
        symbol_table,
        section_table,
        command_table,
        concept_table,
        policy_table,
        guard_table,
        receipt_table,
        protocol_table,
        standard_table,
        depends_on_rel,
        documented_in_rel,
        implements_rel,
        tested_by_rel,
        mentions_rel,
        defines_rel,
        guards_rel,
        validates_rel,
        supersedes_rel,
        contains_rel,
        imports_rel,
        calls_rel,
    )


app = coco.App(
    coco.AppConfig(
        name="ChioKnowledgeBase",
        max_inflight_components=int(os.environ.get("CHIO_KB_MAX_INFLIGHT_COMPONENTS", "8")),
    ),
    app_main,
    sourcedir=REPO_ROOT,
)


async def update_index() -> None:
    async with coco.runtime():
        await coco.show_progress(app.update())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "root":
        print(REPO_ROOT)
    else:
        asyncio.run(update_index())
