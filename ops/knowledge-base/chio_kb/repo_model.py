"""Repository classification and deterministic graph helpers."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import pathlib
import re
import tomllib
from dataclasses import dataclass
from typing import Any

SOURCE_ROOTS = (
    "crates",
    "docs",
    "spec",
    "examples",
    "packages",
    "sdks",
    "integrations",
    "tests",
    "formal",
    "bench",
    ".planning",
)

INCLUDED_PATTERNS = [
    "crates/**/*.rs",
    "crates/**/Cargo.toml",
    "crates/**/*.md",
    "crates/**/*.wit",
    "docs/**/*.md",
    "docs/**/*.json",
    "docs/**/*.yaml",
    "docs/**/*.yml",
    "spec/**/*.md",
    "spec/**/*.json",
    "spec/**/*.yaml",
    "spec/**/*.yml",
    "examples/**/*.rs",
    "examples/**/*.py",
    "examples/**/*.ts",
    "examples/**/*.tsx",
    "examples/**/*.js",
    "examples/**/*.json",
    "examples/**/*.yaml",
    "examples/**/*.yml",
    "examples/**/*.toml",
    "examples/**/*.md",
    "packages/**/*.rs",
    "packages/**/*.py",
    "packages/**/*.ts",
    "packages/**/*.tsx",
    "packages/**/*.js",
    "packages/**/*.json",
    "packages/**/*.yaml",
    "packages/**/*.yml",
    "packages/**/*.toml",
    "packages/**/*.md",
    "packages/**/*.cpp",
    "packages/**/*.hpp",
    "packages/**/*.h",
    "packages/**/*.cc",
    "sdks/**/*.rs",
    "sdks/**/*.py",
    "sdks/**/*.ts",
    "sdks/**/*.tsx",
    "sdks/**/*.js",
    "sdks/**/*.json",
    "sdks/**/*.yaml",
    "sdks/**/*.yml",
    "sdks/**/*.toml",
    "sdks/**/*.md",
    "sdks/**/*.go",
    "sdks/**/*.cs",
    "sdks/**/*.swift",
    "integrations/**/*.rs",
    "integrations/**/*.py",
    "integrations/**/*.json",
    "integrations/**/*.yaml",
    "integrations/**/*.yml",
    "integrations/**/*.toml",
    "integrations/**/*.md",
    "tests/**/*.rs",
    "tests/**/*.py",
    "tests/**/*.json",
    "tests/**/*.yaml",
    "tests/**/*.yml",
    "tests/**/*.toml",
    "tests/**/*.md",
    "formal/**/*.rs",
    "formal/**/*.toml",
    "formal/**/*.md",
    "formal/**/*.json",
    "formal/**/*.yaml",
    "formal/**/*.yml",
    "bench/**/*.rs",
    "bench/**/*.toml",
    "bench/**/*.md",
    ".planning/**/*.md",
    ".planning/**/*.json",
    ".planning/**/*.yaml",
    ".planning/**/*.yml",
]

EXCLUDED_PATTERNS = [
    ".git/**",
    "target/**",
    "**/target/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/.venv/**",
    "**/__pycache__/**",
    "coverage/**",
    "fuzz/artifacts/**",
    "fuzz/coverage/**",
    "tests/conformance/results/generated/**",
    "tests/conformance/reports/generated/**",
    "examples/**/.artifacts/**",
    "examples/**/artifacts/live/**",
    "output/playwright/**",
    ".planning/**/EXECUTION-LOG*.ndjson",
    ".planning/**/raw/**",
    ".env",
    ".env.*",
]

CODE_SUFFIXES = {
    ".rs",
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".go",
    ".cpp",
    ".cc",
    ".cxx",
    ".hpp",
    ".h",
    ".cs",
    ".swift",
    ".sh",
    ".sql",
    ".wit",
}

DOC_SUFFIXES = {".md", ".mdx"}
CONFIG_SUFFIXES = {".toml", ".json", ".yaml", ".yml"}

CONCEPT_RULES = [
    ("capability", "Capability", r"\bcapabilit(?:y|ies)|capability token|grant\b"),
    ("guard", "Guard", r"\bguard(?:s|ed)?\b|redactor|redaction"),
    ("policy", "Policy", r"\bpolic(?:y|ies)\b|authorization|deny|allow"),
    ("receipt", "Receipt", r"\breceipt(?:s)?\b|merkle|append-only|signed decision"),
    ("attestation", "Attestation", r"\battestation|attested|tee|nitro|enclave\b"),
    ("kernel", "Runtime Kernel", r"\bkernel\b|trusted mediator|tcb"),
    ("mcp", "MCP", r"\bmcp\b|model context protocol"),
    ("a2a", "A2A", r"\ba2a\b|agent2agent"),
    ("acp", "ACP", r"\bacp\b|agent communication protocol"),
    ("openapi", "OpenAPI", r"\bopenapi\b|swagger"),
    ("manifest", "Manifest", r"\bmanifest(?:s)?\b"),
    ("settlement", "Settlement", r"\bsettle(?:ment)?\b|payment|credit|market"),
    ("identity", "Identity", r"\bdid\b|credential|federation|reputation"),
    ("control-plane", "Control Plane", r"\bcontrol plane\b|trust control"),
    ("conformance", "Conformance", r"\bconformance\b|qualification|verdict"),
    ("sdk", "SDK", r"\bsdk\b|bindings?|ffi"),
]

SCOPED_CONCEPT_RULES = [
    (
        "capability:kernel-validation",
        "Capability kernel validation",
        "capability",
        "Capability validation behavior in the runtime kernel.",
        ("crates/chio-kernel", "crates/chio-kernel-core", "spec/PROTOCOL.md"),
        r"\bcapabilit(?:y|ies)\b|delegat|revocation|scope|token",
    ),
    (
        "capability:core-types",
        "Capability core types",
        "capability",
        "Capability token and grant data model in core types.",
        ("crates/chio-core", "crates/chio-core-types", "spec/PROTOCOL.md"),
        r"\bcapabilit(?:y|ies)\b|grant|attenuat|delegat",
    ),
    (
        "capability:conformance",
        "Capability conformance",
        "capability",
        "Capability behavior covered by conformance and replay fixtures.",
        ("crates/chio-conformance", "tests/conformance", "tests/replay"),
        r"\bcapabilit(?:y|ies)\b|revocation|scope|verdict|conformance",
    ),
    (
        "receipt:protocol",
        "Receipt protocol",
        "receipt",
        "Receipt protocol contract, checkpoint, and Merkle proof behavior.",
        ("spec/PROTOCOL.md", "spec/schemas", "docs/protocols", "docs/conformance"),
        r"\breceipt(?:s)?\b|merkle|checkpoint|signed decision|inclusion proof",
    ),
    (
        "receipt:storage",
        "Receipt storage",
        "receipt",
        "Receipt persistence and evidence export storage behavior.",
        ("crates/chio-store-sqlite", "crates/chio-cli", "docs"),
        r"\breceipt(?:s)?\b|store|storage|checkpoint|evidence",
    ),
    (
        "receipt:lineage",
        "Receipt lineage",
        "receipt",
        "Receipt lineage, parent receipt, and provenance behavior.",
        ("crates", "docs", "spec"),
        r"\breceipt(?:s)?\b.*\blineage\b|\blineage\b.*\breceipt(?:s)?\b|parentReceipt",
    ),
    (
        "policy:compiler",
        "Policy compiler",
        "policy",
        "Policy compiler and policy schema behavior.",
        ("crates/chio-policy", "docs/guards", "spec"),
        r"\bpolic(?:y|ies)\b|compiler|compile_policy|schema",
    ),
    (
        "policy:runtime",
        "Policy runtime",
        "policy",
        "Runtime policy evaluation and fail-closed behavior.",
        ("crates/chio-kernel", "crates/chio-guards", "crates/chio-policy", "docs"),
        r"\bpolic(?:y|ies)\b|deny|allow|fail-closed|guard",
    ),
    (
        "guard:pipeline",
        "Guard pipeline",
        "guard",
        "Guard pipeline evaluation and composition behavior.",
        ("crates/chio-guards", "crates/chio-kernel", "docs/guards"),
        r"\bguard(?:s|ed)?\b|pipeline|redact|sanitize",
    ),
    (
        "guard:data",
        "Data guard",
        "guard",
        "Data guard behavior for warehouse and data-access controls.",
        ("crates/chio-data-guards", "docs/guards"),
        r"\bguard(?:s|ed)?\b|warehouse|data|redact|sanitize",
    ),
    (
        "guard:wasm",
        "Wasm guard",
        "guard",
        "Wasm guard runtime and guard SDK behavior.",
        ("crates/chio-wasm-guards", "crates/chio-guard-sdk", "docs/guards"),
        r"\bguard(?:s|ed)?\b|wasm|wit|component",
    ),
]

COMMAND_RE = re.compile(r"\bchio\s+[a-z][a-z0-9_-]*(?:\s+[a-z][a-z0-9_-]*){0,2}")
CRATE_MENTION_RE = re.compile(r"\b(?:chio|arc)-[a-z0-9][a-z0-9_-]*\b")
RUST_SYMBOL_RE = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?"
    r"(?:fn|struct|enum|trait|type|mod)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
RUST_SYMBOL_DECL_RE = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?"
    r"(?P<kind>fn|struct|enum|trait|type|mod)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"|^\s*(?P<impl>impl)\s+(?P<impl_name>[A-Za-z_][A-Za-z0-9_:<>]*)"
)
MARKDOWN_HEADING_RE = re.compile(r"(?m)^(#{1,6})\s+(.+?)\s*$")
SUPERSEDES_RE = re.compile(r"\bsupersedes?\s+`?([A-Za-z0-9_./-]+)`?", re.IGNORECASE)
RUST_USE_RE = re.compile(r"(?m)^\s*(?:pub\s+)?use\s+([A-Za-z_][A-Za-z0-9_:]*)")


@dataclass(frozen=True)
class FileInfo:
    path: str
    source_root: str
    language: str
    crate: str
    package: str
    kind: str
    title: str
    nearest_manifest: str
    is_generated: bool
    canonicality: str
    validation_command: str


@dataclass(frozen=True)
class Concept:
    id: str
    name: str
    kind: str
    summary: str


@dataclass(frozen=True)
class SymbolRecord:
    id: str
    name: str
    symbol_kind: str
    path: str
    start_line: int
    end_line: int
    signature: str
    body: str


@dataclass(frozen=True)
class SectionRecord:
    id: str
    title: str
    path: str
    level: int
    start_line: int
    end_line: int
    anchor: str
    content: str


def repo_root_from_env() -> pathlib.Path:
    configured = os.environ.get("CHIO_KB_REPO_ROOT")
    if configured:
        return pathlib.Path(configured).resolve()
    return pathlib.Path(__file__).resolve().parents[3]


def normalize_path(path: pathlib.PurePath | str) -> str:
    raw_input = str(path).replace("\\", "/").strip()
    if raw_input in {"", ".", "./"}:
        return ""
    raw = pathlib.PurePath(raw_input).as_posix().replace("\\", "/").strip()
    raw = raw.removeprefix("file://")

    prefixes: list[str] = []
    configured = os.environ.get("CHIO_KB_REPO_ROOT")
    if configured:
        prefixes.append(pathlib.PurePath(configured).as_posix())
    try:
        prefixes.append(pathlib.Path(__file__).resolve().parents[3].as_posix())
    except IndexError:
        pass
    try:
        prefixes.append(pathlib.Path.cwd().resolve().as_posix())
    except OSError:
        pass
    prefixes.extend(("/workspace", "workspace"))

    for prefix in sorted({p.rstrip("/") for p in prefixes if p}, key=len, reverse=True):
        if raw == prefix:
            raw = ""
            break
        if raw.startswith(prefix + "/"):
            raw = raw[len(prefix) + 1 :]
            break

    raw = raw.lstrip("/")
    while raw.startswith("./"):
        raw = raw[2:]
    if raw.startswith("workspace/"):
        raw = raw.removeprefix("workspace/")
    return raw


def source_root(path: str) -> str:
    first = path.split("/", 1)[0]
    return first if first in SOURCE_ROOTS else "other"


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or "unknown"


def stable_id(*parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:20]
    return digest


def entity_id(kind: str, name: str) -> str:
    return f"{slug(kind)}:{slug(name)}"


def file_entity_id(path: str) -> str:
    return f"file:{path}"


def language_for_path(path: str) -> str:
    suffix = pathlib.PurePath(path).suffix.lower()
    if suffix == ".rs":
        return "rust"
    if suffix == ".toml":
        return "toml"
    if suffix == ".wit":
        return "wit"
    if suffix == ".py":
        return "python"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix == ".js":
        return "javascript"
    if suffix == ".go":
        return "go"
    if suffix in {".cpp", ".cc", ".cxx", ".hpp", ".h"}:
        return "cpp"
    if suffix == ".cs":
        return "csharp"
    if suffix == ".swift":
        return "swift"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".json":
        return "json"
    if suffix in {".md", ".mdx"}:
        return "markdown"
    if suffix == ".sql":
        return "sql"
    if suffix == ".sh":
        return "shell"
    return suffix.lstrip(".") or "text"


def kind_for_path(path: str) -> str:
    pure = pathlib.PurePath(path)
    suffix = pure.suffix.lower()
    parts = pure.parts
    if path.endswith("Cargo.toml"):
        return "manifest"
    if "tests" in parts or pure.name.endswith(("_test.rs", "_tests.rs")):
        return "test"
    if parts and parts[0] == "examples":
        return "example"
    if parts and parts[0] == "spec":
        return "spec"
    if parts and parts[0] == "docs":
        if len(parts) > 1 and parts[1] == "standards":
            return "standard"
        return "doc"
    if parts and parts[0] == ".planning":
        return "plan"
    if suffix in DOC_SUFFIXES:
        return "doc"
    if suffix in CONFIG_SUFFIXES:
        return "config"
    if suffix in CODE_SUFFIXES:
        return "code"
    return "file"


def crate_for_path(path: str) -> str:
    parts = pathlib.PurePath(path).parts
    if len(parts) >= 2 and parts[0] == "crates":
        return parts[1]
    if len(parts) >= 3 and parts[0] in {"examples", "bench", "integrations"}:
        return parts[1]
    return ""


def package_for_path(path: str) -> str:
    parts = pathlib.PurePath(path).parts
    if len(parts) >= 3 and parts[0] == "packages":
        return "/".join(parts[:3])
    if len(parts) >= 2 and parts[0] == "sdks":
        return "/".join(parts[:2])
    return ""


def nearest_manifest_for_path(path: str) -> str:
    norm = normalize_path(path)
    parts = pathlib.PurePath(norm).parts
    if norm.endswith("Cargo.toml"):
        return norm
    if len(parts) >= 2 and parts[0] == "crates":
        return f"crates/{parts[1]}/Cargo.toml"
    if len(parts) >= 3 and parts[0] == "tests":
        return f"tests/{parts[1]}/Cargo.toml"
    if len(parts) >= 2 and parts[0] in {"examples", "bench", "integrations", "formal"}:
        return f"{parts[0]}/{parts[1]}/Cargo.toml"
    if len(parts) >= 3 and parts[0] == "packages":
        return f"{parts[0]}/{parts[1]}/{parts[2]}/package.json"
    if len(parts) >= 2 and parts[0] == "sdks":
        return f"{parts[0]}/{parts[1]}"
    return ""


def is_generated_path(path: str) -> bool:
    parts = pathlib.PurePath(normalize_path(path)).parts
    lowered = [part.lower() for part in parts]
    return any(part in {"_generated", "generated", "gen"} for part in lowered) or any(
        part.endswith(".generated.rs") for part in lowered
    )


def canonicality_for_path(path: str) -> str:
    norm = normalize_path(path)
    parts = pathlib.PurePath(norm).parts
    if is_generated_path(norm):
        return "generated"
    if norm == "spec/PROTOCOL.md":
        return "canonical"
    if norm == "docs/README.md":
        return "canonical"
    if norm.startswith("docs/conformance/"):
        return "canonical"
    if norm.startswith("spec/schemas/"):
        return "canonical"
    if len(parts) >= 3 and parts[0] == "crates" and parts[-1].lower() == "readme.md":
        return "canonical"
    if parts and parts[0] == ".planning":
        return "planning"
    if norm.startswith("docs/research/") or norm.startswith("docs/review/"):
        return "planning"
    if kind_for_path(norm) == "test":
        return "test"
    return "source"


def validation_command_for_path(path: str) -> str:
    norm = normalize_path(path)
    parts = pathlib.PurePath(norm).parts
    crate = crate_for_path(norm)
    if crate and parts and parts[0] == "crates":
        return f"cargo test -p {crate}"
    if len(parts) >= 2 and parts[0] == "tests" and (pathlib.PurePath(norm).suffix == ".rs" or "Cargo.toml" in norm):
        return f"cargo test --manifest-path tests/{parts[1]}/Cargo.toml"
    if norm.startswith("spec/") or norm.startswith("docs/conformance/"):
        return "cargo test -p chio-conformance"
    if norm.startswith("docs/") or norm.startswith(".planning/"):
        return "make kb-eval"
    if norm.startswith("sdks/typescript/") or norm.startswith("packages/"):
        return "npm test"
    if norm.startswith("sdks/python/"):
        return "pytest"
    return ""


def first_markdown_title(text: str, fallback: str) -> str:
    match = MARKDOWN_HEADING_RE.search(text)
    if match:
        return match.group(2).strip().strip("#").strip()
    return pathlib.PurePath(fallback).stem.replace("-", " ").replace("_", " ").strip()


def file_info(path: pathlib.PurePath | str, text: str = "") -> FileInfo:
    norm = normalize_path(path)
    title = first_markdown_title(text, norm) if pathlib.PurePath(norm).suffix.lower() in DOC_SUFFIXES else ""
    return FileInfo(
        path=norm,
        source_root=source_root(norm),
        language=language_for_path(norm),
        crate=crate_for_path(norm),
        package=package_for_path(norm),
        kind=kind_for_path(norm),
        title=title,
        nearest_manifest=nearest_manifest_for_path(norm),
        is_generated=is_generated_path(norm),
        canonicality=canonicality_for_path(norm),
        validation_command=validation_command_for_path(norm),
    )


def is_code_path(path: str) -> bool:
    suffix = pathlib.PurePath(path).suffix.lower()
    return suffix in CODE_SUFFIXES or path.endswith("Cargo.toml")


def is_docs_path(path: str) -> bool:
    suffix = pathlib.PurePath(path).suffix.lower()
    return suffix in DOC_SUFFIXES or kind_for_path(path) in {"doc", "spec", "standard", "plan"}


def should_llm_extract(path: str) -> bool:
    pure = pathlib.PurePath(path)
    parts = pure.parts
    if pure.name.lower() == "readme.md" and parts and parts[0] == "crates":
        return True
    return bool(parts and parts[0] in {"docs", "spec", ".planning"} and pure.suffix.lower() in DOC_SUFFIXES)


def load_cargo_manifest(text: str) -> dict[str, Any]:
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def cargo_package_name(path: str, text: str) -> str:
    if not path.endswith("Cargo.toml"):
        return ""
    package = load_cargo_manifest(text).get("package")
    if isinstance(package, dict):
        name = package.get("name")
        if isinstance(name, str):
            return name
    return crate_for_path(path)


def cargo_dependency_names(text: str) -> list[str]:
    manifest = load_cargo_manifest(text)
    names: set[str] = set()
    for section in (
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "workspace.dependencies",
    ):
        cursor: Any = manifest
        for part in section.split("."):
            cursor = cursor.get(part) if isinstance(cursor, dict) else None
        if isinstance(cursor, dict):
            for name in cursor:
                if name.startswith(("chio-", "arc-")):
                    names.add(name)
    return sorted(names)


def mentioned_crate_names(text: str, limit: int = 100) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for match in CRATE_MENTION_RE.finditer(text):
        name = match.group(0).replace("_", "-")
        if name not in seen:
            seen.add(name)
            names.append(name)
        if len(names) >= limit:
            break
    return names


def extract_symbols(path: str, text: str, limit: int = 50) -> list[str]:
    if language_for_path(path) != "rust":
        return []
    seen: set[str] = set()
    symbols: list[str] = []
    for match in RUST_SYMBOL_RE.finditer(text):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            symbols.append(name)
        if len(symbols) >= limit:
            break
    return symbols


def rust_symbol_records(path: str, text: str, limit: int = 500) -> list[SymbolRecord]:
    if language_for_path(path) != "rust":
        return []
    matches = list(RUST_SYMBOL_DECL_RE.finditer(text))
    records: list[SymbolRecord] = []
    for index, match in enumerate(matches[:limit]):
        kind = match.group("kind") or match.group("impl") or "symbol"
        name = match.group("name") or match.group("impl_name") or "impl"
        start_offset = match.start()
        end_offset = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        start_line = text.count("\n", 0, start_offset) + 1
        end_line = text.count("\n", 0, end_offset) + 1
        signature_end = text.find("\n", start_offset)
        if signature_end == -1:
            signature_end = min(len(text), start_offset + 200)
        signature = text[start_offset:signature_end].strip()
        display_name = f"impl {name}" if kind == "impl" else name
        records.append(
            SymbolRecord(
                id=entity_id("symbol", f"{path}::{display_name}@{start_line}"),
                name=display_name,
                symbol_kind=kind,
                path=path,
                start_line=start_line,
                end_line=end_line,
                signature=signature[:500],
                body=text[start_offset:end_offset],
            )
        )
    return records


def rust_import_roots(text: str, limit: int = 200) -> list[str]:
    roots: list[str] = []
    seen: set[str] = set()
    for match in RUST_USE_RE.finditer(text):
        raw = match.group(1)
        root = raw.split("::", 1)[0].replace("_", "-")
        if root in {"crate", "self", "super"}:
            continue
        if root.startswith(("chio-", "arc-")) and root not in seen:
            seen.add(root)
            roots.append(root)
        if len(roots) >= limit:
            break
    return roots


def rust_symbol_calls(symbols: list[SymbolRecord], limit: int = 1000) -> list[tuple[str, str]]:
    by_name: dict[str, SymbolRecord] = {}
    for symbol in symbols:
        if symbol.symbol_kind == "fn":
            by_name.setdefault(symbol.name, symbol)

    calls: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for source in symbols:
        for name, target in by_name.items():
            if source.id == target.id:
                continue
            if re.search(rf"\b{re.escape(name)}\s*\(", source.body):
                pair = (source.id, target.id)
                if pair not in seen:
                    seen.add(pair)
                    calls.append(pair)
            if len(calls) >= limit:
                return calls
    return calls


def markdown_sections(path: str, text: str, limit: int = 500) -> list[SectionRecord]:
    if pathlib.PurePath(path).suffix.lower() not in DOC_SUFFIXES:
        return []
    matches = list(MARKDOWN_HEADING_RE.finditer(text))
    sections: list[SectionRecord] = []
    for index, match in enumerate(matches[:limit]):
        title = match.group(2).strip()
        start_offset = match.start()
        end_offset = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        start_line = text.count("\n", 0, start_offset) + 1
        end_line = text.count("\n", 0, end_offset) + 1
        level = len(match.group(1))
        content = text[start_offset:end_offset].strip()
        sections.append(
            SectionRecord(
                id=entity_id("section", f"{path}#{slug(title)}@{start_line}"),
                title=title,
                path=path,
                level=level,
                start_line=start_line,
                end_line=end_line,
                anchor=slug(title),
                content=content,
            )
        )
    return sections


def extract_commands(text: str, limit: int = 25) -> list[str]:
    seen: set[str] = set()
    commands: list[str] = []
    for match in COMMAND_RE.finditer(text):
        command = re.sub(r"\s+", " ", match.group(0).strip())
        if command not in seen:
            seen.add(command)
            commands.append(command)
        if len(commands) >= limit:
            break
    return commands


def deterministic_concepts(text: str) -> list[Concept]:
    concepts: list[Concept] = []
    lower = text.lower()
    for kind, name, pattern in CONCEPT_RULES:
        if re.search(pattern, lower, re.IGNORECASE):
            concepts.append(
                Concept(
                    id=entity_id(kind, name),
                    name=name,
                    kind=kind,
                    summary=f"Detected repository concept: {name}.",
                )
            )
    return concepts


def scoped_concepts(path: str, text: str) -> list[Concept]:
    norm = normalize_path(path)
    lower = text.lower()
    concepts: list[Concept] = []
    for concept_id, name, kind, summary, prefixes, pattern in SCOPED_CONCEPT_RULES:
        if not any(norm == prefix or norm.startswith(prefix.rstrip("/") + "/") for prefix in prefixes):
            continue
        if re.search(pattern, lower, re.IGNORECASE):
            concepts.append(Concept(id=concept_id, name=name, kind=kind, summary=summary))
    return concepts


def superseded_targets(text: str) -> list[str]:
    return [match.group(1) for match in SUPERSEDES_RE.finditer(text)]


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def is_excluded(path: str) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in EXCLUDED_PATTERNS)


def is_included(path: str) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in INCLUDED_PATTERNS)


def iter_indexed_files(root: pathlib.Path) -> list[tuple[FileInfo, str]]:
    files: list[tuple[FileInfo, str]] = []
    for source in SOURCE_ROOTS:
        source_path = root / source
        if not source_path.exists():
            continue
        for file_path in source_path.rglob("*"):
            if not file_path.is_file():
                continue
            rel_path = normalize_path(file_path.relative_to(root))
            if is_excluded(rel_path) or not is_included(rel_path):
                continue
            try:
                text = file_path.read_text(errors="replace")
            except OSError:
                continue
            files.append((file_info(rel_path, text), text))
    return files
