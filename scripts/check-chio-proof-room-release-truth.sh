#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 2
fi

python3 - <<'PY'
from __future__ import annotations

import json
import os
import re
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
TRUTH_PATH = Path(
    os.environ.get(
        "CHIO_PROOF_ROOM_RELEASE_TRUTH",
        "fixtures/proof-room/first-run/single-call-authority/release-truth.json",
    )
)
BUNDLE_TRUTH_PATH = Path(
    os.environ.get(
        "CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH",
        "fixtures/proof-room/first-run/single-call-authority/"
        "proof-room-bundle/artifacts/release/release-truth.json",
    )
)
BUNDLE_MANIFEST_PATH = Path(
    os.environ.get(
        "CHIO_PROOF_ROOM_BUNDLE_MANIFEST",
        "fixtures/proof-room/first-run/single-call-authority/proof-room-bundle/manifest.json",
    )
)
SCHEMA_REGISTRY_PATH = Path(
    os.environ.get(
        "CHIO_PROOF_ROOM_SCHEMA_REGISTRY",
        "spec/schemas/registry.json",
    )
)
PROOF_ROOM_BUNDLE_SCHEMA = "chio.proof-room.bundle.v1"
RELEASE_TRUTH_SCHEMA = "chio.proof.release-truth.v1"
RELEASE_TRUTH_RENDERER_HINT = "release-truth"
DOCKER_EVIDENCE_SCHEMA = "chio.proof.docker-quickstart-evidence.v1"
DOCKER_EVIDENCE_RENDERER_HINT = "docker-quickstart-evidence"
REQUIRED_DOCKER_ENDPOINTS = {
    "/manifest.json": "chio.proof-room.bundle.v1",
    "/ui/proof-room-static/load-report.json": "chio.proof-room.verifier-report.v1",
    "/proof-room-fixture-catalog.json": "chio.proof-room.fixture-catalog.v1",
    "/proof-room-fixtures/minimal-passport-valid/verifier-report.json": (
        "chio.transaction.verifier-report.v1"
    ),
    "/proof-room-fixtures/minimal-passport-valid/transaction-passport.json": (
        "passport-minimal-valid"
    ),
    "/proof-room-fixtures/commerce-offline-psp/verifier-report.json": (
        "chio.commerce.order-passport.v1"
    ),
    "/?view=proof-room": "Chio",
}
DEFAULT_DOCS = (
    "README.md",
    "docs",
    "spec/PROTOCOL.md",
)
DEFAULT_CLAIM_DOCS = (
    "README.md",
    "docs/README.md",
    "docs/start-here",
    "docs/release",
    "spec/PROTOCOL.md",
)
DEFAULT_DOC_EXCLUDES = (
    "docs/adr/",
    "docs/operations/",
    "docs/papers/",
    "docs/research/",
)

ALLOW_CONTEXT_RE = re.compile(
    r"\b("
    r"blocked|cannot|does not|false|hold|not|not yet|unavailable|unpublished|"
    r"pre-release|must not|no |without|until|never|beyond|bounded|deferred|"
    r"unsupported|excluded|exclusion"
    r")\b",
    re.IGNORECASE,
)
CLAUSE_BOUNDARY_RE = re.compile(r"[.;!?]")

CLAIM_PATTERNS = {
    "public_release": (
        re.compile(r"\b(public release is available|GA release|tagged release)\b", re.IGNORECASE),
        "public release claim requires release-truth public_release=true",
    ),
    "package_published": (
        re.compile(
            r"\b("
            r"published (?:npm|PyPI|Homebrew|crate|binary|package)|"
            r"(?:npm|PyPI|Homebrew|crate|binary|package) (?:is )?published|"
            r"pip install chio|npm install @chio"
            r")\b",
            re.IGNORECASE,
        ),
        "package publication claim requires release-truth package_published=true",
    ),
    "docker_quickstart": (
        re.compile(
            r"\b("
            r"Docker quickstart is (?:release-qualified|verified|public-proof-certified)|"
            r"release-qualified Docker quickstart|"
            r"Docker image is published"
            r")\b",
            re.IGNORECASE,
        ),
        "Docker availability claim requires release-truth docker_quickstart=true",
    ),
    "hosted_demo": (
        re.compile(r"\b(hosted Proof Room is live|hosted demo is live)\b", re.IGNORECASE),
        "hosted demo claim requires release-truth hosted_demo=true",
    ),
    "chain_evidence": (
        re.compile(
            r"\b(on-chain proof is published|chain transaction is published)\b",
            re.IGNORECASE,
        ),
        "chain evidence claim requires release-truth chain_evidence=true",
    ),
    "transparency_log": (
        re.compile(r"\b(Rekor inclusion|Sigstore transparency log)\b", re.IGNORECASE),
        "transparency log claim requires release-truth transparency_log=true",
    ),
}
COPY_STOP_PATTERNS = {
    "bare_acp": (
        re.compile(r"(?<![A-Za-z0-9_-])ACP(?![A-Za-z0-9_-])"),
        "use ACP-Client or ACP-Commerce, never bare ACP",
    ),
    "ambient_external_authority": (
        re.compile(
            r"\b(?:x402|AP2|ACP-Commerce|web3(?: settlement)?)\b.{0,96}"
            r"\b(?:ambient|universal|authority)\b|"
            r"\b(?:ambient|universal)\b.{0,96}"
            r"\b(?:x402|AP2|ACP-Commerce|web3(?: settlement)?)\b",
            re.IGNORECASE,
        ),
        "external standards must be subordinate evidence, not ambient Chio authority",
    ),
    "chain_evidence_authority": (
        re.compile(
            r"\b(?:on-chain|chain) evidence\b.{0,96}"
            r"\b(?:proves|authorizes|grants|creates|widens)\b.{0,96}"
            r"\b(?:Chio settlement authority|Chio settlement "
            r"(?:release|dispatch|decision)s?)\b",
            re.IGNORECASE,
        ),
        "chain evidence is supporting evidence, not Chio settlement authority",
    ),
    "every_action_overclaim": (
        re.compile(
            r"\b(?:Chio|authority|proof|receipt|verifi(?:es|able|ed)|binds?)\b.{0,96}"
            r"\bevery action\b|"
            r"\bevery action\b.{0,96}"
            r"\b(?:Chio|authority|proof|receipt|verifi(?:es|able|ed)|binds?)\b|"
            r"\bevery-action\b",
            re.IGNORECASE,
        ),
        "every-action claims require a receipt coverage matrix and exclusions",
    ),
    "insurance_pricing_overclaim": (
        re.compile(
            r"\b(?:autonomous insurer pricing|autonomous insurance pricing|insurance pricing)\b",
            re.IGNORECASE,
        ),
        "insurance pricing claims must stay within actuarial and reserve evidence",
    ),
    "autonomous_insurer_overclaim": (
        re.compile(
            r"\bChio\b.{0,64}\b(?:is|runs|operates|provides|ships)\b.{0,64}"
            r"\b(?:an?\s+)?autonomous\s+(?:insurer|insurance)\b",
            re.IGNORECASE,
        ),
        "Chio provides bounded risk evidence, not autonomous insurer authority",
    ),
    "enterprise_overclaim": (
        re.compile(
            r"\bChio\b.{0,96}\b(?:automatically|proves|guarantees)\b.{0,96}"
            r"\benterprise\s+(?:identity|compliance|audit|governance)\b|"
            r"\bChio\b.{0,96}\benterprise\s+(?:identity|compliance|audit|governance)"
            r"\b.{0,96}\b(?:automatically|proves|guarantees)\b",
            re.IGNORECASE,
        ),
        "enterprise claims must stay bounded to verifier evidence and explicit policy",
    ),
    "universal_protocol_overclaim": (
        re.compile(
            r"(?<![A-Za-z0-9_-])universal(?:[ -]+agent)?[ -]+protocol"
            r"(?![A-Za-z0-9_-])",
            re.IGNORECASE,
        ),
        "Chio is not a replacement for external agent protocols",
    ),
    "native_external_authority_overclaim": (
        re.compile(
            r"\bevery external agent protocol natively verifies\b|"
            r"\bnative(?:ly)? across all protocols\b",
            re.IGNORECASE,
        ),
        "external standards are projections, not native Chio authority",
    ),
    "stale_a2a_version": (
        re.compile(
            r"\bA2A\b.{0,96}\bv0\.3\.0\b|\bv0\.3\.0\b.{0,96}\bA2A\b",
            re.IGNORECASE,
        ),
        "A2A launch claims must use the v1.0.0 source-truth row",
    ),
    "stale_slsa_version": (
        re.compile(r"\bSLSA v1\.1\b", re.IGNORECASE),
        "SLSA launch claims must use the pinned current source",
    ),
    "unsupported_openapi_32": (
        re.compile(
            r"\bOpenAPI 3\.2(?: [A-Za-z0-9_-]+){0,3} support\b",
            re.IGNORECASE,
        ),
        "OpenAPI 3.2 support requires a 3.2 fixture",
    ),
    "sigstore_runtime_authority": (
        re.compile(r"\bSigstore proves runtime authorization\b", re.IGNORECASE),
        "Sigstore can support supply-chain transparency, not Chio runtime authority",
    ),
    "webhook_signature_authority": (
        re.compile(
            r"\b(?:a )?webhook signature proves Chio authorization\b",
            re.IGNORECASE,
        ),
        "webhook signatures are event evidence, not Chio authorization",
    ),
    "oauth_token_capability": (
        re.compile(r"\bOAuth tokens are Chio capabilities\b", re.IGNORECASE),
        "OAuth tokens are identity evidence, not Chio capabilities",
    ),
    "spiffe_agent_authority": (
        re.compile(r"\bSPIFFE delegates agent authority\b", re.IGNORECASE),
        "SPIFFE is workload identity evidence, not agent authority",
    ),
    "kubernetes_business_authority": (
        re.compile(
            r"\bKubernetes admission proves business transaction authority\b",
            re.IGNORECASE,
        ),
        "Kubernetes admission is infrastructure evidence, not business authority",
    ),
    "oci_tag_trust": (
        re.compile(r"\bOCI tags are trusted artifact references\b", re.IGNORECASE),
        "OCI evidence must bind digest-pinned references, not mutable tags",
    ),
}


def absolute(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def read_truth(path: Path) -> dict:
    full_path = absolute(path)
    if not full_path.is_file():
        raise SystemExit(f"proof-room.release.truth-missing: {relative(full_path)}")
    with full_path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if value.get("schema") != "chio.proof.release-truth.v1":
        raise SystemExit(f"proof-room.release.schema-mismatch: {relative(full_path)}")
    validate_registered_schema(
        registered_schema_entry("chio.proof.release-truth.v1"),
        full_path,
        "truth",
    )
    truth = value.get("truth")
    if not isinstance(truth, dict):
        raise SystemExit(f"proof-room.release.truth-invalid: {relative(full_path)}")
    for key in CLAIM_PATTERNS:
        if not isinstance(truth.get(key), bool):
            raise SystemExit(f"proof-room.release.truth-key-invalid: {key}")
    return value


def read_json_file(path: Path, label: str) -> dict:
    full_path = absolute(path)
    if not full_path.is_file():
        raise SystemExit(f"proof-room.release.{label}-missing: {relative(full_path)}")
    with full_path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SystemExit(f"proof-room.release.{label}-invalid: {relative(full_path)}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def registered_schema_entry(schema: str) -> dict:
    registry = read_json_file(SCHEMA_REGISTRY_PATH, "schema-registry")
    artifacts = registry.get("artifacts")
    if not isinstance(artifacts, list):
        raise SystemExit("proof-room.release.schema-registry-invalid")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and artifact.get("schema") == schema
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"proof-room.release.schema-unregistered: {schema}"
        )
    schema_file = matches[0].get("schemaFile")
    if not isinstance(schema_file, str) or not schema_file:
        raise SystemExit(
            f"proof-room.release.schema-file-missing: {schema}"
        )
    if not absolute(Path(schema_file)).is_file():
        raise SystemExit(
            f"proof-room.release.schema-file-not-found: {schema_file}"
        )
    return matches[0]


def validate_registered_schema(schema_entry: dict, document_path: Path, label: str) -> None:
    schema_file = schema_entry.get("schemaFile")
    if not isinstance(schema_file, str) or not schema_file:
        raise SystemExit(f"proof-room.release.{label}-schema-file-missing")
    schema_path = absolute(Path(schema_file))
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "chio-spec-validate",
            "--",
            str(schema_path),
            str(document_path),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        if details:
            raise SystemExit(
                f"proof-room.release.{label}-schema-invalid: {details}"
            )
        raise SystemExit(f"proof-room.release.{label}-schema-invalid")


def resolve_bundle_artifact(bundle_root: Path, relative_path: str) -> Path:
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or any(part in {"", ".", ".."} for part in relative_path.split("/"))
    ):
        raise SystemExit(
            f"proof-room.release.artifact-path-invalid: {relative_path}"
        )
    artifact = (bundle_root / relative_path).resolve()
    root = bundle_root.resolve()
    if root not in artifact.parents:
        raise SystemExit(
            f"proof-room.release.artifact-path-escape: {relative_path}"
        )
    return artifact


def docker_evidence_artifact(manifest: dict) -> dict:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise SystemExit("proof-room.release.docker-evidence-unbound: artifacts missing")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and (
            artifact.get("schema") == DOCKER_EVIDENCE_SCHEMA
            or artifact.get("renderer_hint") == DOCKER_EVIDENCE_RENDERER_HINT
        )
    ]
    if len(matches) != 1:
        raise SystemExit(
            "proof-room.release.docker-evidence-unbound: expected one Docker evidence artifact"
        )
    return matches[0]


def release_truth_artifact(manifest: dict) -> dict:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise SystemExit("proof-room.release.bundle-release-truth-unbound: artifacts missing")
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and (
            artifact.get("schema") == RELEASE_TRUTH_SCHEMA
            or artifact.get("renderer_hint") == RELEASE_TRUTH_RENDERER_HINT
        )
    ]
    if len(matches) != 1:
        raise SystemExit(
            "proof-room.release.bundle-release-truth-unbound: expected one release truth artifact"
        )
    return matches[0]


def verify_bundle_release_truth_binding(manifest_path: Path, manifest: dict) -> None:
    artifact = release_truth_artifact(manifest)
    artifact_schema = artifact.get("schema")
    if artifact_schema != RELEASE_TRUTH_SCHEMA:
        raise SystemExit("proof-room.release.bundle-release-truth-schema-mismatch")
    schema_entry = registered_schema_entry(artifact_schema)
    if schema_entry.get("artifactKind") != "proof_release_truth":
        raise SystemExit("proof-room.release.bundle-release-truth-schema-kind-mismatch")
    artifact_path = artifact.get("path")
    artifact_sha256 = artifact.get("sha256")
    if not isinstance(artifact_path, str) or not isinstance(artifact_sha256, str):
        raise SystemExit("proof-room.release.bundle-release-truth-ref-invalid")
    bound_path = resolve_bundle_artifact(manifest_path.parent, artifact_path)
    configured_path = absolute(BUNDLE_TRUTH_PATH).resolve()
    if bound_path != configured_path:
        raise SystemExit("proof-room.release.bundle-release-truth-path-mismatch")
    if not bound_path.is_file():
        raise SystemExit(
            f"proof-room.release.bundle-release-truth-missing: {relative(bound_path)}"
        )
    actual_sha256 = sha256_file(bound_path)
    if actual_sha256 != artifact_sha256:
        raise SystemExit("proof-room.release.bundle-release-truth-digest-mismatch")


def verify_docker_quickstart_evidence(truth: dict) -> None:
    if not truth["docker_quickstart"]:
        return
    manifest_path = absolute(BUNDLE_MANIFEST_PATH)
    manifest = read_json_file(manifest_path, "bundle-manifest")
    validate_registered_schema(
        registered_schema_entry(PROOF_ROOM_BUNDLE_SCHEMA),
        manifest_path,
        "bundle-manifest",
    )
    verify_bundle_release_truth_binding(manifest_path, manifest)
    artifact = docker_evidence_artifact(manifest)
    artifact_schema = artifact.get("schema")
    if artifact_schema != DOCKER_EVIDENCE_SCHEMA:
        raise SystemExit("proof-room.release.docker-evidence-schema-mismatch")
    schema_entry = registered_schema_entry(artifact_schema)
    if schema_entry.get("artifactKind") != "proof_docker_quickstart_evidence":
        raise SystemExit("proof-room.release.docker-evidence-schema-kind-mismatch")
    artifact_path = artifact.get("path")
    artifact_sha256 = artifact.get("sha256")
    if not isinstance(artifact_path, str) or not isinstance(artifact_sha256, str):
        raise SystemExit("proof-room.release.docker-evidence-ref-invalid")
    evidence_path = resolve_bundle_artifact(manifest_path.parent, artifact_path)
    if not evidence_path.is_file():
        raise SystemExit(
            f"proof-room.release.docker-evidence-missing: {relative(evidence_path)}"
        )
    actual_sha256 = sha256_file(evidence_path)
    if actual_sha256 != artifact_sha256:
        raise SystemExit("proof-room.release.docker-evidence-digest-mismatch")
    evidence = read_json_file(evidence_path, "docker-evidence")
    if evidence.get("schema") != artifact_schema:
        raise SystemExit("proof-room.release.docker-evidence-schema-mismatch")
    if evidence.get("verdict") != "verified":
        raise SystemExit("proof-room.release.docker-evidence-not-verified")
    if evidence.get("target") != "chio-proof-room-quickstart":
        raise SystemExit("proof-room.release.docker-evidence-target-mismatch")
    if evidence.get("fixture_root") != "/opt/chio/fixtures/proof-room":
        raise SystemExit("proof-room.release.docker-evidence-fixture-root-missing")
    if evidence.get("doctor_report_path") != "/opt/chio/proof-doctor-report.json":
        raise SystemExit("proof-room.release.docker-evidence-doctor-report-missing")
    endpoints = evidence.get("endpoints")
    if not isinstance(endpoints, list):
        raise SystemExit("proof-room.release.docker-evidence-endpoints-missing")
    observed = {
        endpoint.get("path"): endpoint.get("expected")
        for endpoint in endpoints
        if isinstance(endpoint, dict)
    }
    for path, expected in REQUIRED_DOCKER_ENDPOINTS.items():
        if observed.get(path) != expected:
            raise SystemExit(
                f"proof-room.release.docker-evidence-endpoint-missing: {path}"
            )
    validate_registered_schema(schema_entry, evidence_path, "docker-evidence")


def configured_docs(defaults: tuple[str, ...]) -> list[Path]:
    override = os.environ.get("CHIO_PROOF_ROOM_RELEASE_DOCS")
    raw_docs = override.split(os.pathsep) if override else list(defaults)
    return [absolute(Path(raw)) for raw in raw_docs if raw]


def is_default_doc_excluded(path: Path) -> bool:
    relative_path = relative(path)
    return any(relative_path.startswith(prefix) for prefix in DEFAULT_DOC_EXCLUDES)


def iter_doc_lines(paths: list[Path]):
    for path in paths:
        if path.is_dir():
            children = sorted(
                child for child in path.rglob("*") if child.suffix in {".json", ".md", ".mdx"}
            )
        else:
            children = [path]
        for child in children:
            if not child.exists():
                continue
            if is_default_doc_excluded(child):
                continue
            for line_no, line in enumerate(
                child.read_text(encoding="utf-8").splitlines(), start=1
            ):
                yield child, line_no, line


def claim_has_allowed_context(line: str, match: re.Match[str]) -> bool:
    clause_start = 0
    for boundary in CLAUSE_BOUNDARY_RE.finditer(line, 0, match.start()):
        clause_start = boundary.end()

    next_boundary = CLAUSE_BOUNDARY_RE.search(line, match.end())
    clause_end = next_boundary.start() if next_boundary else len(line)
    return ALLOW_CONTEXT_RE.search(line[clause_start:clause_end]) is not None


def stop_pattern_has_allowed_context(line: str, match: re.Match[str]) -> bool:
    return False


truth_doc = read_truth(TRUTH_PATH)
bundle_truth_doc = read_truth(BUNDLE_TRUTH_PATH)
if truth_doc != bundle_truth_doc:
    raise SystemExit("proof-room.release.truth-drift: bundle release truth differs")

truth = truth_doc["truth"]
verify_docker_quickstart_evidence(truth)
failures: list[str] = []
for path, line_no, line in iter_doc_lines(configured_docs(DEFAULT_CLAIM_DOCS)):
    for key, (pattern, guidance) in CLAIM_PATTERNS.items():
        if truth[key]:
            continue
        if any(
            not claim_has_allowed_context(line, match)
            for match in pattern.finditer(line)
        ):
            failures.append(
                f"{relative(path)}:{line_no}: proof-room.release.unavailable: {key}: {guidance}"
            )
for path, line_no, line in iter_doc_lines(configured_docs(DEFAULT_DOCS)):
    for key, (pattern, guidance) in COPY_STOP_PATTERNS.items():
        if any(
            not stop_pattern_has_allowed_context(line, match)
            for match in pattern.finditer(line)
        ):
            failures.append(
                f"{relative(path)}:{line_no}: proof-room.release.copy-forbidden: {key}: {guidance}"
            )

if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)

print("OK Proof Room release truth")
PY
