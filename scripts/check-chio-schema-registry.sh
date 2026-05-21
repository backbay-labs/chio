#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="$ROOT/spec/schemas/registry.json"

python3 - "$REGISTRY" <<'PY'
import json
import hashlib
import pathlib
import subprocess
import sys

registry_path = pathlib.Path(sys.argv[1])
root = registry_path.parent.parent.parent
manifest_path = registry_path.parent / "MANIFEST.sha256"
registry = json.loads(registry_path.read_text(encoding="utf-8"))
manifest = {}
for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    digest, path = line.split(None, 1)
    manifest[path] = digest
registered_paths = {
    entry.get("schemaFile")
    for entry in registry.get("artifacts", [])
    if entry.get("schemaFile")
}
checked_chio_schema_roots = (
    "spec/schemas/chio-attest/",
    "spec/schemas/chio-federation/",
    "spec/schemas/chio-pheromone/",
    "spec/schemas/chio-runtime/",
)
checked_active_chio_schema_text_roots = checked_chio_schema_roots + (
    "spec/schemas/chio-wire/",
)
errors = []
try:
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", *checked_chio_schema_roots],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tracked_schema_paths = {
        path
        for path in tracked.stdout.decode("utf-8").split("\0")
        if path.endswith(".schema.json")
    }
except (OSError, subprocess.CalledProcessError) as error:
    tracked_schema_paths = set()
    errors.append(f"unable to inspect git-tracked Chio schema files: {error}")

for entry in registry.get("artifacts", []):
    schema_id = entry.get("schema", "<missing schema>")
    schema_file = entry.get("schemaFile", "")
    artifact_kind = entry.get("artifactKind", "")
    introduced_by = entry.get("introducedBy", "")
    status = entry.get("status")

    if schema_file.startswith("spec/schemas/chiodos/"):
        if status != "deprecated-read-compatible":
            errors.append(
                f"{schema_id} points at legacy {schema_file} without deprecated-read-compatible status"
            )
        continue

    if status != "deprecated-read-compatible" and artifact_kind.startswith("chiodos_"):
        errors.append(
            f"{schema_id} is active but still uses legacy artifactKind {artifact_kind}"
        )
    if schema_file.startswith(checked_chio_schema_roots) and "chiodos" in introduced_by.lower():
        errors.append(
            f"{schema_id} has active Chio schema file {schema_file} with legacy introducedBy {introduced_by}"
        )

    if schema_file.startswith("spec/schemas/chio-") and artifact_kind.startswith("chiodos_"):
        errors.append(
            f"{schema_id} has Chio schema file {schema_file} with legacy artifactKind {artifact_kind}"
        )
    if schema_file.startswith(checked_chio_schema_roots):
        path = root / schema_file
        if not path.is_file():
            errors.append(f"{schema_id} points at missing Chio schema file {schema_file}")
        elif manifest.get(schema_file) != hashlib.sha256(path.read_bytes()).hexdigest():
            errors.append(f"{schema_id} has stale or absent MANIFEST.sha256 entry for {schema_file}")

for schema_root in checked_chio_schema_roots:
    for schema_path in sorted((root / schema_root).glob("**/*.schema.json")):
        rel = str(schema_path.relative_to(root))
        if rel not in tracked_schema_paths:
            errors.append(f"Chio schema {rel} is not tracked by git")
        if rel not in registered_paths:
            errors.append(f"Chio schema {rel} is not registered in registry.json")
        if manifest.get(rel) != hashlib.sha256(schema_path.read_bytes()).hexdigest():
            errors.append(f"Chio schema {rel} is absent from MANIFEST.sha256 or has stale hash")
        schema_text = schema_path.read_text(encoding="utf-8")
        title = json.loads(schema_text).get("title", "")
        if "Chiodos" in title:
            errors.append(f"Chio schema {rel} title uses legacy Chiodos naming")
        if "chio.chiodos." in schema_text:
            errors.append(f"Chio schema {rel} allows legacy Chiodos schema ids")
        if '"$ref"' in schema_text and "../../chiodos/" in schema_text:
            errors.append(f"Chio schema {rel} references legacy chiodos schema paths")

for schema_root in checked_active_chio_schema_text_roots:
    for schema_path in sorted((root / schema_root).glob("**/*.schema.json")):
        rel = str(schema_path.relative_to(root))
        schema_text = schema_path.read_text(encoding="utf-8")
        if "Chiodos" in schema_text or "CHIODOS" in schema_text or "chiodos" in schema_text:
            errors.append(f"Active Chio schema {rel} exposes legacy Chiodos wording")

if errors:
    raise SystemExit("\n".join(errors))

print("OK Chio schema registry compatibility metadata")
PY
