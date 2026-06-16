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
    "spec/schemas/chio-agent-web/",
    "spec/schemas/chio-attest/",
    "spec/schemas/chio-commerce/",
    "spec/schemas/chio-crypto/",
    "spec/schemas/chio-disclosure/",
    "spec/schemas/chio-enterprise/",
    "spec/schemas/chio-federation/",
    "spec/schemas/chio-lineage/",
    "spec/schemas/chio-oracle/",
    "spec/schemas/chio-pheromone/",
    "spec/schemas/chio-proof-room/",
    "spec/schemas/chio-risk/",
    "spec/schemas/chio-runtime/",
    "spec/schemas/chio-swarm/",
    "spec/schemas/chio-transparency/",
    "spec/schemas/chio-transaction/",
    "spec/schemas/chio-trust/",
    "spec/schemas/chio-web3/",
    "spec/schemas/chio-workflow/",
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

    if schema_file.startswith("spec/schemas/chio/"):
        errors.append(f"{schema_id} points at retired schema root {schema_file}")
        continue

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
        retired_schema_prefix = "chio." + "chio."
        if retired_schema_prefix in schema_text:
            errors.append(f"Chio schema {rel} allows legacy Chio schema ids")
        if '"$ref"' in schema_text and "../../chio/" in schema_text:
            errors.append(f"Chio schema {rel} references legacy chio schema paths")

for schema_root in checked_active_chio_schema_text_roots:
    for schema_path in sorted((root / schema_root).glob("**/*.schema.json")):
        rel = str(schema_path.relative_to(root))
        schema_text = schema_path.read_text(encoding="utf-8")
        retired_schema_prefix = "chio." + "chio."
        if retired_schema_prefix in schema_text:
            errors.append(f"Active Chio schema {rel} exposes retired schema ids")

if errors:
    raise SystemExit("\n".join(errors))

print("OK Chio schema registry metadata")
PY
