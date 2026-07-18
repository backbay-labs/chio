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
errors = []
manifest = {}
manifest_paths = []
manifest_text = manifest_path.read_text(encoding="utf-8")
for line_number, line in enumerate(manifest_text.splitlines(), 1):
    if not line.strip():
        continue
    parts = line.split(None, 1)
    if len(parts) != 2:
        errors.append(f"MANIFEST.sha256 line {line_number} is malformed")
        continue
    digest, path = parts
    if path in manifest:
        errors.append(f"MANIFEST.sha256 has duplicate entry for {path}")
    manifest[path] = digest
    manifest_paths.append(path)
if manifest_paths != sorted(manifest_paths):
    errors.append("MANIFEST.sha256 entries must be sorted by path")

registry_rel = str(registry_path.relative_to(root))
manifest_rel = str(manifest_path.relative_to(root))

try:
    tracked_schema_inventory = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "spec/schemas",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    expected_manifest_paths = sorted(
        path
        for path in tracked_schema_inventory.stdout.decode("utf-8").split("\0")
        if path.endswith(".schema.json")
        or path in {manifest_rel, registry_rel, "spec/schemas/VERSION"}
    )
except (OSError, subprocess.CalledProcessError) as error:
    expected_manifest_paths = []
    errors.append(f"unable to inspect git-tracked schema manifest inventory: {error}")

if manifest_paths != expected_manifest_paths:
    errors.append("MANIFEST.sha256 path set is not deterministic")

expected_lines_without_self = []
for rel in expected_manifest_paths:
    if rel == manifest_rel:
        continue
    path = root / rel
    if not path.is_file():
        errors.append(f"MANIFEST.sha256 expected path is missing: {rel}")
        continue
    expected_lines_without_self.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {rel}\n")
expected_manifest_self_hash = hashlib.sha256(
    "".join(expected_lines_without_self).encode("utf-8")
).hexdigest()
expected_manifest_content = "".join(
    (
        f"{expected_manifest_self_hash}  {manifest_rel}\n"
        if rel == manifest_rel
        else f"{hashlib.sha256((root / rel).read_bytes()).hexdigest()}  {rel}\n"
    )
    for rel in expected_manifest_paths
    if rel == manifest_rel or (root / rel).is_file()
)
if expected_manifest_paths and manifest_text != expected_manifest_content:
    errors.append("MANIFEST.sha256 bytes do not match deterministic regeneration")

registry_digest = hashlib.sha256(registry_path.read_bytes()).hexdigest()
if manifest.get(registry_rel) != registry_digest:
    errors.append(f"registry.json has stale or absent MANIFEST.sha256 entry for {registry_rel}")

manifest_self_digest = manifest.get(manifest_rel)
if manifest_self_digest is None:
    errors.append(f"MANIFEST.sha256 is missing self-hash entry for {manifest_rel}")
else:
    def manifest_path_from_line(raw_line):
        parts = raw_line.strip().split(None, 1)
        if len(parts) != 2:
            return None
        return parts[1].decode("utf-8", errors="replace")

    manifest_without_self_entry = b"".join(
        raw_line
        for raw_line in manifest_path.read_bytes().splitlines(keepends=True)
        if manifest_path_from_line(raw_line) != manifest_rel
    )
    manifest_self_hash = hashlib.sha256(manifest_without_self_entry).hexdigest()
    if manifest_self_digest != manifest_self_hash:
        errors.append(f"MANIFEST.sha256 has stale self-hash entry for {manifest_rel}")
registered_paths = {
    entry.get("schemaFile")
    for entry in registry.get("artifacts", [])
    if entry.get("schemaFile")
}
checked_chio_schema_roots = (
    "spec/schemas/chio-agent-web/",
    "spec/schemas/chio-attest/",
    "spec/schemas/chio-commerce/",
    "spec/schemas/chio-comptroller/",
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
try:
    tracked = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *checked_chio_schema_roots,
        ],
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

try:
    tracked_active = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *checked_active_chio_schema_text_roots,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tracked_active_schema_paths = {
        path
        for path in tracked_active.stdout.decode("utf-8").split("\0")
        if path.endswith(".schema.json")
    }
except (OSError, subprocess.CalledProcessError) as error:
    tracked_active_schema_paths = set()
    errors.append(f"unable to inspect git-tracked active Chio schema files: {error}")

for entry in registry.get("artifacts", []):
    schema_id = entry.get("schema", "<missing schema>")
    schema_file = entry.get("schemaFile", "")
    artifact_kind = entry.get("artifactKind", "")
    introduced_by = entry.get("introducedBy", "")
    status = entry.get("status")

    if schema_file.startswith("spec/schemas/chio/"):
        errors.append(f"{schema_id} points at inactive schema root {schema_file}")
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
        if '"$ref"' in schema_text and "../../chio/" in schema_text:
            errors.append(f"Chio schema {rel} references inactive chio schema paths")

for schema_root in checked_active_chio_schema_text_roots:
    for schema_path in sorted((root / schema_root).glob("**/*.schema.json")):
        rel = str(schema_path.relative_to(root))
        if schema_root not in checked_chio_schema_roots and rel not in tracked_active_schema_paths:
            errors.append(f"Active Chio schema {rel} is not tracked by git")
        if (
            schema_root not in checked_chio_schema_roots
            and manifest.get(rel) != hashlib.sha256(schema_path.read_bytes()).hexdigest()
        ):
            errors.append(f"Active Chio schema {rel} is absent from MANIFEST.sha256 or has stale hash")
if errors:
    raise SystemExit("\n".join(errors))

print("OK Chio schema registry metadata")
PY
