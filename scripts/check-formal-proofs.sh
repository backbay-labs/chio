#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

formal_root="formal/lean4/Chio"

echo "==> Canonical JSON Lean fixture drift"
python3 scripts/generate-lean-json-fixtures.py --check

if ! command -v lake >/dev/null 2>&1; then
  echo "formal proof check requires lake on PATH (install Lean 4 / elan first)" >&2
  exit 1
fi

echo "==> Lean 4 proof build"
(
  cd "${formal_root}"
  lake build
)

echo "==> Lean 4 placeholder scan"
if command -v rg >/dev/null 2>&1; then
  placeholder_scan=(rg -n '\bsorry\b' \
    "${formal_root}/Chio" \
    "${formal_root}/Chio.lean" \
    -g '*.lean')
else
  placeholder_scan=(grep -RInw --include '*.lean' 'sorry' \
    "${formal_root}/Chio" \
    "${formal_root}/Chio.lean")
fi

if "${placeholder_scan[@]}"; then
  echo "formal proof check failed: found literal sorry in shipped Lean modules" >&2
  exit 1
fi

echo "==> Proof manifest and theorem inventory sanity"
python3 - <<'PY'
import json
import re
from pathlib import Path

repo = Path(".")
manifest_path = repo / "formal" / "proof-manifest.toml"
inventory_path = repo / "formal" / "theorem-inventory.json"
claim_registry_path = repo / "docs" / "reference" / "CLAIM_REGISTRY.md"

def parse_string(value):
    return json.loads(value)

def strip_toml_comment(line):
    in_string = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_string:
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if char == "#" and not in_string:
            return line[:index]
    return line

def parse_manifest_subset(text):
    manifest = {}
    array_key = None
    array_values = []
    in_array_table = False
    for raw_line in text.splitlines():
        line = strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("[[") and line.endswith("]]"):
            if array_key is not None:
                raise SystemExit(f"unterminated proof manifest array: {array_key}")
            in_array_table = True
            continue
        if in_array_table:
            continue
        if array_key is not None:
            if line == "]":
                manifest[array_key] = array_values
                array_key = None
                array_values = []
                continue
            if line.endswith(","):
                line = line[:-1].strip()
            array_values.append(parse_string(line))
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise SystemExit(f"unsupported proof manifest line: {raw_line}")
        key = key.strip()
        value = value.strip()
        if value == "[":
            array_key = key
            array_values = []
        elif value.startswith('"'):
            manifest[key] = parse_string(value.rstrip(","))
        elif value.startswith("[") and value.endswith("]"):
            manifest[key] = json.loads(value)
        elif value.isdigit():
            manifest[key] = int(value)
        else:
            raise SystemExit(f"unsupported proof manifest value for {key}: {value}")
    if array_key is not None:
        raise SystemExit(f"unterminated proof manifest array: {array_key}")
    return manifest

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

def load_toml_subset(path):
    text = path.read_text(encoding="utf-8")
    return tomllib.loads(text) if tomllib else parse_manifest_subset(text)

manifest = load_toml_subset(manifest_path)
if manifest.get("schema") != "chio.proof-manifest.v1":
    raise SystemExit("proof manifest schema mismatch")

for rel in manifest.get("root_modules", []):
    if not (repo / rel).exists():
        raise SystemExit(f"proof manifest root module missing: {rel}")

for rel in manifest.get("covered_rust_modules", []):
    if not (repo / rel).exists():
        raise SystemExit(f"proof manifest covered module missing: {rel}")

assumption_registry = manifest.get("assumption_registry")
if not assumption_registry:
    raise SystemExit("proof manifest missing assumption_registry")
assumption_registry_path = repo / assumption_registry
if not assumption_registry_path.exists():
    raise SystemExit(f"assumption registry missing: {assumption_registry}")
assumption_manifest = load_toml_subset(assumption_registry_path)
if assumption_manifest.get("schema") != "chio.formal-assumptions.v1":
    raise SystemExit("formal assumption registry schema mismatch")
required_assumption_ids = set(assumption_manifest.get("required_assumption_ids", []))
actual_assumption_ids = set()
for encoded in assumption_manifest.get("assumptions", []):
    parts = encoded.split("|")
    if len(parts) != 4:
        raise SystemExit(f"malformed formal assumption entry: {encoded}")
    assumption_id, posture, contract, maps_to = parts
    if not assumption_id or not posture or not contract or not maps_to:
        raise SystemExit(f"incomplete formal assumption entry: {encoded}")
    actual_assumption_ids.add(assumption_id)
if required_assumption_ids != actual_assumption_ids:
    missing = sorted(required_assumption_ids - actual_assumption_ids)
    extra = sorted(actual_assumption_ids - required_assumption_ids)
    raise SystemExit(f"formal assumption registry mismatch; missing={missing} extra={extra}")

for encoded in manifest.get("rust_refinement_lanes", []):
    parts = encoded.split("|")
    if len(parts) != 3:
        raise SystemExit(f"malformed rust refinement lane entry: {encoded}")
    _tool, _status, rel = parts
    if not (repo / rel).exists():
        raise SystemExit(f"rust refinement lane file missing: {rel}")

inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
if inventory.get("schema") != "chio.theorem-inventory.v1":
    raise SystemExit("theorem inventory schema mismatch")

assumptions = inventory.get("assumptions", [])
approved_axioms = manifest.get("allowed_axioms", [])
approved_open_modules = set(manifest.get("allowed_open_modules", []))

if sorted(assumption.get("leanName") for assumption in assumptions) != sorted(approved_axioms):
    raise SystemExit("approved axiom list does not match theorem inventory assumptions")

axiom_declaration = re.compile(
    r"^\s*(?:@\[[^]]*\]\s*)*"
    r"(?:(?:private|protected|noncomputable|unsafe|partial)\s+)*"
    r"(?:axiom|opaque|constant)\s+([A-Za-z0-9_']+)\b"
)

for declaration in (
    "axiom plain : Prop",
    "private axiom hidden : Prop",
    "@[irreducible] protected opaque sealed : Nat",
    "noncomputable constant oracle : Nat",
):
    if axiom_declaration.match(declaration) is None:
        raise SystemExit(f"Lean assumption scanner missed declaration: {declaration}")

def lean_axioms_in_file(lean_file):
    namespace_stack = []
    mutual_depth = 0
    axioms = []
    text = lean_file.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip() == "mutual":
            mutual_depth += 1
            continue
        namespace_match = re.match(r"^\s*namespace\s+([A-Za-z0-9_.']+)\b", line)
        if namespace_match:
            namespace_stack.append(namespace_match.group(1))
            continue
        end_match = re.match(r"^\s*end(?:\s+([A-Za-z0-9_.']+))?\s*$", line)
        if end_match:
            if mutual_depth:
                mutual_depth -= 1
            elif namespace_stack:
                namespace_stack.pop()
            continue
        axiom_match = axiom_declaration.match(line)
        if axiom_match:
            prefix = ".".join(namespace_stack)
            short_name = axiom_match.group(1)
            full_name = f"{prefix}.{short_name}" if prefix else short_name
            axioms.append((full_name, lean_file.relative_to(repo).as_posix()))
    return axioms

def lean_surface_controls_in_file(lean_file):
    namespace_stack = []
    mutual_depth = 0
    opens = []
    exports = []
    abbrevs = []
    for line_number, line in enumerate(lean_file.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip() == "mutual":
            mutual_depth += 1
            continue
        namespace_match = re.match(r"^\s*namespace\s+([A-Za-z0-9_.']+)\b", line)
        if namespace_match:
            namespace_stack.append(namespace_match.group(1))
            continue
        end_match = re.match(r"^\s*end(?:\s+([A-Za-z0-9_.']+))?\s*$", line)
        if end_match:
            if mutual_depth:
                mutual_depth -= 1
            elif namespace_stack:
                namespace_stack.pop()
            continue
        open_match = re.match(r"^\s*open\s+(.+)$", line)
        if open_match:
            for module in re.findall(r"[A-Za-z][A-Za-z0-9_.']*", open_match.group(1)):
                opens.append((module, lean_file.relative_to(repo).as_posix(), line_number))
            continue
        export_match = re.match(r"^\s*export\s+(.+)$", line)
        if export_match:
            exports.append((lean_file.relative_to(repo).as_posix(), line_number))
            continue
        abbrev_match = re.match(r"^\s*abbrev\s+([A-Za-z0-9_']+)\b", line)
        if abbrev_match:
            prefix = ".".join(namespace_stack)
            short_name = abbrev_match.group(1)
            full_name = f"{prefix}.{short_name}" if prefix else short_name
            abbrevs.append((full_name, short_name, lean_file.relative_to(repo).as_posix(), line_number))
    return opens, exports, abbrevs

def lean_named_declarations_in_file(lean_file):
    namespace_stack = []
    mutual_depth = 0
    declarations = set()
    for line in lean_file.read_text(encoding="utf-8").splitlines():
        if line.strip() == "mutual":
            mutual_depth += 1
            continue
        namespace_match = re.match(r"^\s*namespace\s+([A-Za-z0-9_.']+)\b", line)
        if namespace_match:
            namespace_stack.append(namespace_match.group(1))
            continue
        end_match = re.match(r"^\s*end(?:\s+([A-Za-z0-9_.']+))?\s*$", line)
        if end_match:
            if mutual_depth:
                mutual_depth -= 1
            elif namespace_stack:
                namespace_stack.pop()
            continue
        declaration_match = re.match(
            r"^\s*(?:theorem|lemma)\s+([A-Za-z0-9_.']+)\b",
            line,
        )
        if declaration_match:
            prefix = ".".join(namespace_stack)
            short_name = declaration_match.group(1)
            full_name = f"{prefix}.{short_name}" if prefix else short_name
            declarations.add((full_name, lean_file.relative_to(repo).as_posix()))
    return declarations

lean_project_root = repo / "formal" / "lean4" / "Chio"
lean_project_root_resolved = lean_project_root.resolve()

def require_project_lean_file(path_value, item_kind, item_id):
    if not path_value:
        raise SystemExit(f"{item_kind} file missing: {item_id}")
    path = repo / path_value
    if not path.exists():
        raise SystemExit(f"{item_kind} file missing: {item_id}")
    try:
        rel = path.resolve().relative_to(lean_project_root_resolved)
    except ValueError as exc:
        raise SystemExit(f"{item_kind} file outside Chio Lean project: {item_id}") from exc
    if ".lake" in rel.parts:
        raise SystemExit(f"{item_kind} file points into Lean build/dependency tree: {item_id}")
    return path

project_lean_files = sorted(
    path
    for path in lean_project_root.rglob("*.lean")
    if ".lake" not in path.resolve().relative_to(lean_project_root_resolved).parts
)

for assumption in assumptions:
    if assumption.get("kind") != "axiom":
        raise SystemExit(f"assumption is not marked as axiom: {assumption.get('id')}")
    if not assumption.get("rootImported"):
        raise SystemExit(f"assumption not marked rootImported: {assumption.get('id')}")
    assumption_file = require_project_lean_file(
        assumption.get("file"),
        "assumption",
        assumption.get("id"),
    )
    lean_name = assumption.get("leanName", "")
    if not lean_name:
        raise SystemExit(f"assumption leanName missing: {assumption.get('id')}")
    assumption_axioms = {name for name, _ in lean_axioms_in_file(assumption_file)}
    if lean_name not in assumption_axioms:
        raise SystemExit(f"assumption definition missing from file: {assumption.get('id')}")

theorems = inventory.get("theorems", [])
if not theorems:
    raise SystemExit("theorem inventory is empty")

required_property_ids = set(manifest.get("required_property_ids", []))
if required_property_ids != {f"P{i}" for i in range(1, 11)}:
    raise SystemExit("proof manifest must require exactly P1 through P10")

property_matrix_entries = manifest.get("property_matrix", [])
property_matrix = {}
for encoded in property_matrix_entries:
    parts = encoded.split("|")
    if len(parts) != 4:
        raise SystemExit(f"malformed property matrix entry: {encoded}")
    property_id, summary, evidence, theorem_ids = parts
    if property_id not in required_property_ids:
        raise SystemExit(f"unknown property in matrix: {property_id}")
    if property_id in property_matrix:
        raise SystemExit(f"duplicate property matrix entry: {property_id}")
    theorem_list = [theorem_id.strip() for theorem_id in theorem_ids.split(",") if theorem_id.strip()]
    if not summary or not evidence or not theorem_list:
        raise SystemExit(f"incomplete property matrix entry: {encoded}")
    property_matrix[property_id] = theorem_list
if set(property_matrix) != required_property_ids:
    missing = sorted(required_property_ids - set(property_matrix))
    raise SystemExit(f"property matrix missing required properties: {missing}")

inventory_theorem_ids = {theorem.get("id") for theorem in theorems}
inventory_theorem_maps = {}
inventory_maps_to = {property_id: [] for property_id in required_property_ids}

for theorem in theorems:
    if not theorem.get("rootImported"):
        raise SystemExit(f"theorem not marked rootImported: {theorem.get('id')}")
    theorem_file = require_project_lean_file(
        theorem.get("file"),
        "theorem",
        theorem.get("id"),
    )
    lean_name = theorem.get("leanName")
    if not lean_name:
        raise SystemExit(f"theorem leanName missing: {theorem.get('id')}")
    theorem_names = {name for name, _ in lean_named_declarations_in_file(theorem_file)}
    if lean_name not in theorem_names:
        raise SystemExit(f"theorem definition missing from declared file: {theorem.get('id')}")
    maps_to = theorem.get("mapsTo", [])
    if not maps_to:
        raise SystemExit(f"theorem missing mapsTo: {theorem.get('id')}")
    inventory_theorem_maps[theorem.get("id")] = set(maps_to)
    for property_id in maps_to:
        if property_id not in required_property_ids:
            raise SystemExit(f"theorem maps to unknown property {property_id}: {theorem.get('id')}")
        inventory_maps_to[property_id].append(theorem.get("id"))

for property_id, theorem_ids in property_matrix.items():
    for theorem_id in theorem_ids:
        if theorem_id not in inventory_theorem_ids:
            raise SystemExit(f"property matrix references missing theorem id: {property_id} -> {theorem_id}")
        if property_id not in inventory_theorem_maps.get(theorem_id, set()):
            raise SystemExit(
                "property matrix theorem mapping mismatch: "
                f"{property_id} lists {theorem_id}, but theorem mapsTo={sorted(inventory_theorem_maps.get(theorem_id, set()))}"
            )
    if not inventory_maps_to[property_id]:
        raise SystemExit(f"no theorem inventory coverage for property: {property_id}")

for tool_name in ("lean4", "creusot", "kani", "aeneas"):
    if tool_name not in manifest.get("primary_toolchain", []):
        raise SystemExit(f"proof manifest primary toolchain missing {tool_name}")

approved_axiom_names = set(approved_axioms)
approved_axiom_short_names = {name.rsplit(".", 1)[-1] for name in approved_axioms}
found_axioms = []
found_open_modules = []
found_exports = []
found_abbrevs = []
for lean_file in project_lean_files:
    found_axioms.extend(lean_axioms_in_file(lean_file))
    opens, exports, abbrevs = lean_surface_controls_in_file(lean_file)
    found_open_modules.extend(opens)
    found_exports.extend(exports)
    found_abbrevs.extend(abbrevs)

unexpected_axioms = sorted(
    f"{name} ({file})"
    for name, file in found_axioms
    if name not in approved_axiom_names
)
if unexpected_axioms:
    raise SystemExit(
        "unexpected Lean axiom, opaque, or constant declarations found: "
        f"{', '.join(unexpected_axioms)}"
    )

unexpected_open_modules = sorted(
    f"{module} ({file}:{line})"
    for module, file, line in found_open_modules
    if module not in approved_open_modules
)
if unexpected_open_modules:
    raise SystemExit(f"unexpected Lean open modules found: {', '.join(unexpected_open_modules)}")

if found_exports:
    formatted = ", ".join(f"{file}:{line}" for file, line in sorted(found_exports))
    raise SystemExit(f"unexpected Lean export declarations found: {formatted}")

shadowing_abbrevs = sorted(
    f"{full_name} ({file}:{line})"
    for full_name, short_name, file, line in found_abbrevs
    if approved_axiom_names
    and (full_name in approved_axiom_names or short_name in approved_axiom_short_names)
)
if shadowing_abbrevs:
    raise SystemExit(f"Lean abbrevs shadow approved axioms: {', '.join(shadowing_abbrevs)}")

if not claim_registry_path.exists():
    raise SystemExit("claim registry missing: docs/reference/CLAIM_REGISTRY.md")
PY

echo "formal proof check passed"
