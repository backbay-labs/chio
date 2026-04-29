#!/usr/bin/env bash
#
# regen-types.sh - regenerate sdks/go/chio-go-http/types.go from
# spec/schemas/chio-wire/v1/**/*.schema.json via oapi-codegen v2.4.1.
#
# Go uses a committed
# generated file rather than a live `cargo xtask codegen --lang go` pipeline.
# `cargo xtask codegen --lang go` shells out to this script (see
# xtask/src/main.rs::run_codegen). With `--check`, the xtask additionally
# runs `git diff --exit-code sdks/go/chio-go-http/types.go` to surface drift.
#
# Toolchain pin: oapi-codegen v2.4.1 (xtask/codegen-tools.lock.toml [go]).
# Bumping the pin requires re-running this script, committing the regenerated
# bytes, and updating the lock file in the same PR.
#
# Inputs:
#   spec/schemas/chio-wire/v1/**/*.schema.json (35 schema files, JSON Schema
#   draft 2020-12). The script walks them deterministically (sorted by path)
#   and bundles them into a single OpenAPI 3.0 document fed to oapi-codegen.
#
# Outputs:
#   sdks/go/chio-go-http/types.go (header-stamped, deterministic).
#
# Hard requirements:
#   - go on PATH (any 1.21+).
#   - python3 on PATH (stdlib only; used to translate JSON Schema 2020-12 ->
#     OpenAPI 3.0 components.schemas, which oapi-codegen accepts).
#   - git on PATH (used to embed the schema git SHA in the file header).
#
# House rules:
#   - No em dashes (U+2014) in this script or in the emitted file.
#   - Fail closed on any error (`set -euo pipefail`).
#   - Deterministic: sorted file walk, no timestamps in the body, schema git
#     SHA pinned to HEAD of the schema subtree at script-run time.

set -euo pipefail

# --- locate the workspace root ----------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# scripts/ -> chio-go-http/ -> go/ -> sdks/ -> WORKSPACE
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
SCHEMAS_DIR="${WORKSPACE_ROOT}/spec/schemas/chio-wire/v1"
OUTPUT_FILE="${WORKSPACE_ROOT}/sdks/go/chio-go-http/types.go"
PACKAGE_NAME="chio"
OAPI_CODEGEN_VERSION="v2.4.1"

# --- preflight --------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "regen-types.sh: 'go' is required on PATH (Go 1.21+); install Go and re-run" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "regen-types.sh: 'python3' is required on PATH (stdlib only)" >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "regen-types.sh: 'git' is required on PATH" >&2
  exit 2
fi

if [[ ! -d "${SCHEMAS_DIR}" ]]; then
  echo "regen-types.sh: schemas directory ${SCHEMAS_DIR} does not exist" >&2
  exit 2
fi

# --- compute the schema content SHA ----------------------------------------
# Earlier versions of this script ran `git log -1` over the schema subtree
# so the stamp reflected the latest commit that touched a schema. That made
# the stamp depend on git history rather than the actual schema bytes:
#   1. A no-op rebase or commit message edit shifted the SHA without any
#      schema change, dirtying the regenerated file.
#   2. Shallow CI clones (where `git log` returns nothing for the subtree)
#      stamped 'unknown' even when the bytes were correct.
#   3. Staged-but-unindexed-in-HEAD schema edits were classified as 'clean'
#      because `git diff` (working-tree vs index) returned 0 for them.
#
# We replace that with a content hash of the lex-sorted schema files: the
# stamp becomes a deterministic function of the bytes feeding into
# oapi-codegen, regardless of repository state.
cd "${WORKSPACE_ROOT}"
SCHEMA_HEAD_SHA="$(
  python3 - "${SCHEMAS_DIR}" <<'PY'
import hashlib
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
hasher = hashlib.sha256()
files = []
for parent, _, names in os.walk(root):
    for name in names:
        if name.endswith(".schema.json"):
            files.append(Path(parent) / name)
files.sort()
for path in files:
    rel = path.relative_to(root).as_posix()
    hasher.update(rel.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(path.read_bytes())
    hasher.update(b"\0")
print(hasher.hexdigest())
PY
)"
if [[ -z "${SCHEMA_HEAD_SHA}" ]]; then
  SCHEMA_HEAD_SHA="unknown"
fi

SCHEMA_SHA_STAMP="${SCHEMA_HEAD_SHA}"

# --- build a temp work area -------------------------------------------------
WORK_DIR="$(mktemp -d -t chio-go-regen.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

OPENAPI_PATH="${WORK_DIR}/chio-wire-v1.openapi.json"
RAW_OUTPUT_PATH="${WORK_DIR}/types.raw.go"

# --- preprocess JSON Schema 2020-12 -> OpenAPI 3.0 -------------------------
# JSON Schema features that need translation for oapi-codegen v2.4.1:
#   1. `const: X`              -> `enum: [X]`
#   2. property value `true`   -> `{}`        (any-value schema)
#   3. property value `false`  -> `not: {}`   (impossible schema; rarely used)
#   4. `oneOf` member with `type: "null"` -> drop the member, set
#      `nullable: true` on the parent (OpenAPI 3.0 nullable convention)
#   5. `$defs` -> lift into `components.schemas` and rewrite local
#      `$ref: "#/$defs/..."` into `$ref: "#/components/schemas/..."`
#   6. Top-level `$schema` and `$id` keys are stripped (oapi-codegen ignores
#      them; we keep the data flat under components.schemas).
#
# Component naming: `<DirPascal><FilePascal>` for top-level schemas (so
# `agent/heartbeat.schema.json` -> `AgentHeartbeat`,
# `kernel/heartbeat.schema.json` -> `KernelHeartbeat`,
# `trust-control/heartbeat.schema.json` -> `TrustControlHeartbeat`).
# Lifted `$defs` get `<TopComponentName><DefPascal>` suffixes so they don't
# collide across files (e.g. `CapabilityTokenChioScope`,
# `ReceiptRecordDecision`).
python3 - "${SCHEMAS_DIR}" "${OPENAPI_PATH}" <<'PY'
import json
import copy
import os
import sys
from pathlib import Path

schemas_dir = Path(sys.argv[1])
output_path = Path(sys.argv[2])

# Pascalize a string segment (e.g. "tool_call_request" -> "ToolCallRequest",
# "trust-control" -> "TrustControl"). Splits on `_`, `-`, and `.` so all
# three repository conventions normalize the same way.
def pascalize(value: str) -> str:
    out = []
    for part in value.replace("-", "_").replace(".", "_").split("_"):
        if not part:
            continue
        out.append(part[:1].upper() + part[1:])
    return "".join(out)


def collect_schema_files() -> list[Path]:
    files: list[Path] = []
    for root, _, names in os.walk(schemas_dir):
        for name in names:
            if name.endswith(".schema.json"):
                files.append(Path(root) / name)
    files.sort()
    return files


# Recursively rewrite a schema node in-place to be OpenAPI 3.0 compatible.
# `lifts` is the dict (`components.schemas`) we lift `$defs` into; `prefix`
# is the component-name prefix used to disambiguate lifted definitions.
def rewrite(node, lifts: dict, prefix: str):
    if isinstance(node, dict):
        # JSON Schema property whose value is the literal `true` is
        # represented in Python as the bool True after json.loads. Catch
        # that at the parent level (in the property loop below) - by the
        # time we recurse here, dicts are dicts.

        # `const: X` -> `enum: [X]`. Preserve type information so
        # oapi-codegen does not fall back to interface{} for literal
        # discriminator fields.
        if "const" in node:
            value = node.pop("const")
            node["enum"] = [value]
            if isinstance(value, str):
                node.setdefault("type", "string")
            elif isinstance(value, bool):
                node.setdefault("type", "boolean")
            elif isinstance(value, int):
                node.setdefault("type", "integer")
                node.setdefault("format", "int64")
            elif isinstance(value, float):
                node.setdefault("type", "number")

        # JSON Schema enum-only string aliases need an explicit type for
        # oapi-codegen to emit a string type instead of interface{}.
        if "enum" in node and "type" not in node:
            enum_values = node["enum"]
            if isinstance(enum_values, list) and enum_values:
                if all(isinstance(value, str) for value in enum_values):
                    node["type"] = "string"
                elif all(isinstance(value, bool) for value in enum_values):
                    node["type"] = "boolean"
                elif all(isinstance(value, int) for value in enum_values):
                    node["type"] = "integer"
                    node.setdefault("format", "int64")

        # Wire numeric counters and timestamps can exceed platform-width
        # Go int on 32-bit targets. Emit int64 consistently for integer
        # schemas unless a schema has already chosen a narrower format.
        if node.get("type") == "integer":
            node.setdefault("format", "int64")

        # oneOf with a `type: "null"` member -> drop that member and set
        # `nullable: true` on the parent. If only one non-null member
        # remains, inline it (oapi-codegen handles plain nullable types
        # better than a degenerate one-element oneOf).
        if "oneOf" in node and isinstance(node["oneOf"], list):
            non_null = []
            had_null = False
            for member in node["oneOf"]:
                if isinstance(member, dict) and member.get("type") == "null":
                    had_null = True
                    continue
                non_null.append(member)
            if had_null:
                node["oneOf"] = non_null
                node["nullable"] = True
                if len(non_null) == 1 and isinstance(non_null[0], dict):
                    inlined = non_null[0]
                    del node["oneOf"]
                    # Merge inlined keys into the parent. The comment used
                    # to claim `$schema`, `$id`, `title` were dropped, but
                    # only `$schema` and `$id` were actually skipped, so a
                    # member's `title` leaked through and overwrote the
                    # parent's display name in the generated Go field
                    # comment. Add `title` to the skip-list to match the
                    # documented intent.
                    for key, value in inlined.items():
                        if key in ("$schema", "$id", "title"):
                            continue
                        node[key] = value

        # Lift `$defs` (JSON Schema 2020-12) into the components.schemas
        # bag. Rewrite local `$ref` strings to point at the lifted name.
        if "$defs" in node:
            defs = node.pop("$defs") or {}
            # Build the full ref-remap BEFORE recursing so that a $ref
            # inside one def that points at a sibling def resolves
            # correctly regardless of dict iteration order.
            ref_remap: dict[str, str] = {}
            for name in defs.keys():
                lifted_name = f"{prefix}{pascalize(name)}"
                ref_remap[f"#/$defs/{name}"] = (
                    f"#/components/schemas/{lifted_name}"
                )
            # Rewrite refs in every def body first, then recurse for the
            # other transformations (const, oneOf nullability, nested
            # $defs). Splitting the two passes keeps each idempotent.
            for name, def_schema in defs.items():
                _rewrite_refs(def_schema, ref_remap)
                rewrite(def_schema, lifts, prefix)
                lifted_name = f"{prefix}{pascalize(name)}"
                lifts[lifted_name] = def_schema
            # And rewrite refs in the rest of the parent tree.
            _rewrite_refs(node, ref_remap)

        # Handle properties: replace literal `True` (any-value schema) and
        # `False` (impossible) with their object equivalents.
        if "properties" in node and isinstance(node["properties"], dict):
            for key, value in list(node["properties"].items()):
                if value is True:
                    node["properties"][key] = {}
                elif value is False:
                    node["properties"][key] = {"not": {}}

        # JSON Schema `oneOf` members can rely on parent-level property
        # definitions while tightening `required` per variant. OpenAPI
        # generators materialize each member independently, so copy any
        # parent-defined required properties into the member before codegen.
        # Without this, generated Go branch structs for verdict unions drop
        # required payload fields such as deny.reason/deny.guard.
        if (
            "properties" in node
            and isinstance(node["properties"], dict)
            and "oneOf" in node
            and isinstance(node["oneOf"], list)
        ):
            parent_properties = node["properties"]
            for member in node["oneOf"]:
                if not isinstance(member, dict):
                    continue
                required = member.get("required")
                if not isinstance(required, list):
                    continue
                properties = member.setdefault("properties", {})
                if not isinstance(properties, dict):
                    continue
                for key in required:
                    if (
                        isinstance(key, str)
                        and key not in properties
                        and key in parent_properties
                    ):
                        properties[key] = copy.deepcopy(parent_properties[key])

        # Recurse.
        for key, value in list(node.items()):
            if key == "$defs":
                continue
            rewrite(value, lifts, prefix)

    elif isinstance(node, list):
        for idx, item in enumerate(node):
            if item is True:
                node[idx] = {}
            elif item is False:
                node[idx] = {"not": {}}
            else:
                rewrite(item, lifts, prefix)


def _rewrite_refs(node, mapping: dict[str, str]):
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str):
            ref = node["$ref"]
            if ref in mapping:
                node["$ref"] = mapping[ref]
        for value in node.values():
            _rewrite_refs(value, mapping)
    elif isinstance(node, list):
        for item in node:
            _rewrite_refs(item, mapping)


schemas: dict = {}
for path in collect_schema_files():
    rel = path.relative_to(schemas_dir)
    parts = rel.parts
    # Component name = DirPascal + FilePascal. The schemas tree is two
    # levels deep (subtree/file.schema.json), so we expect parts of length
    # 2. Defensive fallback for deeper trees: join all dir segments.
    if len(parts) < 2:
        raise SystemExit(
            f"regen-types.sh: unexpected schema layout: {rel}"
        )
    dir_segments = parts[:-1]
    file_stem = parts[-1].removesuffix(".schema.json")
    name_prefix = "".join(pascalize(seg) for seg in dir_segments)
    component_name = name_prefix + pascalize(file_stem)

    raw = path.read_text(encoding="utf-8")
    schema = json.loads(raw)

    # Strip JSON Schema document keys; OpenAPI components.schemas is just
    # the schema body.
    schema.pop("$schema", None)
    schema.pop("$id", None)

    rewrite(schema, schemas, component_name)
    schemas[component_name] = schema

# Build the final OpenAPI 3.0 document. paths is required by oapi-codegen,
# even when empty. info.title carries the wire-version banner.
spec = {
    "openapi": "3.0.3",
    "info": {
        "title": "chio-wire/v1",
        "version": "1.0.0",
        "description": (
            "Auto-generated OpenAPI bundle of the JSON Schema files under "
            "spec/schemas/chio-wire/v1/. Consumed by sdks/go/chio-go-http/"
            "scripts/regen-types.sh; not published as an HTTP API."
        ),
    },
    "paths": {},
    "components": {
        "schemas": schemas,
    },
}

# Sort keys for determinism. json.dumps with sort_keys handles nested dicts.
output_path.write_text(
    json.dumps(spec, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(
    f"regen-types.sh: bundled {len(schemas)} schemas into "
    f"{output_path.name}",
    file=sys.stderr,
)
PY

# --- run oapi-codegen -------------------------------------------------------
# `-generate types,skip-prune` keeps every schema even when no operation
# references it (we have no operations - all schemas are model-only). The
# `skip-fmt` member is intentionally omitted so oapi-codegen runs gofmt on
# its output; we run gofmt again after prepending our header below for
# safety.
#
# `compatibility.always-prefix-enum-values: true` forces oapi-codegen to
# emit fully-qualified enum constants (`<TypeName><Value>`) rather than
# bare value names. Without it, single-instance enums like
# `TrustControlAttestationWorkloadIdentityScheme = ["spiffe"]` materialize
# as a top-level constant named `Spiffe`, and several distinct enums share
# bare names that pollute and shadow the package namespace
# (e.g. `Allow`, `Attested`, `LeaderHandoff`).
CONFIG_PATH="${WORK_DIR}/oapi-codegen.config.yaml"
cat > "${CONFIG_PATH}" <<CONFIG_EOF
package: ${PACKAGE_NAME}
output: ${RAW_OUTPUT_PATH}
generate:
  models: true
output-options:
  skip-prune: true
compatibility:
  always-prefix-enum-values: true
CONFIG_EOF

echo "regen-types.sh: invoking oapi-codegen ${OAPI_CODEGEN_VERSION}" >&2
GOFLAGS="" GOTOOLCHAIN=auto go run \
  "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -config "${CONFIG_PATH}" \
  "${OPENAPI_PATH}"

if [[ ! -s "${RAW_OUTPUT_PATH}" ]]; then
  echo "regen-types.sh: oapi-codegen produced an empty file" >&2
  exit 3
fi

# --- prepend the chio header -----------------------------------------------
# Mirror the Rust generated header (crates/chio-spec-codegen/src/lib.rs
# GENERATED_HEADER) with Go-style `//` comments. The header lives BEFORE
# the oapi-codegen banner, which we keep as a secondary attribution stamp.
HEADER_FILE="${WORK_DIR}/header.txt"
cat > "${HEADER_FILE}" <<HEADER_EOF
// DO NOT EDIT - regenerate via 'sdks/go/chio-go-http/scripts/regen-types.sh'
// or 'cargo xtask codegen --lang go'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Schema content SHA-256: ${SCHEMA_SHA_STAMP}
// Tool:   oapi-codegen ${OAPI_CODEGEN_VERSION} (see xtask/codegen-tools.lock.toml)
//
// The Schema content SHA-256 is computed from the lex-sorted schema bytes
// (not git history) so the stamp is stable across rebases, shallow clones,
// and dirty working trees.
//
// Manual edits will be overwritten by the next regeneration; the
// spec-drift CI lane runs this script and 'git diff --exit-code'
// to enforce that this file matches the committed bytes.

HEADER_EOF

# Drop the leading "// Package chio provides primitives ..." line oapi-codegen
# emits, since we are using the package for both generated and hand-written
# files (the package doc comment lives in chio.go). Keep the "Code generated
# by ... DO NOT EDIT" banner so editors and tooling that look for it still
# recognize the file as generated.
#
# The oapi-codegen banner shape (verified on v2.4.1) is:
#   // Package chio provides primitives to interact with the openapi HTTP API.
#   //
#   // Code generated by github.com/oapi-codegen/oapi-codegen/v2 version vX DO NOT EDIT.
#   package chio
#
# We strip the first comment line (the misleading "primitives to interact
# with the openapi HTTP API" claim - we are not an HTTP API) and the blank
# comment line below it, but keep the "Code generated" banner.
TAIL_FILE="${WORK_DIR}/types.tail.go"
awk '
  BEGIN { skipped = 0 }
  NR == 1 && /^\/\/ Package .* provides primitives/ { skipped = 1; next }
  NR == 2 && skipped == 1 && /^\/\/$/ { next }
  { print }
' "${RAW_OUTPUT_PATH}" > "${TAIL_FILE}"

# Concatenate header + tail.
cat "${HEADER_FILE}" "${TAIL_FILE}" > "${OUTPUT_FILE}"

python3 - "${OUTPUT_FILE}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")


def replace_once(needle: str, replacement: str) -> None:
    global text
    if needle not in text:
        raise SystemExit(
            f"regen-types.sh: generated hardening pattern missing: {needle[:80]!r}"
        )
    text = text.replace(needle, replacement, 1)


replace_once(
    """\tif t.Result != nil {
\t\tobject["result"], err = json.Marshal(t.Result)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'result': %w", err)
\t\t}
\t}
\tb, err = json.Marshal(object)
\treturn b, err
}
""",
    """\tif t.Result != nil {
\t\tobject["result"], err = json.Marshal(t.Result)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'result': %w", err)
\t\t}
\t}
\tif err := validateJsonrpcResponseObject(object); err != nil {
\t\treturn nil, err
\t}
\tb, err = json.Marshal(object)
\treturn b, err
}
""",
)
replace_once(
    """func (t *JsonrpcNotification_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

// AsJsonrpcRequestId0 returns the union data inside the JsonrpcRequest_Id as a JsonrpcRequestId0
""",
    """func (t *JsonrpcNotification_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

func (t JsonrpcNotification) MarshalJSON() ([]byte, error) {
\tobject := make(map[string]json.RawMessage)
\tvar err error

\tobject["jsonrpc"], err = json.Marshal(t.Jsonrpc)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'jsonrpc': %w", err)
\t}

\tobject["method"], err = json.Marshal(t.Method)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'method': %w", err)
\t}

\tif t.Params != nil {
\t\tobject["params"], err = json.Marshal(t.Params)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'params': %w", err)
\t\t}
\t}

\tif err := validateJsonrpcNotificationObject(object); err != nil {
\t\treturn nil, err
\t}
\treturn json.Marshal(object)
}

func (t *JsonrpcNotification) UnmarshalJSON(b []byte) error {
\tobject := make(map[string]json.RawMessage)
\tif err := json.Unmarshal(b, &object); err != nil {
\t\treturn err
\t}

\tif raw, found := object["jsonrpc"]; found {
\t\tif err := json.Unmarshal(raw, &t.Jsonrpc); err != nil {
\t\t\treturn fmt.Errorf("error reading 'jsonrpc': %w", err)
\t\t}
\t}
\tif raw, found := object["method"]; found {
\t\tif err := json.Unmarshal(raw, &t.Method); err != nil {
\t\t\treturn fmt.Errorf("error reading 'method': %w", err)
\t\t}
\t}
\tif raw, found := object["params"]; found {
\t\tif err := json.Unmarshal(raw, &t.Params); err != nil {
\t\t\treturn fmt.Errorf("error reading 'params': %w", err)
\t\t}
\t}

\treturn validateJsonrpcNotificationObject(object)
}

func validateJsonrpcNotificationObject(object map[string]json.RawMessage) error {
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc notification",
\t\tmap[string]struct{}{"jsonrpc": {}, "method": {}, "params": {}},
\t); err != nil {
\t\treturn err
\t}
\tif _, found := object["id"]; found {
\t\treturn fmt.Errorf("jsonrpc notification must not contain id")
\t}
\tif err := validateJsonrpcLiteralRaw(
\t\tobject,
\t\t"jsonrpc",
\t\tstring(JsonrpcNotificationJsonrpcN20),
\t\t"jsonrpc notification",
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcMethodRaw(object, "jsonrpc notification"); err != nil {
\t\treturn err
\t}
\treturn validateJsonrpcParamsRaw(object, "jsonrpc notification")
}

// AsJsonrpcRequestId0 returns the union data inside the JsonrpcRequest_Id as a JsonrpcRequestId0
""",
)
replace_once(
    """func (t *JsonrpcRequest_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

// AsJsonrpcResponse0 returns the union data inside the JsonrpcResponse as a JsonrpcResponse0
""",
    """func (t *JsonrpcRequest_Params) UnmarshalJSON(b []byte) error {
\terr := t.union.UnmarshalJSON(b)
\treturn err
}

func (t JsonrpcRequest) MarshalJSON() ([]byte, error) {
\tobject := make(map[string]json.RawMessage)
\tvar err error

\tobject["id"], err = json.Marshal(t.Id)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'id': %w", err)
\t}

\tobject["jsonrpc"], err = json.Marshal(t.Jsonrpc)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'jsonrpc': %w", err)
\t}

\tobject["method"], err = json.Marshal(t.Method)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'method': %w", err)
\t}

\tif t.Params != nil {
\t\tobject["params"], err = json.Marshal(t.Params)
\t\tif err != nil {
\t\t\treturn nil, fmt.Errorf("error marshaling 'params': %w", err)
\t\t}
\t}

\tif err := validateJsonrpcRequestObject(object); err != nil {
\t\treturn nil, err
\t}
\treturn json.Marshal(object)
}

func (t *JsonrpcRequest) UnmarshalJSON(b []byte) error {
\tobject := make(map[string]json.RawMessage)
\tif err := json.Unmarshal(b, &object); err != nil {
\t\treturn err
\t}

\tif raw, found := object["id"]; found {
\t\tif err := json.Unmarshal(raw, &t.Id); err != nil {
\t\t\treturn fmt.Errorf("error reading 'id': %w", err)
\t\t}
\t}
\tif raw, found := object["jsonrpc"]; found {
\t\tif err := json.Unmarshal(raw, &t.Jsonrpc); err != nil {
\t\t\treturn fmt.Errorf("error reading 'jsonrpc': %w", err)
\t\t}
\t}
\tif raw, found := object["method"]; found {
\t\tif err := json.Unmarshal(raw, &t.Method); err != nil {
\t\t\treturn fmt.Errorf("error reading 'method': %w", err)
\t\t}
\t}
\tif raw, found := object["params"]; found {
\t\tif err := json.Unmarshal(raw, &t.Params); err != nil {
\t\t\treturn fmt.Errorf("error reading 'params': %w", err)
\t\t}
\t}

\treturn validateJsonrpcRequestObject(object)
}

func validateJsonrpcRequestObject(object map[string]json.RawMessage) error {
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc request",
\t\tmap[string]struct{}{"jsonrpc": {}, "id": {}, "method": {}, "params": {}},
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcLiteralRaw(
\t\tobject,
\t\t"jsonrpc",
\t\tstring(JsonrpcRequestJsonrpcN20),
\t\t"jsonrpc request",
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcMethodRaw(object, "jsonrpc request"); err != nil {
\t\treturn err
\t}
\trawID, found := object["id"]
\tif !found {
\t\treturn fmt.Errorf("jsonrpc request missing id")
\t}
\tif err := validateJsonrpcIdRaw(rawID, "jsonrpc request id"); err != nil {
\t\treturn err
\t}
\treturn validateJsonrpcParamsRaw(object, "jsonrpc request")
}

// AsJsonrpcResponse0 returns the union data inside the JsonrpcResponse as a JsonrpcResponse0
""",
)
replace_once(
    """\tif raw, found := object["result"]; found {
\t\terr = json.Unmarshal(raw, &t.Result)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'result': %w", err)
\t\t}
\t}

\treturn err
}

// AsJsonrpcResponseId0 returns the union data inside the JsonrpcResponse_Id as a JsonrpcResponseId0
""",
    """\tif raw, found := object["result"]; found {
\t\terr = json.Unmarshal(raw, &t.Result)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'result': %w", err)
\t\t}
\t}

\treturn validateJsonrpcResponseObject(object)
}

func validateJsonrpcResponseObject(object map[string]json.RawMessage) error {
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc response",
\t\tmap[string]struct{}{"jsonrpc": {}, "id": {}, "result": {}, "error": {}},
\t); err != nil {
\t\treturn err
\t}
\tif err := validateJsonrpcLiteralRaw(
\t\tobject,
\t\t"jsonrpc",
\t\tstring(JsonrpcResponseJsonrpcN20),
\t\t"jsonrpc response",
\t); err != nil {
\t\treturn err
\t}
\trawID, found := object["id"]
\tif !found {
\t\treturn fmt.Errorf("jsonrpc response missing id")
\t}
\tif err := validateJsonrpcIdRaw(rawID, "jsonrpc response id"); err != nil {
\t\treturn err
\t}
\t_, hasResult := object["result"]
\trawError, hasError := object["error"]
\tif hasResult == hasError {
\t\treturn fmt.Errorf("jsonrpc response must contain exactly one of result or error")
\t}
\tif hasError {
\t\tif err := validateJsonrpcErrorRaw(rawError); err != nil {
\t\t\treturn err
\t\t}
\t}
\treturn nil
}

// AsJsonrpcResponseId0 returns the union data inside the JsonrpcResponse_Id as a JsonrpcResponseId0
""",
)
replace_once(
    """\tobject["verdict"], err = json.Marshal(t.Verdict)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'verdict': %w", err)
\t}

\tb, err = json.Marshal(object)
\treturn b, err
}
""",
    """\tobject["verdict"], err = json.Marshal(t.Verdict)
\tif err != nil {
\t\treturn nil, fmt.Errorf("error marshaling 'verdict': %w", err)
\t}

\tif err := validateProvenanceVerdictLinkObject(object); err != nil {
\t\treturn nil, err
\t}
\tb, err = json.Marshal(object)
\treturn b, err
}
""",
)
replace_once(
    """\tif raw, found := object["verdict"]; found {
\t\terr = json.Unmarshal(raw, &t.Verdict)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'verdict': %w", err)
\t\t}
\t}

\treturn err
}

// AsReceiptRecordDecision0 returns the union data inside the ReceiptRecordDecision as a ReceiptRecordDecision0
""",
    """\tif raw, found := object["verdict"]; found {
\t\terr = json.Unmarshal(raw, &t.Verdict)
\t\tif err != nil {
\t\t\treturn fmt.Errorf("error reading 'verdict': %w", err)
\t\t}
\t}

\treturn validateProvenanceVerdictLinkObject(object)
}

func validateProvenanceVerdictLinkObject(object map[string]json.RawMessage) error {
\tif _, err := requiredNonEmptyJsonString(object, "chainId"); err != nil {
\t\treturn err
\t}
\tif _, err := requiredNonEmptyJsonString(object, "requestId"); err != nil {
\t\treturn err
\t}
\trenderedAt, err := requiredJsonInt64(object, "renderedAt")
\tif err != nil {
\t\treturn err
\t}
\tif renderedAt < 0 {
\t\treturn fmt.Errorf("provenance verdict link renderedAt must be non-negative")
\t}
\tif rawReceiptID, found := object["receiptId"]; found && !rawJsonIsNull(rawReceiptID) {
\t\tif _, err := requiredNonEmptyJsonString(object, "receiptId"); err != nil {
\t\t\treturn err
\t\t}
\t}
\tif rawEvidenceClass, found := object["evidenceClass"]; found && !rawJsonIsNull(rawEvidenceClass) {
\t\tvar evidenceClass ProvenanceVerdictLinkEvidenceClass
\t\tif err := json.Unmarshal(rawEvidenceClass, &evidenceClass); err != nil {
\t\t\treturn fmt.Errorf("error reading 'evidenceClass': %w", err)
\t\t}
\t\tswitch evidenceClass {
\t\tcase ProvenanceVerdictLinkEvidenceClassAsserted,
\t\t\tProvenanceVerdictLinkEvidenceClassObserved,
\t\t\tProvenanceVerdictLinkEvidenceClassVerified:
\t\tdefault:
\t\t\treturn fmt.Errorf("unsupported provenance evidenceClass %q", evidenceClass)
\t\t}
\t}
\trawVerdict, found := object["verdict"]
\tif !found || rawJsonIsNull(rawVerdict) {
\t\treturn fmt.Errorf("provenance verdict link missing verdict")
\t}
\tvar verdict ProvenanceVerdictLinkVerdict
\tif err := json.Unmarshal(rawVerdict, &verdict); err != nil {
\t\treturn fmt.Errorf("error reading 'verdict': %w", err)
\t}

\thasReason := jsonFieldPresentAndNonNull(object, "reason")
\thasGuard := jsonFieldPresentAndNonNull(object, "guard")
\tswitch verdict {
\tcase ProvenanceVerdictLinkVerdictAllow:
\t\tif _, found := object["reason"]; found {
\t\t\treturn fmt.Errorf("allow verdict must not include reason")
\t\t}
\t\tif _, found := object["guard"]; found {
\t\t\treturn fmt.Errorf("allow verdict must not include guard")
\t\t}
\tcase ProvenanceVerdictLinkVerdictDeny:
\t\tif !hasReason || !hasGuard {
\t\t\treturn fmt.Errorf("deny verdict must include reason and guard")
\t\t}
\tcase ProvenanceVerdictLinkVerdictCancel:
\t\tif !hasReason {
\t\t\treturn fmt.Errorf("cancel verdict must include reason")
\t\t}
\t\tif _, found := object["guard"]; found {
\t\t\treturn fmt.Errorf("cancel verdict must not include guard")
\t\t}
\tcase ProvenanceVerdictLinkVerdictIncomplete:
\t\tif !hasReason {
\t\t\treturn fmt.Errorf("incomplete verdict must include reason")
\t\t}
\t\tif _, found := object["guard"]; found {
\t\t\treturn fmt.Errorf("incomplete verdict must not include guard")
\t\t}
\tdefault:
\t\treturn fmt.Errorf("unsupported provenance verdict %q", verdict)
\t}
\treturn nil
}

func validateJsonrpcLiteralRaw(
\tobject map[string]json.RawMessage,
\tkey string,
\twant string,
\tcontext string,
) error {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("%s missing %s", context, key)
\t}
\tvar value string
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn fmt.Errorf("error reading '%s': %w", key, err)
\t}
\tif value != want {
\t\treturn fmt.Errorf("%s %s must be %q", context, key, want)
\t}
\treturn nil
}

func validateJsonrpcAllowedFieldsRaw(
\tobject map[string]json.RawMessage,
\tcontext string,
\tallowed map[string]struct{},
) error {
\tfor key := range object {
\t\tif _, ok := allowed[key]; !ok {
\t\t\treturn fmt.Errorf("%s contains unknown field %q", context, key)
\t\t}
\t}
\treturn nil
}

func validateJsonrpcMethodRaw(object map[string]json.RawMessage, context string) error {
\traw, found := object["method"]
\tif !found || rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("%s missing method", context)
\t}
\tvar method string
\tif err := json.Unmarshal(raw, &method); err != nil {
\t\treturn fmt.Errorf("error reading 'method': %w", err)
\t}
\tif method == "" {
\t\treturn fmt.Errorf("%s method must be non-empty", context)
\t}
\treturn nil
}

func validateJsonrpcIdRaw(raw json.RawMessage, context string) error {
\tif rawJsonIsNull(raw) {
\t\treturn nil
\t}
\tvar idString string
\tif err := json.Unmarshal(raw, &idString); err == nil {
\t\tif idString == "" {
\t\t\treturn fmt.Errorf("%s string must be non-empty", context)
\t\t}
\t\treturn nil
\t}
\tvar idInt int64
\tif err := json.Unmarshal(raw, &idInt); err == nil {
\t\treturn nil
\t}
\treturn fmt.Errorf("%s must be an integer, non-empty string, or null", context)
}

func validateJsonrpcParamsRaw(object map[string]json.RawMessage, context string) error {
\traw, found := object["params"]
\tif !found {
\t\treturn nil
\t}
\tif rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("%s params must not be null", context)
\t}
\tswitch firstJsonByte(raw) {
\tcase '{', '[':
\t\treturn nil
\tdefault:
\t\treturn fmt.Errorf("%s params must be an object or array", context)
\t}
}

func validateJsonrpcErrorRaw(raw json.RawMessage) error {
\tif rawJsonIsNull(raw) {
\t\treturn fmt.Errorf("jsonrpc error response error must not be null")
\t}
\tvar object map[string]json.RawMessage
\tif err := json.Unmarshal(raw, &object); err != nil || object == nil {
\t\tif err != nil {
\t\t\treturn fmt.Errorf("jsonrpc error response error must be an object: %w", err)
\t\t}
\t\treturn fmt.Errorf("jsonrpc error response error must be an object")
\t}
\tif err := validateJsonrpcAllowedFieldsRaw(
\t\tobject,
\t\t"jsonrpc error response error",
\t\tmap[string]struct{}{"code": {}, "message": {}, "data": {}},
\t); err != nil {
\t\treturn err
\t}
\tif _, err := requiredJsonInt64Field(object, "code", "jsonrpc error response error"); err != nil {
\t\treturn err
\t}
\tif _, err := requiredNonEmptyJsonStringField(
\t\tobject,
\t\t"message",
\t\t"jsonrpc error response error",
\t); err != nil {
\t\treturn err
\t}
\treturn nil
}

func requiredNonEmptyJsonStringField(
\tobject map[string]json.RawMessage,
\tkey string,
\tcontext string,
) (string, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn "", fmt.Errorf("%s missing %s", context, key)
\t}
\tvar value string
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn "", fmt.Errorf("error reading '%s': %w", key, err)
\t}
\tif value == "" {
\t\treturn "", fmt.Errorf("%s %s must be non-empty", context, key)
\t}
\treturn value, nil
}

func requiredJsonInt64Field(
\tobject map[string]json.RawMessage,
\tkey string,
\tcontext string,
) (int64, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn 0, fmt.Errorf("%s missing %s", context, key)
\t}
\tvar value int64
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn 0, fmt.Errorf("error reading '%s': %w", key, err)
\t}
\treturn value, nil
}

func firstJsonByte(raw json.RawMessage) byte {
\tfor _, b := range raw {
\t\tswitch b {
\t\tcase ' ', '\\n', '\\r', '\\t':
\t\t\tcontinue
\t\tdefault:
\t\t\treturn b
\t\t}
\t}
\treturn 0
}

func jsonFieldPresentAndNonNull(object map[string]json.RawMessage, key string) bool {
\traw, found := object[key]
\treturn found && !rawJsonIsNull(raw)
}

func requiredNonEmptyJsonString(object map[string]json.RawMessage, key string) (string, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn "", fmt.Errorf("provenance verdict link missing %s", key)
\t}
\tvar value string
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn "", fmt.Errorf("error reading '%s': %w", key, err)
\t}
\tif value == "" {
\t\treturn "", fmt.Errorf("provenance verdict link %s must be non-empty", key)
\t}
\treturn value, nil
}

func requiredJsonInt64(object map[string]json.RawMessage, key string) (int64, error) {
\traw, found := object[key]
\tif !found || rawJsonIsNull(raw) {
\t\treturn 0, fmt.Errorf("provenance verdict link missing %s", key)
\t}
\tvar value int64
\tif err := json.Unmarshal(raw, &value); err != nil {
\t\treturn 0, fmt.Errorf("error reading '%s': %w", key, err)
\t}
\treturn value, nil
}

func rawJsonIsNull(raw json.RawMessage) bool {
\treturn string(raw) == "null"
}

// AsReceiptRecordDecision0 returns the union data inside the ReceiptRecordDecision as a ReceiptRecordDecision0
""",
)

path.write_text(text, encoding="utf-8")
PY

# Final pass: gofmt the file in-place. oapi-codegen already runs gofmt on
# its output, but our header prepend can shift line-numbering across
# versions; gofmt is idempotent so this is safe.
go fmt "${OUTPUT_FILE}" >/dev/null

echo "regen-types.sh: wrote ${OUTPUT_FILE}" >&2
