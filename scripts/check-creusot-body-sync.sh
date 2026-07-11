#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

if [[ "${1:-}" == "--root" ]]; then
  if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 [--root PATH]" >&2
    exit 2
  fi
  repo_root="$(cd "$2" && pwd)"
elif [[ "$#" -ne 0 ]]; then
  echo "usage: $0 [--root PATH]" >&2
  exit 2
fi

python3 - "$repo_root" <<'PY'
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required for Creusot body checks") from exc


@dataclass(frozen=True)
class Function:
    name: str
    parameters: tuple[str, ...]
    body: tuple[str, ...]
    depth: int


def mask_non_code(source: str) -> str:
    masked = list(source)
    length = len(source)
    index = 0

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if masked[position] != "\n":
                masked[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end == -1:
                end = length
            blank(index, end)
            index = end
            continue

        if source.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < length and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise SystemExit("creusot-body-sync: unterminated block comment")
            blank(start, index)
            continue

        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
        if raw:
            start = index
            hashes = raw.group("hashes")
            index += raw.end()
            terminator = '"' + hashes
            end = source.find(terminator, index)
            if end == -1:
                raise SystemExit("creusot-body-sync: unterminated raw string")
            index = end + len(terminator)
            blank(start, index)
            continue

        prefix_length = 1 if source.startswith('b"', index) else 0
        if source[index + prefix_length : index + prefix_length + 1] == '"':
            start = index
            index += prefix_length + 1
            escaped = False
            while index < length:
                char = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            else:
                raise SystemExit("creusot-body-sync: unterminated string")
            blank(start, index)
            continue

        if source[index] == "'":
            start = index
            cursor = index + 1
            escaped = False
            found = False
            while cursor < length and source[cursor] != "\n":
                char = source[cursor]
                cursor += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    found = True
                    break
            if found:
                blank(start, cursor)
                index = cursor
                continue

        index += 1

    return "".join(masked)


def matching(source: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    raise SystemExit(f"creusot-body-sync: unmatched {opening}")


def tokens(source: str) -> tuple[str, ...]:
    return tuple(
        re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|::|->|=>|==>|==|!=|<=|>=|&&|\|\||\.\.|\S",
            source,
        )
    )


def canonical_tokens(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        value
        for index, value in enumerate(values)
        if not (value == "," and index + 1 < len(values) and values[index + 1] == ")")
    )


def parameter_names(signature: str) -> tuple[str, ...]:
    names = []
    start = 0
    nested = 0
    segments = []
    for index, char in enumerate(signature):
        if char in "(<[":
            nested += 1
        elif char in ")>]":
            nested -= 1
        elif char == "," and nested == 0:
            segments.append(signature[start:index])
            start = index + 1
    segments.append(signature[start:])

    for segment in segments:
        if not segment.strip():
            continue
        before_type, separator, _ = segment.partition(":")
        if not separator:
            raise SystemExit(
                "creusot-body-sync: contract parameters must use explicit named types"
            )
        identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", before_type)
        if not identifiers:
            raise SystemExit("creusot-body-sync: contract parameter name is missing")
        names.append(identifiers[-1])
    return tuple(names)


def extract_functions(source: str) -> list[Function]:
    masked = mask_non_code(source)
    depth_at = [0] * (len(masked) + 1)
    depth = 0
    for index, char in enumerate(masked):
        depth_at[index] = depth
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth < 0:
                raise SystemExit("creusot-body-sync: unmatched closing brace")
    depth_at[len(masked)] = depth
    if depth:
        raise SystemExit("creusot-body-sync: unmatched opening brace")

    functions = []
    for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", masked):
        name = match.group(1)
        open_paren = masked.find("(", match.start())
        close_paren = matching(masked, open_paren, "(", ")")
        cursor = close_paren + 1
        while cursor < len(masked) and masked[cursor] not in "{;":
            cursor += 1
        if cursor == len(masked) or masked[cursor] == ";":
            raise SystemExit(f"creusot-body-sync: function {name} has no body")
        close_brace = matching(masked, cursor, "{", "}")
        body_source = masked[cursor + 1 : close_brace]
        functions.append(
            Function(
                name=name,
                parameters=parameter_names(masked[open_paren + 1 : close_paren]),
                body=tokens(body_source),
                depth=depth_at[match.start()],
            )
        )
    return functions


root = Path(sys.argv[1])
manifest_path = root / "formal/rust-verification/creusot-contracts.toml"
contract_path = root / "formal/rust-verification/creusot-core/src/lib.rs"
production_path = root / "crates/kernel/chio-kernel-core/src/formal_aeneas.rs"

for path in (manifest_path, contract_path, production_path):
    if not path.is_file():
        raise SystemExit(f"creusot-body-sync: required input is missing: {path.relative_to(root)}")

manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
mappings = manifest.get("contract_twin")
if not isinstance(mappings, list) or not mappings:
    raise SystemExit("creusot-body-sync: contract_twin must be a non-empty table array")

twins = {}
production_twins = set()
for index, mapping in enumerate(mappings):
    if not isinstance(mapping, dict):
        raise SystemExit(f"creusot-body-sync: contract_twin[{index}] must be a table")
    contract = mapping.get("contract")
    production = mapping.get("production")
    if not isinstance(contract, str) or not contract.endswith("_contract"):
        raise SystemExit(f"creusot-body-sync: invalid contract_twin contract at index {index}")
    if not isinstance(production, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*", production
    ):
        raise SystemExit(f"creusot-body-sync: invalid contract_twin production at index {index}")
    if contract in twins:
        raise SystemExit(f"creusot-body-sync: duplicate contract_twin contract: {contract}")
    if production in production_twins:
        raise SystemExit(f"creusot-body-sync: duplicate production twin: {production}")
    twins[contract] = production
    production_twins.add(production)

contract_source = contract_path.read_text(encoding="utf-8")
masked_contract = mask_non_code(contract_source)
if re.search(r"#\s*!?\s*\[\s*cfg(?:_attr)?\b", masked_contract):
    raise SystemExit(
        "creusot-body-sync: conditional compilation is not allowed in the contract crate"
    )
all_modules = re.findall(
    r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|;)", masked_contract
)
if all_modules != ["aeneas_body"]:
    raise SystemExit(
        "creusot-body-sync: aeneas_body must be the contract crate's only module"
    )
module_matches = list(re.finditer(r"\bmod\s+aeneas_body\s*\{", masked_contract))
if len(module_matches) != 1:
    raise SystemExit("creusot-body-sync: contract crate must define one aeneas_body module")
expected_prefix_tokens = tokens(
    "use creusot_std::prelude::*; #[allow(dead_code)]"
)
if tokens(masked_contract[: module_matches[0].start()]) != expected_prefix_tokens:
    raise SystemExit(
        "creusot-body-sync: aeneas_body must be an unconditional top-level module"
    )
module_open = masked_contract.find("{", module_matches[0].start())
module_close = matching(masked_contract, module_open, "{", "}")
module_source = contract_source[module_open + 1 : module_close]
masked_module = mask_non_code(module_source)
include_matches = list(re.finditer(r"\binclude\s*!", masked_module))
if len(include_matches) != 1:
    raise SystemExit(
        "creusot-body-sync: aeneas_body must contain exactly one real include invocation"
    )
include_pattern = re.compile(
    r"\binclude!\s*\(\s*"
    r'"\.\./\.\./\.\./\.\./crates/kernel/chio-kernel-core/src/formal_aeneas\.rs"'
    r"\s*\)\s*;",
    re.DOTALL,
)
include_match = include_pattern.match(module_source, include_matches[0].start())
if include_match is None:
    raise SystemExit(
        "creusot-body-sync: contract crate must include the production source in aeneas_body"
    )
expected_module_tokens = tokens(
    mask_non_code(
        """
        use creusot_std::{
            prelude::*,
            std::{clone::Clone, cmp::PartialEq, default::Default},
        };
        include!("production.rs");
        """
    )
)
if tokens(masked_module) != expected_module_tokens:
    raise SystemExit(
        "creusot-body-sync: aeneas_body must contain only the allowlisted "
        "Creusot imports and unconditional production include"
    )
if len(re.findall(r"\binclude\s*!", masked_contract)) != 1:
    raise SystemExit("creusot-body-sync: contract crate must contain exactly one real include")

contract_functions = extract_functions(contract_source)
nested = sorted(function.name for function in contract_functions if function.depth != 0)
if nested:
    raise SystemExit(
        "creusot-body-sync: nested function bodies are not allowed: " + ", ".join(nested)
    )
unexpected = sorted(
    function.name for function in contract_functions if not function.name.endswith("_contract")
)
if unexpected:
    raise SystemExit(
        "creusot-body-sync: non-contract function bodies are not allowed: "
        + ", ".join(unexpected)
    )

functions_by_name = {function.name: function for function in contract_functions}
if len(functions_by_name) != len(contract_functions):
    raise SystemExit("creusot-body-sync: duplicate contract function names")

contract_names = set(functions_by_name)
mapping_names = set(twins)
missing_mappings = sorted(contract_names - mapping_names)
extra_mappings = sorted(mapping_names - contract_names)
if missing_mappings:
    raise SystemExit(
        "creusot-body-sync: contract functions missing from contract_twin: "
        + ", ".join(missing_mappings)
    )
if extra_mappings:
    raise SystemExit(
        "creusot-body-sync: contract_twin entries missing from contract crate: "
        + ", ".join(extra_mappings)
    )

production_functions = {
    function.name
    for function in extract_functions(production_path.read_text(encoding="utf-8"))
    if function.depth == 0
}
missing_twins = sorted(production_twins - production_functions)
if missing_twins:
    raise SystemExit(
        "creusot-body-sync: production twins are missing: " + ", ".join(missing_twins)
    )

for contract in sorted(contract_names):
    function = functions_by_name[contract]
    production = twins[contract]
    expected_call = f"aeneas_body::{production}({', '.join(function.parameters)})"
    expected_body = tokens(expected_call)
    if canonical_tokens(function.body) != canonical_tokens(expected_body):
        actual = " ".join(function.body)
        print("creusot-body-sync: BODY DRIFT", file=sys.stderr)
        print(
            f"  contract: {contract} (formal/rust-verification/creusot-core/src/lib.rs)",
            file=sys.stderr,
        )
        print(
            f"  twin:     {production} "
            "(crates/kernel/chio-kernel-core/src/formal_aeneas.rs)",
            file=sys.stderr,
        )
        print(f"  expected: {expected_call}", file=sys.stderr)
        print(f"  actual:   {actual}", file=sys.stderr)
        print("  The contract body must be exactly the expected delegation call.", file=sys.stderr)
        raise SystemExit(1)

print(
    "creusot-body-sync: all contract bodies delegate to their declared production twins"
)
PY
