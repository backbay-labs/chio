#!/usr/bin/env python3
"""Transcribe integer-domain canonical JSON vectors into Lean byte fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "tests/bindings/vectors/canonical/v1.json"
OUTPUT = REPO / "formal/lean4/Chio/Chio/Json/Fixtures.lean"
MODELED_CORPUS_FLOOR = 13
REQUIRED_CASES = {
    "u001f_escape": ("\x1f", '"\\u001f"'),
    "u007f_escape": ("\x7f", '"\x7f"'),
    "u009f_escape": ("\x9f", '"\x9f"'),
    "utf16_key_ordering": (
        {"\ue000": 1, "\U00010000": 2},
        '{"\U00010000":2,"\ue000":1}',
    ),
    "supplementary_plane_key_sort": (
        {"\U0001f600": 1, "a": 1},
        '{"a":1,"\U0001f600":1}',
    ),
}


def in_modeled_domain(value: Any) -> bool:
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, int):
        return -(2**63) <= value <= 2**64 - 1
    if isinstance(value, list):
        return all(in_modeled_domain(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and in_modeled_domain(item)
            for key, item in value.items()
        )
    return False


def model_size(value: Any) -> int:
    if isinstance(value, list):
        return 1 + sum(model_size(item) for item in value)
    if isinstance(value, dict):
        return 1 + sum(model_size(item) for item in value.values())
    return 1


def model_depth(value: Any) -> int:
    if isinstance(value, list):
        return 1 + max((model_depth(item) for item in value), default=0)
    if isinstance(value, dict):
        return 1 + max((model_depth(item) for item in value.values()), default=0)
    return 1


def lean_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    if not name or name[0].isdigit():
        name = f"case_{name}"
    return name


def scalar(code: int) -> str:
    named = {
        8: ".backspace",
        9: ".tab",
        10: ".lineFeed",
        12: ".formFeed",
        13: ".carriageReturn",
        34: ".quote",
        92: ".reverseSolidus",
    }
    if code in named:
        return named[code]
    if code <= 31:
        high, low = divmod(code, 16)
        return (
            f".control ({{ val := {high}, isLt := by decide }} : Fin 16) "
            f"({{ val := {low}, isLt := by decide }} : Fin 16) "
            "(by decide)"
        )
    return f".literal {code} (by decide)"


def scalar_seq(value: str) -> str:
    return "[" + ", ".join(scalar(ord(char)) for char in value) + "]"


def bounded_int(value: int) -> str:
    negative = value < 0
    digits = [int(char) for char in str(abs(value))]
    rendered_digits = ", ".join(
        f"({{ val := {digit}, isLt := by decide }} : Fin 10)" for digit in digits
    )
    return (
        "{ negative := "
        + ("true" if negative else "false")
        + f", digits := [{rendered_digits}], valid := by decide }}"
    )


def utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def array_term(values: list[Any]) -> str:
    result = ".nil"
    for item in reversed(values):
        result = f".cons ({jvalue(item)}) ({result})"
    return result


def object_term(entries: list[tuple[str, Any]]) -> str:
    result = ".nil"
    for key, value in reversed(entries):
        result = f".cons ({scalar_seq(key)}) ({jvalue(value)}) ({result})"
    return result


def jvalue(value: Any) -> str:
    if value is None:
        return ".null"
    if isinstance(value, bool):
        return f".bool {str(value).lower()}"
    if isinstance(value, int):
        return f".int ({bounded_int(value)})"
    if isinstance(value, str):
        return f".str ({scalar_seq(value)})"
    if isinstance(value, list):
        return f".arr ({array_term(value)})"
    if isinstance(value, dict):
        entries = sorted(value.items(), key=lambda item: utf16_key(item[0]))
        return f".obj ({object_term(entries)})"
    raise TypeError(f"unsupported modeled value: {value!r}")


def byte_seq(value: str) -> str:
    return "[" + ", ".join(str(byte) for byte in value.encode("utf-8")) + "]"


def render() -> str:
    corpus = json.loads(SOURCE.read_text(encoding="utf-8"))
    cases: list[tuple[str, Any, str]] = []
    seen_ids: set[str] = set()
    modeled_ids: set[str] = set()
    for item in corpus["cases"]:
        case_id = item["id"]
        if case_id in seen_ids:
            raise RuntimeError(f"duplicate canonical vector id: {case_id}")
        seen_ids.add(case_id)
        parsed = json.loads(item["input_json"])
        required = REQUIRED_CASES.get(case_id)
        if required is not None and (parsed, item["canonical_json"]) != required:
            raise RuntimeError(
                f"canonical regression vector changed unexpectedly: {case_id}"
            )
        if (
            in_modeled_domain(parsed)
            and model_size(parsed) <= 64
            and model_depth(parsed) <= 8
        ):
            cases.append((lean_name(case_id), parsed, item["canonical_json"]))
            modeled_ids.add(case_id)

    missing_required = sorted(REQUIRED_CASES.keys() - seen_ids)
    if missing_required:
        raise RuntimeError(
            "canonical vector corpus lost required regressions: "
            + ", ".join(missing_required)
        )
    filtered_required = sorted(REQUIRED_CASES.keys() - modeled_ids)
    if filtered_required:
        raise RuntimeError(
            "canonical regressions escaped the modeled fixture domain: "
            + ", ".join(filtered_required)
        )

    if len(cases) < MODELED_CORPUS_FLOOR:
        raise RuntimeError(
            "canonical vector corpus lost modeled coverage: "
            f"expected at least {MODELED_CORPUS_FLOOR}, found {len(cases)}"
        )

    lines = [
        "import Chio.Json.Canonical",
        "",
        "set_option autoImplicit false",
        "",
        "namespace Chio.Json.Fixtures",
        "",
        f"def corpusCaseCount : Nat := {len(cases)}",
        "",
    ]
    for name, parsed, expected in cases:
        lines.extend(
            [
                f"def {name} : JValue := {jvalue(parsed)}",
                f"#guard canonical {name} == {byte_seq(expected)}",
                "",
            ]
        )

    lines.extend(["end Chio.Json.Fixtures", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()

    if args.check:
        actual = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if actual != expected:
            print(f"Lean canonical fixtures are stale: {OUTPUT.relative_to(REPO)}", file=sys.stderr)
            return 1
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
