from __future__ import annotations

import json
import math
import re
from decimal import Decimal
from typing import Any

from ..errors import ChioInvariantError, parse_json_text

_EXPONENT_RE = re.compile(r"e([+-])0+(\d+)$")


def _canonical_json_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _canonicalize_float(value: float) -> str:
    if not math.isfinite(value):
        raise ChioInvariantError(
            "canonical_json",
            "canonical JSON does not support non-finite numbers",
        )
    if value == 0.0:
        return "0"
    rendered = repr(value).lower()
    if 1e-6 <= abs(value) < 1e21:
        decimal = format(Decimal(rendered), "f")
        if "." in decimal:
            decimal = decimal.rstrip("0").rstrip(".")
        return decimal
    return _EXPONENT_RE.sub(lambda match: f"e{match.group(1)}{match.group(2)}", rendered)


def canonicalize_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonicalize_float(value)
    if isinstance(value, str):
        return _canonical_json_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ChioInvariantError("canonical_json", "canonical JSON object keys must be strings")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return "{" + ",".join(
            f"{_canonical_json_string(key)}:{canonicalize_json(entry_value)}"
            for key, entry_value in items
        ) + "}"
    raise ChioInvariantError(
        "canonical_json",
        f"canonical JSON does not support values of type {type(value).__name__}",
    )


def canonicalize_json_string(input_text: str) -> str:
    return canonicalize_json(parse_json_text(input_text))
