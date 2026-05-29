from __future__ import annotations

import json
from typing import Any, Literal

ChioInvariantErrorCode = Literal[
    "json",
    "canonical_json",
    "invalid_hex",
    "invalid_public_key",
    "invalid_signature",
]


class ChioError(Exception):
    pass


class ChioInvariantError(ChioError):
    def __init__(self, code: ChioInvariantErrorCode, message: str):
        super().__init__(message)
        self.code = code


class ChioTransportError(ChioError):
    pass


class ChioQueryError(ChioError):
    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


class ChioRpcError(ChioError):
    def __init__(self, message: str, *, code: int | None = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


def parse_json_text(input_text: str) -> Any:
    try:
        return json.loads(input_text)
    except json.JSONDecodeError as exc:
        raise ChioInvariantError("json", "input is not valid JSON") from exc
