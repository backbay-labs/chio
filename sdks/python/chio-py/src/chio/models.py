from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class TransportResponse:
    request: dict[str, Any]
    status: int
    headers: dict[str, str]
    messages: list[dict[str, Any]]


@dataclass(slots=True)
class SessionHandshake:
    initialize_response: TransportResponse
    initialized_response: TransportResponse
