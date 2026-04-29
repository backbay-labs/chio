"""Dataclasses for the chio:guard@0.2.0 WIT guard types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


@dataclass
class GuardRequest:
    """Read-only request context provided to the guard by the host."""

    tool_name: str
    server_id: str
    agent_id: str
    arguments: str
    scopes: list[str] = field(default_factory=list)
    action_type: str | None = None
    extracted_path: str | None = None
    extracted_target: str | None = None
    filesystem_roots: list[str] = field(default_factory=list)
    matched_grant_index: int | None = None


@dataclass
class VerdictAllow:
    """The guard allows the request to proceed."""


@dataclass
class VerdictDeny:
    """The guard denies the request with a human-readable reason."""

    reason: str


Verdict = Union[VerdictAllow, VerdictDeny]
