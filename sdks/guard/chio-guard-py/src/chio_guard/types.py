"""Ergonomic Python dataclasses wrapping the chio:guard@0.2.0 WIT types.

These are hand-written wrappers for developer ergonomics. The generated
componentize-py bindings live in a gitignored directory and are
produced by ``scripts/generate-types.sh``.

All types mirror ``wit/chio-guard/world.wit`` exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


@dataclass
class GuardRequest:
    """Read-only request context provided to the guard by the host.

    Matches the WIT ``guard-request`` record field-for-field.
    """

    tool_name: str
    """Tool being invoked."""

    server_id: str
    """Server hosting the tool."""

    agent_id: str
    """Agent making the request."""

    arguments: str
    """Tool arguments as a JSON-encoded string."""

    scopes: list[str] = field(default_factory=list)
    """Capability scopes granted (serialized scope names)."""

    action_type: str | None = None
    """Host-extracted action type (e.g. ``file_access``, ``network_egress``)."""

    extracted_path: str | None = None
    """Normalized file path for filesystem actions."""

    extracted_target: str | None = None
    """Target domain string for network egress actions."""

    filesystem_roots: list[str] = field(default_factory=list)
    """Session-scoped filesystem roots from the kernel context."""

    matched_grant_index: int | None = None
    """Index of the matched grant in the capability scope."""


@dataclass
class VerdictAllow:
    """The guard allows the request to proceed."""


@dataclass
class VerdictDeny:
    """The guard denies the request with a human-readable reason."""

    reason: str


Verdict = Union[VerdictAllow, VerdictDeny]
"""A guard evaluation result -- either allow or deny with reason."""
