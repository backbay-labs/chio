"""Policy context resource wrappers for chio:guard@0.2.0."""

from __future__ import annotations

from dataclasses import dataclass

from .host import fetch_blob


@dataclass(frozen=True)
class PolicyContext:
    """Guest-side wrapper for a host-owned bundle-handle resource."""

    id: str
    handle: int = 0

    def read(self, offset: int, length: int) -> bytes:
        """Read a byte range from the bundle handle."""

        return fetch_blob(self.handle, offset, length)

    def close(self) -> None:
        """Close the policy context wrapper."""

        return None
