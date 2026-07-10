"""Configuration for the Chio ASGI middleware."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChioASGIConfig:
    """Configuration for ChioASGIMiddleware.

    Parameters
    ----------
    sidecar_url:
        Base URL of the Chio sidecar (default ``http://127.0.0.1:9090``).
    timeout:
        Request timeout in seconds for sidecar calls (default 5).
    exclude_paths:
        Paths that bypass Chio evaluation (e.g. health checks).
    exclude_methods:
        HTTP methods that bypass Chio evaluation (default OPTIONS).
    receipt_header:
        Response header name for the Chio receipt ID (default ``X-Chio-Receipt``).
    fail_open:
        Legacy option retained for source compatibility. Current v1 always
        fails closed when the sidecar is unreachable.
    max_body_bytes:
        Maximum request body bytes buffered for hashing and replay (default 8 MiB).
    """

    sidecar_url: str = "http://127.0.0.1:9090"
    timeout: float = 5.0
    exclude_paths: frozenset[str] = frozenset()
    exclude_methods: frozenset[str] = frozenset({"OPTIONS"})
    receipt_header: str = "X-Chio-Receipt"
    fail_open: bool = False
    max_body_bytes: int = 8 * 1024 * 1024
