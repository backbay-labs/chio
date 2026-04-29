"""Host import wrappers for chio:guard@0.2.0."""

from __future__ import annotations


class HostUnavailableError(RuntimeError):
    """Raised when a host import is called outside a component runtime."""


def _unavailable(name: str) -> HostUnavailableError:
    return HostUnavailableError(
        f"{name} is only available inside a chio:guard@0.2.0 component"
    )


def log(level: int, msg: str) -> None:
    """Emit a log message through the Chio guard host import."""

    raise _unavailable("host.log")


def get_config(key: str) -> str | None:
    """Read a configuration value through the Chio guard host import."""

    raise _unavailable("host.get_config")


def get_time_unix_secs() -> int:
    """Return host wall-clock time in Unix seconds."""

    raise _unavailable("host.get_time_unix_secs")


def fetch_blob(handle: int, offset: int, length: int) -> bytes:
    """Read bytes from a host-owned content bundle blob."""

    raise _unavailable("host.fetch_blob")
