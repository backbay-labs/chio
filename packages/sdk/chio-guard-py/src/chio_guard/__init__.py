"""chio-guard-py -- Python SDK for Chio guard components.

Targets the ``chio:guard@0.2.0`` WIT world. Types are hand-written
dataclasses matching ``wit/chio-guard/world.wit``. The generated
componentize-py bindings are in a gitignored directory and are produced
by ``scripts/generate-types.sh``.
"""

from .host import HostUnavailableError, fetch_blob, get_config, get_time_unix_secs, log
from .policy_context import PolicyContext
from .types import GuardRequest, Verdict, VerdictAllow, VerdictDeny

__all__ = [
    "HostUnavailableError",
    "GuardRequest",
    "PolicyContext",
    "Verdict",
    "VerdictAllow",
    "VerdictDeny",
    "fetch_blob",
    "get_config",
    "get_time_unix_secs",
    "log",
]
