"""chio-adapter-base: shared security and receipt primitives for Chio adapters.

The canonical import path for any primitive is its submodule
(:mod:`chio_adapter_base.security`, :mod:`chio_adapter_base.receipts`,
:mod:`chio_adapter_base.redact`, :mod:`chio_adapter_base.filters`). The
top-level re-exports below are convenience aliases for the most common
names so simple consumers can write::

    from chio_adapter_base import sanitised_env, ReceiptBuffer

without grepping for the submodule. New names should be added to the
submodule first; promote to the top-level only when there are at least
two adapter call sites that justify the convenience.
"""

from __future__ import annotations

from chio_adapter_base.filters import (
    filter_diff_output,
    filter_directory_entries,
    filter_status_output,
    forbidden_path_filter,
)
from chio_adapter_base.receipts import (
    DEFAULT_RECEIPT_BUFFER_MAX,
    ReceiptBuffer,
    append_jsonl,
    canonical_dumps,
)
from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactArgs,
    RedactionPolicy,
    bind_and_redact,
    build_alias_map,
    redact_args,
)
from chio_adapter_base.security import (
    DEFAULT_SHELL_TIMEOUT,
    DEFAULT_SUBPROCESS_MAX_BYTES,
    BoundedSubprocess,
    BoundedSubprocessResult,
    ChioPathEscapeError,
    harden_git_argv,
    reject_shell_argv_escape,
    resolve_within,
    sanitised_env,
)

__version__ = "0.2.0"

__all__ = [
    "DEFAULT_RECEIPT_BUFFER_MAX",
    "DEFAULT_SHELL_TIMEOUT",
    "DEFAULT_SUBPROCESS_MAX_BYTES",
    "DEFAULT_TOOL_POSITIONAL_NAMES",
    "BoundedSubprocess",
    "BoundedSubprocessResult",
    "ChioPathEscapeError",
    "ReceiptBuffer",
    "RedactArgs",
    "RedactionPolicy",
    "__version__",
    "append_jsonl",
    "bind_and_redact",
    "build_alias_map",
    "canonical_dumps",
    "filter_diff_output",
    "filter_directory_entries",
    "filter_status_output",
    "forbidden_path_filter",
    "harden_git_argv",
    "redact_args",
    "reject_shell_argv_escape",
    "resolve_within",
    "sanitised_env",
]
