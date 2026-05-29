"""Chio Dagster integration.

Wraps Dagster's Python SDK (:mod:`dagster`) so every ``@chio_asset`` and
``@chio_op`` materialization flows through the Chio sidecar for
capability-scoped authorisation. Partition keys are forwarded into the
capability evaluation payload so operators can grant access to specific
partitions only (the canonical ``region=eu-west`` data-residency
pattern). Denied materializations raise :class:`PermissionError` (which
Dagster routes to a failed op / asset state); every allow verdict is
attached to the emitted :class:`dagster.AssetMaterialization` as
:class:`dagster.MetadataValue` entries so the Dagster UI renders
receipts on the asset catalog row.

Public surface:

* :func:`chio_asset` -- decorator that wraps a Python function as a
  Dagster :func:`dagster.asset` gated on a Chio capability check.
* :func:`chio_op` -- decorator that wraps a Python function as a
  Dagster :func:`dagster.op` with the same pre-execute gate.
* :class:`ChioIOManager` -- IO manager wrapper that evaluates a
  capability before delegating to an inner manager's
  :meth:`load_input` / :meth:`handle_output`.
* :class:`ChioDagsterError` / :class:`ChioDagsterConfigError` -- error
  types.

The decorators mirror the signatures of :func:`dagster.asset` and
:func:`dagster.op` so Dagster options (``partitions_def``, ``ins``,
``deps``, ``io_manager_key``, ``group_name``, ``retry_policy``, ...)
pass through verbatim.
"""

from chio_dagster.decorators import chio_asset, chio_op
from chio_dagster.errors import ChioDagsterConfigError, ChioDagsterError
from chio_dagster.io_manager import ChioIOManager
from chio_dagster.partitions import extract_partition_info

__all__ = [
    "ChioDagsterConfigError",
    "ChioDagsterError",
    "ChioIOManager",
    "chio_asset",
    "chio_op",
    "extract_partition_info",
]
