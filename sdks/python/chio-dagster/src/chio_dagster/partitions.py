"""Helpers to project Dagster partition context into the Chio evaluation payload.

Dagster partitions subdivide an asset by a key (for example, a date, a
region, or a tenant). A partitioned materialization attaches a
``partition_key`` (or a range of them) to the execution context; an
Chio-governed asset MUST include this key in the capability evaluation
payload so operators can grant access to specific partitions only (the
classic ``region=eu-west`` data-residency pattern).

This module is intentionally tiny: the actual partition read happens on
whichever Dagster context the decorator / IO manager has in hand
(``AssetExecutionContext``, ``OpExecutionContext``, ``OutputContext``,
``InputContext``). The callers import :func:`extract_partition_info` and
merge the returned dict into the ``parameters`` payload they forward to
the sidecar.
"""

from __future__ import annotations

from typing import Any


def extract_partition_info(context: Any) -> dict[str, Any]:
    """Return a partition-info dict for a Chio evaluation payload.

    Recognises the ``has_partition_key`` / ``partition_key`` protocol that
    Dagster exposes on :class:`dagster.AssetExecutionContext`,
    :class:`dagster.OpExecutionContext`, :class:`dagster.OutputContext`,
    and :class:`dagster.InputContext`. Returns an empty dict when the
    context has no partition info (unpartitioned asset / op), which keeps
    the capability payload stable across partitioned and unpartitioned
    materializations.

    Shape
    -----
    ``{}`` when there is no partition.
    ``{"partition_key": "eu-west"}`` when the materialization targets a
        single partition.
    ``{"partition_keys": ["2026-04-15", "2026-04-16"]}`` when the
        materialization targets a range.

    Both fields may appear together when Dagster's context exposes both a
    primary ``partition_key`` and a range (the primary key wins for
    guards that only look at the scalar field).
    """
    info: dict[str, Any] = {}

    # Single partition key -- the common case.
    if _truthy(context, "has_partition_key"):
        key = _safe_attr(context, "partition_key")
        if key is not None:
            info["partition_key"] = str(key)

    # Range of partition keys -- backfills and multi-partition ranges.
    if _truthy(context, "has_partition_key_range"):
        keys = _safe_attr(context, "partition_keys")
        if keys is not None:
            try:
                materialized = [str(k) for k in keys]
            except TypeError:
                materialized = []
            if materialized:
                info["partition_keys"] = materialized

    # IOManager OutputContext / InputContext expose ``has_asset_partitions``
    # + ``asset_partition_key`` / ``asset_partition_keys`` instead of the
    # plainer asset-context surface. Pick them up so the IO manager carries
    # the same partition fields as the asset decorator.
    if "partition_key" not in info and _truthy(context, "has_asset_partitions"):
        asset_key = _safe_attr(context, "asset_partition_key")
        if asset_key is not None:
            info["partition_key"] = str(asset_key)
        if "partition_keys" not in info:
            asset_keys = _safe_attr(context, "asset_partition_keys")
            if asset_keys is not None:
                try:
                    materialized = [str(k) for k in asset_keys]
                except TypeError:
                    materialized = []
                if materialized:
                    info["partition_keys"] = materialized

    return info


def _truthy(context: Any, attr: str) -> bool:
    """Return ``True`` when ``context.attr`` exists and is truthy.

    ``has_partition_key`` is a property on the Dagster contexts; reading
    it on an unpartitioned context can raise in some versions. We guard
    against that and treat any access error as "no partition".
    """
    try:
        value = getattr(context, attr, None)
    except Exception:
        return False
    return bool(value)


def _safe_attr(context: Any, attr: str) -> Any:
    """Read ``context.attr``, swallowing any access-time errors."""
    try:
        return getattr(context, attr, None)
    except Exception:
        return None


__all__ = [
    "extract_partition_info",
]
