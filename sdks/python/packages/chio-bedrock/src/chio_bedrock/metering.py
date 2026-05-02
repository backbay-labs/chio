"""Marketplace metering payload helpers for Bedrock receipt overage."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

DEFAULT_DIMENSION = "bedrock_receipt_overage"


def metering_callback(
    *,
    receipt: Mapping[str, Any],
    customer_identifier: str,
    product_code: str,
    dimension: str = DEFAULT_DIMENSION,
    quantity: int = 1,
) -> dict[str, Any]:
    """Build a Marketplace metering callback payload.

    The returned shape mirrors the fields needed by `MeterUsage` or
    `BatchMeterUsage` while remaining deterministic for local tests.
    """

    if quantity <= 0:
        raise ValueError("quantity must be positive")
    receipt_id = receipt.get("id")
    timestamp = receipt.get("timestamp")
    tenant_id = receipt.get("tenant_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        raise ValueError("receipt id is required for metering")
    if not isinstance(timestamp, int):
        raise ValueError("receipt timestamp is required for metering")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("receipt tenant_id is required for metering")

    return {
        "api": "MeterUsage",
        "product_code": product_code,
        "customer_identifier": customer_identifier,
        "usage_dimension": dimension,
        "usage_quantity": quantity,
        "timestamp": timestamp,
        "dry_run": False,
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
    }
