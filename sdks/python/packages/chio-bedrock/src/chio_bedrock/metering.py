"""Marketplace metering payload helpers for Bedrock receipt overage."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from chio_bedrock.receipt import (
    TrustedVerification,
    verify_trusted_receipt,
)

DEFAULT_DIMENSION = "bedrock_receipt_overage"


class MeteringTrustError(ValueError):
    """Raised when a metering receipt fails trusted verification.

    Carries the structured `TrustedVerification` outcome so callers can
    surface which individual check failed (signature, content-addressed
    id, parameter-hash binding, or signer trust). Inherits from
    `ValueError` so existing fail-closed call sites that catch
    `ValueError` continue to behave correctly.
    """

    def __init__(self, message: str, verification: TrustedVerification) -> None:
        super().__init__(message)
        self.verification = verification


def _is_authoritative_metering_receipt(receipt: Mapping[str, Any]) -> bool:
    """Semantic shape check for an authoritative mediated receipt.

    This intentionally no longer gates on signature or id hex shape;
    cryptographic trust is enforced by `verify_trusted_receipt`. The
    remaining checks confirm the receipt's semantic kind, boundary, and
    trust level match an authoritative mediated authorization decision.
    """

    decision = receipt.get("decision")
    return (
        receipt.get("receipt_kind") == "mediated_decision"
        and receipt.get("boundary_class") == "prevent"
        and receipt.get("trust_level") == "mediated"
        and isinstance(decision, Mapping)
        and decision.get("verdict") == "allow"
    )


def metering_callback(
    *,
    receipt: Mapping[str, Any],
    customer_identifier: str,
    product_code: str,
    invocation_parameters: Mapping[str, Any],
    trusted_kernel_keys: Iterable[str],
    dimension: str = DEFAULT_DIMENSION,
    quantity: int = 1,
) -> dict[str, Any]:
    """Build a Marketplace metering callback payload, gated by trust.

    Fails closed unless the receipt:

    - matches the semantic shape of an authoritative mediated authorization
      decision (`mediated_decision` + `prevent` + `mediated` + verdict
      `allow`), and
    - passes `verify_trusted_receipt` (signature, content-addressed id,
      parameter-hash bind to `invocation_parameters`, signer in
      `trusted_kernel_keys`).

    Shape-only acceptance is no longer permitted. `trusted_kernel_keys`
    and `invocation_parameters` are required keyword-only arguments. The
    verifier only needs public keys: callers never have to hold the
    kernel's private signing secret.
    """

    if quantity <= 0:
        raise ValueError("quantity must be positive")

    if not _is_authoritative_metering_receipt(receipt):
        raise ValueError(
            "metering requires an authoritative mediated authorization receipt"
        )

    verification = verify_trusted_receipt(
        receipt,
        trusted_kernel_keys=trusted_kernel_keys,
        invocation_parameters=invocation_parameters,
    )
    if not verification.ok:
        raise MeteringTrustError(
            "metering receipt failed trusted verification: "
            + ("; ".join(verification.reasons) or "unknown reason"),
            verification,
        )

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
