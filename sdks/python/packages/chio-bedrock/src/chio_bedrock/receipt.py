"""Chio receipt-shaped helpers for Bedrock SDK calls."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from typing import Any

BEDROCK_REGION = "us-east-1"
DEFAULT_KERNEL_KEY = "chio-bedrock-sdk-local-kernel"
DEFAULT_POLICY_HASH = "chio-bedrock-marketplace-policy-v1"
DEFAULT_SIGNING_KEY = "chio-bedrock-local-verifier"

Receipt = dict[str, Any]


def _canonical_json(value: Mapping[str, Any] | list[Any] | str | int | bool | None) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash_value(value: Mapping[str, Any] | list[Any] | str | int | bool | None) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sign_body(body: Mapping[str, Any], signing_key: str) -> str:
    material = _canonical_json(body) + signing_key
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def issue_receipt(
    *,
    capability_id: str,
    tenant_id: str,
    model_id: str,
    parameters: Mapping[str, Any],
    response: Mapping[str, Any] | None,
    principal_arn: str,
    account_id: str,
    policy_hash: str = DEFAULT_POLICY_HASH,
    kernel_key: str = DEFAULT_KERNEL_KEY,
    signing_key: str = DEFAULT_SIGNING_KEY,
    timestamp: int | None = None,
    receipt_id: str | None = None,
) -> Receipt:
    """Create a Chio receipt-compatible dictionary for a Bedrock call.

    This helper keeps the outer field names aligned with `ChioReceipt` in
    `chio-core-types`. Production deployments replace the local test
    signature with the kernel signature emitted by the Rust adapter.
    """

    if not capability_id or not tenant_id or not model_id:
        raise ValueError("capability_id, tenant_id, and model_id are required")
    if not principal_arn or not account_id:
        raise ValueError("principal_arn and account_id are required")

    safe_response: Mapping[str, Any] = response or {}
    action = {
        "parameters": dict(parameters),
        "parameter_hash": _hash_value(dict(parameters)),
    }
    metadata = {
        "surface": "aws-bedrock",
        "version": 1,
        "region": BEDROCK_REGION,
        "model_id": model_id,
        "principal_arn": principal_arn,
        "account_id": account_id,
    }
    body: Receipt = {
        "id": receipt_id or f"rcpt-bedrock-{uuid.uuid4()}",
        "timestamp": timestamp or int(time.time()),
        "capability_id": capability_id,
        "tool_server": "aws-bedrock",
        "tool_name": "bedrock.converse",
        "action": action,
        "decision": {"verdict": "allow"},
        "content_hash": _hash_value(safe_response),
        "policy_hash": policy_hash,
        "evidence": [
            {
                "guard_name": "AwsMarketplaceEntitlementGuard",
                "verdict": True,
                "details": "entitlement checked before Bedrock invocation",
            },
            {
                "guard_name": "BedrockRegionGuard",
                "verdict": True,
                "details": "region pinned to us-east-1",
            },
        ],
        "metadata": metadata,
        "tenant_id": tenant_id,
        "kernel_key": kernel_key,
    }
    body["signature"] = _sign_body(body, signing_key)
    return body


def verify_receipt(receipt: Mapping[str, Any], signing_key: str = DEFAULT_SIGNING_KEY) -> bool:
    """Verify the local SDK receipt signature and required Bedrock metadata."""

    try:
        signature = receipt.get("signature")
        if not isinstance(signature, str) or not signature:
            return False
        body = dict(receipt)
        body.pop("signature", None)
        metadata = body.get("metadata")
        if not isinstance(metadata, Mapping):
            return False
        if metadata.get("surface") != "aws-bedrock":
            return False
        if metadata.get("region") != BEDROCK_REGION:
            return False
        required = [
            "id",
            "timestamp",
            "capability_id",
            "tool_server",
            "tool_name",
            "action",
            "decision",
            "content_hash",
            "policy_hash",
            "tenant_id",
            "kernel_key",
        ]
        if any(field not in body for field in required):
            return False
        return _sign_body(body, signing_key) == signature
    except (TypeError, ValueError):
        return False
