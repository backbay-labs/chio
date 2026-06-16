"""Chio receipt-shaped helpers for Bedrock SDK calls."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

BEDROCK_REGION = "us-east-1"
DEFAULT_KERNEL_KEY = "chio-bedrock-sdk-local-kernel"
DEFAULT_POLICY_HASH = "chio-bedrock-marketplace-policy-v1"
DEFAULT_SIGNING_KEY = "chio-bedrock-local-verifier"

Receipt = dict[str, Any]

_EXPONENT_RE = re.compile(r"e([+-])0+(\d+)$")
_ID_REQUIRED_FIELDS = (
    "timestamp",
    "capability_id",
    "tool_server",
    "tool_name",
    "action",
    "receipt_kind",
    "boundary_class",
    "tool_origin",
    "redaction_mode",
    "content_hash",
    "policy_hash",
    "trust_level",
    "kernel_key",
)
_ID_OPTIONAL_FIELDS = (
    "decision",
    "observation_outcome",
    "actor_chain",
    "evidence",
    "metadata",
    "tenant_id",
)
_KNOWN_RECEIPT_FIELDS = frozenset(
    {"id", "signature", "algorithm", *_ID_REQUIRED_FIELDS, *_ID_OPTIONAL_FIELDS}
)
_VALID_OBSERVATION_OUTCOMES = frozenset({"observed", "evaluated", "dropped"})
_VALID_REDACTION_MODES = frozenset({"none", "summary", "redacted"})


def _canonicalize_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("canonical JSON does not support non-finite numbers")
    if value == 0.0:
        return "0"
    rendered = repr(value).lower()
    if 1e-6 <= abs(value) < 1e21:
        decimal = format(Decimal(rendered), "f")
        if "." in decimal:
            decimal = decimal.rstrip("0").rstrip(".")
        return decimal
    return _EXPONENT_RE.sub(lambda match: f"e{match.group(1)}{match.group(2)}", rendered)


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonicalize_float(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("canonical JSON object keys must be strings")
        items = sorted(value.items(), key=lambda item: item[0].encode("utf-16-be"))
        return "{" + ",".join(
            f"{json.dumps(key, ensure_ascii=False, separators=(',', ':'))}:{_canonical_json(entry_value)}"
            for key, entry_value in items
        ) + "}"
    raise TypeError(f"canonical JSON does not support {type(value).__name__}")


def _hash_value(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _receipt_id_input(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = {field: receipt[field] for field in _ID_REQUIRED_FIELDS}
    if receipt.get("decision") is not None:
        value["decision"] = receipt["decision"]
    if receipt.get("observation_outcome") is not None:
        value["observation_outcome"] = receipt["observation_outcome"]
    if receipt.get("actor_chain"):
        value["actor_chain"] = receipt["actor_chain"]
    if receipt.get("evidence"):
        value["evidence"] = receipt["evidence"]
    if receipt.get("metadata") is not None:
        value["metadata"] = receipt["metadata"]
    if receipt.get("tenant_id") is not None:
        value["tenant_id"] = receipt["tenant_id"]
    return value


def _content_addressed_receipt_id(receipt: Mapping[str, Any]) -> str:
    return _hash_value(_receipt_id_input(receipt))


def _sign_body(body: Mapping[str, Any], signing_key: str) -> str:
    signing_body = {"id": body["id"], "body": _receipt_id_input(body)}
    return hmac.new(
        signing_key.encode("utf-8"),
        _canonical_json(signing_body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _is_sha256_hex(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.lower()
    return (
        len(text) == 64
        and all(character in "0123456789abcdef" for character in text)
    )


def _validate_trace_receipt(body: Mapping[str, Any]) -> bool:
    if body.get("receipt_kind") != "trace_observation":
        return False
    if body.get("boundary_class") != "detect_only":
        return False
    if body.get("trust_level") != "verified":
        return False
    if "decision" in body:
        return False
    if body.get("observation_outcome") not in _VALID_OBSERVATION_OUTCOMES:
        return False
    if body.get("tool_origin") != "host_executed_provider_reported":
        return False
    if body.get("redaction_mode") not in _VALID_REDACTION_MODES:
        return False
    actor_chain = body.get("actor_chain")
    if actor_chain is not None and not isinstance(actor_chain, list):
        return False
    evidence = body.get("evidence")
    if evidence is not None and not isinstance(evidence, list):
        return False
    action = body.get("action")
    if not isinstance(action, Mapping):
        return False
    if "parameters" not in action:
        return False
    parameter_hash = action.get("parameter_hash")
    if not isinstance(parameter_hash, str):
        return False
    if parameter_hash != _hash_value(action["parameters"]):
        return False
    return True


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
    """Create a Chio trace receipt-compatible dictionary for a Bedrock call.

    This helper keeps the outer field names aligned with `ChioReceipt` in
    `chio-core-types`. Bedrock SDK calls are provider-reported observations,
    not kernel-mediated authorization receipts.
    """

    if not capability_id or not tenant_id or not model_id:
        raise ValueError("capability_id, tenant_id, and model_id are required")
    if not principal_arn or not account_id:
        raise ValueError("principal_arn and account_id are required")

    safe_response: Mapping[str, Any] = response or {}
    issued_at = timestamp if timestamp is not None else int(time.time())
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
        "timestamp": issued_at,
        "capability_id": capability_id,
        "tool_server": "aws-bedrock",
        "tool_name": "bedrock.converse",
        "action": action,
        "receipt_kind": "trace_observation",
        "boundary_class": "detect_only",
        "observation_outcome": "observed",
        "tool_origin": "host_executed_provider_reported",
        "redaction_mode": "redacted",
        "actor_chain": [],
        "trust_level": "verified",
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
    computed_id = _content_addressed_receipt_id(body)
    if receipt_id is not None and receipt_id != computed_id:
        raise ValueError("receipt_id must match the v1 content-addressed receipt id")
    body = {"id": computed_id, **body}
    body["signature"] = _sign_body(body, signing_key)
    return body


@dataclass(frozen=True)
class TrustedVerification:
    """Structured outcome of a trusted Chio receipt verification.

    Each boolean tracks the result of one independent check. `reasons`
    accumulates human-readable failure notes that callers can surface in
    audit logs. The receipt is considered fit for authoritative metering
    only when `ok` is `True`.
    """

    signature_ok: bool = False
    receipt_id_ok: bool = False
    parameter_hash_ok: bool = False
    signer_trusted: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return (
            self.signature_ok
            and self.receipt_id_ok
            and self.parameter_hash_ok
            and self.signer_trusted
            and not self.reasons
        )

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.ok


def _coerce_ed25519_private_key(signing_key: Any) -> ed25519.Ed25519PrivateKey:
    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        return signing_key
    if isinstance(signing_key, (bytes, bytearray)):
        seed = bytes(signing_key)
    elif isinstance(signing_key, str):
        try:
            seed = bytes.fromhex(signing_key)
        except ValueError as exc:
            raise ValueError("ed25519 signing key string must be hex") from exc
    else:
        raise TypeError(
            "signing_key must be Ed25519PrivateKey, raw 32-byte seed, or hex string"
        )
    if len(seed) != 32:
        raise ValueError("ed25519 signing key seed must be 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _coerce_ed25519_public_key(public_key: Any) -> ed25519.Ed25519PublicKey:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return public_key
    if isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
    elif isinstance(public_key, str):
        try:
            raw = bytes.fromhex(public_key)
        except ValueError as exc:
            raise ValueError("ed25519 public key string must be hex") from exc
    else:
        raise TypeError(
            "public key must be Ed25519PublicKey, raw 32 bytes, or hex string"
        )
    if len(raw) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def sign_trusted_receipt_body(body: Mapping[str, Any], signing_key: Any) -> str:
    """Produce an ed25519 hex signature over the canonical id-bound body.

    The body must already have its `id` populated. This helper is the
    counterpart of `verify_trusted_receipt`: tests and the local kernel
    use it to mint authoritative-shaped receipts that the SDK can then
    verify before accepting them for metering.
    """

    if "id" not in body:
        raise ValueError("body must contain an id before signing")
    private_key = _coerce_ed25519_private_key(signing_key)
    signing_body = {"id": body["id"], "body": _receipt_id_input(body)}
    signature = private_key.sign(_canonical_json(signing_body).encode("utf-8"))
    return signature.hex()


def verify_trusted_receipt(
    receipt: Mapping[str, Any],
    *,
    trusted_kernel_keys: Iterable[str],
    invocation_parameters: Mapping[str, Any],
) -> TrustedVerification:
    """Verify a trusted Chio receipt is fit for authoritative metering.

    Runs four independent checks and surfaces each outcome:

    1. The receipt carries a valid ed25519 signature over the canonical
       id-bound body, verified using the receipt's `kernel_key` (a hex
       ed25519 public key).
    2. The receipt id is the content-addressed v1 SHA-256 of the canonical
       id input.
    3. `action.parameter_hash` binds to the canonical hash of the
       caller-supplied `invocation_parameters`.
    4. The receipt's `kernel_key` (hex ed25519 public key) is a member of
       the trusted-kernel-key set.

    This verifier only requires public keys: callers configure a set of
    trusted kernel public keys and never hold the kernel's private
    signing secret. Signature verification is ed25519.
    """

    reasons: list[str] = []
    trusted_keys = frozenset(trusted_kernel_keys)

    claimed_kernel_key = receipt.get("kernel_key")
    signer_trusted = (
        isinstance(claimed_kernel_key, str)
        and claimed_kernel_key != ""
        and claimed_kernel_key in trusted_keys
    )
    if not signer_trusted:
        reasons.append("kernel_key is not in trusted_kernel_keys")

    public_key: ed25519.Ed25519PublicKey | None = None
    if isinstance(claimed_kernel_key, str) and claimed_kernel_key:
        try:
            public_key = _coerce_ed25519_public_key(claimed_kernel_key)
        except (TypeError, ValueError) as exc:
            reasons.append(f"kernel_key is not a valid ed25519 public key: {exc}")
    else:
        reasons.append("kernel_key is missing or not a hex string")

    signature_ok = False
    if public_key is not None:
        signature_hex = receipt.get("signature")
        if not isinstance(signature_hex, str) or not signature_hex:
            reasons.append("signature is missing or empty")
        else:
            signature_bytes: bytes | None
            try:
                signature_bytes = bytes.fromhex(signature_hex)
            except ValueError:
                reasons.append("signature is not valid hex")
                signature_bytes = None
            if signature_bytes is not None:
                body_for_signing = dict(receipt)
                body_for_signing.pop("signature", None)
                if "id" not in body_for_signing:
                    reasons.append("receipt is missing id for signature verification")
                else:
                    try:
                        signing_body = {
                            "id": body_for_signing["id"],
                            "body": _receipt_id_input(body_for_signing),
                        }
                        message = _canonical_json(signing_body).encode("utf-8")
                        public_key.verify(signature_bytes, message)
                        signature_ok = True
                    except InvalidSignature:
                        reasons.append("ed25519 signature did not verify")
                    except (KeyError, TypeError, ValueError) as exc:
                        reasons.append(f"signature verification error: {exc}")

    receipt_id_ok = False
    try:
        receipt_id = receipt.get("id")
        expected_id = _content_addressed_receipt_id(receipt)
        receipt_id_ok = (
            isinstance(receipt_id, str)
            and _is_sha256_hex(receipt_id)
            and receipt_id.lower() == expected_id
        )
        if not receipt_id_ok:
            reasons.append("receipt id is not the content-addressed v1 hash")
    except (KeyError, TypeError, ValueError) as exc:
        reasons.append(f"receipt id verification error: {exc}")

    parameter_hash_ok = False
    action = receipt.get("action")
    if not isinstance(action, Mapping):
        reasons.append("action is missing or malformed")
    else:
        receipt_parameter_hash = action.get("parameter_hash")
        try:
            expected_parameter_hash = _hash_value(dict(invocation_parameters))
        except (TypeError, ValueError) as exc:
            reasons.append(f"invocation_parameters not canonicalisable: {exc}")
            expected_parameter_hash = None
        if (
            isinstance(receipt_parameter_hash, str)
            and expected_parameter_hash is not None
            and hmac.compare_digest(receipt_parameter_hash, expected_parameter_hash)
        ):
            parameter_hash_ok = True
        else:
            reasons.append(
                "action.parameter_hash does not bind to invocation_parameters"
            )

    return TrustedVerification(
        signature_ok=signature_ok,
        receipt_id_ok=receipt_id_ok,
        parameter_hash_ok=parameter_hash_ok,
        signer_trusted=signer_trusted,
        reasons=tuple(reasons),
    )


def verify_receipt(receipt: Mapping[str, Any], signing_key: str = DEFAULT_SIGNING_KEY) -> bool:
    """Verify the local SDK receipt signature and required Bedrock metadata."""

    try:
        signature = receipt.get("signature")
        if not isinstance(signature, str) or not signature:
            return False
        body = dict(receipt)
        body.pop("signature", None)
        if set(body) - (_KNOWN_RECEIPT_FIELDS - {"signature"}):
            return False
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
            "receipt_kind",
            "boundary_class",
            "observation_outcome",
            "tool_origin",
            "redaction_mode",
            "trust_level",
            "content_hash",
            "policy_hash",
            "tenant_id",
            "kernel_key",
        ]
        if any(field not in body for field in required):
            return False
        if not _is_sha256_hex(body.get("id")):
            return False
        if not _validate_trace_receipt(body):
            return False
        if _content_addressed_receipt_id(body) != body["id"].lower():
            return False
        expected_signature = _sign_body(body, signing_key)
        return hmac.compare_digest(expected_signature, signature)
    except (KeyError, TypeError, ValueError):
        return False
