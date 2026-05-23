from __future__ import annotations

from typing import Any

from ..errors import ChioInvariantError, parse_json_text
from .hashing import sha256_hex_utf8
from .json import canonicalize_json
from .signing import (
    public_key_hex_matches,
    verify_chio_signature,
)


def _safe_verify_receipt_signature(
    signed_text: str,
    signature: str,
    public_key: str,
) -> bool:
    """Dispatch through ``verify_chio_signature``, swallowing algorithm errors.

    Receipts signed with algorithms this SDK build does not yet support fail
    closed by reporting ``signature_valid: False`` rather than propagating an
    exception, mirroring the TS behaviour.
    """

    try:
        return verify_chio_signature(signed_text, signature, public_key)
    except ChioInvariantError:
        return False


def parse_receipt_json(input_text: str) -> dict[str, Any]:
    return parse_json_text(input_text)


def _receipt_body(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"algorithm", "signature"}
    }


def receipt_body_canonical_json(receipt: dict[str, Any]) -> str:
    return canonicalize_json(_receipt_body(receipt))


def _receipt_id_input(receipt: dict[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "timestamp": receipt["timestamp"],
        "capability_id": receipt["capability_id"],
        "tool_server": receipt["tool_server"],
        "tool_name": receipt["tool_name"],
        "action": receipt["action"],
        "receipt_kind": receipt["receipt_kind"],
        "boundary_class": receipt["boundary_class"],
        "tool_origin": receipt["tool_origin"],
        "redaction_mode": receipt["redaction_mode"],
        "content_hash": receipt["content_hash"],
        "policy_hash": receipt["policy_hash"],
        "kernel_key": receipt["kernel_key"],
    }
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
    value["trust_level"] = receipt["trust_level"]
    if receipt.get("tenant_id") is not None:
        value["tenant_id"] = receipt["tenant_id"]
    return value


def _content_addressed_receipt_id(receipt: dict[str, Any]) -> str:
    return sha256_hex_utf8(canonicalize_json(_receipt_id_input(receipt)))


def receipt_signing_body_canonical_json(receipt: dict[str, Any]) -> str:
    return canonicalize_json({
        "id": receipt["id"],
        "body": _receipt_id_input(receipt),
    })


def _receipt_semantics(receipt: dict[str, Any]) -> tuple[str, str]:
    return receipt["receipt_kind"], receipt["boundary_class"]


def _result_label(receipt_kind: str, boundary_class: str, decision: str) -> str:
    if receipt_kind == "mediated_decision" and boundary_class == "prevent" and decision == "allow":
        return "Authorized"
    if receipt_kind == "trace_observation":
        return "Observed"
    if receipt_kind == "advisory_evaluation":
        return "Advisory"
    return {
        "allow": "Allowed",
        "deny": "Denied",
        "cancelled": "Cancelled",
        "incomplete": "Incomplete",
        "none": "Invalid",
    }[decision]


def _valid_observation_outcome(value: Any) -> bool:
    return value in {"observed", "evaluated", "dropped"}


def _semantically_signable(receipt: dict[str, Any], decision: str) -> bool:
    receipt_kind, boundary_class = _receipt_semantics(receipt)
    trust_level = receipt.get("trust_level")
    observation_outcome = receipt.get("observation_outcome")
    if receipt_kind == "mediated_decision":
        return (
            boundary_class == "prevent"
            and trust_level == "mediated"
            and decision != "none"
            and observation_outcome is None
        )
    if receipt_kind == "trace_observation":
        return (
            boundary_class == "detect_only"
            and trust_level == "verified"
            and decision == "none"
            and _valid_observation_outcome(observation_outcome)
        )
    if receipt_kind == "advisory_evaluation":
        return (
            boundary_class == "advisory_only"
            and trust_level == "advisory"
            and decision == "none"
            and _valid_observation_outcome(observation_outcome)
        )
    return False


def verify_receipt(
    receipt: dict[str, Any],
    trusted_signers: list[str] | None = None,
) -> dict[str, Any]:
    decision_value = receipt.get("decision")
    decision = (
        decision_value.get("verdict", "none")
        if isinstance(decision_value, dict)
        else "none"
    )
    receipt_kind, boundary_class = _receipt_semantics(receipt)
    semantic_authorized = receipt_kind == "mediated_decision" and boundary_class == "prevent" and decision == "allow"
    receipt_id_valid = receipt["id"] == _content_addressed_receipt_id(receipt)
    signature_valid = (
        receipt_id_valid
        and _semantically_signable(receipt, decision)
        and _safe_verify_receipt_signature(
            receipt_signing_body_canonical_json(receipt),
            receipt["signature"],
            receipt["kernel_key"],
        )
    )
    parameter_hash_valid = receipt["action"]["parameter_hash"] == sha256_hex_utf8(
        canonicalize_json(receipt["action"]["parameters"])
    )
    signer_trusted = bool(trusted_signers) and any(
        public_key_hex_matches(signer, receipt["kernel_key"])
        for signer in trusted_signers or []
    )
    authorized = (
        semantic_authorized
        and signature_valid
        and parameter_hash_valid
        and receipt_id_valid
        and signer_trusted
    )
    return {
        "signature_valid": signature_valid,
        "parameter_hash_valid": parameter_hash_valid,
        "receipt_id_valid": receipt_id_valid,
        "decision": decision,
        "receipt_kind": receipt_kind,
        "boundary_class": boundary_class,
        "trust_level": receipt["trust_level"],
        "result": _result_label(receipt_kind, boundary_class, decision),
        "authorized": authorized,
        "signer_key_hex": receipt["kernel_key"],
        "signer_trusted": signer_trusted,
        "ok": signature_valid and parameter_hash_valid and receipt_id_valid and signer_trusted,
    }


def verify_receipt_with_trusted_signers(
    receipt: dict[str, Any],
    trusted_signers: list[str],
) -> dict[str, Any]:
    return verify_receipt(receipt, trusted_signers)


def verify_receipt_json(input_text: str) -> dict[str, Any]:
    return verify_receipt(parse_receipt_json(input_text))
