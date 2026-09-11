"""Verify HTTP receipts against an operator-selected signer set."""

from __future__ import annotations

import re
from typing import Any

from ..errors import ChioInvariantError
from .hashing import sha256_hex_utf8
from .json import canonicalize_json
from .signing import is_valid_public_key_hex, public_key_hex_matches, verify_chio_signature


def verify_http_receipt_with_trusted_signers(
    receipt: dict[str, Any],
    trusted_signers: list[str],
) -> dict[str, Any]:
    """Verify the HTTP wire format, content-addressed ID and signer trust.

    ``ok`` establishes a valid decision record, including a valid refusal.
    ``authorized`` additionally requires an allow verdict. Request matching and
    whether a response records evaluation or a final effect remain explicit
    caller responsibilities; inspect ``request_id`` and signed status metadata.
    """
    result: dict[str, Any] = {
        "ok": False,
        "receipt_id_valid": False,
        "signature_valid": False,
        "signer_trusted": False,
        "semantics_valid": False,
        "authorized": False,
    }
    try:
        key = receipt["kernel_key"]
        if not isinstance(key, str) or not is_valid_public_key_hex(key):
            return result
        body = {name: value for name, value in receipt.items() if name != "signature"}
        identity = {name: value for name, value in body.items() if name != "id"}
        result["receipt_id_valid"] = sha256_hex_utf8(canonicalize_json(identity)) == receipt["id"]
        result["signature_valid"] = verify_chio_signature(
            canonicalize_json(body), receipt["signature"], key
        )
        result["signer_trusted"] = any(
            isinstance(trusted, str)
            and is_valid_public_key_hex(trusted)
            and public_key_hex_matches(key, trusted)
            for trusted in trusted_signers
        )
        verdict = receipt["verdict"]["verdict"]
        result["semantics_valid"] = (
            receipt["receipt_kind"] == "mediated_decision"
            and receipt["boundary_class"] == "prevent"
            and receipt["trust_level"] == "mediated"
            and receipt.get("observation_outcome") is None
            and receipt["tool_origin"]
            in {"caller_executed", "host_executed_provider_reported", "host_executed_unmediated"}
            and receipt["method"]
            in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
            and isinstance(receipt["request_id"], str)
            and bool(receipt["request_id"])
            and isinstance(receipt["route_pattern"], str)
            and type(receipt["response_status"]) is int
            and 100 <= receipt["response_status"] <= 599
            and type(receipt["timestamp"]) is int
            and receipt["timestamp"] >= 0
            and receipt["redaction_mode"] in {"none", "summary", "redacted"}
            and all(
                isinstance(receipt[name], str) and re.fullmatch(r"[0-9a-f]{64}", receipt[name])
                for name in ("content_hash", "policy_hash", "caller_identity_hash")
            )
            and verdict in {"allow", "deny", "cancel", "incomplete"}
        )
        result["ok"] = all(
            result[name]
            for name in ("receipt_id_valid", "signature_valid", "signer_trusted", "semantics_valid")
        )
        result["authorized"] = result["ok"] and verdict == "allow"
    except (ChioInvariantError, KeyError, TypeError, ValueError, AttributeError):
        pass
    return result
