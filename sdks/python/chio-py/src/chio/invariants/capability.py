from __future__ import annotations

from typing import Any

from ..errors import parse_json_text
from .json import canonicalize_json
from .signing import verify_utf8_message_ed25519


def parse_capability_json(input_text: str) -> dict[str, Any]:
    return parse_json_text(input_text)


def _capability_body(capability: dict[str, Any]) -> dict[str, Any]:
    omitted = {
        "algorithm",
        "attenuation_proof",
        "budget_share_bps",
        "caveats",
        "schema",
        "scope_attenuations",
        "signature",
    }
    return {key: value for key, value in capability.items() if key not in omitted}


def _delegation_link_body(link: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in link.items() if key != "signature"}


def capability_body_canonical_json(capability: dict[str, Any]) -> str:
    return canonicalize_json(_capability_body(capability))


def _non_empty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def capability_signing_body(capability: dict[str, Any]) -> dict[str, Any]:
    body = _capability_body(capability)
    signing_body = {
        "schema": capability.get("schema", "chio.capability.v1"),
        **body,
    }
    if not _non_empty_list(signing_body.get("delegation_chain")):
        signing_body.pop("delegation_chain", None)
    if _non_empty_list(capability.get("caveats")):
        signing_body["caveats"] = capability["caveats"]
    if _non_empty_list(capability.get("scope_attenuations")):
        signing_body["scope_attenuations"] = capability["scope_attenuations"]
    if capability.get("attenuation_proof") is not None:
        signing_body["attenuation_proof"] = capability["attenuation_proof"]
    if capability.get("budget_share_bps") is not None:
        signing_body["budget_share_bps"] = capability["budget_share_bps"]
    return signing_body


def capability_signing_body_canonical_json(capability: dict[str, Any]) -> str:
    return canonicalize_json(capability_signing_body(capability))


def _verify_delegation_chain(
    chain: list[dict[str, Any]],
    max_delegation_depth: int | None,
) -> bool:
    if max_delegation_depth is not None and len(chain) > max_delegation_depth:
        return False
    for index, current in enumerate(chain):
        if not verify_utf8_message_ed25519(
            canonicalize_json(_delegation_link_body(current)),
            current["delegator"],
            current["signature"],
        ):
            return False
        if index > 0:
            previous = chain[index - 1]
            if previous["delegatee"] != current["delegator"]:
                return False
            if current["timestamp"] < previous["timestamp"]:
                return False
    return True


def verify_capability(
    capability: dict[str, Any],
    now: int,
    max_delegation_depth: int | None = None,
) -> dict[str, Any]:
    if now < capability["issued_at"]:
        time_status = "not_yet_valid"
    elif now >= capability["expires_at"]:
        time_status = "expired"
    else:
        time_status = "valid"
    return {
        "signature_valid": verify_utf8_message_ed25519(
            capability_signing_body_canonical_json(capability),
            capability["issuer"],
            capability["signature"],
        ),
        "delegation_chain_valid": _verify_delegation_chain(
            capability.get("delegation_chain", []),
            max_delegation_depth,
        ),
        "time_valid": time_status == "valid",
        "time_status": time_status,
    }


def verify_capability_json(
    input_text: str,
    now: int,
    max_delegation_depth: int | None = None,
) -> dict[str, Any]:
    return verify_capability(parse_capability_json(input_text), now, max_delegation_depth)
