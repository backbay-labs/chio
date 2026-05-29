from __future__ import annotations

from typing import Any

from ..errors import parse_json_text
from .json import canonicalize_json
from .signing import is_valid_public_key_hex, public_key_hex_matches, verify_utf8_message_ed25519


def parse_signed_manifest_json(input_text: str) -> dict[str, Any]:
    return parse_json_text(input_text)


def signed_manifest_body_canonical_json(signed_manifest: dict[str, Any]) -> str:
    return canonicalize_json(signed_manifest["manifest"])


def _validate_manifest_structure(manifest: dict[str, Any]) -> bool:
    if manifest.get("schema") != "chio.manifest.v1":
        return False
    tools = manifest.get("tools", [])
    if not tools:
        return False
    seen: set[str] = set()
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str) or name in seen:
            return False
        seen.add(name)
    return True


def verify_signed_manifest(signed_manifest: dict[str, Any]) -> dict[str, Any]:
    embedded_public_key_valid = is_valid_public_key_hex(
        signed_manifest["manifest"]["public_key"]
    )
    return {
        "structure_valid": _validate_manifest_structure(signed_manifest["manifest"]),
        "signature_valid": verify_utf8_message_ed25519(
            signed_manifest_body_canonical_json(signed_manifest),
            signed_manifest["signer_key"],
            signed_manifest["signature"],
        ),
        "embedded_public_key_valid": embedded_public_key_valid,
        "embedded_public_key_matches_signer": embedded_public_key_valid
        and public_key_hex_matches(
            signed_manifest["manifest"]["public_key"],
            signed_manifest["signer_key"],
        ),
    }


def verify_signed_manifest_json(input_text: str) -> dict[str, Any]:
    return verify_signed_manifest(parse_signed_manifest_json(input_text))
