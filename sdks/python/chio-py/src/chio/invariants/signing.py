from __future__ import annotations

from typing import Any

from pure25519.ed25519_oop import BadSignatureError, SigningKey, VerifyingKey

from ..errors import ChioInvariantError
from .json import canonicalize_json_string


def _normalize_hex(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def _hex_to_bytes(value: str, *, expected_bytes: int, code: str) -> bytes:
    normalized = _normalize_hex(value).lower()
    if len(normalized) != expected_bytes * 2:
        raise ChioInvariantError(code, f"expected {expected_bytes} bytes of hex, got {len(normalized) // 2}")
    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ChioInvariantError(code, "value is not valid hexadecimal") from exc


def _signing_key_from_seed_hex(seed_hex: str) -> SigningKey:
    return SigningKey(_hex_to_bytes(seed_hex, expected_bytes=32, code="invalid_hex"))


def _verifying_key_from_hex(public_key_hex: str) -> VerifyingKey:
    try:
        return VerifyingKey(_hex_to_bytes(public_key_hex, expected_bytes=32, code="invalid_public_key"))
    except ValueError as exc:
        raise ChioInvariantError("invalid_public_key", "value is not a valid Ed25519 public key") from exc


def is_valid_public_key_hex(value: str) -> bool:
    try:
        _hex_to_bytes(value, expected_bytes=32, code="invalid_public_key")
        return True
    except ChioInvariantError:
        return False


def is_valid_signature_hex(value: str) -> bool:
    try:
        _hex_to_bytes(value, expected_bytes=64, code="invalid_signature")
        return True
    except ChioInvariantError:
        return False


def public_key_hex_matches(left: str, right: str) -> bool:
    return _normalize_hex(left).lower() == _normalize_hex(right).lower()


def sign_utf8_message_ed25519(input_text: str, seed_hex: str) -> dict[str, str]:
    signing_key = _signing_key_from_seed_hex(seed_hex)
    signature = signing_key.sign(input_text.encode("utf-8"))
    return {
        "public_key_hex": signing_key.get_verifying_key().to_bytes().hex(),
        "signature_hex": signature.hex(),
    }


def verify_utf8_message_ed25519(
    input_text: str,
    public_key_hex: str,
    signature_hex: str,
) -> bool:
    verifying_key = _verifying_key_from_hex(public_key_hex)
    signature = _hex_to_bytes(signature_hex, expected_bytes=64, code="invalid_signature")
    try:
        verifying_key.verify(signature, input_text.encode("utf-8"))
    except BadSignatureError:
        return False
    return True


def sign_json_string_ed25519(input_text: str, seed_hex: str) -> dict[str, str]:
    canonical_json = canonicalize_json_string(input_text)
    signed = sign_utf8_message_ed25519(canonical_json, seed_hex)
    return {
        "canonical_json": canonical_json,
        "public_key_hex": signed["public_key_hex"],
        "signature_hex": signed["signature_hex"],
    }


def verify_json_string_signature_ed25519(
    input_text: str,
    public_key_hex: str,
    signature_hex: str,
) -> bool:
    return verify_utf8_message_ed25519(
        canonicalize_json_string(input_text),
        public_key_hex,
        signature_hex,
    )


def verify_chio_signature(
    signed_bytes: bytes | str,
    signature: str,
    public_key: str,
) -> bool:
    """Verify a Chio v1 wire signature, dispatching on its algorithm prefix.

    The v1 receipt signature pattern accepts bare 128-hex (Ed25519), ``p256:``
    prefixed ECDSA P-256/sha256, and ``p384:`` prefixed ECDSA P-384/sha384
    encodings. This SDK build currently supports Ed25519 inline via
    ``pure25519``. ECDSA and hybrid post-quantum prefixes raise
    ``ChioInvariantError`` until a FIPS-capable backend is wired in.
    """

    if isinstance(signed_bytes, (bytes, bytearray)):
        message_text = bytes(signed_bytes).decode("utf-8")
    else:
        message_text = signed_bytes

    if signature.startswith("p256:"):
        # ECDSA P-256 verification is not wired; reject fail-closed so
        # unsupported receipts cannot be silently accepted.
        raise ChioInvariantError(
            "invalid_signature",
            "ECDSA P-256 signatures are not yet supported by this SDK build",
        )
    if signature.startswith("p384:"):
        # ECDSA P-384 verification is not wired; reject fail-closed.
        raise ChioInvariantError(
            "invalid_signature",
            "ECDSA P-384 signatures are not yet supported by this SDK build",
        )
    if signature.startswith("hybrid:"):
        raise ChioInvariantError(
            "invalid_signature",
            "hybrid post-quantum signatures are not supported by this SDK build",
        )

    return verify_utf8_message_ed25519(message_text, public_key, signature)
