from __future__ import annotations

import hashlib


def sha256_hex_bytes(input_bytes: bytes) -> str:
    return hashlib.sha256(input_bytes).hexdigest()


def sha256_hex_utf8(input_text: str) -> str:
    return sha256_hex_bytes(input_text.encode("utf-8"))
