"""Exact signed application evidence, independently checked by every consumer."""

import hashlib
import json
from pathlib import Path

from chio.invariants import canonicalize_json, verify_receipt_with_trusted_signers
from nacl.signing import VerifyKey


def canonical(value):
    return canonicalize_json(value).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    import os
    import uuid

    path = Path(path)
    temporary = path.with_name(path.name + "." + str(uuid.uuid4()))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def signed(body, key):
    return {"body": body, "signature": key.sign(canonical(body)).signature.hex()}


def verify_signed(document, public_key):
    VerifyKey(bytes.fromhex(public_key)).verify(
        canonical(document["body"]), bytes.fromhex(document["signature"])
    )
    return document["body"]


def verify_result(result, signer, request=None):
    receipt = result["receipt"]
    verified = verify_receipt_with_trusted_signers(receipt, [signer])
    if not verified["ok"]:
        raise ValueError("Receipt signature or selected signer failed: " + str(verified))
    if request is not None:
        if receipt["capability_id"] != request["capability"]["id"]:
            raise ValueError("Receipt capability substitution")
        if (
            receipt["tool_server"] != request["server_id"]
            or receipt["tool_name"] != request["tool_name"]
        ):
            raise ValueError("Receipt tool substitution")
        if receipt["action"]["parameter_hash"] != digest(request["arguments"]):
            raise ValueError("Receipt arguments substitution")
        if receipt["metadata"]["receipt_context"]["request_id"] != request["request_id"]:
            raise ValueError("Receipt request substitution")
    if result["output"] is not None and receipt["content_hash"] != digest(result["output"]):
        raise ValueError("Receipt output substitution")
    return receipt
