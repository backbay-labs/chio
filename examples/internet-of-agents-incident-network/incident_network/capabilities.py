"""Capability delegation and approval tokens (Ed25519 client-side signing)."""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

# -- Canonical JSON -----------------------------------------------------------

def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


# -- Identities ---------------------------------------------------------------

@dataclass
class Identity:
    name: str
    key: SigningKey

    @property
    def pk(self) -> str:
        return self.key.verify_key.encode(encoder=HexEncoder).decode()

    @property
    def seed(self) -> str:
        return self.key.encode(encoder=HexEncoder).decode()

    def sign(self, body: dict[str, Any]) -> str:
        return self.key.sign(_canonical(body)).signature.hex()


@dataclass(frozen=True)
class PublicKey:
    name: str
    pk: str


def gen_identity(name: str) -> Identity:
    return Identity(name=name, key=SigningKey.generate())


def from_seed(name: str, seed_hex: str) -> Identity:
    return Identity(name=name, key=SigningKey(seed_hex, encoder=HexEncoder))


# -- Signature verification (offline reviewer only) ---------------------------

def verify_sig(pk_hex: str, body: dict[str, Any], sig_hex: str) -> bool:
    try:
        VerifyKey(pk_hex, encoder=HexEncoder).verify(_canonical(body), bytes.fromhex(sig_hex))
        return True
    except BadSignatureError:
        return False


# -- Capability body extraction -----------------------------------------------

def wire_scope(scope: dict[str, Any]) -> dict[str, Any]:
    """Use the Rust scope wire representation before signing a legacy v1 body.

    Rust omits empty scope families and empty constraints. Signing their input
    spelling instead causes signature verification to fail after typed decoding.
    This adapter only normalizes serialization; it does not authorize delegation.
    """
    result = {}
    for family, grants in scope.items():
        if family not in {"grants", "resource_grants", "prompt_grants"}:
            raise ValueError(f"Unknown scope family: {family}")
        if grants:
            result[family] = [
                {key: value for key, value in grant.items()
                 if value is not None and not (key == "constraints" and value == [])}
                for grant in grants
            ]
    return result


def cap_body(cap: dict[str, Any]) -> dict[str, Any]:
    b = {
        "id": cap["id"], "issuer": cap["issuer"], "subject": cap["subject"],
        "scope": wire_scope(cap["scope"]), "issued_at": cap["issued_at"], "expires_at": cap["expires_at"],
    }
    if cap.get("delegation_chain"):
        b["delegation_chain"] = [{key: value for key, value in link.items()
                                  if not (key == "attenuations" and value == [])}
                                 for link in cap["delegation_chain"]]
    return b


def link_body(link: dict[str, Any]) -> dict[str, Any]:
    b = {
        "capability_id": link["capability_id"], "delegator": link["delegator"],
        "delegatee": link["delegatee"], "timestamp": link["timestamp"],
    }
    if link.get("attenuations"):
        b["attenuations"] = link["attenuations"]
    return b


# -- Delegation ---------------------------------------------------------------

def delegate(
    *,
    parent: dict[str, Any],
    delegator: Identity,
    delegatee: Identity | PublicKey,
    scope: dict[str, Any],
    ttl: int,
    attenuations: list[dict] | None = None,
    cap_id: str | None = None,
) -> dict[str, Any]:
    if parent["subject"] != delegator.pk:
        raise ValueError("The delegator must be the parent capability subject")
    if ttl <= 0:
        raise ValueError("Delegation lifetime must be positive")
    now = int(time.time())
    if now >= parent["expires_at"]:
        raise ValueError("The parent capability expired")
    link = {
        "capability_id": parent["id"],
        "delegator": delegator.pk,
        "delegatee": delegatee.pk,
        "attenuations": attenuations or [],
        "timestamp": now,
    }
    link["signature"] = delegator.sign(link_body(link))
    cap = {
        "id": cap_id or f"cap-{uuid.uuid4().hex[:12]}",
        "issuer": delegator.pk,
        "subject": delegatee.pk,
        "scope": wire_scope(scope),
        "issued_at": now,
        "expires_at": min(parent["expires_at"], now + ttl),
        "delegation_chain": [*parent.get("delegation_chain", []), link],
    }
    cap["signature"] = delegator.sign(cap_body(cap))
    return cap


# -- Approval tokens ----------------------------------------------------------

def _token_body(t: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": t["id"], "approver": t["approver"], "subject": t["subject"],
        "governed_intent_hash": t["governed_intent_hash"],
        "request_id": t["request_id"],
        "issued_at": t["issued_at"], "expires_at": t["expires_at"],
        "decision": t["decision"],
    }


def intent_hash(intent: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(intent)).hexdigest()


def issue_approval(
    *, approver: Identity, subject_pk: str, intent_hash_val: str,
    request_id: str, ttl: int, decision: str = "approved",
) -> dict[str, Any]:
    now = int(time.time())
    tok = {
        "id": f"approval-{uuid.uuid4().hex[:12]}",
        "approver": approver.pk, "subject": subject_pk,
        "governed_intent_hash": intent_hash_val, "request_id": request_id,
        "issued_at": now, "expires_at": now + ttl, "decision": decision,
    }
    tok["signature"] = approver.sign(_token_body(tok))
    return tok


def verify_approval(
    token: dict[str, Any], *, subject_pk: str, request_id: str,
    intent_hash_val: str, now: int | None = None,
) -> tuple[bool, str | None]:
    ts = now or int(time.time())
    if not verify_sig(token["approver"], _token_body(token), token["signature"]):
        return False, "invalid_approval_signature"
    checks = [
        (token.get("decision") == "approved", "approval_denied"),
        (token.get("subject") == subject_pk, "approval_subject_mismatch"),
        (token.get("request_id") == request_id, "approval_request_mismatch"),
        (token.get("governed_intent_hash") == intent_hash_val, "approval_intent_mismatch"),
        (token["issued_at"] <= ts < token["expires_at"], "approval_expired"),
    ]
    for ok, reason in checks:
        if not ok:
            return False, reason
    return True, None
