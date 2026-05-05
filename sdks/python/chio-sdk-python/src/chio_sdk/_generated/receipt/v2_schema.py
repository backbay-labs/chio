# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 168c92102b530411f244aeff273362ff27544e7ce7b3c6623f51c9ecb4d58e62
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class TrustLevel(Enum):
    mediated = "mediated"
    verified = "verified"
    advisory = "advisory"


class ParentReceiptId(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class Hlc(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    wallSeconds: conint(ge=0)
    logical: conint(ge=0)
    kernelId: constr(min_length=1)


class ReceiptV2BodyHashInput(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.receipt.v2"] = Field(..., alias="schema")
    timestamp: conint(ge=0)
    capabilityId: constr(min_length=1)
    toolServer: constr(min_length=1)
    toolName: constr(min_length=1)
    action: dict[str, Any]
    decision: dict[str, Any]
    contentHash: constr(min_length=1)
    policyHash: constr(min_length=1)
    evidence: list[dict[str, Any]] | None = None
    metadata: Any | None = None
    trustLevel: TrustLevel | None = None
    tenantId: str | None = None
    chainId: constr(min_length=1)
    parentReceiptIds: list[ParentReceiptId] | None = Field(
        None, description="Canonical sorted and deduplicated parent body_hash values."
    )
    parentSetHash: constr(pattern=r"^[0-9a-f]{64}$")
    dagOrdinal: conint(ge=0)
    hlc: Hlc
    kernelKey: constr(min_length=64)


class ChioReceiptV2(BaseModel):
    """
    Content-addressed v2 receipt. bodyHash is H(canonical_jcs(ReceiptV2BodyHashInput)); receiptId is a non-authoritative legacy UUIDv7 tooling alias and is not used for replay.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    receiptId: constr(min_length=1)
    bodyHash: constr(pattern=r"^[0-9a-f]{64}$")
    body: ReceiptV2BodyHashInput
    algorithm: Algorithm | None = None
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$"
    )
