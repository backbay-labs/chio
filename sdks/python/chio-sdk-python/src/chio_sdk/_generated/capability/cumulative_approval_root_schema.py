# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d7264a73c6278a903994c0945d1fc7ba5300063d0cc3a6b8666fdf08f66175e5
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class CumulativeRootMonetaryAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class CumulativeRootPublicKey(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )


class CumulativeRootSigningAlgorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class CumulativeRootSignature(
    RootModel[
        constr(
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
        )
    ]
):
    root: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.cumulative-approval-root.v1"] = Field(..., alias="schema")
    signer_key_epoch: conint(ge=0)
    root_capability_id: constr(min_length=1)
    root_capability_hash: constr(pattern=r"^[0-9a-f]{64}$")
    root_issuer: CumulativeRootPublicKey
    root_subject: CumulativeRootPublicKey
    root_scope_hash: constr(pattern=r"^[0-9a-f]{64}$")
    root_grant_hash: constr(pattern=r"^[0-9a-f]{64}$")
    approval_budget_id: constr(min_length=1)
    approval_budget_epoch: conint(ge=0)
    threshold: CumulativeRootMonetaryAmount
    root_expires_at: conint(ge=0)


class ChioCumulativeApprovalRootBinding(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    algorithm: CumulativeRootSigningAlgorithm | None = None
    signature: CumulativeRootSignature
