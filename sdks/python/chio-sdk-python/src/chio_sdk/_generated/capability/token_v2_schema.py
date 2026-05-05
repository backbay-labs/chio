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

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class ScopeAttenuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: constr(min_length=1)


class Kind(Enum):
    restrict_tool = "restrict_tool"
    bind_session = "bind_session"
    restrict_audience = "restrict_audience"
    restrict_geo = "restrict_geo"
    restrict_time_window = "restrict_time_window"


class Caveat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    predicate: constr(min_length=1)
    sig: (
        constr(
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$"
        )
        | None
    ) = None


class GrantKind(Enum):
    tool = "tool"
    resource = "resource"
    prompt = "prompt"


class GrantSubsetRelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grantKind: GrantKind
    childIndex: conint(ge=0)
    parentIndex: conint(ge=0)
    subset: Literal[True]


class AttenuationWitness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    normalizedParentScope: constr(min_length=2)
    normalizedChildScope: constr(min_length=2)
    subsetRelations: list[GrantSubsetRelation] | None = None
    restrictedPredicates: list[str] | None = None


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parentScopeHash: constr(pattern=r"^[0-9a-f]{64}$")
    childScopeHash: constr(pattern=r"^[0-9a-f]{64}$")
    normalizedSubsetProof: AttenuationWitness


class ChioCapabilitytokenV2(BaseModel):
    """
    Schema-tagged v2 capability token with typed caveats, first-class attenuation fields, an attenuation_proof witness, and a reserved hybrid algorithm enum value for the T2.1 compatibility path.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capability.v2"] = Field(..., alias="schema")
    id: constr(min_length=1)
    issuer: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$"
    )
    subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$"
    )
    scope: dict[str, Any] = Field(
        ...,
        description="ChioScope. The Rust verifier hashes the RFC 8785 canonical form for attenuation_proof.childScopeHash.",
    )
    issued_at: conint(ge=0)
    expires_at: conint(ge=0)
    delegation_chain: list[dict[str, Any]] | None = None
    algorithm: Algorithm | None = None
    caveats: list[Caveat] | None = None
    scope_attenuations: list[ScopeAttenuation] | None = None
    attenuation_proof: AttenuationProof
    budget_share_bps: conint(ge=0, le=10000) | None = Field(
        None,
        description="Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.",
    )
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$"
    )
