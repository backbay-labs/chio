# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: bc02beb22e700f6dcb4ff8bacf886190c87ed37499a515db8e09dfd0f87c2e00
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


class Operation(Enum):
    invoke = "invoke"
    read_result = "read_result"
    read = "read"
    subscribe = "subscribe"
    get = "get"
    delegate = "delegate"


class MonetaryAmount(BaseModel):
    """
    A monetary amount in the currency's smallest minor unit. Mirrors `MonetaryAmount`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class Constraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
    """

    type: constr(min_length=1)
    value: Any | None = None


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
            pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
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


class ToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    server_id: constr(min_length=1)
    tool_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)
    constraints: list[Constraint] | None = None
    max_invocations: conint(ge=0) | None = None
    max_cost_per_invocation: MonetaryAmount | None = None
    max_total_cost: MonetaryAmount | None = None
    dpop_required: bool | None = None


class ResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    uri_pattern: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class PromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    prompt_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class AttenuationWitness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    normalizedParentScope: constr(min_length=2)
    normalizedChildScope: constr(min_length=2)
    subsetRelations: list[GrantSubsetRelation] | None = None
    restrictedPredicates: list[str] | None = None


class ChioScope(BaseModel):
    """
    What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[ToolGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None
    prompt_grants: list[PromptGrant] | None = None


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
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    scope: ChioScope
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
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
