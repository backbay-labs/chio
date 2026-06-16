# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: eaf359bf7e7491596ce506611867f9d94868e653a710c2218be266a71e512e5b
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Operation(Enum):
    invoke = "invoke"
    read_result = "read_result"
    read = "read"
    subscribe = "subscribe"
    get = "get"
    delegate = "delegate"


class Constraint(BaseModel):
    type: constr(min_length=1)
    value: Any | None = None


class MaxCostPerInvocation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class MaxTotalCost(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    server_id: constr(min_length=1)
    tool_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)
    constraints: list[Constraint] | None = None
    max_invocations: conint(ge=0) | None = None
    max_cost_per_invocation: MaxCostPerInvocation | None = None
    max_total_cost: MaxTotalCost | None = None
    dpop_required: bool | None = None


class ResourceGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    uri_pattern: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class PromptGrant(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    prompt_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class Scope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[Grant] | None = None
    resource_grants: list[ResourceGrant] | None = None
    prompt_grants: list[PromptGrant] | None = None


class DelegationChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: constr(min_length=1)
    delegator: constr(pattern=r"^[0-9a-f]{64}$")
    delegatee: constr(pattern=r"^[0-9a-f]{64}$")
    attenuations: list[dict[str, Any]] | None = None
    timestamp: conint(ge=0)
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"
    hybrid = "hybrid"


class Caveat(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: constr(min_length=1)
    predicate: Any
    enforced_at: constr(min_length=1) | None = None


class ScopeAttenuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: constr(min_length=1)


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parent_scope_hash: constr(pattern=r"^[0-9a-f]{64}$")
    child_scope_hash: constr(pattern=r"^[0-9a-f]{64}$")
    normalized_subset_proof: list[str]


class Capability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capability.v1"] = Field(
        "chio.capability.v1",
        alias="schema",
        description="Signed-artifact schema ID for live capability-token serialization.",
    )
    id: constr(min_length=1)
    issuer: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    scope: Scope
    issued_at: conint(ge=0)
    expires_at: conint(ge=0)
    delegation_chain: list[DelegationChainItem] | None = None
    algorithm: Algorithm | None = None
    caveats: list[Caveat] | None = None
    scope_attenuations: list[ScopeAttenuation] | None = None
    attenuation_proof: AttenuationProof | None = None
    budget_share_bps: conint(ge=0, le=10000) | None = None
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )


class ChioKernelmessageCapabilityList(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["capability_list"]
    capabilities: list[Capability]
