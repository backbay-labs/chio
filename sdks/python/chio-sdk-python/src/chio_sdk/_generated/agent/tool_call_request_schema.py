# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 3ed943267c60942b5a63a39515fbbc1a553d614d895d142e307096a7a99c7da2
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
    signature: constr(pattern=r"^[0-9a-f]{128}$")


class CapabilityToken(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(min_length=1)
    issuer: constr(pattern=r"^[0-9a-f]{64}$")
    subject: constr(pattern=r"^[0-9a-f]{64}$")
    scope: Scope
    issued_at: conint(ge=0)
    expires_at: conint(ge=0)
    delegation_chain: list[DelegationChainItem] | None = None
    signature: constr(pattern=r"^[0-9a-f]{128}$")


class ChioAgentmessageToolCallRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["tool_call_request"]
    id: constr(min_length=1)
    capability_token: CapabilityToken
    server_id: constr(min_length=1)
    tool: constr(min_length=1)
    params: Any
