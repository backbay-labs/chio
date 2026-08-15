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
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr

from . import aggregate_invocation_budget_schema, cumulative_approval_root_schema


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


class GenericConstraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    type: constr(min_length=1)
    value: Any | None = None


class Value(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    threshold_units: conint(ge=0)


class LegacyApprovalConstraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["require_approval_above"]
    value: Value


class Value1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    threshold: MonetaryAmount
    approval_budget_id: constr(min_length=1)
    approval_budget_epoch: conint(ge=0)
    cumulative_approval_root_binding: Any | None = None


class CumulativeApprovalDirectConstraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["require_cumulative_approval_above"]
    value: Value1


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


class Attenuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: constr(min_length=1)


class DelegationLink(BaseModel):
    """
    A single delegation link. The required scope_hash binds the authorized parent scope used by the next hop's attenuation_proof.parent_scope_hash.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: constr(min_length=1)
    delegator: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$"
    )
    delegatee: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+)$"
    )
    attenuations: list[Attenuation] | None = None
    timestamp: conint(ge=0)
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$"
    )
    scope_hash: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ...,
        description="RFC 8785 canonical scope hash for this delegation hop. Runtime verification rejects links that omit it.",
    )


class GrantKind(Enum):
    tool = "tool"
    resource = "resource"
    prompt = "prompt"


class Subset(Enum):
    boolean_True = True


class GrantSubsetRelation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    grantKind: GrantKind
    childIndex: conint(ge=0)
    parentIndex: conint(ge=0)
    subset: Subset


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


class Value2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    threshold: MonetaryAmount
    approval_budget_id: constr(min_length=1)
    approval_budget_epoch: conint(ge=0)
    cumulative_approval_root_binding: (
        cumulative_approval_root_schema.ChioCumulativeApprovalRootBinding
    )


class CumulativeApprovalDelegableConstraint(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["require_cumulative_approval_above"]
    value: Value2


class AttenuationWitness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    normalizedParentScope: constr(min_length=2)
    normalizedChildScope: constr(min_length=2)
    subsetRelations: list[GrantSubsetRelation] | None = None
    restrictedPredicates: list[str] | None = None


class Constraint(
    RootModel[
        GenericConstraint
        | LegacyApprovalConstraint
        | CumulativeApprovalDirectConstraint
        | CumulativeApprovalDelegableConstraint
    ]
):
    root: (
        GenericConstraint
        | LegacyApprovalConstraint
        | CumulativeApprovalDirectConstraint
        | CumulativeApprovalDelegableConstraint
    )

    @property
    def type(self) -> str:
        return self.root.type

    @property
    def value(self) -> Any:
        return self.root.value


class AttenuationProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parentScopeHash: constr(pattern=r"^[0-9a-f]{64}$")
    childScopeHash: constr(pattern=r"^[0-9a-f]{64}$")
    normalizedSubsetProof: AttenuationWitness


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


class ChioCapabilitytoken(BaseModel):
    """
    A Chio capability token with typed caveats, attenuation fields, attenuation proof, budget share, and hybrid signing support folded into the unreleased v1 wire shape.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capability.v1"] = Field("chio.capability.v1", alias="schema")
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
    delegation_chain: list[DelegationLink] | None = None
    aggregate_invocation_budget: (
        aggregate_invocation_budget_schema.ChioAggregateInvocationBudget | None
    ) = None
    algorithm: Algorithm | None = None
    caveats: list[Caveat] | None = None
    scope_attenuations: list[ScopeAttenuation] | None = None
    attenuation_proof: AttenuationProof | None = None
    budget_share_bps: conint(ge=0, le=10000) | None = Field(
        None,
        description="Fixed-point child share in basis points. Values above 10000 re-amplify budget and fail closed.",
    )
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
