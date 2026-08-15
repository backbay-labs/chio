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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint

from . import aggregate_budget_root_schema


class ChioAggregateInvocationBudget1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Literal["capability"]
    max_invocations: conint(ge=0, le=4294967295)
    root_binding: Any | None = None


class ChioAggregateInvocationBudget2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    scope: Literal["delegation_family"]
    max_invocations: conint(ge=0, le=4294967295)
    root_binding: aggregate_budget_root_schema.ChioAggregateBudgetRootBinding


class ChioAggregateInvocationBudget(
    RootModel[ChioAggregateInvocationBudget1 | ChioAggregateInvocationBudget2]
):
    root: ChioAggregateInvocationBudget1 | ChioAggregateInvocationBudget2 = Field(
        ..., title="Chio Aggregate Invocation Budget"
    )
