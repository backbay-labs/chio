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

from pydantic import BaseModel, ConfigDict, conint, constr

from . import active_response_governed_intent_schema


class MaxAmount(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["tool_invocation"]


class Body3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["active_response_plan"]
    value: active_response_governed_intent_schema.ChioGovernedActiveResponseIntentBody


class ChioGovernedTransactionIntent(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(min_length=1)
    server_id: constr(min_length=1)
    tool_name: constr(min_length=1)
    purpose: str
    max_amount: MaxAmount | None = None
    commerce: dict[str, Any] | None = None
    metered_billing: dict[str, Any] | None = None
    runtime_attestation: dict[str, Any] | None = None
    call_chain: dict[str, Any] | None = None
    autonomy: dict[str, Any] | None = None
    context: Any | None = None
    body: Body | Body3 | None = None
