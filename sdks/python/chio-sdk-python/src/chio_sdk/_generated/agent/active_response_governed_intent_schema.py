# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 63696e53010dca489dd90f0f71166c42511e6e9734e364a6e3cd564e8d04693b
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class OrderedEffect(Enum):
    throttle_session = "throttle_session"
    restrict_egress = "restrict_egress"
    suspend_session = "suspend_session"
    suspend_capability_set = "suspend_capability_set"
    freeze_issuance = "freeze_issuance"


class ChioGovernedActiveResponseIntentBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    plan_schema: Literal["chio.governed-response-plan.v1"]
    plan_id: constr(min_length=1)
    operator_capability_id: constr(min_length=1)
    operator_capability_hash: constr(pattern=r"^[0-9a-f]{64}$")
    operator_capability_expires_at: conint(ge=1)
    executor_subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    canonical_plan_body: dict[str, Any]
    plan_body_hash: constr(pattern=r"^[0-9a-f]{64}$")
    target_binding: dict[str, Any]
    ordered_effects: list[OrderedEffect] = Field(..., max_length=32, min_length=1)
    expires_at: conint(ge=1)
    rollback_binding: dict[str, Any]
