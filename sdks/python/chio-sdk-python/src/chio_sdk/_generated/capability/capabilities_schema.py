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
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class MaxCapabilitySchema(Enum):
    chio_capability_v1 = "chio.capability.v1"
    chio_capability_v2 = "chio.capability.v2"


class ChioCapabilityNegotiationV1(BaseModel):
    """
    Feature bitset exchanged during federation trust establishment. Malformed feature names and unsupported schema IDs fail closed before peers negotiate capability v2, receipt v2, or anchor-batch support.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capabilities.v1"] = Field(..., alias="schema")
    features: dict[str, bool] | None = Field(
        None,
        description="String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.",
    )
    maxCapabilitySchema: MaxCapabilitySchema
