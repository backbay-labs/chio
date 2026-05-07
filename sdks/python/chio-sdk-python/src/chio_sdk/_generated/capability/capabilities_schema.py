# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d680571b15f2c519e43943d2ec4e7754e54e544f1245ac1e25d16952856342c9
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

_CHIO_FEATURE_NAME_RE = re.compile(r"^[a-z0-9_.-]{1,96}$")


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

    @model_validator(mode="after")
    def _validate_feature_names(self) -> "ChioCapabilityNegotiationV1":
        if self.features is None:
            return self
        for name in self.features:
            if not _CHIO_FEATURE_NAME_RE.match(name):
                raise ValueError(
                    f"capability feature name {name!r} does not match "
                    f"propertyNames pattern ^[a-z0-9_.-]{{1,96}}$"
                )
        return self
