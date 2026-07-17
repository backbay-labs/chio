# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9d7b17b15b33f7dcc9d52da37c9fb906c57911cdfd78424c344f5ce58b160468
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Literal

import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

_CHIO_FEATURE_NAME_RE = re.compile(r"^[a-z0-9_.-]{1,96}$")


class ChioCapabilityNegotiationV1(BaseModel):
    """
    Feature bitset exchanged during federation trust establishment. Malformed feature names and unsupported schema IDs fail closed.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.capabilities.v1"] = Field(..., alias="schema")
    features: dict[str, bool] | None = Field(
        None,
        description="String-keyed feature bitset. Peers proceed only with the intersection of true values advertised by both sides.",
    )

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
