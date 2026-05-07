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

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ChioAgentmessageListCapabilities(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["list_capabilities"]
