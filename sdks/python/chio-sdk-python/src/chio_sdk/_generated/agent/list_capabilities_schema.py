# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9f24fc984622e90fbadd2f5d5e6ed6115c591601711058eff10e9d6f1343e6ff
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
