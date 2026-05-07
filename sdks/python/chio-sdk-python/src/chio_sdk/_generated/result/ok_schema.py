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

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class ChioToolcallresultOk(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["ok"]
    value: Any
