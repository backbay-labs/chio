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

from pydantic import BaseModel, ConfigDict


class ChioToolcallerrorCapabilityRevoked(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_revoked"]
