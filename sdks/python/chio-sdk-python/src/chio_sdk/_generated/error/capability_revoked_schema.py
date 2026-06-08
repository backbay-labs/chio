# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 61971d0fd9521328df208fed380e2ce1e207c4d8c906b7576b864af1911371e5
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
