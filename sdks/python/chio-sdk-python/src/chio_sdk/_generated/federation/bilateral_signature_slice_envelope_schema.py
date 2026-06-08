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

from pydantic import BaseModel, ConfigDict, Field, constr


class Signature(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    keyid: constr(pattern=r"^[0-9a-f]{64}$")
    sig: constr(min_length=1)


class ChioBilateralDsseSignatureSliceEnvelope(BaseModel):
    """
    Top-level DSSE envelope for Chio bilateral signature-slice artifacts. The base64 payload is the canonical JSON in-toto Statement described by bilateral-signature-slice.schema.json.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    payloadType: Literal["application/vnd.in-toto+json"]
    payload: constr(min_length=1)
    signatures: list[Signature] = Field(..., max_length=2, min_length=2)
