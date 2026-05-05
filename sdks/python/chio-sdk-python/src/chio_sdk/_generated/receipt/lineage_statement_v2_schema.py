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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class ParentReceiptId(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class ChioReceiptLineageStatementV2(BaseModel):
    """
    Signed multi-parent lineage statement. parentReceiptIds are v2 body_hash values, canonical sorted and deduplicated, with parentSetHash = H(canonical(parentReceiptIds)).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.receipt_lineage_statement.v2"] = Field(..., alias="schema")
    id: constr(min_length=1)
    childBodyHash: constr(pattern=r"^[0-9a-f]{64}$")
    chainId: constr(min_length=1)
    parentReceiptIds: list[ParentReceiptId]
    parentSetHash: constr(pattern=r"^[0-9a-f]{64}$")
    issuedAt: conint(ge=0)
    kernelKey: constr(min_length=64)
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:[a-z0-9_-]+:[a-z0-9_-]+:[a-z0-9_+.-]+:[0-9a-f]+:[0-9a-f]+)$"
    )
