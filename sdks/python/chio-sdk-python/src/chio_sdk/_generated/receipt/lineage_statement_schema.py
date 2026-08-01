# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 27975bf17d3c195d530b2e28ac498870376a2aeb649e8b3126f61b882beedf84
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class RelationKind(Enum):
    local_child = "local_child"
    continued = "continued"


class EvidenceClass(Enum):
    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class SessionAnchorReference(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sessionAnchorId: constr(min_length=1)
    sessionAnchorHash: constr(min_length=1)


class ChioReceiptLineageStatement(BaseModel):
    """
    Signed pairwise receipt lineage statement. Multi-parent lineage views are derived aggregates over these signed parent-child statements.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.receipt_lineage_statement.v1"] = Field(..., alias="schema")
    id: constr(min_length=1)
    parentReceiptId: constr(min_length=1)
    childReceiptId: constr(min_length=1)
    parentRequestId: constr(min_length=1)
    childRequestId: constr(min_length=1)
    parentSessionAnchor: SessionAnchorReference
    childSessionAnchor: SessionAnchorReference
    relationKind: RelationKind
    evidenceClass: EvidenceClass
    continuationTokenId: constr(min_length=1) | None = None
    issuedAt: conint(ge=0)
    kernelKey: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
