# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 8ba0a80532a71a901c67466299ea1bfe1de2852479f67791d2ff4b08be726a8c
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class CheckpointId(RootModel[constr(min_length=1)]):
    root: constr(min_length=1)


class Inclusion(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    checkpointId: constr(min_length=1)
    leafHash: constr(pattern=r"^(0x)?[0-9a-f]{64}$")
    proof: dict[str, Any]


class Kind(Enum):
    rekor = "rekor"
    ots = "ots"
    solana_memo = "solana_memo"


class Witness(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    witnessId: constr(min_length=1)
    root: constr(pattern=r"^(0x)?[0-9a-f]{64}$")
    observedAt: conint(ge=0) | None = None


class WitnessState1(BaseModel):
    """
    W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["pending"]


class WitnessState3(BaseModel):
    """
    W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["stale"]
    last_verified: conint(ge=0)
    error: constr(min_length=1)


class WitnessReceipt(BaseModel):
    """
    Verifier-bound receipt returned by a public-witness lane. OTS receipts remain advisory until the lane carries trusted Bitcoin header or calendar-backed commitment evidence.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Kind
    externalUuid: constr(min_length=1)
    publishedAt: conint(ge=0)
    inclusionProof: constr(
        pattern=r"^$|^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
    )
    witnessRoot: constr(pattern=r"^(0x)?[0-9a-f]{64}$")
    bodyHash: constr(pattern=r"^(0x)?[0-9a-f]{64}$")


class WitnessState2(BaseModel):
    """
    W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    kind: Literal["witnessed"]
    receipt: WitnessReceipt
    observed_at: conint(ge=0)


class WitnessState(RootModel[WitnessState1 | WitnessState2 | WitnessState3]):
    root: WitnessState1 | WitnessState2 | WitnessState3 = Field(
        ...,
        description="W2.3 lifecycle for the public-witness lane. Defaults to {kind: pending} when omitted to preserve wire compatibility for v1 batches that pre-date the state machine.",
    )


class Body(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.anchor_batch.v1"] = Field(..., alias="schema")
    treeRoot: constr(pattern=r"^(0x)?[0-9a-f]{64}$")
    checkpointIds: list[CheckpointId] = Field(..., min_length=1)
    inclusions: list[Inclusion] = Field(..., min_length=1)
    witness: Witness
    issuedAt: conint(ge=0)
    signerKey: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    witnessState: WitnessState | None = None


class ChioAnchorBatchV1(BaseModel):
    """
    Signed additive Merkle batch over receipts or checkpoints. Local receipt signatures remain authoritative; the batch adds continuity and public-witness timestamping.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    body: Body
    signature: constr(
        pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+|hybrid:([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+):[0-9a-f]{6618}:(ed25519|p256|p384)\+mldsa65)$"
    )
