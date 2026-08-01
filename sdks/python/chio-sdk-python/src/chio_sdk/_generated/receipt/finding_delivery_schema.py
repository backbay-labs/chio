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
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class TransformProfile(Enum):
    identity = "identity"


class DigestCheck(Enum):
    matched = "matched"
    mismatched = "mismatched"


class MediaTypeCheck(Enum):
    matched = "matched"
    mismatched = "mismatched"
    not_evaluated = "not_evaluated"


class SettlementMode(Enum):
    local_reversible_hold = "local_reversible_hold"


class Digest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class Identifier(RootModel[constr(pattern=r"^[A-Za-z0-9._:-]{1,512}$")]):
    root: constr(pattern=r"^[A-Za-z0-9._:-]{1,512}$")


class HierarchicalIdentifier(RootModel[constr(pattern=r"^[A-Za-z0-9._:/-]{1,512}$")]):
    root: constr(pattern=r"^[A-Za-z0-9._:/-]{1,512}$")


class IJsonU64NonZero(RootModel[conint(ge=1, le=9007199254740991)]):
    root: conint(ge=1, le=9007199254740991)


class StatusProof(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    feed_id: HierarchicalIdentifier
    key_domain_nonce: Literal[3318287169837494]
    map_epoch: IJsonU64NonZero
    status_epoch_artifact_sha256: Digest
    proof_sha256: Digest
    root_hash: Digest
    non_inclusion_checked_at: IJsonU64NonZero


class ChioFindingDeliveryReceiptMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.finding.delivery.v1"] = Field(..., alias="schema")
    finding_id: Identifier
    listing_id: Identifier
    transform_profile: TransformProfile
    digest_check: DigestCheck
    media_type_check: MediaTypeCheck
    settlement_mode: SettlementMode
    accepted_bid_envelope_sha256: Digest
    venue_admission_envelope_sha256: Digest
    reservation_id: Identifier
    purchase_intent_id: Identifier
    authoritative_payment_operation_id: Identifier
    status_proof: StatusProof | None = None
