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

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class TokenDigest(RootModel[constr(pattern=r"^[0-9a-f]{64}$")]):
    root: constr(pattern=r"^[0-9a-f]{64}$")


class ChioVerifiedApprovalSetBody(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    token_digests: list[TokenDigest] = Field(..., max_length=32, min_length=1)
    policy_hash: constr(pattern=r"^[0-9a-f]{64}$")
    threshold: conint(ge=1, le=32)
    eligible_set_digest: constr(pattern=r"^[0-9a-f]{64}$")
    request_id: constr(min_length=1)
    governed_intent_hash: constr(pattern=r"^[0-9a-f]{64}$")
    subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}|hybrid:([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194}):[0-9a-f]{3904}:(ed25519|p256|p384)\+mldsa65)$"
    )
    authorizing_capability_digest: constr(pattern=r"^[0-9a-f]{64}$")
    threshold_proposal_hash: constr(pattern=r"^[0-9a-f]{64}$")
    proposal_id: constr(min_length=1)
    proposal_created_at: conint(ge=0)
    proposal_deadline: conint(ge=1)
