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

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Digest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    sha256: constr(pattern=r"^[0-9a-f]{64}$")


class SubjectItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: constr(pattern=r"^chio-receipt:.+")
    digest: Digest


class CoSign(Enum):
    bilateral_required = "bilateral_required"
    bilateral_if_cross_org = "bilateral_if_cross_org"


class CrossOrgVisibility(Enum):
    private = "private"
    treaty_only = "treaty_only"
    federated = "federated"
    public = "public"


class HashRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alg: Literal["sha256"]
    value: constr(pattern=r"^[0-9a-f]{64}$")


class KernelIdentity(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    kernel_id: constr(min_length=1)
    passport_key_fingerprint: constr(pattern=r"^[0-9a-f]{64}$")
    alg: Literal["ed25519"]


class CapabilityLeaseRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    lease_id: constr(min_length=1)
    issuer: constr(min_length=1)
    expires_at_unix_ms: conint(ge=0)
    scope_digest: HashRecord | None = None


class Verdict(Enum):
    allow = "allow"
    deny = "deny"


class PolicyVerdict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Verdict
    policy_id: constr(min_length=1)
    policy_version: constr(min_length=1)
    rationale_code: constr(min_length=1) | None = None


class JointDisposition(Enum):
    allow = "allow"
    deny = "deny"


class PolicyEvaluationSummary(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    server_a_verdict: PolicyVerdict
    server_b_verdict: PolicyVerdict
    joint_disposition: JointDisposition | None = None


class GovernanceReceiptRef(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    receipt_id: constr(min_length=1)
    kernel_id: constr(min_length=1)
    digest: HashRecord


class Predicate(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: Literal["chio.bilateral-signature-slice.v1"] = Field(..., alias="schema")
    invocation_id: constr(min_length=1)
    tool_server_a: KernelIdentity
    tool_server_b: KernelIdentity
    tool_name: constr(min_length=1)
    co_sign: CoSign
    consistency_model: Literal["crdt-commutative"]
    cross_org_visibility: CrossOrgVisibility
    timestamp_unix_ms: conint(ge=0)
    receipt_canonical_json: constr(min_length=2)
    capability_lease_ref: CapabilityLeaseRef | None = None
    policy_evaluation_summary: PolicyEvaluationSummary | None = None
    governance_receipt_ref: GovernanceReceiptRef | None = None
    consistency_anchor: constr(min_length=1) | None = None


class ChioBilateralDsseSignatureSliceStatement(BaseModel):
    """
    Bounded in-toto Statement payload for Chio bilateral DSSE signature slices. This is not the strict treaty-bound bilateral invocation predicate.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    field_type: Literal["https://in-toto.io/Statement/v1"] = Field(..., alias="_type")
    subject: list[SubjectItem] = Field(..., max_length=1, min_length=1)
    predicateType: Literal["chio.bilateral-signature-slice.v1"]
    predicate: Predicate
