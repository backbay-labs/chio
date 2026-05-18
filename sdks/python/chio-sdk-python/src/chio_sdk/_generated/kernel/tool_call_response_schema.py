# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 31d733bff1206a7961e2e9bccbc59a4de576f3e3f9cfaf465469e3c66d48fba7
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, conint, constr

from ..receipt.record_schema import ChioReceiptRecord


class Result(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["ok"]
    value: Any


class Result1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["stream_complete"]
    total_chunks: conint(ge=0)


class Result2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["cancelled"]
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)


class Result3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["incomplete"]
    reason: constr(min_length=1)
    chunks_received: conint(ge=0)


class Error(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_denied"]
    detail: constr(min_length=1)


class Error9(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_expired"]


class Error10(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["capability_revoked"]


class Detail(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard: constr(min_length=1)
    reason: constr(min_length=1)


class Error11(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["policy_denied"]
    detail: Detail


class Error12(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["tool_server_error"]
    detail: constr(min_length=1)


class Error13(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    code: Literal["internal_error"]
    detail: constr(min_length=1)


class Result4(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    status: Literal["err"]
    error: Error | Error9 | Error10 | Error11 | Error12 | Error13


class Action(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    parameters: Any
    parameter_hash: constr(pattern=r"^[0-9a-f]{64}$")


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["allow"]


class Decision6(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["deny"]
    reason: constr(min_length=1)
    guard: constr(min_length=1)


class Decision7(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["cancelled"]
    reason: constr(min_length=1)


class Decision8(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["incomplete"]
    reason: constr(min_length=1)


class ReceiptKind(Enum):
    mediated_decision = "mediated_decision"
    trace_observation = "trace_observation"
    advisory_evaluation = "advisory_evaluation"


class BoundaryClass(Enum):
    prevent = "prevent"
    detect_only = "detect_only"
    advisory_only = "advisory_only"


class ObservationOutcome(Enum):
    observed = "observed"
    evaluated = "evaluated"
    dropped = "dropped"


class ToolOrigin(Enum):
    caller_executed = "caller_executed"
    host_executed_provider_reported = "host_executed_provider_reported"
    host_executed_unmediated = "host_executed_unmediated"


class RedactionMode(Enum):
    none = "none"
    summary = "summary"
    redacted = "redacted"


class ActorChainItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    actor_id: constr(min_length=1)
    actor_kind: str | None = None


class EvidenceItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard_name: constr(min_length=1)
    verdict: bool
    details: str | None = None


class TrustLevel(Enum):
    mediated = "mediated"
    verified = "verified"
    advisory = "advisory"


class Algorithm(Enum):
    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(pattern=r"^[0-9a-f]{64}$")
    timestamp: conint(ge=0)
    capability_id: constr(min_length=1)
    tool_server: constr(min_length=1)
    tool_name: constr(min_length=1)
    action: Action
    decision: Decision | Decision6 | Decision7 | Decision8 | None = None
    receipt_kind: ReceiptKind
    boundary_class: BoundaryClass
    observation_outcome: ObservationOutcome | None = None
    tool_origin: ToolOrigin
    redaction_mode: RedactionMode
    actor_chain: list[ActorChainItem] | None = None
    content_hash: constr(pattern=r"^[0-9a-f]{64}$")
    policy_hash: constr(min_length=1)
    evidence: list[EvidenceItem] | None = None
    metadata: Any | None = None
    trust_level: TrustLevel
    tenant_id: constr(min_length=1) | None = None
    kernel_key: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
    )
    algorithm: Algorithm | None = None
    signature: constr(pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$")


class ChioKernelmessageToolCallResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["tool_call_response"]
    id: constr(min_length=1)
    result: Result | Result1 | Result2 | Result3 | Result4
    receipt: ChioReceiptRecord
