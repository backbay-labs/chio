# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 3ed943267c60942b5a63a39515fbbc1a553d614d895d142e307096a7a99c7da2
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, conint, constr


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


class EvidenceItem(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    guard_name: constr(min_length=1)
    verdict: bool
    details: str | None = None


class Receipt(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(min_length=1)
    timestamp: conint(ge=0)
    capability_id: constr(min_length=1)
    tool_server: constr(min_length=1)
    tool_name: constr(min_length=1)
    action: Action
    decision: Decision | Decision6 | Decision7 | Decision8
    content_hash: constr(pattern=r"^[0-9a-f]{64}$")
    policy_hash: constr(pattern=r"^[0-9a-f]{64}$")
    evidence: list[EvidenceItem] | None = None
    metadata: Any | None = None
    kernel_key: constr(pattern=r"^[0-9a-f]{64}$")
    signature: constr(pattern=r"^[0-9a-f]{128}$")


class ChioKernelmessageToolCallResponse(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["tool_call_response"]
    id: constr(min_length=1)
    result: Result | Result1 | Result2 | Result3 | Result4
    receipt: Receipt
