# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 63696e53010dca489dd90f0f71166c42511e6e9734e364a6e3cd564e8d04693b
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, constr

from ..capability import (
    governed_approval_token_schema,
    supplemental_authorization_schema,
    threshold_approval_proposal_schema,
    token_schema,
)
from ..kernel import execution_nonce_schema
from . import governed_transaction_intent_schema


class ChioAgentmessageToolCallRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    type: Literal["tool_call_request"]
    id: constr(min_length=1)
    capability_token: token_schema.ChioCapabilitytoken
    server_id: constr(min_length=1)
    tool: constr(min_length=1)
    params: Any
    governed_intent: (
        governed_transaction_intent_schema.ChioGovernedTransactionIntent | None
    ) = None
    approval_token: governed_approval_token_schema.ChioGovernedApprovalToken | None = (
        None
    )
    approval_tokens: (
        list[governed_approval_token_schema.ChioGovernedApprovalToken] | None
    ) = Field(None, max_length=32)
    threshold_approval_proposal: (
        threshold_approval_proposal_schema.ChioThresholdApprovalProposal | None
    ) = None
    supplemental_authorization: (
        supplemental_authorization_schema.ChioOpaqueSupplementalAuthorization | None
    ) = None
    execution_nonce: execution_nonce_schema.ChioSignedExecutionNonce | None = None
