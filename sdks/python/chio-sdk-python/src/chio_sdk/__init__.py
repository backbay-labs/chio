"""Chio SDK for Python -- thin HTTP client to the Chio sidecar kernel."""

from typing import Any

from chio_sdk.models import (
    ChioHttpRequest,
    ChioPassthrough,
    ChioReceipt,
    ChioScope,
    Attenuation,
    AuthMethod,
    CallerIdentity,
    CapabilityToken,
    CapabilityTokenBody,
    Constraint,
    Decision,
    DelegationLink,
    EvaluateResponse,
    GuardEvidence,
    HttpReceipt,
    MonetaryAmount,
    Operation,
    PromptGrant,
    ResourceGrant,
    ToolCallAction,
    ToolGrant,
    Verdict,
)
from chio_sdk.errors import (
    ChioError,
    ChioConnectionError,
    ChioDeniedError,
    ChioTimeoutError,
    ChioValidationError,
)
from chio_sdk.models_approvals import (
    Approval,
    ApprovalResponse,
    ApprovalVerdict,
    PendingApproval,
    PendingApprovalList,
    ResolvedApproval,
    SubmitApprovalResult,
)
from chio_sdk.testing import (
    MockChioClient,
    MockVerdict,
    RecordedCall,
    allow_all,
    deny_all,
    with_policy,
)
from chio_sdk.finding import (
    BuyerFindingEstimate,
    FindingBidCeilingError,
    FindingBidCeilingInput,
    FindingBidCeilingPolicy,
    finding_bid_ceiling,
)

__all__ = [
    # Client
    "ChioClient",
    # Testing
    "MockChioClient",
    "MockVerdict",
    "RecordedCall",
    "allow_all",
    "deny_all",
    "with_policy",
    # Cognition market buyer-local policy
    "BuyerFindingEstimate",
    "FindingBidCeilingError",
    "FindingBidCeilingInput",
    "FindingBidCeilingPolicy",
    "finding_bid_ceiling",
    # Models -- capabilities
    "CapabilityToken",
    "CapabilityTokenBody",
    "ChioScope",
    "ChioHttpRequest",
    "ChioPassthrough",
    "ToolGrant",
    "ResourceGrant",
    "PromptGrant",
    "Operation",
    "Constraint",
    "MonetaryAmount",
    "DelegationLink",
    "Attenuation",
    # Models -- receipts
    "ChioReceipt",
    "HttpReceipt",
    "EvaluateResponse",
    "Decision",
    "Verdict",
    "ToolCallAction",
    "GuardEvidence",
    # Models -- identity
    "CallerIdentity",
    "AuthMethod",
    # Models -- approvals
    "Approval",
    "ApprovalResponse",
    "ApprovalVerdict",
    "PendingApproval",
    "PendingApprovalList",
    "ResolvedApproval",
    "SubmitApprovalResult",
    # Errors
    "ChioError",
    "ChioConnectionError",
    "ChioDeniedError",
    "ChioTimeoutError",
    "ChioValidationError",
]


def __getattr__(name: str) -> Any:
    if name == "ChioClient":
        from chio_sdk.client import ChioClient

        return ChioClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
