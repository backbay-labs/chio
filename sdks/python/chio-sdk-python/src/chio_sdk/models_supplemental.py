# Hand-typed models with no generated equivalent in chio_sdk._generated.
# Re-exported through chio_sdk.models: AuthMethod, CallerIdentity,
# CapabilityTokenBody, ChioHttpRequest, ChioPassthrough, EvaluateResponse,
# GovernedAutonomyTier, HttpReceipt, Verdict, VerifyReceiptResponse.

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Primitive enums
# ---------------------------------------------------------------------------


class GovernedAutonomyTier(str, enum.Enum):
    """Governed autonomy tier for economically sensitive actions."""

    DIRECT = "direct"
    DELEGATED = "delegated"
    AUTONOMOUS = "autonomous"


# ---------------------------------------------------------------------------
# Decision / Verdict
# ---------------------------------------------------------------------------


class Verdict(BaseModel):
    """HTTP-layer verdict, consistent with Decision but carries HTTP context."""

    verdict: str  # "allow", "deny", "cancel", "incomplete"
    reason: str | None = None
    guard: str | None = None
    http_status: int | None = None

    @classmethod
    def allow(cls) -> Verdict:
        return cls(verdict="allow")

    @classmethod
    def deny(
        cls, reason: str, guard: str, http_status: int = 403
    ) -> Verdict:
        return cls(verdict="deny", reason=reason, guard=guard, http_status=http_status)

    @property
    def is_allowed(self) -> bool:
        return self.verdict == "allow"

    @property
    def is_denied(self) -> bool:
        return self.verdict == "deny"

    def to_decision(self) -> Any:
        """Convert to core Decision type (from chio_sdk.models)."""
        from chio_sdk._generated import Decision as GenDecision
        if self.verdict == "allow":
            from chio_sdk._generated.receipt.record_schema import Decision1
            return GenDecision(root=Decision1(verdict="allow"))
        if self.verdict == "deny":
            from chio_sdk._generated.receipt.record_schema import Decision2
            return GenDecision(root=Decision2(verdict="deny", reason=self.reason or "", guard=self.guard or ""))
        if self.verdict == "cancel":
            from chio_sdk._generated.receipt.record_schema import Decision3
            return GenDecision(root=Decision3(verdict="cancelled", reason=self.reason or ""))
        from chio_sdk._generated.receipt.record_schema import Decision4
        return GenDecision(root=Decision4(verdict="incomplete", reason=self.reason or ""))


# ---------------------------------------------------------------------------
# Guard Evidence (used by HttpReceipt)
# ---------------------------------------------------------------------------


class _GuardEvidenceMinimal(BaseModel):
    """Minimal guard evidence shape used by HttpReceipt."""

    guard_name: str
    verdict: bool
    details: str | None = None


# ---------------------------------------------------------------------------
# Caller Identity / Auth Method
# ---------------------------------------------------------------------------


class AuthMethod(BaseModel):
    """How the caller authenticated.

    Tagged union with ``method`` discriminator.
    """

    method: str  # "bearer", "api_key", "cookie", "mtls_certificate", "anonymous"
    token_hash: str | None = None
    key_name: str | None = None
    key_hash: str | None = None
    cookie_name: str | None = None
    cookie_hash: str | None = None
    subject_dn: str | None = None
    fingerprint: str | None = None

    @classmethod
    def bearer(cls, token_hash: str) -> AuthMethod:
        return cls(method="bearer", token_hash=token_hash)

    @classmethod
    def api_key(cls, key_name: str, key_hash: str) -> AuthMethod:
        return cls(method="api_key", key_name=key_name, key_hash=key_hash)

    @classmethod
    def cookie(cls, cookie_name: str, cookie_hash: str) -> AuthMethod:
        return cls(method="cookie", cookie_name=cookie_name, cookie_hash=cookie_hash)

    @classmethod
    def anonymous(cls) -> AuthMethod:
        return cls(method="anonymous")


class CallerIdentity(BaseModel):
    """Identity of the caller as extracted from the HTTP request."""

    subject: str
    auth_method: AuthMethod
    verified: bool = False
    tenant: str | None = None
    agent_id: str | None = None

    @classmethod
    def anonymous(cls) -> CallerIdentity:
        return cls(
            subject="anonymous",
            auth_method=AuthMethod.anonymous(),
            verified=False,
        )


# ---------------------------------------------------------------------------
# HTTP Receipt
# ---------------------------------------------------------------------------


def _validate_observation_receipt_semantics(
    *,
    receipt_kind: str | None,
    boundary_class: str | None,
    trust_level: str | None,
    observation_outcome: str | None,
) -> None:
    if receipt_kind is None:
        return
    if receipt_kind == "mediated_decision":
        if boundary_class != "prevent":
            raise ValueError("mediated_decision receipts must use boundary_class prevent")
        if trust_level != "mediated":
            raise ValueError("mediated_decision receipts must use trust_level mediated")
        if observation_outcome is not None:
            raise ValueError("mediated_decision receipts must omit observation_outcome")
        return
    if receipt_kind == "trace_observation":
        if boundary_class != "detect_only":
            raise ValueError("trace_observation receipts must use boundary_class detect_only")
        if trust_level != "verified":
            raise ValueError("trace_observation receipts must use trust_level verified")
        if observation_outcome is None:
            raise ValueError("trace_observation receipts must include observation_outcome")
        return
    if receipt_kind == "advisory_evaluation":
        if boundary_class != "advisory_only":
            raise ValueError("advisory_evaluation receipts must use boundary_class advisory_only")
        if trust_level != "advisory":
            raise ValueError("advisory_evaluation receipts must use trust_level advisory")
        if observation_outcome is None:
            raise ValueError("advisory_evaluation receipts must include observation_outcome")
        return
    raise ValueError("receipt_kind must be a current v1 receipt kind")


class HttpReceipt(BaseModel):
    """Signed receipt for an HTTP request evaluation."""

    id: str
    request_id: str
    route_pattern: str
    method: str
    caller_identity_hash: str
    session_id: str | None = None
    verdict: Verdict
    receipt_kind: str | None = None
    boundary_class: str | None = None
    observation_outcome: str | None = None
    tool_origin: str | None = None
    redaction_mode: str | None = None
    actor_chain: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[_GuardEvidenceMinimal] = Field(default_factory=list)
    response_status: int = Field(
        description=(
            "Chio evaluation-time HTTP status; allow receipts may be signed "
            "before downstream response completion."
        )
    )
    timestamp: int
    content_hash: str
    policy_hash: str
    capability_id: str | None = None
    metadata: dict[str, Any] | None = None
    kernel_key: str
    signature: str
    trust_level: str

    @model_validator(mode="after")
    def _validate_semantic_coherence(self) -> "HttpReceipt":
        _validate_observation_receipt_semantics(
            receipt_kind=self.receipt_kind,
            boundary_class=self.boundary_class,
            trust_level=self.trust_level,
            observation_outcome=self.observation_outcome,
        )
        return self

    @property
    def is_allowed(self) -> bool:
        return (
            self.receipt_kind == "mediated_decision"
            and self.boundary_class == "prevent"
            and self.observation_outcome is None
            and self.trust_level == "mediated"
            and self.verdict.is_allowed
        )

    @property
    def is_denied(self) -> bool:
        return self.verdict.is_denied


# ---------------------------------------------------------------------------
# HTTP substrate request/response
# ---------------------------------------------------------------------------


class ChioHttpRequest(BaseModel):
    """Normalized HTTP substrate request submitted to the Chio sidecar."""

    request_id: str
    method: str
    route_pattern: str
    path: str
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    caller: CallerIdentity
    body_hash: str | None = None
    body_length: int = 0
    session_id: str | None = None
    capability_id: str | None = None
    model_metadata: dict[str, Any] | None = None
    timestamp: int


class EvaluateResponse(BaseModel):
    """Sidecar response for HTTP request evaluation."""

    verdict: Verdict
    receipt: HttpReceipt
    evidence: list[_GuardEvidenceMinimal] = Field(default_factory=list)


class VerifyReceiptResponse(BaseModel):
    """Structured authority result returned by /chio/verify."""

    signature_valid: bool
    signer_trusted: bool
    receipt_id_valid: bool
    parameter_hash_valid: bool
    receipt_kind: str
    boundary_class: str
    trust_level: str
    result: str
    authorized: bool
    signer_key_hex: str
    ok: bool

    @staticmethod
    def _receipt_allows(receipt: Any) -> bool:
        is_allowed = getattr(receipt, "is_allowed", None)
        if isinstance(is_allowed, bool):
            return is_allowed

        verdict = getattr(receipt, "verdict", None)
        verdict_allowed = getattr(verdict, "is_allowed", None)
        if isinstance(verdict_allowed, bool):
            return verdict_allowed
        if getattr(verdict, "verdict", None) == "allow":
            return True

        decision = getattr(receipt, "decision", None)
        decision_root = getattr(decision, "root", decision)
        return getattr(decision_root, "verdict", None) == "allow"

    def authorizes(self, receipt: Any) -> bool:
        if not (
            self.ok
            and self.authorized
            and self.signature_valid
            and self.signer_trusted
            and self.receipt_id_valid
            and self.parameter_hash_valid
        ):
            return False
        return (
            self._receipt_allows(receipt)
            and self.receipt_kind == "mediated_decision"
            and self.boundary_class == "prevent"
            and self.trust_level == "mediated"
            and self.result == "allow"
        )


# ---------------------------------------------------------------------------
# Capability Token Body (convenience wrapper)
# ---------------------------------------------------------------------------


class CapabilityTokenBody(BaseModel):
    """The body of a capability token (everything except the signature)."""

    id: str
    issuer: str  # hex-encoded Ed25519 public key
    subject: str  # hex-encoded Ed25519 public key
    scope: Any  # ChioScope from _generated.capability
    issued_at: int
    expires_at: int
    delegation_chain: list[Any] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Passthrough
# ---------------------------------------------------------------------------


class ChioPassthrough(BaseModel):
    """Explicit fail-open degraded state where no Chio receipt exists."""

    mode: str
    error: str
    message: str
