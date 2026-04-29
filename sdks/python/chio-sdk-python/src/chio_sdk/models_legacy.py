# chio-deprecation: this hand-typed module is preserved for one release
# cycle so adapter authors can grep for unported usage. New code should
# import the generated Pydantic models from `chio_sdk._generated` (produced
# by `cargo xtask codegen --lang python`).
"""Hand-typed Python models mirroring Chio core Rust types (LEGACY).

The 17 framework adapters under sdks/python/chio-* re-export from
``chio_sdk.models``, which currently re-exports from this module so the
classmethod surface (``Decision.allow()``, ``AuthMethod.bearer()``,
``ChioScope.is_subset_of`` etc.) and the convenience helpers stay backward
compatible while the generated bindings under ``chio_sdk._generated`` settle.

All models use Pydantic v2 for validation and serialization. Field names and
serde tags match the canonical JSON representation used by the Rust kernel so
that payloads are byte-compatible across languages.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Primitive enums
# ---------------------------------------------------------------------------


class Operation(str, enum.Enum):
    """Allowed operation on a tool, resource, or prompt grant."""

    INVOKE = "invoke"
    READ_RESULT = "read_result"
    READ = "read"
    SUBSCRIBE = "subscribe"
    GET = "get"
    DELEGATE = "delegate"

    @classmethod
    def _missing_(cls, value: object) -> Operation | None:
        if isinstance(value, str):
            legacy_alias = {
                "Invoke": cls.INVOKE,
                "ReadResult": cls.READ_RESULT,
                "Read": cls.READ,
                "Subscribe": cls.SUBSCRIBE,
                "Get": cls.GET,
                "Delegate": cls.DELEGATE,
            }.get(value)
            if legacy_alias is not None:
                return legacy_alias
        return None


class RuntimeAssuranceTier(str, enum.Enum):
    """Runtime attestation assurance tier."""

    NONE = "none"
    BASIC = "basic"
    ATTESTED = "attested"
    VERIFIED = "verified"


class GovernedAutonomyTier(str, enum.Enum):
    """Governed autonomy tier for economically sensitive actions."""

    DIRECT = "direct"
    DELEGATED = "delegated"
    AUTONOMOUS = "autonomous"


# ---------------------------------------------------------------------------
# Monetary
# ---------------------------------------------------------------------------


class MonetaryAmount(BaseModel):
    """Minor-unit monetary amount (e.g. cents for USD)."""

    units: int
    currency: str


# ---------------------------------------------------------------------------
# Constraints
# ---------------------------------------------------------------------------


class Constraint(BaseModel):
    """A constraint on tool parameters.

    Uses a tagged union matching the Rust ``#[serde(tag = "type", content = "value")]``
    representation.
    """

    type: str
    value: Any | None = None

    @classmethod
    def path_prefix(cls, prefix: str) -> Constraint:
        return cls(type="path_prefix", value=prefix)

    @classmethod
    def domain_exact(cls, domain: str) -> Constraint:
        return cls(type="domain_exact", value=domain)

    @classmethod
    def domain_glob(cls, pattern: str) -> Constraint:
        return cls(type="domain_glob", value=pattern)

    @classmethod
    def regex_match(cls, pattern: str) -> Constraint:
        return cls(type="regex_match", value=pattern)

    @classmethod
    def max_length(cls, length: int) -> Constraint:
        return cls(type="max_length", value=length)

    @classmethod
    def governed_intent_required(cls) -> Constraint:
        return cls(type="governed_intent_required", value=None)


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------


class ToolGrant(BaseModel):
    """Authorization for a single tool on a single server."""

    server_id: str
    tool_name: str
    operations: list[Operation]
    constraints: list[Constraint] = Field(default_factory=list)
    max_invocations: int | None = None
    max_cost_per_invocation: MonetaryAmount | None = None
    max_total_cost: MonetaryAmount | None = None
    dpop_required: bool | None = None

    def is_subset_of(self, parent: ToolGrant) -> bool:
        """Check whether this grant is a subset of ``parent``."""
        if parent.server_id != "*" and self.server_id != parent.server_id:
            return False
        if parent.tool_name != "*" and self.tool_name != parent.tool_name:
            return False
        if not all(op in parent.operations for op in self.operations):
            return False
        if parent.max_invocations is not None:
            if self.max_invocations is None or self.max_invocations > parent.max_invocations:
                return False
        if not all(pc in self.constraints for pc in parent.constraints):
            return False
        if parent.max_cost_per_invocation is not None:
            if (
                self.max_cost_per_invocation is None
                or self.max_cost_per_invocation.currency != parent.max_cost_per_invocation.currency
                or self.max_cost_per_invocation.units > parent.max_cost_per_invocation.units
            ):
                return False
        if parent.max_total_cost is not None:
            if (
                self.max_total_cost is None
                or self.max_total_cost.currency != parent.max_total_cost.currency
                or self.max_total_cost.units > parent.max_total_cost.units
            ):
                return False
        if parent.dpop_required is True and self.dpop_required is not True:
            return False
        return True


class ResourceGrant(BaseModel):
    """Authorization for reading or subscribing to a resource."""

    uri_pattern: str
    operations: list[Operation]

    def is_subset_of(self, parent: ResourceGrant) -> bool:
        if parent.uri_pattern != "*" and self.uri_pattern != parent.uri_pattern:
            return False
        return all(op in parent.operations for op in self.operations)


class PromptGrant(BaseModel):
    """Authorization for retrieving a prompt by name."""

    prompt_name: str
    operations: list[Operation]

    def is_subset_of(self, parent: PromptGrant) -> bool:
        if parent.prompt_name != "*" and self.prompt_name != parent.prompt_name:
            return False
        return all(op in parent.operations for op in self.operations)


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


class ChioScope(BaseModel):
    """What a capability token authorizes."""

    grants: list[ToolGrant] = Field(default_factory=list)
    resource_grants: list[ResourceGrant] = Field(default_factory=list)
    prompt_grants: list[PromptGrant] = Field(default_factory=list)

    def is_subset_of(self, other: ChioScope) -> bool:
        grants_ok = all(
            any(g.is_subset_of(pg) for pg in other.grants)
            for g in self.grants
        )
        resources_ok = all(
            any(g.is_subset_of(pg) for pg in other.resource_grants)
            for g in self.resource_grants
        )
        prompts_ok = all(
            any(g.is_subset_of(pg) for pg in other.prompt_grants)
            for g in self.prompt_grants
        )
        return grants_ok and resources_ok and prompts_ok


# ---------------------------------------------------------------------------
# Attenuation / Delegation
# ---------------------------------------------------------------------------


class Attenuation(BaseModel):
    """Describes how a scope was narrowed during delegation.

    Tagged union with ``type`` discriminator matching Rust serde representation.
    """

    type: str
    server_id: str | None = None
    tool_name: str | None = None
    operation: Operation | None = None
    constraint: Constraint | None = None
    max_invocations: int | None = None

    @classmethod
    def remove_tool(cls, server_id: str, tool_name: str) -> Attenuation:
        return cls(type="remove_tool", server_id=server_id, tool_name=tool_name)

    @classmethod
    def remove_operation(
        cls, server_id: str, tool_name: str, operation: Operation
    ) -> Attenuation:
        return cls(
            type="remove_operation",
            server_id=server_id,
            tool_name=tool_name,
            operation=operation,
        )

    @classmethod
    def add_constraint(
        cls, server_id: str, tool_name: str, constraint: Constraint
    ) -> Attenuation:
        return cls(
            type="add_constraint",
            server_id=server_id,
            tool_name=tool_name,
            constraint=constraint,
        )


class DelegationLink(BaseModel):
    """A link in the delegation chain."""

    capability_id: str
    delegator: str  # hex-encoded Ed25519 public key
    delegatee: str  # hex-encoded Ed25519 public key
    attenuations: list[Attenuation] = Field(default_factory=list)
    timestamp: int
    signature: str  # hex-encoded Ed25519 signature


# ---------------------------------------------------------------------------
# Capability Token
# ---------------------------------------------------------------------------


class CapabilityTokenBody(BaseModel):
    """The body of a capability token (everything except the signature)."""

    id: str
    issuer: str  # hex-encoded Ed25519 public key
    subject: str  # hex-encoded Ed25519 public key
    scope: ChioScope
    issued_at: int
    expires_at: int
    delegation_chain: list[DelegationLink] = Field(default_factory=list)


class CapabilityToken(BaseModel):
    """Ed25519-signed, scoped, time-bounded capability token."""

    id: str
    issuer: str
    subject: str
    scope: ChioScope
    issued_at: int
    expires_at: int
    delegation_chain: list[DelegationLink] = Field(default_factory=list)
    signature: str

    def body(self) -> CapabilityTokenBody:
        """Extract the body (everything except the signature)."""
        return CapabilityTokenBody(
            id=self.id,
            issuer=self.issuer,
            subject=self.subject,
            scope=self.scope,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            delegation_chain=self.delegation_chain,
        )

    def is_expired_at(self, now: int) -> bool:
        """Check whether the token has expired at the given unix timestamp."""
        return now >= self.expires_at

    def is_valid_at(self, now: int) -> bool:
        """Check whether the token is valid at the given unix timestamp."""
        return now >= self.issued_at and now < self.expires_at


# ---------------------------------------------------------------------------
# Decision / Verdict
# ---------------------------------------------------------------------------


class Decision(BaseModel):
    """The kernel's verdict on a tool call.

    Uses a tagged union with ``verdict`` discriminator matching the Rust
    ``#[serde(tag = "verdict", rename_all = "snake_case")]`` representation.
    """

    verdict: str  # "allow", "deny", "cancelled", "incomplete"
    reason: str | None = None
    guard: str | None = None

    @classmethod
    def allow(cls) -> Decision:
        return cls(verdict="allow")

    @classmethod
    def deny(cls, reason: str, guard: str) -> Decision:
        return cls(verdict="deny", reason=reason, guard=guard)

    @classmethod
    def cancelled(cls, reason: str) -> Decision:
        return cls(verdict="cancelled", reason=reason)

    @classmethod
    def incomplete(cls, reason: str) -> Decision:
        return cls(verdict="incomplete", reason=reason)

    @property
    def is_allowed(self) -> bool:
        return self.verdict == "allow"

    @property
    def is_denied(self) -> bool:
        return self.verdict == "deny"


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

    def to_decision(self) -> Decision:
        """Convert to core Decision type."""
        if self.verdict == "allow":
            return Decision.allow()
        if self.verdict == "deny":
            return Decision.deny(
                reason=self.reason or "",
                guard=self.guard or "",
            )
        if self.verdict == "cancel":
            return Decision.cancelled(reason=self.reason or "")
        return Decision.incomplete(reason=self.reason or "")


# ---------------------------------------------------------------------------
# Guard Evidence
# ---------------------------------------------------------------------------


class GuardEvidence(BaseModel):
    """Evidence from a single guard's evaluation."""

    guard_name: str
    verdict: bool
    details: str | None = None


# ---------------------------------------------------------------------------
# Tool Call Action
# ---------------------------------------------------------------------------


class ToolCallAction(BaseModel):
    """Describes the tool call that was evaluated."""

    parameters: dict[str, Any] = Field(default_factory=dict)
    parameter_hash: str


# ---------------------------------------------------------------------------
# Chio Receipt
# ---------------------------------------------------------------------------


class ChioReceipt(BaseModel):
    """Signed proof that a tool call was evaluated by the kernel."""

    id: str
    timestamp: int
    capability_id: str
    tool_server: str
    tool_name: str
    action: ToolCallAction
    decision: Decision
    content_hash: str
    policy_hash: str
    evidence: list[GuardEvidence] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None
    kernel_key: str  # hex-encoded Ed25519 public key
    signature: str  # hex-encoded Ed25519 signature

    @property
    def is_allowed(self) -> bool:
        return self.decision.is_allowed

    @property
    def is_denied(self) -> bool:
        return self.decision.is_denied


# ---------------------------------------------------------------------------
# HTTP Receipt
# ---------------------------------------------------------------------------


class HttpReceipt(BaseModel):
    """Signed receipt for an HTTP request evaluation."""

    id: str
    request_id: str
    route_pattern: str
    method: str
    caller_identity_hash: str
    session_id: str | None = None
    verdict: Verdict
    evidence: list[GuardEvidence] = Field(default_factory=list)
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

    @property
    def is_allowed(self) -> bool:
        return self.verdict.is_allowed

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
    evidence: list[GuardEvidence] = Field(default_factory=list)


class ChioPassthrough(BaseModel):
    """Explicit fail-open degraded state where no Chio receipt exists."""

    mode: str
    error: str
    message: str


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
