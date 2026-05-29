# Public Pydantic v2 surface for chio-sdk-python.
#
# This module re-exports from ``chio_sdk._generated`` (the code-generated Pydantic
# bindings produced by ``cargo xtask codegen --lang python``) rather than
# hand-typed duplicates of those generated types.
#
# Importer call-sites (adapters, framework integrations, tests) continue to use the
# same names; where the generated module exports a type under a prefixed alias (e.g.
# ``CapabilityConstraint`` to avoid shadowing across subpackages) we re-alias it back
# to the bare expected name here.
#
# House rules: no em dashes (U+2014); use `-` or parentheses.
"""Typed Python models mirroring Chio core Rust types.

Re-exports from :mod:`chio_sdk._generated`. The generated Pydantic-v2 modules
under :mod:`chio_sdk._generated` are authoritative for wire shape; this module
preserves the convenience surface until adapter call-sites migrate to importing
directly from :mod:`chio_sdk._generated`.

Ten names (AuthMethod, CallerIdentity, CapabilityTokenBody, ChioHttpRequest,
ChioPassthrough, EvaluateResponse, GovernedAutonomyTier, HttpReceipt, Verdict,
VerifyReceiptResponse) have no confirmed generated equivalent and are still
sourced from :mod:`chio_sdk.models_supplemental`. See REPORT block at the bottom of
this file. Those names block full deletion of models_supplemental.
"""

from __future__ import annotations

from chio_sdk import _generated
from chio_sdk._generated import (
    # Direct name matches
    Attenuation,
    CapabilityToken,
    ChioScope,
    Decision,
    DelegationLink,
    GuardEvidence,
    MonetaryAmount,
    SCHEMA_SHA256,
    ToolCallAction,
    ToolGrant,
    # Prefixed aliases in _generated that we re-export under their original names
    CapabilityConstraint as Constraint,
    CapabilityOperation as Operation,
    CapabilityPromptGrant as PromptGrant,
    CapabilityResourceGrant as ResourceGrant,
    ChioReceiptRecord as ChioReceipt,
    TrustControlTier as RuntimeAssuranceTier,
)
from chio_sdk._generated.receipt.record_schema import Decision1, Decision2

# The following types have no confirmed generated equivalent and are preserved
# from models_supplemental. See the UNRESOLVED REPORT at the bottom of this file.
from chio_sdk.models_supplemental import (
    AuthMethod,
    CallerIdentity,
    CapabilityTokenBody,
    ChioHttpRequest,
    ChioPassthrough,
    EvaluateResponse,
    GovernedAutonomyTier,
    HttpReceipt,
    Verdict,
    VerifyReceiptResponse,
)

# `generated` is the namespace under which all schema-derived Pydantic v2
# types live. Subpackages mirror spec/schemas/chio-wire/v1/ (agent/, anchor/,
# capability/, error/, federation/, jsonrpc/, kernel/, provenance/, receipt/,
# result/, trust_control/). Example:
#     from chio_sdk.models import generated
#     token = generated.capability.token_schema.ChioCapabilitytoken(...)
generated = _generated


def _decision_allow(cls: type[Decision]) -> Decision:
    return cls(root=Decision1(verdict="allow"))


def _decision_deny(
    cls: type[Decision],
    reason: str,
    guard: str,
) -> Decision:
    return cls(root=Decision2(verdict="deny", reason=reason, guard=guard))


def _decision_verdict(self: Decision) -> str:
    return self.root.verdict


def _decision_reason(self: Decision) -> str | None:
    return getattr(self.root, "reason", None)


def _decision_guard(self: Decision) -> str | None:
    return getattr(self.root, "guard", None)


def _operation_set(operations: list[Operation]) -> set[str]:
    return {getattr(operation, "value", str(operation)) for operation in operations}


def _operation_missing(cls: type[Operation], value: object) -> Operation | None:
    legacy_names = {
        "Invoke": "invoke",
        "ReadResult": "read_result",
        "Read": "read",
        "Subscribe": "subscribe",
        "Get": "get",
        "Delegate": "delegate",
    }
    if isinstance(value, str):
        member_name = legacy_names.get(value, value)
        if hasattr(cls, member_name):
            return getattr(cls, member_name)
    return None


def _constraint_key(constraint: Constraint) -> str:
    return constraint.model_dump_json(exclude_none=True)


def _constraint_path_prefix(cls: type[Constraint], prefix: str) -> Constraint:
    return cls(type="path_prefix", value=prefix)


def _constraint_domain_exact(cls: type[Constraint], domain: str) -> Constraint:
    return cls(type="domain_exact", value=domain)


def _constraint_max_length(cls: type[Constraint], length: int) -> Constraint:
    return cls(type="max_length", value=length)


def _attenuation_remove_tool(
    cls: type[Attenuation],
    server_id: str,
    tool_name: str,
) -> Attenuation:
    return cls(type="remove_tool", server_id=server_id, tool_name=tool_name)


def _attenuation_add_constraint(
    cls: type[Attenuation],
    server_id: str,
    tool_name: str,
    constraint: Constraint,
) -> Attenuation:
    return cls(
        type="add_constraint",
        server_id=server_id,
        tool_name=tool_name,
        constraint=constraint,
    )


def _money_within(child: MonetaryAmount | None, parent: MonetaryAmount | None) -> bool:
    if parent is None:
        return True
    if child is None:
        return False
    return child.currency == parent.currency and child.units <= parent.units


def _optional_cap_within(child: int | None, parent: int | None) -> bool:
    if parent is None:
        return True
    return child is not None and child <= parent


def _pattern_allows(child: str, parent: str) -> bool:
    if parent == "*":
        return True
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    return child == parent


def _tool_grant_is_subset_of(self: ToolGrant, parent: ToolGrant) -> bool:
    if parent.server_id != "*" and self.server_id != parent.server_id:
        return False
    if parent.tool_name != "*" and self.tool_name != parent.tool_name:
        return False
    if not _operation_set(self.operations).issubset(_operation_set(parent.operations)):
        return False
    parent_constraints = {
        _constraint_key(constraint) for constraint in parent.constraints or []
    }
    child_constraints = {
        _constraint_key(constraint) for constraint in self.constraints or []
    }
    if not parent_constraints.issubset(child_constraints):
        return False
    if not _optional_cap_within(self.max_invocations, parent.max_invocations):
        return False
    if not _money_within(self.max_cost_per_invocation, parent.max_cost_per_invocation):
        return False
    if not _money_within(self.max_total_cost, parent.max_total_cost):
        return False
    if parent.dpop_required and not self.dpop_required:
        return False
    return True


def _resource_grant_is_subset_of(self: ResourceGrant, parent: ResourceGrant) -> bool:
    if not _pattern_allows(self.uri_pattern, parent.uri_pattern):
        return False
    return _operation_set(self.operations).issubset(_operation_set(parent.operations))


def _prompt_grant_is_subset_of(self: PromptGrant, parent: PromptGrant) -> bool:
    if not _pattern_allows(self.prompt_name, parent.prompt_name):
        return False
    return _operation_set(self.operations).issubset(_operation_set(parent.operations))


def _scope_is_subset_of(self: ChioScope, parent: ChioScope) -> bool:
    parent_tool_grants = parent.grants or []
    for grant in self.grants or []:
        if not any(
            grant.is_subset_of(parent_grant) for parent_grant in parent_tool_grants
        ):
            return False
    parent_resource_grants = parent.resource_grants or []
    for grant in self.resource_grants or []:
        if not any(
            grant.is_subset_of(parent_grant)
            for parent_grant in parent_resource_grants
        ):
            return False
    parent_prompt_grants = parent.prompt_grants or []
    for grant in self.prompt_grants or []:
        if not any(
            grant.is_subset_of(parent_grant)
            for parent_grant in parent_prompt_grants
        ):
            return False
    return True


def _token_is_valid_at(self: CapabilityToken, timestamp: int) -> bool:
    return self.issued_at <= timestamp < self.expires_at


def _token_is_expired_at(self: CapabilityToken, timestamp: int) -> bool:
    return timestamp >= self.expires_at


def _token_body(self: CapabilityToken) -> CapabilityTokenBody:
    return CapabilityTokenBody(
        id=self.id,
        issuer=self.issuer,
        subject=self.subject,
        scope=self.scope,
        issued_at=self.issued_at,
        expires_at=self.expires_at,
        delegation_chain=self.delegation_chain or [],
    )


def _receipt_is_allowed(self: ChioReceipt) -> bool:
    return bool(self.decision and self.decision.is_allowed)


def _receipt_is_denied(self: ChioReceipt) -> bool:
    return bool(self.decision and self.decision.is_denied)


Decision.allow = classmethod(_decision_allow)  # type: ignore[attr-defined]
Decision.deny = classmethod(_decision_deny)  # type: ignore[attr-defined]
Decision.verdict = property(_decision_verdict)  # type: ignore[attr-defined]
Decision.reason = property(_decision_reason)  # type: ignore[attr-defined]
Decision.guard = property(_decision_guard)  # type: ignore[attr-defined]
Decision.is_allowed = property(  # type: ignore[attr-defined]
    lambda self: self.root.verdict == "allow"
)
Decision.is_denied = property(  # type: ignore[attr-defined]
    lambda self: self.root.verdict == "deny"
)
ChioReceipt.is_allowed = property(_receipt_is_allowed)  # type: ignore[attr-defined]
ChioReceipt.is_denied = property(_receipt_is_denied)  # type: ignore[attr-defined]
ToolGrant.is_subset_of = _tool_grant_is_subset_of  # type: ignore[attr-defined]
ResourceGrant.is_subset_of = _resource_grant_is_subset_of  # type: ignore[attr-defined]
PromptGrant.is_subset_of = _prompt_grant_is_subset_of  # type: ignore[attr-defined]
ChioScope.is_subset_of = _scope_is_subset_of  # type: ignore[attr-defined]
CapabilityToken.is_valid_at = _token_is_valid_at  # type: ignore[attr-defined]
CapabilityToken.is_expired_at = _token_is_expired_at  # type: ignore[attr-defined]
CapabilityToken.body = _token_body  # type: ignore[attr-defined]
Operation._missing_ = classmethod(_operation_missing)  # type: ignore[attr-defined]
Constraint.path_prefix = classmethod(  # type: ignore[attr-defined]
    _constraint_path_prefix
)
Constraint.domain_exact = classmethod(  # type: ignore[attr-defined]
    _constraint_domain_exact
)
Constraint.max_length = classmethod(  # type: ignore[attr-defined]
    _constraint_max_length
)
Attenuation.remove_tool = classmethod(  # type: ignore[attr-defined]
    _attenuation_remove_tool
)
Attenuation.add_constraint = classmethod(  # type: ignore[attr-defined]
    _attenuation_add_constraint
)
for _operation_name in (
    "invoke",
    "read_result",
    "read",
    "subscribe",
    "get",
    "delegate",
):
    if hasattr(Operation, _operation_name):
        setattr(Operation, _operation_name.upper(), getattr(Operation, _operation_name))

__all__ = [
    # Schema pin (re-exported from `_generated`)
    "SCHEMA_SHA256",
    "generated",
    # Generated types (direct matches)
    "Attenuation",
    "CapabilityToken",
    "ChioReceipt",
    "ChioScope",
    "Constraint",
    "Decision",
    "DelegationLink",
    "GuardEvidence",
    "MonetaryAmount",
    "Operation",
    "PromptGrant",
    "ResourceGrant",
    "RuntimeAssuranceTier",
    "ToolCallAction",
    "ToolGrant",
    # Unresolved: still sourced from models_supplemental (see report below)
    "AuthMethod",
    "CallerIdentity",
    "CapabilityTokenBody",
    "ChioHttpRequest",
    "ChioPassthrough",
    "EvaluateResponse",
    "GovernedAutonomyTier",
    "HttpReceipt",
    "Verdict",
    "VerifyReceiptResponse",
]

# ---------------------------------------------------------------------------
# UNRESOLVED REPORT (for orchestrator)
#
# The following 10 names exported by this shim have NO confirmed generated
# equivalent in chio_sdk._generated as of schema sha256
# 303b50183ef215723ba3d2cf0370c6cb7ac7f08616ccf6cd5a76dc4214dcf730.
# They are still sourced from models_supplemental and BLOCK full deletion of that
# file:
#
#   1. AuthMethod         - HTTP authentication method tagged union; no
#                           generated counterpart found.
#   2. CallerIdentity     - Caller identity extracted from HTTP requests; no
#                           generated counterpart found.
#   3. CapabilityTokenBody - Convenience wrapper (token minus signature); no
#                           generated counterpart found.
#   4. ChioHttpRequest    - Normalized HTTP substrate request; no generated
#                           counterpart found.
#   5. ChioPassthrough    - Explicit fail-open degraded-state marker; no
#                           generated counterpart found.
#   6. EvaluateResponse   - Sidecar HTTP evaluation response; no generated
#                           counterpart found.
#   7. GovernedAutonomyTier - Autonomy tier enum (direct/delegated/autonomous);
#                           no generated counterpart found.
#   8. HttpReceipt        - Signed HTTP-layer receipt; no generated counterpart
#                           found (ChioReceiptRecord covers tool-call receipts
#                           only).
#   9. Verdict            - HTTP-layer verdict with http_status field; the
#                           generated FederationVerdict and ProvenanceVerdict
#                           are unrelated enums.
#  10. VerifyReceiptResponse - Structured /chio/verify authority result; no
#                           generated counterpart found.
# ---------------------------------------------------------------------------
