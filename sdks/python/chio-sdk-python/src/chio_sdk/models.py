# Public Pydantic v2 surface for chio-sdk-python.
#
# This module re-exports the legacy hand-typed surface from
# ``chio_sdk.models_legacy`` so the 17 framework adapters under sdks/python/*
# (which import from ``chio_sdk.models``) keep working unchanged while the
# generated Pydantic bindings under ``chio_sdk._generated`` settle. The
# generated module is also re-exported as ``chio_sdk.models.generated`` so
# new consumers can opt in to the schema-derived types directly.
#
# House rules: no em dashes (U+2014); use `-` or parentheses.
"""Typed Python models mirroring Chio core Rust types.

Compatibility shim re-exporting from :mod:`chio_sdk.models_legacy`. The
generated Pydantic-v2 modules under :mod:`chio_sdk._generated` are
authoritative for wire shape; this module preserves the convenience surface
(classmethods, subset checks) until adapter call-sites migrate.
"""

from __future__ import annotations

from chio_sdk import _generated
from chio_sdk._generated import SCHEMA_SHA256
from chio_sdk.models_legacy import (
    Attenuation,
    AuthMethod,
    CallerIdentity,
    CapabilityToken,
    CapabilityTokenBody,
    ChioHttpRequest,
    ChioPassthrough,
    ChioReceipt,
    ChioScope,
    Constraint,
    Decision,
    DelegationLink,
    EvaluateResponse,
    GovernedAutonomyTier,
    GuardEvidence,
    HttpReceipt,
    MonetaryAmount,
    Operation,
    PromptGrant,
    ResourceGrant,
    RuntimeAssuranceTier,
    ToolCallAction,
    ToolGrant,
    Verdict,
)

# `generated` is the namespace under which the schema-derived Pydantic v2
# types live. Subpackages mirror `spec/schemas/chio-wire/v1/` (agent/,
# capability/, error/, jsonrpc/, kernel/, provenance/, receipt/, result/,
# trust_control/). Example:
#     from chio_sdk.models import generated
#     token = generated.capability.token_schema.CapabilityToken(...)
generated = _generated

__all__ = [
    # Schema pin (re-exported from `_generated`)
    "SCHEMA_SHA256",
    "generated",
    # Legacy hand-typed surface
    "Attenuation",
    "AuthMethod",
    "CallerIdentity",
    "CapabilityToken",
    "CapabilityTokenBody",
    "ChioHttpRequest",
    "ChioPassthrough",
    "ChioReceipt",
    "ChioScope",
    "Constraint",
    "Decision",
    "DelegationLink",
    "EvaluateResponse",
    "GovernedAutonomyTier",
    "GuardEvidence",
    "HttpReceipt",
    "MonetaryAmount",
    "Operation",
    "PromptGrant",
    "ResourceGrant",
    "RuntimeAssuranceTier",
    "ToolCallAction",
    "ToolGrant",
    "Verdict",
]
