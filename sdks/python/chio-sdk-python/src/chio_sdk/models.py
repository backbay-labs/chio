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
