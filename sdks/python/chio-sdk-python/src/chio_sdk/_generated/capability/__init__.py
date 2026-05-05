# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 168c92102b530411f244aeff273362ff27544e7ce7b3c6623f51c9ecb4d58e62
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.

from __future__ import annotations

from .capabilities_schema import ChioCapabilityNegotiationV1, MaxCapabilitySchema
from .grant_schema import ChioCapabilityGrant
from .revocation_schema import ChioCapabilityRevocationEntry
from .token_schema import ChioCapabilitytoken
from .token_v1_schema import ChioCapabilitytokenV1
from .token_v2_schema import AttenuationProof, AttenuationWitness, Caveat, ChioCapabilitytokenV2, GrantKind, GrantSubsetRelation, Kind, ScopeAttenuation

__all__ = [
    "AttenuationProof",
    "AttenuationWitness",
    "Caveat",
    "ChioCapabilityGrant",
    "ChioCapabilityNegotiationV1",
    "ChioCapabilityRevocationEntry",
    "ChioCapabilitytoken",
    "ChioCapabilitytokenV1",
    "ChioCapabilitytokenV2",
    "GrantKind",
    "GrantSubsetRelation",
    "Kind",
    "MaxCapabilitySchema",
    "ScopeAttenuation",
]
