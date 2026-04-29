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

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Tier(Enum):
    """
    Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.
    """

    none = "none"
    basic = "basic"
    attested = "attested"
    verified = "verified"


class Scheme(Enum):
    """
    Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).
    """

    spiffe = "spiffe"


class CredentialKind(Enum):
    """
    Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.
    """

    uri = "uri"
    x509_svid = "x509_svid"
    jwt_svid = "jwt_svid"


class WorkloadIdentity(BaseModel):
    """
    Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    scheme: Scheme = Field(
        ...,
        description="Identity scheme Chio recognized from the upstream evidence. Mirrors `WorkloadIdentityScheme` (lines 273-278).",
    )
    credentialKind: CredentialKind = Field(
        ...,
        description="Credential family that authenticated the workload. Mirrors `WorkloadCredentialKind` (lines 280-288) which uses `serde(rename_all = snake_case)`.",
    )
    uri: constr(min_length=1) = Field(
        ..., description="Canonical workload identifier URI."
    )
    trustDomain: constr(min_length=1) = Field(
        ..., description="Stable trust domain resolved from the identifier."
    )
    path: str = Field(
        ..., description="Canonical workload path within the trust domain."
    )


class ChioTrustControlRuntimeAttestationEvidence(BaseModel):
    """
    One normalized runtime attestation evidence statement carried alongside trust-control authority operations and governed capability issuance. The shape names the upstream attestation schema, the verifier or relying party that accepted the evidence, the normalized assurance tier Chio resolved, the evidence's issued-at and expires-at bounds, and a stable SHA-256 digest of the underlying attestation payload. Optional fields preserve a runtime or workload identifier and a normalized SPIFFE workload identity when the verifier exposed one. Mirrors the `RuntimeAttestationEvidence` struct in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so wire field names are snake_case. Verifier adapters and trust-control issuance call sites in `crates/chio-control-plane/src/attestation.rs` populate this shape after running the per-vendor verifier bridges (Azure MAA, AWS Nitro, Google Confidential VM).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    schema_: constr(min_length=1) = Field(
        ...,
        alias="schema",
        description="Schema or format identifier of the upstream attestation statement (for example `azure-maa-jwt`, `aws-nitro-cose-sign1`, `google-confidential-vm-jwt`).",
    )
    verifier: constr(min_length=1) = Field(
        ...,
        description="Attestation verifier or relying party that accepted the evidence.",
    )
    tier: Tier = Field(
        ...,
        description="Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240) which uses `serde(rename_all = snake_case)`.",
    )
    issued_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when this attestation was issued."
    )
    expires_at: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) when this attestation expires. Trust-control fails closed when `now < issued_at` or `now >= expires_at`.",
    )
    evidence_sha256: constr(min_length=1) = Field(
        ...,
        description="Stable SHA-256 digest of the attestation evidence payload. Used as the binding identifier for receipts and for sender-constrained continuity proofs.",
    )
    runtime_identity: constr(min_length=1) | None = Field(
        None,
        description="Optional runtime or workload identifier associated with the evidence. SPIFFE URIs are normalized into `workload_identity`; non-SPIFFE values are preserved as opaque verifier metadata. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent.",
    )
    workload_identity: WorkloadIdentity | None = Field(
        None,
        description="Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity.",
    )
    claims: Any | None = Field(
        None,
        description="Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims.",
    )
