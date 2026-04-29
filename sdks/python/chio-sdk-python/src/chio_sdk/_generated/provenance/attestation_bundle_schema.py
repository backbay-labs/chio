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


class EvidenceClass(Enum):
    """
    Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.
    """

    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class Tier(Enum):
    """
    Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).
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
    Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.
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


class Statement(BaseModel):
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
        description="Normalized assurance tier resolved from the evidence. Mirrors `RuntimeAssuranceTier` in capability.rs (lines 234-240).",
    )
    issued_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when this attestation was issued."
    )
    expires_at: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) when this attestation expires. Bundle assembly fails closed when `assembledAt < issued_at` or `assembledAt >= expires_at`.",
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
        description="Optional normalized workload identity when the upstream verifier exposed one explicitly. Mirrors `WorkloadIdentity` in capability.rs (lines 290-304) which uses `serde(rename_all = camelCase)`. Omitted when the upstream verifier did not expose a typed workload identity. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/workload_identity`.",
    )
    claims: Any | None = Field(
        None,
        description="Optional structured claims preserved for adapters or operator inspection. Verifier-family-specific (for example `claims.azureMaa`, `claims.awsNitro`, `claims.googleAttestation`) and validated by per-vendor bridges, not by this schema. Omitted when the verifier did not expose preserved claims. Identical in shape to `chio-wire/v1/trust-control/attestation.schema.json#/properties/claims`.",
    )


class ChioProvenanceAttestationBundle(BaseModel):
    """
    One bundle of corroborating runtime attestation evidence statements that anchor a governed call-chain context to a verified runtime. Names the `chainId` it binds to (matching `provenance/context.schema.json`), the canonical evidence-class Chio resolved across the bundle, the unix-second `assembledAt` timestamp, and the ordered list of normalized statements. Each statement mirrors the `RuntimeAttestationEvidence` shape and is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json`; the family is inlined rather than `$ref`'d. Field names are camelCase to match `GovernedCallChainContext`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this bundle attests. Matches the `chainId` carried by `provenance/context.schema.json`.",
    )
    evidenceClass: EvidenceClass = Field(
        ...,
        description="Canonical evidence class Chio resolved across the bundle as a whole. Mirrors `GovernedProvenanceEvidenceClass` in `crates/chio-core-types/src/capability.rs` (lines 1303-1314), which uses `serde(rename_all = snake_case)`. The bundle's class is the floor across its statements: a single `asserted` statement holds the bundle to `asserted` regardless of how many `verified` statements accompany it.",
    )
    assembledAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the bundle was assembled. Used to bound bundle freshness and to establish ordering with respect to receipts emitted from the same kernel.",
    )
    statements: list[Statement] = Field(
        ...,
        description="Ordered list of normalized runtime attestation evidence statements. Each statement is structurally identical to `chio-wire/v1/trust-control/attestation.schema.json` and mirrors `RuntimeAttestationEvidence` in `crates/chio-core-types/src/capability.rs` (lines 484-507). The struct does not carry `serde(rename_all)`, so the per-statement scalar fields are snake_case; the embedded `workload_identity` carries `serde(rename_all = camelCase)` so its inner fields are camelCase. Optional fields (`runtime_identity`, `workload_identity`, `claims`) are omitted from the wire when their underlying `Option<...>` is `None`.",
        min_length=1,
    )
    issuer: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the bundle assembler (kernel, gateway, or trust-control authority). Omitted when the bundle is locally assembled by the receiving kernel.",
    )
