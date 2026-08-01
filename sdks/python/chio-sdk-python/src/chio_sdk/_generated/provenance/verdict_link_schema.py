# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 27975bf17d3c195d530b2e28ac498870376a2aeb649e8b3126f61b882beedf84
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr, model_validator


class Verdict(Enum):
    """
    Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.
    """

    allow = "allow"
    deny = "deny"
    cancel = "cancel"
    incomplete = "incomplete"


class EvidenceClass(Enum):
    """
    Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.
    """

    asserted = "asserted"
    observed = "observed"
    verified = "verified"


class ChioProvenanceVerdictLink1(BaseModel):
    """
    Allow verdicts MUST NOT carry `reason` or `guard`; the policy engine emits these fields only on rejection.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["allow"] = Field(
        ...,
        description="Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
    )
    requestId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.",
    )
    receiptId: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
    )
    renderedAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
    )
    reason: str | None = Field(
        None,
        description="Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
    )
    guard: str | None = Field(
        None,
        description="Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
    )
    evidenceClass: EvidenceClass | None = Field(
        None,
        description="Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.",
    )

    @model_validator(mode="after")
    def _allow_excludes_rejection_fields(self) -> "ChioProvenanceVerdictLink1":
        if "reason" in self.model_fields_set or "guard" in self.model_fields_set:
            raise ValueError("allow verdict must not include reason or guard")
        return self


class ChioProvenanceVerdictLink2(BaseModel):
    """
    Deny verdicts MUST carry both a human-readable `reason` and the `guard` identifier that produced the denial. Mirrors the deny branch of `chio-http/v1/verdict.schema.json`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["deny"] = Field(
        ...,
        description="Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
    )
    requestId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.",
    )
    receiptId: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
    )
    renderedAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
    )
    reason: str = Field(
        ...,
        description="Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
    )
    guard: str = Field(
        ...,
        description="Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
    )
    evidenceClass: EvidenceClass | None = Field(
        None,
        description="Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.",
    )


class ChioProvenanceVerdictLink3(BaseModel):
    """
    Cancel verdicts MUST carry `reason` (operator or transport cancellation rationale) and MUST NOT carry `guard`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["cancel"] = Field(
        ...,
        description="Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
    )
    requestId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.",
    )
    receiptId: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
    )
    renderedAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
    )
    reason: str = Field(
        ...,
        description="Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
    )
    guard: str | None = Field(
        None,
        description="Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
    )
    evidenceClass: EvidenceClass | None = Field(
        None,
        description="Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.",
    )

    @model_validator(mode="after")
    def _cancel_excludes_guard(self) -> "ChioProvenanceVerdictLink3":
        if "guard" in self.model_fields_set:
            raise ValueError("cancel verdict must not include guard")
        return self


class ChioProvenanceVerdictLink4(BaseModel):
    """
    Incomplete verdicts MUST carry `reason` describing the terminal failure mode (for example interrupted upstream stream) and MUST NOT carry `guard`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["incomplete"] = Field(
        ...,
        description="Policy verdict decision Chio returned for the bound request. Vocabulary matches `spec/schemas/chio-http/v1/verdict.schema.json` and `StepVerdictKind` (Allowed, Denied) plus the cancel and incomplete terminal states defined under `spec/schemas/chio-wire/v1/result/`.",
    )
    requestId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the Chio request the verdict applies to. Threads the verdict into the request lineage carried by `RequestLineageMode` in `crates/core/chio-core-types`.",
    )
    receiptId: constr(min_length=1) | None = Field(
        None,
        description="Optional identifier of the Chio receipt the verdict was committed under. Omitted when the verdict was rendered before any receipt was minted (for example a pre-execution plan denial). When present, the receipt is the canonical artifact for downstream verification.",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier of the governed call chain this verdict ties back to. Matches the `chainId` carried by `provenance/context.schema.json` and `provenance/attestation-bundle.schema.json`.",
    )
    renderedAt: conint(ge=0) = Field(
        ...,
        description="Unix timestamp (seconds) at which the policy engine rendered this verdict. Monotonic with respect to receipts emitted from the same kernel.",
    )
    reason: str = Field(
        ...,
        description="Policy reason string. Required by the HTTP verdict union (and by this schema's `oneOf`) for `deny`, `cancel`, and `incomplete` verdicts. Forbidden for `allow`.",
    )
    guard: str | None = Field(
        None,
        description="Policy guard identifier that produced a `deny` verdict. Required by the HTTP verdict union (and by this schema's `oneOf`) when `verdict` is `deny`. Forbidden for non-deny verdicts.",
    )
    evidenceClass: EvidenceClass | None = Field(
        None,
        description="Optional provenance evidence class Chio resolved at the time the verdict was rendered. Mirrors `GovernedProvenanceEvidenceClass` in `crates/core/chio-core-types`. Omitted when the verdict was rendered without consulting the provenance graph.",
    )

    @model_validator(mode="after")
    def _incomplete_excludes_guard(self) -> "ChioProvenanceVerdictLink4":
        if "guard" in self.model_fields_set:
            raise ValueError("incomplete verdict must not include guard")
        return self


class ChioProvenanceVerdictLink(
    RootModel[
        ChioProvenanceVerdictLink1
        | ChioProvenanceVerdictLink2
        | ChioProvenanceVerdictLink3
        | ChioProvenanceVerdictLink4
    ]
):
    root: (
        ChioProvenanceVerdictLink1
        | ChioProvenanceVerdictLink2
        | ChioProvenanceVerdictLink3
        | ChioProvenanceVerdictLink4
    ) = Field(
        ...,
        description="One link binding a Chio policy verdict to the provenance graph. The link names the `verdict` decision that Chio's policy engine returned (`allow`, `deny`, `cancel`, `incomplete`), the `requestId` and optional `receiptId` the verdict applies to, and the `chainId` that ties the verdict back to a delegated call-chain context. Verdict-specific required fields are enforced via `oneOf` so the wire shape stays in lock-step with the HTTP verdict union in `spec/schemas/chio-http/v1/verdict.schema.json`: `deny` requires both `reason` and `guard`; `cancel` and `incomplete` require `reason`; `allow` rejects either. The verdict vocabulary mirrors the HTTP verdict tagged union. Field names are camelCase to match the governed call-chain context family this link binds to.",
        title="Chio Provenance Verdict Link",
    )
