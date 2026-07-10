# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: 9d7b17b15b33f7dcc9d52da37c9fb906c57911cdfd78424c344f5ce58b160468
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, constr


class ChioProvenanceCallChainContext(BaseModel):
    """
    One delegated call-chain context bound into a governed Chio request. The context names the stable `chainId` that identifies the delegated transaction, the upstream `parentRequestId` inside the trusted domain, the optional `parentReceiptId` when the upstream parent receipt is already available, the root `originSubject` that started the chain, and the immediate `delegatorSubject` that handed control to the current subject. Chio binds this shape into governed transactions and promotes it through the provenance evidence classes (`asserted`, `observed`, `verified`) defined in `crates/core/chio-core-types` (`GovernedProvenanceEvidenceClass`). Mirrors the `GovernedCallChainContext` struct in `crates/core/chio-core-types`. The struct uses `serde(rename_all = camelCase)` so wire field names are camelCase.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    chainId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier for the delegated transaction or call chain. Constant for the duration of the chain; bound into every receipt the chain produces.",
    )
    parentRequestId: constr(min_length=1) = Field(
        ...,
        description="Upstream parent request identifier inside the trusted domain. Used to thread the call into the upstream session lineage.",
    )
    parentReceiptId: constr(min_length=1) | None = Field(
        None,
        description="Optional upstream parent receipt identifier when the parent receipt is already available. Omitted via `serde(skip_serializing_if = Option::is_none)` when absent. When present, Chio can promote the context from `asserted` to `observed` or `verified` by matching it against `LocalParentReceiptLinkage` evidence.",
    )
    originSubject: constr(min_length=1) = Field(
        ...,
        description="Root or originating subject for the governed chain (the subject that started the delegation, expressed in the same canonical form as capability subject keys).",
    )
    delegatorSubject: constr(min_length=1) = Field(
        ...,
        description="Immediate delegator subject that handed control to the current subject. Distinct from `originSubject` for chains longer than one hop.",
    )
