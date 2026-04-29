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
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint, constr


class TrustLevel(Enum):
    """
    Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.
    """

    mediated = "mediated"
    verified = "verified"
    advisory = "advisory"


class Algorithm(Enum):
    """
    Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
    """

    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"


class ToolCallAction(BaseModel):
    """
    Describes the tool call that was evaluated. Mirrors `ToolCallAction`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    parameters: Any = Field(
        ...,
        description="The parameters that were passed to the tool (or attempted). Free-form JSON value (mirrors `serde_json::Value`).",
    )
    parameter_hash: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ..., description="SHA-256 hex hash of the canonical JSON of `parameters`."
    )


class Decision1(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["allow"]


class Decision2(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["deny"]
    reason: str = Field(..., description="Human-readable reason for the denial.")
    guard: str = Field(
        ..., description="The guard or validation step that triggered the denial."
    )


class Decision3(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["cancelled"]
    reason: str = Field(..., description="Human-readable reason for the cancellation.")


class Decision4(BaseModel):
    """
    The Kernel's verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    verdict: Literal["incomplete"]
    reason: str = Field(
        ..., description="Human-readable reason for the incomplete terminal state."
    )


class Decision(RootModel[Decision1 | Decision2 | Decision3 | Decision4]):
    root: Decision1 | Decision2 | Decision3 | Decision4 = Field(
        ...,
        description='The Kernel\'s verdict on the tool call. Internally tagged enum mirroring `Decision` in `chio-core-types` (`#[serde(tag = "verdict", rename_all = "snake_case")]`).',
    )


class GuardEvidence(BaseModel):
    """
    Evidence from a single guard's evaluation. Mirrors `GuardEvidence`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    guard_name: constr(min_length=1) = Field(
        ..., description="Name of the guard (e.g. `ForbiddenPathGuard`)."
    )
    verdict: bool = Field(
        ..., description="Whether the guard passed (true) or denied (false)."
    )
    details: str | None = Field(
        None, description="Optional details about the guard's decision."
    )


class ChioReceiptRecord(BaseModel):
    """
    A signed Chio receipt: proof that a tool call was evaluated by the Kernel. Mirrors the serde shape of `ChioReceipt` in `crates/chio-core-types/src/receipt.rs`. The `signature` field covers the canonical JSON of `ChioReceiptBody` (every field below except `algorithm` and `signature`). The `algorithm` envelope field is informational (verification dispatches off the self-describing hex prefix on the signature itself) and is omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Optional fields (`evidence`, `metadata`, `trust_level`, `tenant_id`, `algorithm`) are skipped on the wire when set to their default or unset values.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(min_length=1) = Field(
        ..., description="Unique receipt ID. UUIDv7 recommended."
    )
    timestamp: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when the receipt was created."
    )
    capability_id: constr(min_length=1) = Field(
        ..., description="ID of the capability token that was exercised (or presented)."
    )
    tool_server: constr(min_length=1) = Field(
        ..., description="Tool server that handled the invocation."
    )
    tool_name: constr(min_length=1) = Field(
        ..., description="Tool that was invoked (or attempted)."
    )
    action: ToolCallAction
    decision: Decision
    content_hash: constr(pattern=r"^[0-9a-f]{64}$") = Field(
        ..., description="SHA-256 hex hash of the evaluated content for this receipt."
    )
    policy_hash: constr(min_length=1) = Field(
        ...,
        description="SHA-256 hash (or symbolic identifier) of the policy that was applied. Mirrors the `String` shape on `ChioReceipt::policy_hash` rather than enforcing a hex pattern, since some deployments embed a symbolic version id (e.g. `policy-bindings-v1`) rather than a raw digest.",
    )
    evidence: list[GuardEvidence] | None = Field(
        None,
        description='Per-guard evidence collected during evaluation. Omitted from the wire when empty (matches `#[serde(skip_serializing_if = "Vec::is_empty")]`).',
    )
    metadata: Any | None = Field(
        None,
        description="Optional receipt metadata for stream/accounting/financial details. Schema-less by design (mirrors `Option<serde_json::Value>`).",
    )
    trust_level: TrustLevel | None = Field(
        None,
        description="Strength of kernel mediation that produced this receipt. Defaults to `mediated`. Older receipts that omit this field deserialize to `mediated` for backward compatibility.",
    )
    tenant_id: constr(min_length=1) | None = Field(
        None,
        description="Phase 1.5 multi-tenant receipt isolation: tenant identifier for multi-tenant deployments. Absent in single-tenant mode; derived from the authenticated session's enterprise identity context, never from caller-provided request fields. Omitted from the wire when unset so single-tenant receipts remain byte-identical.",
    )
    kernel_key: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
    ) = Field(
        ...,
        description="Kernel public key (for verification without out-of-band lookup). Bare 64-char lowercase hex string for Ed25519, `p256:<130-char hex>` for uncompressed SEC1 P-256 (65 bytes; leading byte `0x04`), or `p384:<194-char hex>` for uncompressed SEC1 P-384 (97 bytes; leading byte `0x04`). Anything outside these length classes is rejected at decode time by `PublicKey::from_hex` in `crates/chio-core-types/src/crypto.rs`.",
    )
    algorithm: Algorithm | None = Field(
        None,
        description="Signing algorithm envelope hint. Omitted for legacy Ed25519 receipts to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
    )
    signature: constr(pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$") = (
        Field(
            ...,
            description="Hex-encoded signature over the canonical JSON of the receipt body. Bare 128-char lowercase hex for Ed25519 (`Signature::from_hex` in `crates/chio-core-types/src/crypto.rs` requires exactly 64 bytes for the bare path), or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
        )
    )
