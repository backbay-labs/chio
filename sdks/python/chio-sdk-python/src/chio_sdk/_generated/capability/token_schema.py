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


class Algorithm(Enum):
    """
    Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.
    """

    ed25519 = "ed25519"
    p256 = "p256"
    p384 = "p384"


class Operation(Enum):
    invoke = "invoke"
    read_result = "read_result"
    read = "read"
    subscribe = "subscribe"
    get = "get"
    delegate = "delegate"


class MonetaryAmount(BaseModel):
    """
    A monetary amount in the currency's smallest minor unit (e.g. cents for USD). Mirrors `MonetaryAmount`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    units: conint(ge=0)
    currency: constr(min_length=1)


class Constraint(BaseModel):
    """
    Tagged enum mirroring `Constraint`. Encoded as `{ type, value }` (or `{ type }` for unit variants like `governed_intent_required`). The variant set is intentionally extensible per ADR-TYPE-EVOLUTION; this schema validates the discriminator only and lets downstream guards interpret the `value`.
    """

    type: constr(min_length=1)
    value: Any | None = None


class Attenuation(BaseModel):
    type: constr(min_length=1)


class DelegationLink(BaseModel):
    """
    A single link in a delegation chain. Mirrors `DelegationLink`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    capability_id: constr(min_length=1)
    delegator: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
    ) = Field(
        ...,
        description="Delegating public key. Same encoding as the token-level `issuer`/`subject`.",
    )
    delegatee: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
    ) = Field(
        ...,
        description="Receiving public key. Same encoding as the token-level `issuer`/`subject`.",
    )
    attenuations: list[Attenuation] | None = None
    timestamp: conint(ge=0)
    signature: constr(pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$") = (
        Field(
            ...,
            description="Delegation-link signature. Same encoding as the token-level `signature`.",
        )
    )


class ToolGrant(BaseModel):
    """
    Authorization to invoke a single tool. Mirrors `ToolGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    server_id: constr(min_length=1) = Field(
        ...,
        description="Tool server identifier from the manifest. Use `*` to match any server (only valid in parent grants for delegation).",
    )
    tool_name: constr(min_length=1) = Field(
        ...,
        description="Tool name on the server. Use `*` to match any tool (only valid in parent grants for delegation).",
    )
    operations: list[Operation] = Field(..., min_length=1)
    constraints: list[Constraint] | None = None
    max_invocations: conint(ge=0) | None = None
    max_cost_per_invocation: MonetaryAmount | None = None
    max_total_cost: MonetaryAmount | None = None
    dpop_required: bool | None = Field(
        None,
        description="If true, the kernel requires a valid DPoP proof for every invocation under this grant.",
    )


class ResourceGrant(BaseModel):
    """
    Authorization for reading or subscribing to a resource. Mirrors `ResourceGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    uri_pattern: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class PromptGrant(BaseModel):
    """
    Authorization for retrieving a prompt by name. Mirrors `PromptGrant`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    prompt_name: constr(min_length=1)
    operations: list[Operation] = Field(..., min_length=1)


class ChioScope(BaseModel):
    """
    What a capability token authorizes. Mirrors `ChioScope` in `chio-core-types`.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    grants: list[ToolGrant] | None = None
    resource_grants: list[ResourceGrant] | None = None
    prompt_grants: list[PromptGrant] | None = None


class ChioCapabilitytoken(BaseModel):
    """
    A Chio capability token: an Ed25519-signed (or FIPS-algorithm), scoped, time-bounded authorization to invoke a tool. Mirrors the serde shape of `CapabilityToken` in `crates/chio-core-types/src/capability.rs`. The `signature` field covers the canonical JSON of all other fields except `algorithm`. The `algorithm` envelope field is informational (verification dispatches off the signature hex prefix) and is omitted for legacy Ed25519 tokens. PublicKey serde renders Ed25519 keys as bare 64-character lowercase hex (`PublicKey::to_hex` in `crates/chio-core-types/src/crypto.rs`), and renders FIPS keys with a self-describing prefix (`p256:<130-char hex>` for uncompressed SEC1 P-256, `p384:<194-char hex>` for P-384). Signatures follow the same convention: bare 128-char hex for Ed25519, `p256:<DER hex>` and `p384:<DER hex>` for FIPS algorithms. The grant `$defs` (`toolGrant`, `resourceGrant`, `promptGrant`, `operation`, `monetaryAmount`, `constraint`) are duplicated with `capability/grant.schema.json` because the current Rust codegen pipeline (`typify =0.4.3`) does not support cross-file `$ref`; both copies must be kept byte-identical when either file is edited until the M01 phase 3 codegen split lands.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    id: constr(min_length=1) = Field(
        ..., description="Unique token ID (UUIDv7 recommended), used for revocation."
    )
    issuer: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
    ) = Field(
        ...,
        description="Public key of the Capability Authority (or delegating agent) that issued this token. Bare 64-char lowercase hex for Ed25519, or `p256:<130-char hex>` / `p384:<194-char hex>` for FIPS algorithms (uncompressed SEC1 encoding).",
    )
    subject: constr(
        pattern=r"^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$"
    ) = Field(
        ...,
        description="Public key of the agent this capability is bound to (DPoP sender constraint). Same encoding as `issuer`.",
    )
    scope: ChioScope
    issued_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when the token was issued."
    )
    expires_at: conint(ge=0) = Field(
        ..., description="Unix timestamp (seconds) when the token expires."
    )
    delegation_chain: list[DelegationLink] | None = Field(
        None,
        description="Ordered list of delegation links from the root authority to this token. Omitted (or empty) for direct issuances.",
    )
    algorithm: Algorithm | None = Field(
        None,
        description="Signing algorithm envelope hint. Omitted for legacy Ed25519 tokens to preserve byte-for-byte compatibility. Verification dispatches off the signature hex prefix, not this field.",
    )
    signature: constr(pattern=r"^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$") = (
        Field(
            ...,
            description="Hex-encoded signature over the canonical JSON of the token body. Bare 128-char hex for Ed25519, or `p256:<DER hex>` / `p384:<DER hex>` for FIPS algorithms. The DER-encoded ECDSA payload length varies (~70-72 bytes for P-256, ~104-110 bytes for P-384) so the FIPS hex bodies are matched as `[0-9a-f]+` and validated by length-aware decoders downstream.",
        )
    )
