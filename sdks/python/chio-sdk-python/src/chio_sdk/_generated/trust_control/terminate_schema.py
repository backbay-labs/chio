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

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class Reason(Enum):
    """
    Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.
    """

    leader_handoff = "leader_handoff"
    quorum_lost = "quorum_lost"
    operator_stepdown = "operator_stepdown"
    term_advanced = "term_advanced"


class ChioTrustControlLeaseTermination(BaseModel):
    """
    One trust-control termination request that voluntarily releases a held authority lease before its TTL expires. Termination names the lease being released (`leaseId` plus `leaseEpoch`), the leader URL releasing it, and a typed `reason` so operators can distinguish leader handoff from quorum loss or operator-initiated stepdown. Drafted from `spec/PROTOCOL.md` section 9 prose plus the lease invalidation paths in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 1595-1611) where loss of quorum or a leader change clears `lease_expires_at` and bumps the election term. NOTE: this schema is drafted from prose; there is no dedicated `LeaseTerminateRequest` Rust struct in the live trust-control surface yet. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3. Wire field names follow the `serde(rename_all = camelCase)` convention used by the sibling lease projection so the families stay consistent on the wire.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    leaseId: constr(min_length=1) = Field(
        ...,
        description="Lease identifier being released. Must match the `leaseId` previously projected by the lease schema.",
    )
    leaseEpoch: conint(ge=0) = Field(
        ..., description="Lease epoch carried alongside `leaseId`."
    )
    leaderUrl: constr(min_length=1) = Field(
        ..., description="Normalized URL of the leader releasing the lease."
    )
    reason: Reason = Field(
        ...,
        description="Typed reason for releasing the lease. `leader_handoff` covers planned reassignment, `quorum_lost` covers detected loss of cluster quorum, `operator_stepdown` covers explicit operator action, and `term_advanced` covers a higher election term superseding the lease.",
    )
    observedAt: conint(ge=0) = Field(
        ...,
        description="Unix-millisecond timestamp at which the releasing leader observed the condition that motivated termination.",
    )
    successorLeaderUrl: constr(min_length=1) | None = Field(
        None,
        description="Optional normalized URL of the successor leader, when termination is part of a planned handoff.",
    )
