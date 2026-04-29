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

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class ChioTrustControlLeaseHeartbeat(BaseModel):
    """
    One trust-control heartbeat used to refresh a held authority lease before it expires. The heartbeat names the lease being refreshed (`leaseId` plus `leaseEpoch`), the leader URL claiming continued ownership, and the unix-millisecond observation timestamp at which the heartbeat was issued. Drafted from `spec/PROTOCOL.md` section 9 prose around `/v1/internal/cluster/status` and the cluster lease lifecycle described in `crates/chio-cli/src/trust_control/cluster_and_reports.rs` (lines 832-877). NOTE: this schema is drafted from prose plus the `ClusterAuthorityLeaseView` shape; there is no dedicated `LeaseHeartbeatRequest` Rust struct in the live trust-control surface yet, so wire field names follow the same `serde(rename_all = camelCase)` convention used by the lease projection. The dedicated request/response struct is expected to land alongside the cluster RPC formalization in M09 P3.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    leaseId: constr(min_length=1) = Field(
        ...,
        description="Lease identifier being refreshed. Must match the `leaseId` previously projected by the lease schema.",
    )
    leaseEpoch: conint(ge=0) = Field(
        ...,
        description="Lease epoch carried alongside `leaseId`. Trust-control fails closed if the heartbeat targets a stale epoch.",
    )
    leaderUrl: constr(min_length=1) = Field(
        ...,
        description="Normalized URL of the leader claiming continued ownership of the lease.",
    )
    observedAt: conint(ge=0) = Field(
        ...,
        description="Unix-millisecond timestamp at which the leader observed the cluster state that motivated this heartbeat.",
    )
    proposedExpiresAt: conint(ge=0) | None = Field(
        None,
        description="Optional unix-millisecond timestamp the leader proposes for the refreshed `leaseExpiresAt`. Trust-control may clamp this to the policy-bounded TTL.",
    )
