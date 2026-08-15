# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.
#
# Source: spec/schemas/chio-wire/v1/**/*.schema.json
# Tool:   datamodel-code-generator==0.34.0 (see xtask/codegen-tools.lock.toml)
# Schema sha256: d7264a73c6278a903994c0945d1fc7ba5300063d0cc3a6b8666fdf08f66175e5
#
# Manual edits will be overwritten by the next regeneration; the
# spec-drift CI lane enforces this header on every file
# under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.


from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, conint, constr


class ChioTrustControlAuthorityLease(BaseModel):
    """
    One operator-visible authority lease projection emitted by the trust-control service over `/v1/internal/cluster/status` and the budget-write authority block. A lease names the leader URL that currently holds the trust-control authority, the cluster election term that minted it, the lease identifier and epoch that scope subsequent budget and revocation writes, and the unix-second expiry plus configured TTL that bound the lease's continued validity. Wire field names are camelCase. `leaseValid` is true only when the cluster has quorum and `leaseExpiresAt` is still in the future. NOTE: `leaseExpiresAt` and `termStartedAt` are unix seconds (`unix_timestamp_now() + leaseTtlMs / 1000`), even though `leaseTtlMs` itself is in milliseconds. The asymmetry mirrors the live runtime shape and is preserved on the wire so consumers do not have to re-scale by 1000.
    """

    model_config = ConfigDict(
        extra="forbid",
    )
    authorityId: constr(min_length=1) = Field(
        ...,
        description="Stable identifier for the authority that holds the lease. In the current bounded release this equals the leader URL.",
    )
    leaderUrl: constr(min_length=1) = Field(
        ...,
        description="Normalized URL of the cluster node that currently holds the authority lease.",
    )
    term: conint(ge=0) = Field(
        ...,
        description="Cluster election term that minted this lease. Monotonically non-decreasing.",
    )
    leaseId: constr(min_length=1) = Field(
        ...,
        description="Composite lease identifier in the form `{leaderUrl}#term-{leaseEpoch}`. Authoritative for downstream writes.",
    )
    leaseEpoch: conint(ge=0) = Field(
        ...,
        description="Lease epoch carried alongside `leaseId`. Currently equals `term`; kept distinct on the wire so future epoch bumps within a term remain expressible.",
    )
    termStartedAt: conint(ge=0) | None = Field(
        None,
        description="Optional unix-second timestamp at which the current term began on this leader. Omitted when unknown (no quorum or no leader).",
    )
    leaseExpiresAt: conint(ge=0) = Field(
        ...,
        description="Unix-second timestamp at which the lease expires if not renewed. Computed as `unix_timestamp_now() + leaseTtlMs / 1000`. The unit is seconds (not milliseconds) even though the configured TTL is expressed in milliseconds; downstream consumers MUST treat this field as a unix-second timestamp.",
    )
    leaseTtlMs: conint(ge=0) = Field(
        ...,
        description="Configured lease time-to-live in milliseconds. Bounded between 500ms and 5000ms. NOTE: this field is the only millisecond-denominated quantity in the lease projection; `termStartedAt` and `leaseExpiresAt` are unix seconds.",
    )
    leaseValid: bool = Field(
        ...,
        description="True only when the cluster currently has quorum and `leaseExpiresAt` has not yet passed. Trust-control fails closed and rejects authority-bearing writes when this is false.",
    )
