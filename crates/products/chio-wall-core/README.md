# chio-wall-core

`chio-wall-core` defines the typed JSON contracts for Chio-Wall's control-path
artifacts: the schemas, enums, and fail-closed validation for the bounded
evidence bundle that the `chio-wall` CLI produces for buyer review. It is a
pure data crate with no I/O and no dependency on any other `chio-*` crate.

Use this crate for the Chio-Wall artifact types and their `validate()` methods.
The CLI that builds these artifacts from real capability tokens, guard
evaluation, and signed receipts, then writes and exports them, is `chio-wall`.

## Responsibilities

- Define the seven Chio-Wall artifact schemas, each tagged with its own
  `CHIO_WALL_*_SCHEMA` constant: control profile, policy snapshot,
  authorization context, guard outcome, denied-access record, buyer review
  package, and control package.
- Constrain Chio-Wall to one buyer motion and one control surface at the type
  level: `ChioWallBuyerMotion` and `ChioWallControlSurface` are single-variant
  enums (`ControlRoomBarrierReview`, `ToolAccessDomainBoundary`).
- Validate each artifact independently: schema-tag match, non-empty /
  non-padded / control-character-free strings, unique list entries, and
  `fail_closed` fields that must stay `true`.
- Own `ChioWallControlPackage::validate`, which requires the complete bounded
  artifact set (all seven `ChioWallArtifactKind` variants, no duplicates).
- Define the `ChioWallContractError` taxonomy every validator returns.

## Public API

- `ChioWallControlProfile`, `ChioWallPolicySnapshot`, `ChioWallAuthorizationContext`,
  `ChioWallGuardOutcome`, `ChioWallDeniedAccessRecord`, `ChioWallBuyerReviewPackage`,
  `ChioWallControlPackage`, `ChioWallArtifact` - the artifact structs, each with a
  `validate(&self) -> Result<(), ChioWallContractError>` method.
- `ChioWallBuyerMotion`, `ChioWallControlSurface`, `ChioWallInformationDomain`,
  `ChioWallGuardDecision`, `ChioWallArtifactKind` - the closed enums the
  artifacts are built from.
- `ChioWallContractError` - schema, field, and JSON error variants.
- Schema constants: `CHIO_WALL_CONTROL_PROFILE_SCHEMA`, `CHIO_WALL_POLICY_SNAPSHOT_SCHEMA`,
  `CHIO_WALL_AUTHORIZATION_CONTEXT_SCHEMA`, `CHIO_WALL_GUARD_OUTCOME_SCHEMA`,
  `CHIO_WALL_DENIED_ACCESS_RECORD_SCHEMA`, `CHIO_WALL_BUYER_REVIEW_PACKAGE_SCHEMA`,
  `CHIO_WALL_CONTROL_PACKAGE_SCHEMA`.

## Usage

```rust
use chio_wall_core::{
    ChioWallBuyerMotion, ChioWallControlProfile, ChioWallControlSurface,
    ChioWallInformationDomain, CHIO_WALL_CONTROL_PROFILE_SCHEMA,
};

let profile = ChioWallControlProfile {
    schema: CHIO_WALL_CONTROL_PROFILE_SCHEMA.to_string(),
    profile_id: "wall-profile".to_string(),
    workflow_id: "wf-1".to_string(),
    buyer_motion: ChioWallBuyerMotion::ControlRoomBarrierReview,
    control_surface: ChioWallControlSurface::ToolAccessDomainBoundary,
    source_domain: ChioWallInformationDomain::Research,
    protected_domain: ChioWallInformationDomain::Execution,
    retained_artifact_policy: "retain-minimum".to_string(),
    intended_use: "boundary review".to_string(),
    fail_closed: true,
};
assert!(profile.validate().is_ok());
```

## Testing

`cargo test -p chio-wall-core`

## See also

- `chio-wall` - the CLI that builds, writes, and exports these artifacts.
