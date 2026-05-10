# Trajectory 5.2 Tickets

## T5.2-001: Fold proof evidence baseline

Owner-class: release integrator.

Acceptance:

- PR #630 is merged or folded into `main`.
- Baseline SHA is recorded as
  `7f56cf5383fc1caa7a4f06b4cd59e45177f00496`.

Status: Done.

## T5.2-002: Machine-readable mutation recast

Owner-class: assurance owner.

Acceptance:

- Each trust-boundary mutation JSON keeps its measured values.
- Each row carries a valid `chio.assurance-recast.v1` object.
- Strict bounded gate reports the six rows as OK non-release recasts.

Status: Done.

## T5.2-003: C5 and package boundary recast

Owner-class: release owner.

Acceptance:

- C5 marker says deferred, no release claim, and strict recast accepted.
- `releases.toml` parks `v0.1.0-bounded-chiodome` outside active release
  scope.
- Strict gate reports both rows as OK.

Status: Done.

## T5.2-004: Refresh evidence manifest

Owner-class: release integrator.

Acceptance:

- `audits/evidence/bounded-assurance-manifest.json` hashes all changed
  release-truth evidence and planning docs.
- `bash scripts/check-bounded-ship-bar.sh` passes in default mode.

Status: Done.

## T5.2-005: T6 shadow planning boundary

Owner-class: protocol strategist.

Acceptance:

- T6 design, ticket map, and dependencies are written.
- T6 docs are explicitly draft, non-normative, and specs-only.
- No T6 runtime code, schema enforcement, verifier behavior, or release claim
  is added.

Status: Done.
