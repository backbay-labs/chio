# chio-iac

Infrastructure-as-Code governance for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps Terraform and Pulumi with Chio's two-phase capability model so
that `terraform plan` and `terraform apply` (and every Pulumi program
invocation) flow through the Chio sidecar for capability-scoped
authorisation, and so that the resource types a plan touches are
checked against an allowlist before any cloud mutation occurs.

## Why two-phase

Terraform's existing `plan` / `apply` split maps directly to Chio's
capability tiers:

- `infra:plan` is low-privilege. It reads configuration, queries
  providers, and produces a plan file. It never mutates the cloud.
- `infra:apply` is high-privilege. It actually runs the plan against
  the cloud. The apply capability is only granted to a capability that
  passes a plan-review step that parses the plan output and denies
  resource types outside the granted scope.

A single agent can hold `infra:plan` broadly and `infra:apply` narrowly.
Operators can review the plan (automatically or manually) before the
apply-scoped capability is minted.

## Install

```bash
uv pip install chio-iac          # Terraform CLI wrapper only
uv pip install 'chio-iac[pulumi]'  # add the Pulumi decorator
```

The package depends on `chio-sdk-python` and `pydantic>=2.5`. Terraform
is invoked as a subprocess; the package never links a Terraform library.

## Terraform CLI wrapper

```bash
# Plan: requires infra:plan scope. Never mutates the cloud.
python -m chio_iac terraform plan \
    --capability-id cap-infra-plan-42 \
    --working-dir ./terraform

# Apply: requires infra:apply scope + plan-review.
# The allowlist and denylist are glob-aware.
python -m chio_iac terraform apply \
    --capability-id cap-infra-apply-42 \
    --working-dir ./terraform \
    --allow 'aws_db_*' \
    --allow 'aws_elasticache_*' \
    --deny 'aws_iam_*'

# Destroy: apply-scoped; --allow-destroy is required.
python -m chio_iac terraform destroy \
    --capability-id cap-infra-apply-42 \
    --working-dir ./terraform \
    --allow 'aws_db_*' \
    --allow-destroy
```

Arguments after `--` are passed through to `terraform` verbatim:

```bash
python -m chio_iac terraform plan \
    --capability-id cap-infra-plan-42 \
    -- \
    -var-file=envs/prod.tfvars
```

Exit codes:

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | `terraform` ran successfully under an allow verdict |
| N>0  | `terraform` itself failed with that returncode      |
| 2    | Chio denied (sidecar deny or plan-review deny)       |
| 3    | configuration error before any sidecar call        |
| 4    | sidecar transport / kernel error (retryable)        |

## Library API

```python
import asyncio

from chio_iac import (
    PlanReviewGuard,
    ResourceTypeAllowlist,
    ResourceTypeDenylist,
    run_terraform,
)


async def ship_database() -> None:
    # Plan phase.
    await run_terraform(
        "plan",
        capability_id="cap-plan-42",
        working_dir="./terraform",
    )

    # Apply phase, with plan-review.
    await run_terraform(
        "apply",
        capability_id="cap-apply-42",
        working_dir="./terraform",
        plan_review_guard=PlanReviewGuard(
            allowlist=ResourceTypeAllowlist(patterns=["aws_db_*"]),
            denylist=ResourceTypeDenylist(patterns=["aws_iam_*"]),
        ),
    )


asyncio.run(ship_database())
```

Deny paths raise `ChioIACPlanReviewError` (when the plan contains
out-of-scope resource types) or `ChioIACError` (when the sidecar denies
the operation). Both expose the structured deny context via `to_dict()`
for structured logging.

## Pulumi decorator

```python
from chio_iac import chio_pulumi, record_resource, ResourceTypeAllowlist


@chio_pulumi(
    capability_id="cap-apply-42",
    allowlist=ResourceTypeAllowlist(patterns=["aws:rds/*", "aws:elasticache/*"]),
)
def staging_program() -> None:
    # Opt into plan-review by recording the resource types this
    # program will register.
    record_resource("aws:rds/instance:Instance", name="db", action="create")

    # Actual Pulumi resource registration follows.
    import pulumi_aws as aws
    aws.rds.Instance("db", engine="postgres", instance_class="db.t3.small")


# Run inside `pulumi automation`, `pulumi up`, or a test harness.
staging_program()
```

The decorator runs the program twice on apply: once in a collection
pass to learn which resource types it registers (plan-review) and once
for real. Programs that do not call `record_resource` get the
sidecar-level capability check without a plan-review step -- the kernel
retains final say.

## Testing

The SDK ships with an `chio_sdk.testing.MockChioClient`; inject it via
`chio_client=` on `run_terraform` or `chio_pulumi` to exercise your
wiring offline:

```python
from chio_sdk.testing import allow_all, deny_all

await run_terraform(
    "plan",
    capability_id="cap",
    chio_client=allow_all(),
)
```

See `tests/test_terraform.py` and `tests/test_pulumi.py` for worked
examples covering plan / apply scope split, allowlist / denylist
precedence, destroy gating, and sidecar-vs-plan-review ordering.

## Supported plan shapes

`PlanReviewGuard.review` accepts three plan shapes:

1. Terraform `show -json` output (the `resource_changes` list).
2. Pulumi preview `resources` list (`{type, urn, action}` entries).
3. Pulumi preview `steps` list (`{op, newState: {type, urn}}` entries).

The action set understood by the guard: `create`, `update`, `delete`,
`replace`, `no-op`, `read`. `delete` and `replace` are denied by
default unless the capability sets `allow_destroy=True`.

## Error types

- `ChioIACError` -- sidecar denied or failed. Carries the structured
  verdict (guard, reason, receipt id, full decision).
- `ChioIACPlanReviewError` -- plan contained out-of-scope resource
  types. Subclass of `ChioIACError`; adds a `violations` list with one
  entry per denied resource (`resource_type`, `address`, `action`,
  `reason`).
- `ChioIACConfigError` -- local configuration mistake (missing
  capability, missing binary, missing plan file, etc.). Raised before
  any sidecar call.
