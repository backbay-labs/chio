# chio-dagster

Dagster integration for the [Chio protocol](../../../spec/PROTOCOL.md).
Wraps Dagster's `@asset` and `@op` decorators so every materialization
is capability-checked via the Chio sidecar kernel, denied materializations
raise `PermissionError` (which Dagster routes to a failed run state),
and every allow verdict is attached to the emitted
`AssetMaterialization` as `MetadataValue` entries so the Dagster UI
renders Chio receipts directly on the asset catalog.

## Install

```bash
uv pip install chio-dagster
# or
pip install chio-dagster
```

The package depends on `chio-sdk-python`, `dagster>=1.8,<2`, and
`pydantic>=2.5`.

## Quickstart

```python
from chio_sdk.models import ChioScope, Operation, ToolGrant
from dagster import (
    AssetExecutionContext,
    Definitions,
    StaticPartitionsDefinition,
)
from chio_dagster import chio_asset


REGION_PARTITIONS = StaticPartitionsDefinition(
    ["us-east", "eu-west", "ap-south"]
)

EMBED_SCOPE = ChioScope(
    grants=[
        ToolGrant(
            server_id="ml-srv",
            tool_name="customer_embeddings",
            operations=[Operation.INVOKE],
        )
    ]
)


@chio_asset(
    scope=EMBED_SCOPE,
    capability_id="cap-ml-embed",
    tool_server="ml-srv",
    partitions_def=REGION_PARTITIONS,
)
def customer_embeddings(
    context: AssetExecutionContext,
) -> list[dict]:
    # If we reach here, Chio evaluated and approved the materialization
    # for this partition (context.partition_key is included in the
    # evaluation payload).
    return embedding_model.encode_for(context.partition_key)


defs = Definitions(assets=[customer_embeddings])
```

## Behaviour

- Each `@chio_asset` materialization evaluates via the Chio sidecar
  before the compute function runs. Allow verdicts proceed; deny
  verdicts raise `PermissionError` and Dagster records a `FAILURE`
  run state.
- Partitioned assets include the partition key (and the full partition
  info) in the capability evaluation payload -- guards can grant
  access to specific partitions only (the canonical
  `region=eu-west` data-residency pattern).
- Allow receipts are attached to the emitted
  `AssetMaterialization` as `MetadataValue` entries:
  `chio_receipt_id`, `chio_verdict`, `chio_capability_id`,
  `chio_tool_server`, `chio_tool_name`, and -- when present --
  `chio_partition_key`.
- Deny verdicts attach `chio_verdict="deny"`, `chio_reason`, and
  `chio_guard` to the output metadata so the failure is traceable on
  the Dagster UI even though the run transitions to `FAILURE`.
- Dagster's `@asset` / `@op` options (`partitions_def`, `ins`,
  `deps`, `io_manager_key`, `group_name`, `retry_policy`, `metadata`,
  ...) pass through `@chio_asset` / `@chio_op` verbatim.
- Sync and async compute functions are both supported.

### `ChioIOManager`

Wraps an inner `IOManager` with a Chio capability check on every
`handle_output` / `load_input`. This is the natural enforcement
point for data governance: the IO manager knows the destination
(warehouse, S3 bucket, local FS) the asset will land in, and Chio
decides whether the capability permits writes there.

```python
from dagster import FilesystemIOManager
from chio_dagster import ChioIOManager

chio_governed_fs = ChioIOManager(
    FilesystemIOManager(base_dir="/var/dagster/storage"),
    capability_id="cap-data-governance",
    tool_server="chio_data",
).as_io_manager()

defs = Definitions(
    assets=[customer_embeddings],
    resources={"io_manager": chio_governed_fs},
)
```

Partition keys flow through to the IO manager evaluation payload
(`parameters["partition_key"]`) the same way they flow through to
the asset decorator's evaluation, so the same guards work on either
surface.

## Error types

- `ChioDagsterError` -- raised on deny. Carries the structured verdict
  (guard, reason, receipt id, partition key, decision). The decorator
  attaches it to `PermissionError.chio_error` so `except PermissionError`
  remains the canonical catch.
- `ChioDagsterConfigError` -- raised at materialization time for
  configuration mistakes (missing `capability_id`, wrapper with an
  inner manager that doesn't implement the `IOManager` interface).

## Testing

The SDK ships a drop-in `MockChioClient` via `chio_sdk.testing`. Inject
it with `chio_client=` on the decorator or IO manager to exercise your
pipeline offline:

```python
from chio_sdk.testing import allow_all, deny_all

@chio_asset(
    capability_id="cap-1",
    tool_server="srv",
    chio_client=allow_all(),
)
def my_asset(context: AssetExecutionContext) -> int: ...
```

See `tests/test_chio_asset.py` and `tests/test_io_manager.py` in this
repository for worked examples, including the partition-scoped deny
pattern.
