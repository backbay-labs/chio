# chio-adapter-base

Shared security and receipt primitives for the Chio Python adapter family.

> **Status: scaffold only.** Phase 1 of the extraction defines the public
> API and ships a smoke-test for the import surface. Phase 2 ports the
> implementations from `chio-hermes` and migrates the first sibling adapter.
> See `.planning/chio-adapter-base/PLAN.md` in the chio repository for the
> full plan.

## Why this package exists

Seven hardening primitives were invented in `chio-hermes` (per-tool
argument redaction, subprocess environment scrubbing, git argv
hardening, bounded subprocess capture, receipt buffering and JSONL
append, forbidden-path output filtering, shell argv escape checks).
Today none of them ship in the other Chio Python adapters
(`chio-langchain`, `chio-llamaindex`, `chio-crewai`, `chio-airflow`,
`chio-iac`, etc.). That is a silent compliance gap: tool arguments
that `chio-hermes` redacts are written verbatim by sibling adapters,
and subprocesses that `chio-hermes` bounds at 1 MiB run unbounded in
`chio-iac`.

`chio-adapter-base` extracts the seven primitives into one tested
package so the family can converge on one implementation.

## Where to redact: pre-evaluation vs post-tool-call

There are two valid places to redact tool args, and they trade off
defense-in-depth against per-call forensics:

**Pre-evaluation (the chio-langchain/llamaindex/crewai/iac/airflow/ray/
temporal/langgraph/dagster/prefect pattern):** redact args BEFORE handing
them to `ChioClient.evaluate_tool_call`. Pros: the sidecar (and its
receipt log) never see secrets; defense-in-depth assumes the sidecar
itself may be compromised or run in a less-trusted process. Cons: the
sidecar's policy can't make decisions based on field content (e.g., "block
if content contains 'API_KEY'"); the signed `parameter_hash` in the
receipt is uniform across all chio_file_write calls (cannot distinguish
which file was written). Use byte_count + path + tool_call_id together
for forensic correlation.

**Post-tool-call (the chio-hermes pattern):** send raw args to
`evaluate_tool_call`, then redact at the receipt-write boundary
(`make_post_tool_call` in chio-hermes hooks.py). Pros: policy sees real
content; parameter_hash is unique per call. Cons: secrets flow through
the sidecar (must trust it); the sidecar's own logging must redact too
(chio-api-protect handles this server-side via `redact_args` on the
receipt-store path).

**Picking one:** chio-hermes embeds the sidecar in-process so the trust
boundary is different; the 9 sibling adapters run agent code in a
separate process from the sidecar, so the on-the-wire trust boundary
favors pre-evaluation. Both are valid; choose based on your sidecar
deployment topology.

The `bind_and_redact` helper (added in 0.1.1) is the canonical entry
point for the pre-evaluation pattern when the wrapper sees the tool call
as ``(*args, **kwargs)`` rather than as a pre-named dict. Sibling
adapters that previously hand-rolled inline ``_build_redacted_parameters``
/ ``_redact_method_call`` / ``_task_parameters`` helpers can swap them
for an import.

## Public API

Surface organised by threat-model area, not by a flat namespace.

```python
from chio_adapter_base.security import (
    sanitised_env,
    harden_git_argv,
    reject_shell_argv_escape,
    BoundedSubprocess,
    BoundedSubprocessResult,
)
from chio_adapter_base.receipts import (
    ReceiptBuffer,
    append_jsonl,
    DEFAULT_RECEIPT_BUFFER_MAX,
)
from chio_adapter_base.redact import (
    redact_args,
    RedactionPolicy,
    bind_and_redact,
    DEFAULT_TOOL_POSITIONAL_NAMES,
)
from chio_adapter_base.filters import (
    forbidden_path_filter,
)
```

A small set of the most common names is also re-exported from the
top-level package for convenience:

```python
from chio_adapter_base import sanitised_env, ReceiptBuffer, redact_args
```

## Migration story

| step | release                                                   | what changes                                                  |
|------|-----------------------------------------------------------|----------------------------------------------------------------|
| 1    | `chio-adapter-base 0.1.0`                                 | this package ships with all seven primitives                   |
| 2    | `chio-hermes 0.1.1` (canary)                              | `chio-hermes` re-exports the primitives from this package      |
| 3    | `chio-langchain 0.2.0`, `chio-llamaindex 0.2.0`, ...      | sibling adapters add `redact_args` to their tool wrappers      |
| 4    | `chio-iac 0.2.0`, `chio-airflow 0.2.0`                    | adapters with subprocess paths adopt `BoundedSubprocess`       |
| 5    | `chio-hermes 0.2.0`                                       | `chio-hermes` deletes the inline copies and the re-export shim |

Sibling adapters pin `chio-adapter-base>=0.1.0,<0.2`.

## Design notes

- Each primitive has a docstring pointing at the `chio-hermes` source
  it is being ported from, so the source-of-truth path is unambiguous
  during the migration.
- The package depends only on `chio-sdk-python`. It must NOT depend on
  `chio-hermes` (circular) or on any sibling adapter.
- No `_underscore_prefixed` names in the public API. Consumers were
  expected to know that `_sanitised_env` was a contract; we are
  fixing that bug as we extract.
