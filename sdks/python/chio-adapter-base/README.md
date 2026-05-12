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
