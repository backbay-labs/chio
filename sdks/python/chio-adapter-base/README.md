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
defense-in-depth against per-call forensics. The comparison table
below is the single source of truth; the prose underneath expands on
each row, and the decision tree at the end picks one given an
adapter's deployment topology.

### Comparison: pre-evaluation vs post-tool-call

| Pattern | Where redact runs | Sidecar sees | `parameter_hash` uniqueness | When to use | Who uses it (today) |
| --- | --- | --- | --- | --- | --- |
| **Pre-evaluation** | In the wrapper, BEFORE `ChioClient.evaluate_tool_call` | Stub `{"omitted": true, "byte_count": N}` only | Uniform across all calls to the same tool; correlate with `path` + `tool_call_id` + `byte_count` | Sidecar runs out-of-process (different trust boundary); operator policy is path-based, not content-based; defense-in-depth requires zero secrets on the sidecar wire | chio-langchain, chio-llamaindex, chio-crewai, chio-iac, chio-airflow, chio-ray, chio-temporal, chio-langgraph, chio-dagster, chio-prefect, chio-autogen, chio-streaming |
| **Post-tool-call** | In a `post_tool_call` / receipt-write hook, AFTER the sidecar verdict | Raw payload (so policy can make content-based decisions) | Unique per call (sidecar hashes the real bytes) | Sidecar runs in-process or in the same trust boundary as the agent; policy needs to inspect content (e.g. "deny if `content` matches a secret pattern"); audit trail wants per-call provenance | chio-hermes |

**Pre-evaluation prose.** Redact args BEFORE handing them to
`ChioClient.evaluate_tool_call`. The sidecar (and its receipt log)
never see secrets, so a compromised sidecar cannot exfiltrate
`chio_file_write.content` body bytes. The trade-off is that the
signed `parameter_hash` in the receipt is uniform across all
`chio_file_write` calls (it hashes a fixed stub plus the path), so
forensic correlation has to use `byte_count + path + tool_call_id`
together rather than a single hash field. The `bind_and_redact`
helper (added in 0.1.1, hardened in 0.2.0) is the canonical entry
point for this pattern when the wrapper sees the tool call as
`(*args, **kwargs)` rather than as a pre-named dict.

**Post-tool-call prose.** Send raw args to `evaluate_tool_call`, then
redact at the receipt-write boundary (see
`make_post_tool_call` in `sdks/python/chio-hermes/src/chio_hermes/hooks.py`).
Policy sees real content, so rules like "block if `content` contains
`API_KEY`" are expressible. The trade-off: secrets flow through the
sidecar, so the sidecar's own logging path must redact too
(`chio-api-protect` handles this server-side via `redact_args` on the
receipt-store path). This pattern only makes sense when the sidecar
shares a trust boundary with the agent process, which is the case in
chio-hermes (the plugin runs inside the Hermes process and the
sidecar is a localhost HTTP listener mounted by the same operator).

### Decision tree: which pattern fits your adapter

Walk these top-down; the first "yes" picks your pattern.

1. **Does your adapter run agent code in a separate process from the
   Chio sidecar (separate container, separate VM, separate trust
   boundary)?** -> Yes: **pre-evaluation**. The on-the-wire trust
   boundary makes secrets-on-the-wire the dominant risk; redact before
   the sidecar sees them. (This is every adapter in the table above
   except chio-hermes.)
2. **Does your adapter's policy need to make decisions based on field
   content (e.g. "deny `chio_file_write` if `content` contains
   credential-shaped strings")?** -> Yes: **post-tool-call**. The
   policy must see the real bytes, so redaction has to happen
   downstream of the verdict. Accept the trust-boundary cost.
3. **Does your wrapper see the tool call as a pre-named `dict`
   (i.e. `{"path": ..., "content": ...}` already), or does it see
   `(*args, **kwargs)`?** -> Pre-named dict: call `redact_args`
   directly. `(*args, **kwargs)`: call `bind_and_redact`, which
   binds positional values to parameter names first, then runs
   redaction over the named view, then rebuilds the original wire
   shape so positional values stay positional and keyword values
   stay keyword.
4. **Are you adding the first redaction call to a brand-new
   adapter?** -> Default to **pre-evaluation** with `bind_and_redact`.
   It is the more conservative choice (defense-in-depth), and the
   decision can be revisited if the policy needs content-aware rules
   later.

The chio-hermes precedent is documented in
`docs/integrations/CHIO-ADAPTER-BASE.md` (this file's
"chio-hermes precedent reconciliation" section); the migration
mechanics for adapter authors live in `ADAPTER-MIGRATION.md`.

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
