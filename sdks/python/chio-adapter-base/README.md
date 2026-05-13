# chio-adapter-base

Shared security and receipt primitives for the Chio Python adapter family.

> **Status: shipping.** The first non-pre-release publish on PyPI is
> `0.2.0`; see `CHANGELOG.md` for the breaking notes and
> `ADAPTER-MIGRATION.md` for the adapter-author migration recipe.

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
| **Pre-evaluation** | In the wrapper, BEFORE `ChioClient.evaluate_tool_call` | Non-body fields verbatim (path, command, ...) plus the body-field stub `{"omitted": true, "byte_count": N}` | Hash varies with the preserved non-body fields and `byte_count`; deterministic given `(tool_name, path, byte_count)`; use `tool_call_id` for per-call provenance | Sidecar runs out-of-process (different trust boundary); operator policy is path-based, not content-based; defense-in-depth requires zero body bytes on the sidecar wire | chio-langchain, chio-llamaindex, chio-crewai, chio-iac, chio-airflow, chio-ray, chio-temporal, chio-langgraph, chio-dagster, chio-prefect, chio-autogen, chio-streaming |
| **Post-tool-call** | In a `post_tool_call` / receipt-write hook, AFTER the sidecar verdict | Raw payload (so policy can make content-based decisions) | Unique per call (sidecar hashes the real bytes) | Sidecar runs in-process or in the same trust boundary as the agent; policy needs to inspect content (e.g. "deny if `content` matches a secret pattern"); audit trail wants per-call provenance | chio-hermes |

**Pre-evaluation prose.** Redact args BEFORE handing them to
`ChioClient.evaluate_tool_call`. The sidecar (and its receipt log)
see the redacted-stub for protected fields only
(`chio_file_write.content`, `chio_file_edit.patch`); other
parameters such as `path` pass through verbatim, so a compromised
sidecar cannot exfiltrate body bytes but can still see file paths.
The signed `parameter_hash` in the receipt is uniform across calls
only for the redacted slot's byte count; the hash still varies with
the preserved non-body fields (path, command, ...) and with
`byte_count` itself, so two calls that write different bodies of
different sizes to the same path produce different hashes. Forensic
correlation uses `path + byte_count + tool_call_id` together rather
than expecting per-call uniqueness from a single hash field. The
`bind_and_redact` helper (added in 0.1.1, hardened in 0.2.0) is the
canonical entry point for this pattern when the wrapper sees the
tool call as `(*args, **kwargs)` rather than as a pre-named dict.

**Post-tool-call prose.** Send raw args to `evaluate_tool_call`, then
redact at the receipt-write boundary. The chio-hermes Python plugin
redacts via `redact_args` in its `make_post_tool_call` hook
(`sdks/python/chio-hermes/src/chio_hermes/hooks.py`) before writing to
its session-local JSONL audit log. Policy sees real content, so rules
like "block if `content` contains `API_KEY`" are expressible. The
trade-off: secrets flow through the sidecar, so the sidecar's own
logging path is a separate concern handled in the sidecar's own crate
(the Rust HTTP proxy `chio-api-protect` does not import the Python
`redact_args` helper). This pattern only makes sense when the sidecar
shares a trust boundary with the agent process, which is the case in
chio-hermes (the plugin runs inside the Hermes process and the
sidecar is a localhost HTTP listener mounted by the same operator).

### Decision tree: which pattern fits your adapter

The tree picks BOTH a pattern (pre-evaluation vs post-tool-call) and a
helper (`redact_args` vs `bind_and_redact`). Walk Q1 first; the answer
constrains Q2.

1. **Does your adapter run agent code in a separate process from the
   Chio sidecar (separate container, separate VM, separate trust
   boundary)?** -> Yes: **pre-evaluation**. The on-the-wire trust
   boundary makes body-bytes-on-the-wire the dominant risk; redact
   before the sidecar sees them. (This is every adapter in the table
   above except chio-hermes.) Skip Q2 and go to Q3 for helper
   selection.
2. **(Only if Q1 was NO.) Does your adapter's policy need to make
   decisions based on field content (e.g. "deny `chio_file_write` if
   `content` contains credential-shaped strings")?** -> Yes:
   **post-tool-call**. The policy must see the real bytes, so
   redaction has to happen downstream of the verdict. The shared
   trust boundary you confirmed in Q1 makes the cost acceptable.
   No: **pre-evaluation** is fine; defense-in-depth is still cheap
   when the trust boundary is shared. (If you answered YES to Q1,
   content-aware policy is incompatible with pre-evaluation; either
   redesign the policy to be path-based or move it server-side onto
   the same trust boundary as the agent.)
3. **(Helper selection.) Does your wrapper see the tool call as a
   pre-named `dict` (i.e. `{"path": ..., "content": ...}` already),
   or does it see `(*args, **kwargs)`?** -> Pre-named dict: call
   `redact_args` directly. `(*args, **kwargs)`: call
   `bind_and_redact`, which binds positional values to parameter
   names first, then runs redaction over the named view, then
   rebuilds the original wire shape so positional values stay
   positional and keyword values stay keyword.
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

The "Where to redact" comparison table, the decision tree, and the
helper selection above subsume the original step-by-step migration
plan. The current floor-pin matrix is:

- Adapters that already adopted `bind_and_redact` and want the v0.2.0
  helper hardening (today: `chio-prefect 0.1.2` per PR #679) pin
  `chio-adapter-base>=0.2.0,<0.3`.
- Adapters that only call `redact_args` and have no exposure to the
  v0.2.0 `bind_and_redact` edge cells stay on
  `chio-adapter-base>=0.1.0,<0.2` until they touch their wrappers
  next; the call sites are byte-identical across 0.1.x and 0.2.0.

`docs/integrations/CHIO-ADAPTER-BASE.md` Section 4 carries the
current per-adapter pin table. `ADAPTER-MIGRATION.md` is the
adapter-author recipe for bumping a floor pin from 0.1.x to 0.2.0.

## Design notes

- Each primitive has a docstring pointing at the `chio-hermes` source
  it is being ported from, so the source-of-truth path is unambiguous
  during the migration.
- The package depends only on `chio-sdk-python`. It must NOT depend on
  `chio-hermes` (circular) or on any sibling adapter.
- No `_underscore_prefixed` names in the public API. Consumers were
  expected to know that `_sanitised_env` was a contract; we are
  fixing that bug as we extract.
