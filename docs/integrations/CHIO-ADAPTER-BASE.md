# chio-adapter-base integration

`chio-adapter-base` is the shared security and receipt-primitive
package that every Chio Python adapter family depends on. It is not
itself an adapter and not an end-user package; it is the boundary
between the Chio sidecar contract and the framework integrations
(`chio-langchain`, `chio-llamaindex`, `chio-crewai`, `chio-iac`,
`chio-airflow`, `chio-ray`, `chio-temporal`, `chio-langgraph`,
`chio-dagster`, `chio-prefect`, `chio-autogen`, `chio-streaming`,
`chio-hermes`).

This page is for users browsing the Chio docs who want to know what
`chio-adapter-base` is, why it exists, and which adapter consumes
which primitive. Adapter authors who are migrating an existing
adapter onto the helper should read
`sdks/python/chio-adapter-base/ADAPTER-MIGRATION.md` instead.

## 1. Purpose

`chio-adapter-base` extracts the seven hardening primitives that
were originally invented in `chio-hermes` (per-tool argument
redaction, subprocess environment scrubbing, git argv hardening,
bounded subprocess capture, receipt buffering and JSONL append,
forbidden-path output filtering, shell argv escape checks) into a
single tested package so the twelve sibling adapters can converge
on one implementation.

Without `chio-adapter-base`, each adapter that wraps a host
framework reinvented these primitives inline, with predictable
drift: tool arguments that `chio-hermes` redacted were written
verbatim by sibling adapters; subprocesses that `chio-hermes`
bounded at 1 MiB ran unbounded in `chio-iac`. The package closes
that silent compliance gap by giving every adapter the same
import path for the same code.

## 2. The seven primitives

Source files live under
`sdks/python/chio-adapter-base/src/chio_adapter_base/`.

### `redact_args` (`redact.py`)

Replace tool-arg fields that carry raw bodies (the `content` of
`chio_file_write`, the `patch` of `chio_file_edit`) with a
byte-count stub
(`{"omitted": True, "byte_count": <utf-8-len>}`) so embedded
secrets do not land in the receipt log. Path / message fields are
preserved. Adapters extend the field set with a custom
`RedactionPolicy`. Source: `redact.py:95`.

### `sanitised_env` (`security.py`)

Strip credential-carrying env vars from the inherited environment
before spawning a child process. The denylist matches name
prefixes (`AWS_*`, `OPENAI_*`, `ANTHROPIC_*`, `GH_*`, `VAULT_*`,
...), suffixes (`_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`,
...), and an exact list (`OPENAI_API_KEY`, `GH_TOKEN`,
`DATABASE_URL`, ...). Benign locale and shell variables (`PATH`,
`HOME`, `LANG`, `TZ`, `USER`, `SHELL`) are preserved. Source:
`security.py`.

### `harden_git_argv` (`security.py`)

Inject `--no-verify` into `git commit` argv (pre-commit /
commit-msg / prepare-commit-msg hooks execute repo-local scripts;
treating them as inert would let an attacker who controls the
repo escalate from "model can call git_commit" to arbitrary code
execution). Specifically: locate the `commit` subcommand, insert
`--no-verify` immediately after it if not already present, and
reject any explicit `--verify` (raised as `PermissionError`)
because that would override the hardening. The helper is scoped
to `git commit`; non-commit invocations are returned unchanged.
Other dangerous shapes (e.g. `git push --force`) are out of scope
for this helper. Source: `security.py`.

### `BoundedSubprocess` (`security.py`)

Synchronous and async subprocess runner that caps each pipe at a
per-stream byte limit (default 1 MiB). When the cap is reached,
additional output is discarded (not preserved) and the result
envelope carries `output_truncated: True`; the subprocess itself
continues running until it exits normally or trips the timeout.
The reader threads keep draining past the cap so the producer
never blocks on a full pipe (a blocked pipe would otherwise stall
`wait()` and surface as a timeout instead of as truncation).
Without this cap, a `yes` or large `git diff` would buffer until
OOM. Returns a `BoundedSubprocessResult` dataclass with fields
`argv`, `returncode`, `stdout`, `stderr`, `output_truncated`, and
`timed_out`. Source: `security.py`.

### `ReceiptBuffer` (`receipts.py`)

In-memory FIFO deque of recorded receipts capped at
`DEFAULT_RECEIPT_BUFFER_MAX` (1000). The cap applies to the
global recorded-receipt buffer, not a per-task quota. Adapters
expose this through their own slash command or HTTP endpoint
(e.g. chio-hermes's `/chio receipts`). Source: `receipts.py`.

### `forbidden_path_filter` (`filters.py`)

Post-filters listing-shape outputs (directory entries, diff
hunks, `git status` lines) against `policy.check_read` so a
listing surface cannot be used to confirm secret-file existence.
The format-aware wrappers (`filter_directory_entries`,
`filter_diff_output`, `filter_status_output`) handle each shape
without losing surrounding structure. Source: `filters.py`.

### `reject_shell_argv_escape` (`security.py`)

Path-escape check on argv values for tools that accept a path
plus a shell-resolved command (e.g. `chio_file_edit`'s call into
`patch(1)`). Raises `ChioPathEscapeError` (a subclass of
`PermissionError`) so adapters can branch on workspace escape
versus other permission denials. Source: `security.py`.

## 3. `bind_and_redact`: deep dive

The pre-evaluation redaction pattern (see Section 5 below) needs
named-arg keys to apply a `RedactionPolicy`. Many adapter wrappers
see the tool call as `(*args, **kwargs)` rather than as a
pre-named dict, so binding positional values to parameter names
is a prerequisite for redaction. Doing that binding correctly
against the full Python signature space is non-trivial; nine
sibling adapters re-derived the binding logic inline before the
0.1.1 helper consolidated it.

`bind_and_redact(fn, args, kwargs, *, tool_name, policy=None,
drop_self=False, positional_table=None)` covers six orthogonal
axes:

1. **Signature shape**: `fixed-positional`, `fixed+kwonly`,
   `fixed+VAR_POSITIONAL`, `fixed+VAR_KEYWORD`,
   `pure VAR_POSITIONAL`, `pure VAR_KEYWORD`,
   `pure VAR_POSITIONAL+VAR_KEYWORD`, `fn=None`,
   non-introspectable callable (C extension).
2. **Args presence**: empty, single positional, multiple
   positional, more positional than fixed slots.
3. **Kwargs presence**: empty, single matching, single
   non-matching, conflict with positional slot.
4. **Default-table presence**: tool in
   `DEFAULT_TOOL_POSITIONAL_NAMES`, tool not in default.
5. **Policy**: `chio_default()`, custom matching, custom
   non-matching.
6. **`positional_table` override**: `None` (use chio default),
   custom (REPLACES default; v0.3 explicitly documents the
   REPLACE semantic that v0.1.1 already shipped).

The chio-default positional-name table
(`DEFAULT_TOOL_POSITIONAL_NAMES`) covers `chio_file_write` and
`chio_file_edit` (the two body-bearing tools in the chio-default
policy). Adapters with custom tools pass their own table; that
custom table REPLACES the default rather than extending it (this
is the behaviour that shipped in v0.1.1 and that v0.3 now
explicitly documents). See `ADAPTER-MIGRATION.md` section 5 for
the merge recipe when both the chio-default tools and custom
tools need coverage from a single table.

The helper preserves wire shape: positional values stay
positional in the rebuilt `args`, keyword values stay keyword in
the rebuilt `kwargs`. Callers can therefore pass the result
straight to
`ChioClient.evaluate_tool_call(parameters={"args": ...,
"kwargs": ...})` without the `parameter_hash` drifting.

`build_alias_map` is also public for adapters and API docs that need
to inspect how wrapper names map onto canonical tool slots. It is a
diagnostic and testing helper; production adapter call sites should
prefer `bind_and_redact`.

## 4. Adapters consuming chio-adapter-base today

The current floor pin matrix (as of `chio-adapter-base 0.2.0`):

| Adapter | Pin | Primary primitives consumed |
| --- | --- | --- |
| [`chio-hermes`](../../sdks/python/chio-hermes/) | `>=0.1.0,<0.2` | `redact_args`, `RedactionPolicy.chio_default`, `BoundedSubprocess`, `sanitised_env`, `harden_git_argv`, `forbidden_path_filter`, `ReceiptBuffer` |
| [`chio-prefect`](../../sdks/python/chio-prefect/) | `>=0.2.0,<0.3` | `bind_and_redact`, `redact_args` |
| [`chio-airflow`](../../sdks/python/chio-airflow/) | `>=0.1.1,<0.2` | `bind_and_redact`, `RedactionPolicy` |
| [`chio-ray`](../../sdks/python/chio-ray/) | `>=0.1.1,<0.2` | `bind_and_redact`, `RedactionPolicy` |
| [`chio-temporal`](../../sdks/python/chio-temporal/) | `>=0.1.1,<0.2` | `redact_args` |
| [`chio-langchain`](../../sdks/python/chio-langchain/) | `>=0.1.0,<0.2` | `redact_args` (kwargs-only call surface; no `bind_and_redact` needed) |
| [`chio-llamaindex`](../../sdks/python/chio-llamaindex/) | `>=0.1.0,<0.2` | `redact_args` (kwargs-only) |
| [`chio-crewai`](../../sdks/python/chio-crewai/) | `>=0.1.0,<0.2` | `redact_args` (kwargs-only) |
| [`chio-langgraph`](../../sdks/python/chio-langgraph/) | `>=0.1.0,<0.2` | `redact_args` |
| [`chio-dagster`](../../sdks/python/chio-dagster/) | `>=0.1.0,<0.2` | `redact_args` |
| [`chio-iac`](../../sdks/python/chio-iac/) | `>=0.1.0,<0.2` | `redact_args`, `RedactionPolicy` |
| [`chio-autogen`](../../sdks/python/chio-autogen/) | `>=0.1.0,<0.2` | `redact_args` |
| [`chio-streaming`](../../sdks/python/chio-streaming/) | `>=0.1.0,<0.2` | `redact_args` |

chio-prefect bumped to `>=0.2.0,<0.3` in PR #679; the prefect
canary collapse onto `bind_and_redact` exercises the v0.2.0 helper
hardening against a real adapter. The migration of the OTHER
adapters' floor pins is not part of this release-docs PR; those
bumps should land in a separate v0.2.x cleanup after the 0.2.0
package is published.

## 5. chio-hermes precedent reconciliation

The twelve sibling adapters redact pre-evaluation. chio-hermes
redacts post-tool-call. Both are valid; the choice depends on
where the sidecar trust boundary sits relative to the agent
process.

The full comparison table, prose, and decision tree live in
[`chio-adapter-base/README.md` "Where to redact" section](../../sdks/python/chio-adapter-base/README.md#where-to-redact-pre-evaluation-vs-post-tool-call).
The short version:

- chio-hermes embeds the sidecar in-process (the plugin runs
  inside the Hermes process; the sidecar is a localhost HTTP
  listener mounted by the same operator). The trust boundary is
  shared, so secrets-on-the-wire is not the dominant risk;
  letting the policy see real content lets it make content-based
  decisions, and the post-tool-call hook
  (`make_post_tool_call` in
  `sdks/python/chio-hermes/src/chio_hermes/hooks.py:211`) handles
  redaction at the receipt-write boundary using
  `redact_args(tool_name, dict(args or {}),
  policy=_DEFAULT_REDACTION_POLICY)`.
- The twelve sibling adapters run agent code in a separate
  process from the sidecar (separate container, separate VM,
  separate trust boundary). On-the-wire trust favours
  pre-evaluation: `redact_args` (or `bind_and_redact` when the
  wrapper sees `(*args, **kwargs)`) runs in the wrapper before
  `ChioClient.evaluate_tool_call` is called, so the sidecar
  never sees the body bytes.

Both paths use the same `chio_adapter_base.redact` module; only
the call site differs. Choose based on your sidecar deployment
topology, not on per-tool taste.
