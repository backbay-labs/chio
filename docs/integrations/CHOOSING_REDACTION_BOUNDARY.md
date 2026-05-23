# Choosing the redaction boundary: pre-evaluation vs post-tool-call

This page is the standalone decision-tree mirror for the "Where to
redact" guidance in
[`sdks/python/chio-adapter-base/README.md`](../../sdks/python/chio-adapter-base/README.md#where-to-redact-pre-evaluation-vs-post-tool-call).
That README is the single source of truth for the comparison table,
the prose, and the canonical decision tree; this page extracts the
decision tree into a docs-tree-discoverable form so readers landing
in `docs/` can find it without grepping into `sdks/python/`.

## When to use which pattern

There are two valid places to redact tool args, and they trade off
defense-in-depth against per-call forensics:

- **Pre-evaluation** (every chio sibling adapter except chio-hermes):
  redact in the wrapper BEFORE handing args to
  `ChioClient.evaluate_tool_call`. The sidecar (and its receipt
  log) never sees body bytes. Suitable when the sidecar runs in a
  separate process from the agent (different trust boundary) and
  the operator policy is path-based, not content-based.
- **Post-tool-call** (chio-hermes): send raw args to
  `evaluate_tool_call`, then redact at the receipt-write boundary.
  Policy can make content-based decisions; the trade-off is that
  body bytes flow through the sidecar. Suitable when the sidecar
  shares a trust boundary with the agent process.

## Decision tree

The tree picks BOTH a pattern and a helper. Walk Q1 first; the
answer constrains Q2.

1. **Does your adapter run agent code in a separate process from
   the Chio sidecar (separate container, separate VM, separate
   trust boundary)?** -> Yes: **pre-evaluation**. Skip Q2 and go
   to Q3 for helper selection.
2. **(Only if Q1 was NO.) Does your adapter's policy need to make
   decisions based on field content?** -> Yes: **post-tool-call**.
   No: **pre-evaluation** is fine; defense-in-depth is still cheap
   when the trust boundary is shared. (If you answered YES to Q1,
   content-aware policy is incompatible with pre-evaluation;
   either redesign the policy to be path-based or move it
   server-side onto the same trust boundary as the agent.)
3. **(Helper selection.) Does your wrapper see the tool call as a
   pre-named `dict` or as `(*args, **kwargs)`?** -> Pre-named
   dict: call `redact_args` directly. `(*args, **kwargs)`: call
   `bind_and_redact`.
4. **First redaction call in a brand-new adapter?** -> Default to
   **pre-evaluation** with `bind_and_redact`.

## Cross-links

- README source of truth:
  [`sdks/python/chio-adapter-base/README.md`](../../sdks/python/chio-adapter-base/README.md#where-to-redact-pre-evaluation-vs-post-tool-call)
- Adapter-author migration recipe:
  [`sdks/python/chio-adapter-base/ADAPTER-MIGRATION.md`](../../sdks/python/chio-adapter-base/ADAPTER-MIGRATION.md)
- Integration overview and per-adapter pin matrix:
  [`docs/integrations/CHIO-ADAPTER-BASE.md`](CHIO-ADAPTER-BASE.md)
- Release notes for the 0.2.0 helper hardening:
  [`docs/integrations/RELEASE_NOTES_v0.2.0.md`](RELEASE_NOTES_v0.2.0.md)
