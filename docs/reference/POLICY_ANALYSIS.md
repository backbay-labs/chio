# Policy Analysis

`chio policy analyze` checks an effective HushSpec policy for redundant or
conflicting rules and can compare a candidate policy with an older policy.
The comparison asks whether every input admitted by the candidate is also
admitted by the older policy.

```bash
chio policy analyze policy.yaml
chio policy analyze new.yaml --against old.yaml --format json
chio policy analyze policy.yaml --fail-on notice --max-atoms 20000
```

Inheritance is resolved before analysis. Each source document is limited to
4 MiB, inheritance chains are limited to 32 documents, and the default policy
limit is 10,000 authored atoms. Invalid YAML, invalid HushSpec, and exhausted
analysis limits fail closed. Glob products also have hard state, transition, and
alphabet-construction budgets shared by the whole analysis. Matcher comparisons,
production-evaluator confirmations, and emitted findings have aggregate caps
derived from the atom limit, so adversarial rule sets fail with exit code 2
instead of expanding quadratic work or output. Finite action sets use exact set
relations before a widening witness is confirmed by the production evaluator.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | No finding reached the configured `--fail-on` threshold. |
| `1` | At least one finding reached the threshold. |
| `2` | Loading, parsing, validation, or bounded analysis failed. |

`--fail-on` accepts `notice`, `warning`, or `error` and defaults to
`warning`. Opaque fields are notices, so they are visible without making the
default gate noisy.

## Analysis Boundary

The analyzer decides glob relations using a bounded product construction over
the same `*`, `**`, `?`, slash, and newline semantics used by the reference
evaluator. Exact set and Boolean fields and supported numeric boundaries are
lowered into the same analysis IR. Every configured field outside that
fragment is emitted in `not_analyzed`.

Policy comparison produces one of three statuses:

- `refines`: no widening exists in the supported fragment.
- `does_not_refine`: the report includes a concrete input admitted by the new
  policy and denied by the old policy. The production evaluator confirms the
  witness before it is emitted.
- `inconclusive`: a changed field uses semantics outside the bounded fragment.

An inconclusive comparison is an error-severity finding. It is never promoted
to `refines`.

## JSON Schema

JSON output uses schema identifier `chio.policy-analysis.v1`. The
machine-readable schema is `spec/schemas/policy/analysis-report.schema.json`.

```json
{
  "schema": "chio.policy-analysis.v1",
  "policy_sha256": "<effective-policy-sha256>",
  "against_sha256": "<comparison-policy-sha256>",
  "findings": [
    {
      "id": "REFINE-0001",
      "kind": "refinement_failure",
      "severity": "error",
      "block": "tool_access",
      "rule_ref": {
        "field": "allow",
        "index": 1,
        "pattern": "repo.write"
      },
      "message": "new policy admits an input denied by the comparison policy",
      "witness": {
        "action_type": "tool_call",
        "target": "repo.write"
      }
    }
  ],
  "not_analyzed": [],
  "refinement": { "status": "does_not_refine" },
  "summary": { "errors": 1, "warnings": 0, "notices": 0 }
}
```

`policy_sha256` uses the same effective-policy hash function as HushSpec audit
receipts. Finding IDs are assigned deterministically within each report.
Fail-closed JSON errors are written to stderr with schema identifier
`chio.policy-analysis.error.v1` and a non-empty `error` string.

This is executable static analysis, not a formal verification claim. The
formal proof boundary remains defined by `formal/proof-manifest.toml`.
