# Verdict Matrix Scenario Format

This directory holds the cross-SDK verdict comparison corpus, drivers, and
diff oracle. This document fixes the scenario shape every driver shares.

## File Layout

Scenarios are JSON files under `scenarios/`. Each file contains one scenario.
The manifest at `manifest.toml` records the active scenario root, driver set,
scenario count, and corpus hash pin.

## Required Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Must be `chio.verdict-matrix.scenario.v1`. |
| `id` | string | Stable kebab-case identifier. |
| `title` | string | Human-readable scenario title. |
| `category` | string | One of `capability`, `revocation`, `replay`, `redaction`, `receipt`, `delivery_contract`, or `finding_purchase`. |
| `description` | string | Short description of the boundary being checked. |
| `script` | table | Driver-neutral inputs for the SDK under test. |
| `expected` | table | Expected semantic verdict tuple. |

## Optional Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `tags` | array of strings | Extra selectors for local and CI runs. |
| `requires` | array of strings | Capabilities a driver must support to run the scenario. |
| `artifacts` | array of strings | Artifact names the driver should emit. |
| `timeout_ms` | integer | Per-scenario timeout override. |

## Verdict Tuple

The `expected` table has this shape:

```toml
[expected]
verdict = "allow"
reason_code = "urn:chio:error:none"
scope_set = ["tool:read"]
```

`verdict` is one of `allow`, `deny`, or `error`. `reason_code` is a string
identifier from the shared Chio error registry when the registry is available.
`scope_set` is sorted lexicographically before comparison. Drivers may emit
additional diagnostics, but the diff oracle compares only this tuple.

## Script Table

The `script` table is driver-neutral. It must describe the same logical
operation for every SDK without naming SDK internals.

```json
{
  "schema": "chio.verdict-matrix.scenario.v1",
  "id": "capability-read-only-allows-read",
  "title": "Read-only capability allows read",
  "category": "capability",
  "description": "A read-only scope permits a read operation and no broader access.",
  "tags": ["scaffold-example"],
  "requires": ["rust-kernel"],
  "script": {
    "operation": "tool.call",
    "tool": "files.read",
    "input_json": "{\"path\":\"README.md\"}",
    "capability_scopes": ["tool:read"],
    "required_scope": "tool:read"
  },
  "expected": {
    "verdict": "allow",
    "reason_code": "urn:chio:error:none",
    "scope_set": ["tool:read"]
  }
}
```

## Compatibility Rules

- Unknown top-level fields are rejected by loaders.
- Unknown fields inside `script` are preserved for driver-specific evolution.
- Missing required fields fail closed during scenario load.
- A driver that cannot run a scenario reports `unsupported`, not `pass`.
- Scenario IDs are stable once added to the manifest.
