# Chio-Wall Validation Package

**Milestone:** `v2.50`

---

## Purpose

`control-path validate` is the canonical close-out command for the bounded
Chio-Wall lane. It generates the control-path bundle, writes the validation
report, and emits one explicit expansion decision instead of implying a generic
barrier platform or multi-product hardening program.

---

## Command

```bash
cargo run -p chio-wall -- control-path validate --output target/chio-wall-control-path-validation
```

---

## Output Layout

```text
target/chio-wall-control-path-validation/
├── control-path/
│   ├── control-profile.json
│   ├── policy-snapshot.json
│   ├── authorization-context.json
│   ├── guard-outcome.json
│   ├── denied-access-record.json
│   ├── buyer-review-package.json
│   ├── control-package.json
│   ├── control-path-summary.json
│   └── chio-evidence/
├── validation-report.json
└── expansion-decision.json
```

---

## Supported Claim

This package supports one bounded claim only:

> Chio-Wall can record one denied cross-domain tool-access event for one
> `control_room_barrier_review` buyer motion using one fail-closed
> `tool_access_domain_boundary` control surface on Chio without turning MERCURY
> into Chio-Wall or widening into a generic barrier platform.

---

## Non-Claims

This package does not claim:

- multiple buyer motions
- complete information-barrier coverage
- generic barrier-platform breadth
- MERCURY workflow evidence readiness
- multi-product platform hardening
