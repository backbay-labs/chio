# chio-policy Architecture Notes

## Boundaries

- `models.rs` owns the HushSpec schema, YAML parser hardening, rule-block
  inventory, and extension structs.
- `validate.rs` owns schema and semantic validation before policies are
  compiled or evaluated.
- `merge.rs` and `resolve.rs` own inheritance, deep merge, and filesystem
  resolution.
- `evaluate/*` owns the reference allow, warn, and deny evaluator, including
  condition filtering, posture transitions, and origin profile selection.
- `compiler.rs` owns translation from HushSpec intent into Chio guard
  pipelines, post-invocation hooks, and default `ChioScope` fragments.
- `receipt.rs` owns audited evaluation receipts. The crate does not own guard
  internals, receipt signing, capability verification, or persistent runtime
  state.

## Current Pain Point

`rules.tool_access.require_workload_identity.path_prefixes` is a policy
admission boundary for SPIFFE/SVID-style runtime identities. The evaluator
currently treats configured path prefixes as raw strings, so a policy prefix
such as `/payments` can also match a sibling workload path such as
`/payments-v2/worker`. That silently widens runtime identity admission beyond
the path segment the operator named. The compiler already fails closed for
workload-identity requirements when building default scopes because capability
grants cannot encode that predicate, so the reference evaluator is the owning
boundary that must preserve the identity semantics.

## Security And API Constraints

- Invalid HushSpec documents must reject before guard or scope materialization.
- Public parser, validator, compiler, and evaluator APIs should remain
  compatible.
- Workload identity path prefixes must match either the exact workload path or
  a child segment boundary, never a sibling string prefix.
- The root prefix `/` should keep matching all canonical workload paths.
- Trailing slash input in policy prefixes should remain compatible by
  normalizing to the same segment boundary.
- Existing tool allow/block/default semantics, runtime-assurance checks,
  warning-only workload identity preferences, posture checks, conditions, and
  default-scope compilation must remain stable.

## Affected Dependents

The owning-crate change is internal to `chio-policy` and affects callers of the
reference evaluator, including control-plane and CLI policy-check paths that
evaluate HushSpec tool access rules with runtime attestation context. No
dependent API change is planned. `chio-core` already owns SPIFFE workload
identity parsing and binding; this slice aligns policy matching with that
canonical path shape.

## Implemented Improvement

Workload identity matching now evaluates `path_prefixes` through a segment
boundary helper. Regression coverage proves `/payments-v2/worker` no longer
satisfies `/payments`, while exact and child-segment matches continue to pass.
