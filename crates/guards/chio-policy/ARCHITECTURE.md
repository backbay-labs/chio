# chio-policy Architecture Notes

## Boundaries

- `models.rs` owns the HushSpec schema, YAML parser hardening, rule-block
  inventory, and extension structs. Parser hardening and schema regression
  tests live in `models/tests.rs`.
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

## Workload Identity Path Matching

`rules.tool_access.require_workload_identity.path_prefixes` is a policy
admission boundary for SPIFFE/SVID-style runtime identities. The evaluator owns
this boundary: the compiler fails closed for workload-identity requirements when
building default scopes because capability grants cannot encode the predicate,
so the evaluator must preserve the identity semantics directly.

Path prefixes match on segment boundaries, not raw string prefixes. A prefix
such as `/payments` must not match a sibling workload path such as
`/payments-v2/worker`, which would silently widen runtime identity admission
beyond the path segment the operator named. `chio-core` owns SPIFFE workload
identity parsing and binding; policy matching follows that canonical path shape.

## Security And API Constraints

- Invalid HushSpec documents must reject before guard or scope materialization.
- Public parser, validator, compiler, and evaluator APIs are stable.
- Workload identity path prefixes match either the exact workload path or a
  child segment boundary, never a sibling string prefix.
- The root prefix `/` matches all canonical workload paths.
- Trailing slash input in policy prefixes normalizes to the same segment
  boundary.
- Tool allow/block/default semantics, runtime-assurance checks, warning-only
  workload identity preferences, posture checks, conditions, and default-scope
  compilation are stable.
