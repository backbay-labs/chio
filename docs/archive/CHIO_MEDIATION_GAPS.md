# CHIO Mediation Gaps - Kernel Work Items Surfaced by Demo Hardening

This document tracks two kernel-level gaps that prevent CLI-mediated
`chio check` paths from enforcing spend-aware guards, surfaced during
the tiny-hedge-fund demo hardening. Both gaps have been worked
around at the `chio-bridge` layer (see `chio-bridge@0.2.2` release
notes) and are blocked for a clean upstream fix in arc itself.

Neither gap is a regression; both have been latent since
`chio-bridge@0.2.2` when `rules.velocity` and `rules.human_in_loop`
re-landed as first-class rule variants on `chio-policy`. The MCP-edge path
(daemon mode via `chio mcp serve-http`) is similarly affected: the
edge does not synthesise governed intents or per-invocation cost
estimates from `tools/call` metadata.

---

## Gap 3: Missing `governed_intent` synthesis for `rules.human_in_loop.approve_above`

### Symptom

Policies that set `rules.human_in_loop.approve_above: <cents>` compile
to a `Constraint::RequireApprovalAbove { threshold_units }` kernel
constraint. When that constraint evaluates against a tool call that
lacks a `governed_intent` on the request envelope, the approval guard
fail-closes with:

```text
RequireApprovalAbove requires a governed intent with max_amount (threshold=<N>)
```

The CLI (`chio check --policy <path> --tool <name> --params <json>`)
has no surface for attaching a `GovernedTransactionIntent`, so every
tool call under a policy with `approve_above` set is denied - even
calls whose params carry an obvious-to-a-human dollar amount.

### Kernel path

- Enforcement:
  `arc/crates/chio-kernel/src/approval.rs:518-550`
  (`ApprovalPolicy::evaluate` → `Constraint::RequireApprovalAbove`
  branch: `governed_intent.as_ref().and_then(|i| i.max_amount.as_ref())`
  returns `None` → returns `HitlVerdict::Deny`).
- Request envelope:
  `arc/crates/chio-kernel/src/approval.rs:96`
  (`pub governed_intent: Option<GovernedTransactionIntent>` on the
  `ApprovalRequest`).
- Request-matching entry point:
  `arc/crates/chio-kernel/src/request_matching.rs` (grep
  `governed_intent`) - the CLI-mediation dispatcher forwards the
  request envelope to the guards pipeline verbatim; no synthesis
  hook between parse and match.

### Why CLI paths don't produce `governed_intent`

`chio check` accepts `--params <json>` but has no understanding of
which param slot represents a monetary amount, nor which currency.
Adding a `--governed-intent-amount-usd` flag is brittle (wrong level
of abstraction; every policy's tool inventory is different).

### Proposed fix (choose one)

1. **Policy-level tool → cost table.** Extend `chio-policy`'s
   `human_in_loop` block with an optional
   `tool_cost_estimators: {<tool_name>: {param: "qty", mul: {param: "price"}}}`
   map that the kernel resolves into a synthetic `GovernedTransactionIntent`
   at request-matching time. **Recommended** - it keeps the policy
   self-describing and auditable; no CLI API surface churn.
2. **Hook-side intent on PreToolUse stdin.** Extend the Claude Code
   / Codex / OpenCode PreToolUse JSON shape with a
   `governed_intent: {max_amount: {units: ..., currency: "USD"}}`
   field; the `chio-bridge` pretooluse hook synthesises it from a
   plugin-author-supplied cost oracle and forwards on stdin to
   `chio check`. Requires a new CLI flag
   (`--governed-intent-stdin`) and an opt-in parse path in
   `chio-cli/src/cli/types.rs::Check`.
3. **Kernel default-to-zero when absent.** Change
   `approval.rs:540-548` so that `None` on
   `governed_intent.max_amount` is treated as `units = 0` (i.e.
   "below threshold") rather than a fail-closed deny. **Not
   recommended** - silently under-enforces a rule the policy
   author explicitly set.

The `chio-bridge@0.2.2` release re-landed the `human_in_loop` rule variant;
the block therein is effectively unreachable today from CLI-mediated flows.
The bridge-side workaround
(`chio-hedge-fund-demo/policy/hedge.policy.runtime.yaml`) omits
`approve_above` to unblock the demo's runtime, and retains
`hedge.policy.yaml` as the shipping spec so the gap is documented
at the policy layer.

---

## Gap 4: Missing `max_cost_per_invocation` synthesis for `rules.velocity.max_spend_per_window`

### Symptom

Policies that set `rules.velocity.max_spend_per_window: <cents>` compile
to a velocity guard that, on every check, invokes:

```text
// chio-guards/src/velocity.rs:201-210
grant
    .max_cost_per_invocation
    .as_ref()
    .map(|amount| amount.units)
    .ok_or_else(|| {
        KernelError::Internal(
            "velocity guard spend limiting requires max_cost_per_invocation on the matched grant".to_string(),
        )
    })
```

The CLI-mediation path issues no capability at all before
`chio check`, so the matched grant's `max_cost_per_invocation` is
`None`, and every call through the velocity guard's spend branch
errors out with the `KernelError::Internal` shown above. Net effect:
a policy that sets a spend window without also (manually) attenuating
every capability grant with a per-invocation cap is fail-closed on
every call.

### Kernel path

- Enforcement:
  `arc/crates/chio-guards/src/velocity.rs:171-187` (the
  `self.config.max_spend_per_window` arm) calls
  `planned_spend_units(ctx)` at lines 190-211, which requires
  `grant.max_cost_per_invocation` to be `Some(...)`.
- Grant type:
  `arc/crates/chio-core-types/src/capability.rs` (grep
  `max_cost_per_invocation`) - `Option<MonetaryAmount>` on `ToolGrant`,
  populated at capability-issuance time via
  `POST /v1/capabilities/issue`'s `scope.grants[].maxCostPerInvocation`.
- Policy → kernel translation:
  `arc/crates/chio-policy/src/compiler.rs` compiles
  `rules.velocity.max_spend_per_window` → `VelocityGuardConfig`;
  there is no cross-reference between `velocity` and each grant's
  `max_cost_per_invocation` at compile time.

### Why CLI paths don't synthesise it

The CLI `chio check` path has no concept of a capability at all; it
evaluates the policy as a standalone HushSpec against the provided
tool + params. The kernel assumes a bonded capability is in flight
and that grants were pre-attenuated with per-invocation caps. For
MCP-edge paths (`chio mcp serve-http`), the capability IS in flight
- but the edge doesn't stamp a `max_cost_per_invocation` on freshly
issued grants when the policy's `velocity.max_spend_per_window`
implies one.

### Proposed fix

Recommended: **arc-side default for grant synthesis in the policy
compiler.** When `rules.velocity.max_spend_per_window` is set and a
matched grant has no `max_cost_per_invocation`, treat the call as
if the grant exposed zero cost - pass the velocity spend branch as a
no-op (Verdict::Allow for this call) rather than fail-closed with
a KernelError. Gate this behind a policy-level opt-in
(`rules.velocity.default_grant_cost_to_zero: true`) so older callers
that rely on the hard-fail signal keep today's semantics. Compatible
with both CLI and MCP-edge mediation.

Alternative: **policy compiler rewrites grants at compile time.** The
compiler could splice a default `max_cost_per_invocation` onto every
grant when the policy carries `max_spend_per_window`; value source
would be a new `rules.velocity.default_cost_per_invocation_units`
knob. More explicit than the opt-in above, but it requires every
policy author to remember the knob exists. Less ergonomic.

Either way, the fix is compiler-side, not guard-side.

### Bridge-side workaround (shipped in chio-bridge@0.2.2)

`chio-bridge@0.2.2` implements a bridge-owned spend ledger over the
trust plane's existing `POST /v1/budgets/authorize-exposure`
endpoint (see `arc/crates/chio-control-plane/src/trust_control/http_handlers_b.rs:2214`
and `service_types.rs:2041-2062`). A new
`ChioBridge.check(call, {capabilityId, costUsd})` option threads the
bonded capability id + per-call cost into that endpoint; the trust
plane's budget store accumulates spend per `(capability_id, grant_index)`
and returns `allowed: false` once cumulative exposure exceeds
`maxTotalExposureUnits`. The bridge maps `allowed: false` to
`{decision: "cancelled", guard: "velocity"}`. Cost attribution is
pluggable via `CHIO_COST_ORACLE_PATH` (the PreToolUse hook dynamically
imports an operator-supplied module). The hedge-fund demo's oracle
(`chio-hedge-fund-demo/scripts/cost-oracle.mjs`) computes
`place_order` cost as `qty * quote.ask_price` from the demo's fixture.

This works around Gap 4 without modifying arc, but it leaves the
kernel's velocity guard dark for every non-bridge consumer. The
upstream fix is still required.

---

## References

- Work that landed `velocity` + `human_in_loop` as first-class rule variants:
  `chio-policy/src/models.rs::Rules` (rename from `arc-policy`).
- Bridge workaround: `chio-bridge@0.2.2`:
  `standalone/chio-bridge/src/check.ts` -> `mediateBudget`;
  `standalone/chio-bridge/src/index.ts::bond` and
  `deriveCapabilityScopeFromPolicy`.
- Kernel file:line citations in this doc were validated against the
  `chio-bridge@0.2.2` snapshot of arc. If the kernel refactors approval
  or velocity, re-anchor the lines before quoting.
