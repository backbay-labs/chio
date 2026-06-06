# Tool Pricing Guide

Chio tool manifests can advertise pricing metadata so operators and authorities
can plan budgets before any tool call is attempted.

Pricing metadata is advisory discovery data. The hard stop still comes from the
capability grant's monetary budget fields:

- `max_cost_per_invocation`
- `max_total_cost`

The practical flow is:

1. the tool server publishes a signed manifest with pricing
2. an operator or authority reads that quote
3. the authority issues a capability whose monetary budget is consistent with
   the advertised price and local safety margin
4. the kernel enforces the issued budget at invocation time

## Manifest Pricing Fields

Each `ToolDefinition` may include:

```json
{
  "pricing": {
    "pricing_model": "per_invocation",
    "unit_price": { "units": 25, "currency": "USD" },
    "billing_unit": "invocation"
  }
}
```

Supported pricing models:

- `flat`: one fixed base price
- `per_invocation`: one fixed unit price for each call
- `per_unit`: price scales with a declared billing unit such as `1k_tokens`
- `hybrid`: base price plus unit price

## Native Rust Example

The maintained native example in [`examples/hello-tool`](../../examples/hello-tool) now publishes pricing directly from `NativeTool`:

```rust
use chio_mcp_adapter::native::NativeTool;

let greet_tool = NativeTool::new(
    "greet",
    "Returns a personalized greeting",
    serde_json::json!({
        "type": "object",
        "properties": {
            "name": { "type": "string" }
        },
        "required": ["name"]
    }),
)
.read_only()
.per_invocation_price(25, "USD");
```

That produces manifest metadata equivalent to:

```json
{
  "name": "greet",
  "pricing": {
    "pricing_model": "per_invocation",
    "unit_price": { "units": 25, "currency": "USD" },
    "billing_unit": "invocation"
  }
}
```

## Budget Planning From A Quote

Assume a tool advertises:

- `pricing_model = per_invocation`
- `unit_price = 25 USD minor units`
- expected workload = `40` calls

Then a straightforward planning pass is:

```text
expected_total = 40 * 25 = 1000
safety_margin  = 200
grant_total    = 1200
per_call_cap   = 25
```

The corresponding `ToolGrant` is:

```rust
use chio_core::capability::{MonetaryAmount, Operation, ToolGrant};

let grant = ToolGrant {
    server_id: "srv-hello".to_string(),
    tool_name: "greet".to_string(),
    operations: vec![Operation::Invoke],
    constraints: vec![],
    max_invocations: None,
    max_cost_per_invocation: Some(MonetaryAmount {
        units: 25,
        currency: "USD".to_string(),
    }),
    max_total_cost: Some(MonetaryAmount {
        units: 1200,
        currency: "USD".to_string(),
    }),
    dpop_required: Some(true),
};
```

This does two different jobs:

- the manifest quote tells the authority what budget to issue
- the grant budget tells the kernel what to enforce

Do not collapse those concepts. A quoted price is not the enforcement boundary.

## Governed Metered Billing Quotes

Manifest pricing remains advisory discovery data. When an operator wants to
bind a concrete pre-execution quote into a governed request, Chio now supports a
typed `governed_intent.metered_billing` contract for payment-rail-neutral
metered tools.

That block carries:

- `settlement_mode`: `must_prepay`, `hold_capture`, or `allow_then_settle`
- `quote.quote_id`: stable quote identifier from the metering or billing system
- `quote.provider`: billing authority that issued the quote
- `quote.billing_unit`: unit such as `invocation` or `1k_tokens`
- `quote.quoted_units`: estimated billable units
- `quote.quoted_cost`: estimated monetary amount
- `quote.issued_at` and optional `quote.expires_at`
- optional `max_billed_units`: explicit upper bound on billable units for the
  governed request

This gives Chio a truthful two-source contract:

1. pre-execution quote and settlement posture live in
   `governed_intent.metered_billing`
2. kernel-side charged or attempted money still lives in `metadata.financial`
3. later post-execution usage evidence is reconciled through a mutable
   trust-control sidecar keyed by `receipt_id`, with report/export views that
   sit next to the signed receipt rather than rewriting it

That is intentionally different from saying the quote itself is the enforced
budget. The enforced budget is still the issued capability plus any explicit
governed `max_amount` bound.

The operational rule is strict: adapter evidence is auditable and queryable,
but signed receipt truth is immutable. Chio reports quote, kernel-observed
financial truth, and external metered evidence side by side instead of
flattening them into one mutable field.

## Planning Rules By Pricing Model

- `flat`: set `max_cost_per_invocation` to the flat quote and `max_total_cost`
  to `flat_quote * allowed_invocations`, plus any explicit margin
- `per_invocation`: same as flat, but the billing unit should remain
  `invocation`
- `per_unit`: compute a conservative per-call estimate from the expected unit
  ceiling for one call, then set `max_cost_per_invocation` to that estimate
- `hybrid`: `per_call_estimate = base_price + (unit_price * expected_units_per_call)`

When the real tool may overrun the advisory quote, set the budget from the
worst-case amount you are willing to authorize, not from the optimistic quote.

## Important Current Limitation

The current policy YAML and HushSpec authoring path does not yet encode
monetary default-capability issuance. Monetary planning happens in the
capability issuance or authority layer, not as a declarative policy shortcut.

That means the truthful flow today is:

1. publish pricing in the manifest
2. read the manifest in operator or authority code
3. issue a budgeted capability explicitly

Do not document or rely on a YAML-based pricing-to-budget pipeline that does not
exist yet.

## Safety Notes

- keep pricing currency and grant currency identical until multi-currency
  support ships
- size `max_total_cost` with HA overrun headroom in clustered deployments
- require DPoP on spend-bearing grants so quoted authority stays bound to the
  intended subject
- treat manifest pricing as operator input, not a billing truth source

## Related Docs

- [MONETARY_BUDGETS_GUIDE.md](MONETARY_BUDGETS_GUIDE.md)
- [`examples/hello-tool/README.md`](../../examples/hello-tool/README.md)
