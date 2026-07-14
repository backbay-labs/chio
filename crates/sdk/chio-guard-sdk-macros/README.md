# chio-guard-sdk-macros

`chio-guard-sdk-macros` is a proc-macro crate (`[lib] proc-macro = true`) that
provides the `#[chio_guard]` attribute macro for the Chio WASM guard SDK.
Applied to a plain `fn evaluate(req: GuardRequest) -> GuardVerdict`, it
validates the signature at compile time and expands the function into the
full WASM ABI surface a Chio guard binary must export. It has no runtime
footprint of its own: everything it produces is Rust source tokens, resolved
when the caller's crate compiles.

## Responsibilities

- Validate that the annotated function is exactly `fn evaluate(req:
  GuardRequest) -> GuardVerdict`: correct name, synchronous, safe,
  non-generic, non-variadic, a free function (no receiver), with a single
  argument and matching argument/return type names. Any violation is a
  `syn::Error` compile error, not a runtime failure.
- Rename the validated function to `__chio_guard_user_<name>`, preserving its
  attributes, visibility, and body.
- Generate the `#[no_mangle] pub extern "C" fn evaluate(ptr: i32, len: i32) ->
  i32` entry point that decodes the request, calls the renamed function, and
  encodes the verdict.
- Re-export `chio_alloc`, `chio_free`, and `chio_deny_reason` from
  `chio_guard_sdk` so the compiled WASM module exposes them as top-level ABI
  exports.

## Public API

- `chio_guard` (`#[proc_macro_attribute]`) - annotate `fn evaluate(req:
  GuardRequest) -> GuardVerdict`. Takes no macro arguments; any are ignored.

## Usage

```rust,ignore
use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    if req.tool_name == "dangerous_tool" {
        GuardVerdict::deny("tool is blocked by policy")
    } else {
        GuardVerdict::allow()
    }
}
```

## Testing

`cargo test -p chio-guard-sdk-macros` runs the unit tests for
`validate_guard_fn`. Macro-expansion output is exercised indirectly:
`examples/guards/tool-gate` and `examples/guards/enriched-inspector` apply
`#[chio_guard]` and compile as workspace members.

## See also

- `chio-guard-sdk` - the runtime SDK the generated code calls into (`alloc`,
  `glue`, `read_request`, `encode_verdict`, `VERDICT_DENY`). A sibling
  dependency, not a re-export: guard crates depend on both directly.
- `chio-wasm-guards` - the host-side loader that instantiates the compiled
  guard module and calls its exported `evaluate` function.
- `chio-cli` - scaffolds new guard crates whose generated `Cargo.toml`
  depends on both `chio-guard-sdk` and this crate.
