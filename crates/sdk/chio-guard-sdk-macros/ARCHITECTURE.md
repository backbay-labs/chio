# chio-guard-sdk-macros architecture

## Overview

The crate is a pure code generator: `[lib] proc-macro = true` means it
compiles to a compiler plugin invoked during the caller's macro expansion,
and none of its own code ships into the final WASM binary. Its trust position
is compile-time tooling, not a runtime dependency edge - it has no `chio-*`
crate dependencies at all. The design is a single fixed-shape macro:
`#[chio_guard]` accepts exactly one function signature and rejects everything
else as a compile error, so the generated ABI surface never has to handle a
malformed guest export.

## Module map

| Path | Responsibility |
|------|-----------------|
| `src/lib.rs` | The entire crate: `validate_guard_fn` (signature validation), `type_path_ends_with_ident` (syntactic type-name matching), and the `chio_guard` attribute macro (token generation). Unit tests for the validator live inline under `#[cfg(test)] mod tests`. |

## Boundaries

- `chio-guard-sdk` owns the guest-side runtime ABI: request decoding
  (`read_request`), verdict encoding (`encode_verdict`), allocator exports
  (`alloc`), and structured deny-reason serialization (`glue`).
- `chio-wasm-guards` owns the host side: loading a `.wasm` module,
  instantiating it with fuel and memory limits, writing the request into
  guest linear memory, and calling the exported `evaluate` function. It
  defines its own host-side `GuardRequest`/`GuardVerdict` and
  `VERDICT_ALLOW`/`VERDICT_DENY` in `abi.rs`, mirroring the guest-side types
  across the WASM boundary rather than sharing them.
- This crate owns only compile-time validation and code generation: it turns
  a guard author's function into the tokens that satisfy both of the above.

## Macro expansion

1. `chio_guard` parses the annotated item as a `syn::ItemFn` via
   `parse_macro_input!`.
2. `validate_guard_fn` checks the signature. On the first failure it returns
   a `syn::Error`; the macro converts it with `err.to_compile_error()` and
   returns immediately, so the caller sees a compile error rather than
   expanded code.
3. On success, the original function is renamed to `__chio_guard_user_<name>`
   via `format_ident!`, keeping its attributes, visibility, and body
   unchanged.
4. `quote!` emits, in order: re-exports of `chio_guard_sdk::alloc::{chio_alloc,
   chio_free}` and `chio_guard_sdk::glue::chio_deny_reason`; the renamed
   function; and the `#[no_mangle] pub extern "C" fn evaluate(ptr: i32, len:
   i32) -> i32` entry point.
5. The generated `evaluate` calls `chio_guard_sdk::read_request` (unsafe,
   from the raw `ptr`/`len` pair) and returns `chio_guard_sdk::VERDICT_DENY`
   on decode failure; otherwise it calls the renamed function and passes the
   result to `chio_guard_sdk::encode_verdict`.
6. The `chio_guard_sdk::*` paths in the expansion are unresolved names at
   macro-expansion time. They resolve only when the caller's crate, which
   must itself depend on `chio-guard-sdk`, compiles the expanded tokens.

## Invariants and failure modes

- Validation is fail-closed on shape: async, const, unsafe, non-Rust ABI,
  generic, variadic, method-receiver, wrong-argument-count, and wrong-name
  signatures are all rejected before any tokens are generated.
- `type_path_ends_with_ident` matches only the final path segment name
  (`GuardRequest`, `GuardVerdict`). It cannot resolve full type identity
  because proc-macros run before type checking; a same-named type from an
  unrelated module still passes this check and is only caught by the
  ordinary Rust compiler once the expansion is type-checked.
- The generated ABI entry point fails closed at the decode boundary: if
  `read_request` cannot decode the guest linear-memory buffer, it returns
  `chio_guard_sdk::VERDICT_DENY` without calling the user function.
- The exported symbol name is fixed at `evaluate`, so the macro can be
  applied at most once per module: a second application would re-declare the
  same `#[no_mangle] extern "C" fn evaluate` and the same
  `chio_alloc`/`chio_free`/`chio_deny_reason` re-exports.

## Dependencies

No internal `chio-*` crate dependencies. External: `syn` (`features =
["full"]`) for parsing the annotated item into an AST, `quote` for building
the output `TokenStream`, and `proc-macro2` for the underlying token types.
The coupling to `chio-guard-sdk` is a naming contract in the generated
tokens, not a `Cargo.toml` dependency edge; guard crates add
`chio-guard-sdk` themselves for the expansion to compile.
