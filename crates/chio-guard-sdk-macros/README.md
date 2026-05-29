# chio-guard-sdk-macros

`chio-guard-sdk-macros` is the proc-macro crate for the Chio WASM guard SDK. It
provides the `#[chio_guard]` attribute macro that transforms a plain
`fn evaluate(req: GuardRequest) -> GuardVerdict` into a complete WASM guard
binary with all ABI exports: the `evaluate` entry point, the
`chio_alloc` / `chio_free` allocator re-exports, and the `chio_deny_reason`
structured deny-reason re-export.

This crate is re-exported through `chio-guard-sdk`; guard authors normally
depend on the SDK rather than these macros directly.
