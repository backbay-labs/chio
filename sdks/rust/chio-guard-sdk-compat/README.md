# chio-guard-sdk-compat (compatibility path)

Rust compatibility package for the `chio:guard@0.2.0` guest SDK. This crate is
a thin shim that re-exports the canonical workspace crate at
`crates/chio-guard-sdk` without changing any request or verdict call sites. The
package is named `chio-guard-sdk-compat` to avoid colliding with the canonical
workspace package, but it still builds a library named `chio_guard_sdk` (see the
`[lib]` table) so existing `use chio_guard_sdk::...` imports keep working.

New guard authors should depend on the canonical `crates/chio-guard-sdk`
directly. This path exists to keep existing imports working.
