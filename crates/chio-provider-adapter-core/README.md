# chio-provider-adapter-core

`chio-provider-adapter-core` holds the shared primitives used by Chio's
provider-native tool adapters. It exposes the `Provider` identity trait, a
fail-closed SSE stream parser and `GatedStream` result, an HTTP transport
helper with a `ProviderError` taxonomy, and shared deny-reason and
loaded-weights helpers. The crate forbids `unsafe` code.

Use this crate when implementing or refactoring a provider adapter (for
example `chio-openai` or `chio-anthropic-tools-adapter`). The cross-provider
`ProviderAdapter` trait and `ToolInvocation` shape live in
`chio-tool-call-fabric`.
