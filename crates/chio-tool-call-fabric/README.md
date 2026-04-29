# chio-tool-call-fabric

Provider-agnostic tool-call fabric for Chio LLM adapter integrations.

This crate hosts the shared `ProviderAdapter` trait surface, the canonical
`ToolInvocation` shape, the `ProvenanceStamp` contract, and the streaming
state machine consumed by per-provider adapters (`chio-openai`,
`chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`). Each
adapter implements `lift(ProviderRequest) -> ToolInvocation` and
`lower(VerdictResult, ToolResult) -> ProviderResponse` so verdict-time
enforcement and receipt emission stay identical across providers.

T1 (this commit) scaffolds the workspace member; T2-T6 fill in the trait
surface, provenance signing helper, streaming state machine, and
lift/lower conformance fixtures. See
`.planning/trajectory/07-provider-native-adapters.md` Phase 1 for the
authoritative spec.
