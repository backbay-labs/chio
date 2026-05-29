# chio-tool-call-fabric

Provider-agnostic tool-call fabric for Chio LLM adapter integrations.

This crate hosts the shared `ProviderAdapter` trait surface, the canonical
`ToolInvocation` shape, the `ProvenanceStamp` contract, and the streaming
state machine consumed by per-provider adapters (`chio-openai`,
`chio-anthropic-tools-adapter`, `chio-bedrock-converse-adapter`). Each
adapter implements `lift(ProviderRequest) -> ToolInvocation` and
`lower(VerdictResult, ToolResult) -> ProviderResponse` so verdict-time
enforcement and receipt emission stay identical across providers.

The trait surface, provenance signing helper, streaming state machine, and
lift/lower conformance fixtures are shared by every provider adapter, so a
single Chio policy file enforces uniformly across OpenAI Responses, Anthropic
Messages, and Bedrock Converse. See `spec/PROTOCOL.md` for the normative
wire-level spec.
