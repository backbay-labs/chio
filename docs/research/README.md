# Chio Research Notes

> These notes were written when the project was named ARC. Chio is the current
> name; treat "ARC" and references to `arc-*` crates throughout this folder as
> the historical names for Chio and its `chio-*` crates.

This folder collects working research for turning Chio from a promising security kernel into a true MCP replacement.

Read in this order:

1. [01-current-state.md](01-current-state.md)
2. [02-mcp-surface-area.md](02-mcp-surface-area.md)
3. [03-gap-analysis.md](03-gap-analysis.md)
4. [04-strategy-options.md](04-strategy-options.md)
5. [05-v1-principles.md](05-v1-principles.md)
6. [06-proposed-architecture.md](06-proposed-architecture.md)
7. [07-implementation-details.md](07-implementation-details.md)
8. [../ROADMAP_V1.md](../archive/ROADMAP_V1.md)
9. [../EXECUTION_PLAN.md](../operations/EXECUTION_PLAN.md)
10. [../DISTRIBUTED_CONTROL_PLAN.md](../operations/DISTRIBUTED_CONTROL_PLAN.md)
11. [../HA_CONTROL_AUTH_PLAN.md](../operations/HA_CONTROL_AUTH_PLAN.md)
12. [../adr/README.md](../adr/README.md)
13. [../archive/epics/README.md](../archive/epics/README.md)
14. [08-conformance-harness-research.md](08-conformance-harness-research.md)
15. [09-compatibility-matrix-design.md](09-compatibility-matrix-design.md)
16. [10-sdk-typescript-plan.md](10-sdk-typescript-plan.md)
17. [11-sdk-python-plan.md](11-sdk-python-plan.md)
18. [12-sdk-go-plan.md](12-sdk-go-plan.md)
19. [../BINDINGS_CORE_PLAN.md](../operations/BINDINGS_CORE_PLAN.md)
20. [../SDK_PARITY_EXECUTION_ROADMAP.md](../operations/SDK_PARITY_EXECUTION_ROADMAP.md)
21. [../POST_REVIEW_EXECUTION_PLAN.md](../archive/POST_REVIEW_EXECUTION_PLAN.md)

Short version:

- ARC already has the right security center of gravity: capability tokens, mediation, guards, and signed receipts.
- ARC does not yet own enough protocol surface to replace MCP.
- The most viable path is not "ignore MCP and start over."
- The most viable path is "become the secure session layer and trust plane underneath an MCP-compatible edge, then add ARC-native guarantees on top."

Primary external references used in this research:

- MCP overview: <https://modelcontextprotocol.io/specification/2025-06-18/basic/index>
- MCP lifecycle: <https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle>
- MCP authorization: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- MCP tools: <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP resources: <https://modelcontextprotocol.io/specification/2025-11-25/server/resources>
- MCP prompts: <https://modelcontextprotocol.io/specification/2025-11-25/server/prompts>
- MCP sampling: <https://modelcontextprotocol.io/specification/2025-11-25/client/sampling>
- MCP elicitation: <https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation>
- MCP roots: <https://modelcontextprotocol.io/specification/2025-11-25/client/roots>
- MCP progress: <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress>
- MCP cancellation: <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation>
- MCP tasks: <https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks>
- MCP pagination: <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination>
- MCP logging: <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/logging>
- MCP completion: <https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion>

Primary local references used in this research:

- [spec/PROTOCOL.md](../../spec/PROTOCOL.md)
- [crates/arc-core/src/message.rs](../../crates/chio-core-types/src/message.rs)
- [crates/arc-kernel/src/transport.rs](../../crates/chio-kernel/src/transport.rs)
- [crates/arc-mcp-adapter/src/lib.rs](../../crates/chio-mcp-adapter/src/lib.rs)
- [crates/arc-policy/src/compiler.rs](../../crates/chio-policy/src/compiler.rs)
- [crates/chio-control-plane/src/policy.rs](../../crates/chio-control-plane/src/policy.rs)
