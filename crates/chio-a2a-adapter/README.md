# chio-a2a-adapter

`chio-a2a-adapter` is a thin A2A-to-Chio adapter for agent-card discovery and
`SendMessage` mediation. It loads an A2A agent card, maps the remote agent's
surface into a Chio `ToolManifest`, and routes `SendMessage` traffic through
the kernel so capability validation, the egress contract, and receipt signing
apply to cross-agent calls.

Use this crate to govern calls to an external A2A agent. It is a mediation
shim, not a full A2A server; the HTTP edge that exposes Chio over A2A is
`chio-a2a-edge`.
