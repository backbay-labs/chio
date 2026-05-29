# chio-external-guards

`chio-external-guards` hosts the concrete HTTP-backed guard adapters (cloud
guardrail and threat-intel guards) that need an HTTP transport dependency. The
generic async adapter, retry, caching, and circuit-breaker infrastructure
itself lives in `chio-guards`; this crate provides the specific external
integrations layered on top of it.

Use this crate when wiring Chio's guard pipeline to an external moderation or
threat-intelligence service.
