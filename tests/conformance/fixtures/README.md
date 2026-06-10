# Shared Fixtures

This directory holds shared conformance assets such as:

- policy files
- manifests
- mock transcripts
- reusable upstream server fixtures

`mcp_core/` contains:

- `mock_mcp_server.py`
  Minimal stdio MCP server used by the live remote HTTP harness.
- `policy.yaml`
  Chio policy that grants the wrapped MCP core fixture tool, resource, and prompt access.
