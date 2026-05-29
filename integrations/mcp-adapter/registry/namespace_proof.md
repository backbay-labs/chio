# MCP Registry Namespace Proof

Namespace: `dev.chio`

Validation method for the registry submission: GitHub challenge in the
`backbay-labs/chio` repository. DNS challenge remains the fallback if the
registry reviewer requires domain-level proof for `chio.world`.

Planned challenge record:

- Repository: `https://github.com/backbay-labs/chio`
- File: `.well-known/mcp-registry/dev.chio.json`
- Subject: `dev.chio`
- Contact: `security@chio.world`

This record is prepared before submission so M10.P5 can submit the registry
entry without changing the namespace proof shape.
