# MCP Registry Namespace Proof

Namespace: `dev.chio`

Validation method for trajectory-3 submission: GitHub challenge in the
`backbay/chio` repository. DNS challenge remains the fallback if the
registry reviewer requires domain-level proof for `chio.dev`.

Planned challenge record:

- Repository: `https://github.com/backbay/chio`
- File: `.well-known/mcp-registry/dev.chio.json`
- Subject: `dev.chio`
- Contact: `security@chio.dev`

This record is prepared before submission so M10.P5 can submit the registry
entry without changing the namespace proof shape.
