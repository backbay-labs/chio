# Chio Error Registry

`registry.yaml` is the source of truth for stable Chio error URNs. It sits
beside `chio-error-registry.v1.json`, which remains the wire-side numeric
JSON-RPC registry. The URN registry points one way into the numeric registry
with optional `jsonrpc_code` values.

Each entry carries:

- `urn`: `urn:chio:error:<domain>:<code>`
- `domain`: one of the eighteen seed domains
- `severity`: `info`, `warning`, `error`, or `fatal`
- `summary` and `help`: user-facing diagnostic text
- `string_code`: machine-readable string error code for existing `CHIO-*` surfaces
- `jsonrpc_code`: optional pointer to `chio-error-registry.v1.json`
- `since`: semver tag for the registry entry
- `stability`: `stable`, `unstable`, or `deprecated`
- `consumed_by`: crate names expected to consume or emit the entry

The first seed spans the ten core domains plus the eight reserved domains so
later consumers can add codes without adding domains.
