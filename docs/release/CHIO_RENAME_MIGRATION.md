# Chio Rename Migration Guide

**Status:** cutover update

## Goal

Complete the Chio rename in a way that is survivable for operators, SDK
consumers, and historical artifact verification without keeping deprecated
brand aliases on maintained runtime surfaces.

## Cutover Contract

The rename uses a Chio-only runtime contract:

- Chio becomes the primary product name and documented entrypoint
- historical Chio artifacts remain verifiable when they already use Chio
  identifiers
- maintained runtime, CLI, SDK, protocol, and formal-verification surfaces do
  not keep deprecated brand aliases

## Migration Matrix

| Surface | Chio behavior |
|---------|---------------|
| Rust crates | `chio-*` names are canonical; historical package names are not maintained |
| CLI binary | `chio` is the only documented binary |
| CLI docs/examples | Chio examples are canonical |
| TypeScript SDK | Chio package names are canonical |
| Python SDK | Chio distribution and import names are canonical |
| Go SDK | Chio module paths are canonical |
| Environment variables | `CHIO_*` names are canonical where the runtime exposes branded envs |
| Signed artifacts | `chio.*` artifact families are canonical |
| Portable-trust identity | `did:chio` is the shipped canonical DID method |
| Native service authoring API | `NativeChioServiceBuilder` / `NativeChioService` are canonical |
| MCP streaming extension | `chioToolStreaming` / `chioToolStream` are canonical |

## Intentional Compatibility Decisions

The post-sweep contract is:

- frozen and canonical: `did:chio`, `chio.*` artifact schema IDs, and
  `notifications/chio/tool_call_chunk`
- removed deprecated aliases across identity, native service, and streaming
  extension surfaces
- not kept: historical branding across maintained docs, examples, crate names,
  or primary CLI/package surfaces

## Rollout Order

1. **Inventory and contract**
   Finish the inventory and contract step before renaming code or packages.

2. **Workspace and packaging**
   Rename repo metadata, crates, CLI, and SDK package surfaces.

3. **Protocol and identity**
   Apply schema and DID transition work after verifiers/importers
   are ready for Chio-only identifiers.

4. **Docs and qualification**
   Rewrite public/operator docs and run full Chio qualification.

## Operator Notes

- do not rewrite stored historical receipts or passports just to match the new
  name
- upgrade verifiers/importers before switching issuance defaults
- use `CHIO_MCP_SESSION_*` env names

## SDK Consumer Notes

- expect package rename guidance per ecosystem during the packaging step
- prefer Chio-branded imports/examples once they ship
- do not rely on deprecated import aliases
