# chio-lsp architecture

## Overview

`chio-lsp` is an editor-facing language server: an edge process that speaks
LSP over stdio to a text editor and never touches the Chio kernel, policy
engine, or runtime state. It hosts a `tower-lsp` server around a
`dashmap`-backed document cache and dispatches each request to a provider
module chosen by a coarse `DocumentLanguage` classification (`chio.yaml`,
manifest, guard DSL, other). Diagnostics are hand-rolled structural checks
over parsed YAML (required keys, sequence shape, URN prefixes), not
schema-file validation; each provider emits the same `urn:chio:error:*`
registry codes the CLI uses so editor and CLI surfaces agree on what is valid.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public module declarations and re-exports. `#![forbid(unsafe_code)]`. |
| `src/main.rs` | `chio-lsp` binary entry point; calls `server::run_stdio()`. |
| `src/server.rs` | `tower_lsp::LanguageServer` impl: `initialize`/`initialized`/`shutdown`, `did_open`/`did_change`/`did_close`, `completion`, `hover`, `goto_definition`, diagnostics publication. |
| `src/document.rs` | `DocumentCache` (`DashMap<Url, DocumentEntry>`) and `DocumentLanguage::detect`. |
| `src/position.rs` | UTF-16 LSP column <-> UTF-8 byte offset conversion, saturating on overshoot. |
| `src/diagnostics/mod.rs` | `validate` dispatch and the shared `diagnostic_with_urn` builder (1-based parser location -> 0-based LSP `Range`). |
| `src/diagnostics/chio_yaml.rs` | `chio.yaml` check: required top-level keys `version`, `policy`. |
| `src/diagnostics/manifest.rs` | Manifest check: `tools:` sequence, each entry requires `id`. |
| `src/diagnostics/guard_dsl.rs` | Guard DSL check: `guards:` sequence, each stage requires `id:` matching `urn:chio:guard:*`. |
| `src/completion/mod.rs` | `complete` dispatch for `chio.yaml`: a line-prefix / enclosing-section scan (not a YAML parse) picks scope, guard, or top-level-key completions. |
| `src/completion/scopes.rs` | Static catalog of `urn:chio:scope:*` completion items. |
| `src/completion/guards.rs` | Static catalog of `urn:chio:guard:*` completion items. |
| `src/hover/mod.rs` | `hover`: URN extraction at a position, then lookup against `chio_errors::lookup_error_code` or the completion catalogs. |
| `src/definition/mod.rs` | `definition`: URN extraction restricted to `urn:chio:scope:*` / `urn:chio:guard:*`. |
| `src/definition/resolver.rs` | URN token extraction and resolution: scoped on-disk manifest lookup, else first occurrence in the open document. |

## Request lifecycle

1. `did_open` classifies the document (`DocumentLanguage::detect`; a reported
   language id wins over the URI suffix) and inserts it into `DocumentCache`.
   This is the only handler that admits a new URI.
2. `did_change` (negotiated as `TextDocumentSyncKind::FULL`, one full-body
   change per notification) replaces the cached text via
   `DocumentCache::replace`. An unknown URI returns `None` and the handler is
   a no-op: no insertion, no diagnostics publish.
3. Both `did_open` and `did_change` call `publish_diagnostics`, which routes
   through `diagnostics::validate` and sends
   `textDocument/publishDiagnostics`.
4. `completion`, `hover`, and `goto_definition` each read the cached entry by
   URI (`DocumentCache::get`) and return empty/`None` on a cache miss rather
   than reading the file directly.
5. `did_close` removes the URI from the cache and publishes an empty
   diagnostics list to clear the editor's squiggles.

## Invariants and failure modes

- The crate forbids unsafe code (`#![forbid(unsafe_code)]`).
- Fails closed on an unknown `didChange` URI: no cache mutation, no
  diagnostics publish.
- Completion is implemented for `chio.yaml` only; `complete()` returns an
  empty list for `Manifest`, `GuardDsl`, and `Other` regardless of cursor
  position. Hover and definition run for `ChioYaml`, `Manifest`, and
  `GuardDsl`; diagnostics runs a dedicated provider for each of those three
  and returns nothing for `Other`.
- `definition::resolver::scoped_manifest_path` fails closed on the on-disk
  manifest hop: rejects absolute paths, rejects any path containing a `..`,
  root, or prefix component, rejects filenames outside the manifest naming
  pattern (`*.chio-manifest.yaml`/`.yml` or `chio-manifest.yaml`/`.yml`), and
  requires the canonicalized target to stay inside the canonicalized document
  directory.
- `position` conversions saturate rather than panic when a column overshoots
  the line, and only return byte indices on `char` boundaries, so multibyte
  prefixes cannot panic completion, hover, or definition.
- Every diagnostics provider treats an empty document and a non-mapping
  top-level YAML value as a hard error rather than skipping validation.
- `URN_MANIFEST_TOOL_NOT_REGISTERED` is reserved for a runtime manifest
  lookup this crate does not perform; no provider here emits it, only
  `URN_MANIFEST_SCHEMA_INVALID` for structural defects.

## Dependencies

Internal: `chio-errors` supplies `lookup_error_code` and the generated
`ErrorCodeSpec` registry backing hover text for `urn:chio:error:*` codes; not
aliased. External: `tower-lsp` (the `LanguageServer` trait and `lsp_types`),
`tokio` (async runtime for stdio and the binary), `dashmap` (the concurrent
document cache), `serde_yml` (YAML parsing in all three diagnostics
providers).
