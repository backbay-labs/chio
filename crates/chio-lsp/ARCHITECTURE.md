# chio-lsp Architecture

## Boundary

`chio-lsp` owns editor-facing language intelligence for Chio documents over
LSP stdio. It caches opened documents, classifies them as `chio.yaml`,
manifest, guard DSL, or other text, and routes requests to diagnostics,
completion, hover, and go-to-definition providers. It does not run the kernel,
evaluate policies, load arbitrary project files, or mutate workspace state.

## Module Boundaries

- `server` owns the `tower-lsp` lifecycle and request handlers.
- `document` owns the URI-keyed cache and language classification.
- `diagnostics` owns registry-coded LSP diagnostics for each document language.
- `completion` owns deterministic static completion catalogs.
- `hover` owns registry and catalog help rendering.
- `definition` owns URN extraction and scoped go-to-definition resolution.
- `position` owns UTF-16 LSP position conversion before string slicing.

## Pain Points

- The document cache currently treats an unknown `didChange` as an implicit
  open by inserting a new entry when no existing document is present.
- That blurs the LSP lifecycle boundary: `didOpen` is the operation that
  provides the language id and admits a document into the cache.
- Unknown changes can therefore publish diagnostics for documents the server
  did not accept through the open path.
- Diagnostics, hover, and definition code already fail closed for unknown
  languages and unsafe manifest paths; the cache lifecycle should follow the
  same model.

## Security And API Constraints

- Preserve the public crate surface: `DocumentCache`, `DocumentEntry`,
  `DocumentLanguage`, `ChioLanguageServer`, and `ServerCapabilitiesSnapshot`.
- Preserve editor contract behavior from `editors/README.md`: stdio LSP,
  registry-coded diagnostics, completion, hover, and go-to-definition.
- Keep `didOpen` as the only operation that admits a document and records the
  initial language classification.
- Keep `didChange` versioned, full-sync only, and side-effect free when the URI
  is not already open.
- Keep UTF-16 range conversion and scoped manifest-file resolution intact.

## Affected Dependents

`cargo tree -i chio-lsp --workspace` reports no direct Rust dependents.
First-party editor packages under `editors/` depend on the `chio-lsp` binary
contract and LSP behavior. The planned change should require no transitive
source edits.

## Planned Improvement

Harden the document-cache lifecycle so `DocumentCache::replace` updates only an
existing opened document. Unknown `didChange` events should return `None`,
leave the cache unchanged, and avoid diagnostic publication.

This is architectural because it makes the cache an explicit LSP lifecycle
state machine instead of a generic URI map:
`didOpen` admits and classifies, `didChange` mutates existing state,
`didClose` removes state.

## Verification Focus

Tests should cover `didOpen` admission, ignored unknown `didChange` events,
`didClose` removal, UTF-16 position conversion at multibyte boundaries,
registry-coded diagnostics for `chio.yaml`, manifest, and guard DSL documents,
and no filesystem reads outside explicit manifest resolution paths.
