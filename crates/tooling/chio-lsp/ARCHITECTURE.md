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

## Cache Lifecycle

The document cache is an explicit LSP lifecycle state machine, not a generic URI
map: `didOpen` admits and classifies a document, `didChange` mutates existing
state, and `didClose` removes state. `didOpen` is the only operation that
provides the language id and admits a document into the cache.
`DocumentCache::replace` updates only an already-open document; an unknown
`didChange` returns `None`, leaves the cache unchanged, and publishes no
diagnostics, so the server never surfaces diagnostics for documents it did not
accept through the open path. Diagnostics, hover, and definition code fail
closed for unknown languages and unsafe manifest paths under the same model.

## Security And API Constraints

- Preserve the public crate surface: `DocumentCache`, `DocumentEntry`,
  `DocumentLanguage`, `ChioLanguageServer`, and `ServerCapabilitiesSnapshot`.
- Preserve editor contract behavior from `integrations/editors/README.md`: stdio LSP,
  registry-coded diagnostics, completion, hover, and go-to-definition.
- Keep `didOpen` as the only operation that admits a document and records the
  initial language classification.
- Keep `didChange` versioned, full-sync only, and side-effect free when the URI
  is not already open.
- Keep UTF-16 range conversion and scoped manifest-file resolution intact.

## Dependents

`cargo tree -i chio-lsp --workspace` reports no direct Rust dependents.
First-party editor packages under `integrations/editors/` depend on the
`chio-lsp` binary contract and LSP behavior, not its Rust source.

## Verification Focus

Tests should cover `didOpen` admission, ignored unknown `didChange` events,
`didClose` removal, UTF-16 position conversion at multibyte boundaries,
registry-coded diagnostics for `chio.yaml`, manifest, and guard DSL documents,
and no filesystem reads outside explicit manifest resolution paths.
