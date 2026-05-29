//! tower-lsp server skeleton.
//!
//! Implements the minimal `LanguageServer` lifecycle (`initialize`,
//! `initialized`, `shutdown`) plus the text-document open / change /
//! close handlers that drive the document cache. Diagnostics,
//! completion, hover, and go-to-definition are implemented in the
//! sibling modules.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::{
    CompletionOptions, CompletionParams, CompletionResponse, DidChangeTextDocumentParams,
    DidCloseTextDocumentParams, DidOpenTextDocumentParams, GotoDefinitionParams,
    GotoDefinitionResponse, Hover, HoverParams, HoverProviderCapability, InitializeParams,
    InitializeResult, InitializedParams, MessageType, OneOf, ServerCapabilities, ServerInfo,
    TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tower_lsp::{Client, LanguageServer};

use crate::document::DocumentCache;

/// Snapshot of the capabilities the server advertises in
/// `initialize`. Exposed so integration tests can pin the contract
/// without re-deriving the full LSP `ServerCapabilities` shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerCapabilitiesSnapshot {
    pub text_document_sync_full: bool,
    pub completion: bool,
    pub hover: bool,
    pub definition: bool,
}

#[derive(Debug)]
pub struct ChioLanguageServer {
    client: Client,
    documents: DocumentCache,
    initialized: AtomicBool,
    shutdown_requested: AtomicBool,
}

impl ChioLanguageServer {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self {
            client,
            documents: DocumentCache::new(),
            initialized: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    /// Construct a server bound to a pre-built document cache.
    /// Used by tests that want to inspect the cache after lifecycle
    /// events fire.
    #[must_use]
    pub fn with_cache(client: Client, documents: DocumentCache) -> Self {
        Self {
            client,
            documents,
            initialized: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn documents(&self) -> DocumentCache {
        self.documents.clone()
    }

    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Capabilities advertised in `initialize`: text-document-sync,
    /// completion, hover, definition, and diagnostics.
    #[must_use]
    pub fn capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            completion_provider: Some(CompletionOptions {
                trigger_characters: Some(vec![":".to_string(), " ".to_string(), "-".to_string()]),
                ..CompletionOptions::default()
            }),
            hover_provider: Some(HoverProviderCapability::Simple(true)),
            definition_provider: Some(OneOf::Left(true)),
            ..ServerCapabilities::default()
        }
    }

    #[must_use]
    pub fn capabilities_snapshot() -> ServerCapabilitiesSnapshot {
        let caps = Self::capabilities();
        let sync_full = matches!(
            caps.text_document_sync,
            Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL))
        );
        ServerCapabilitiesSnapshot {
            text_document_sync_full: sync_full,
            completion: caps.completion_provider.is_some(),
            hover: caps.hover_provider.is_some(),
            definition: caps.definition_provider.is_some(),
        }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for ChioLanguageServer {
    async fn initialize(&self, _params: InitializeParams) -> LspResult<InitializeResult> {
        Ok(InitializeResult {
            capabilities: Self::capabilities(),
            server_info: Some(ServerInfo {
                name: "chio-lsp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }),
        })
    }

    async fn initialized(&self, _params: InitializedParams) {
        self.initialized.store(true, Ordering::SeqCst);
        self.client
            .log_message(MessageType::INFO, "chio-lsp initialized")
            .await;
    }

    async fn shutdown(&self) -> LspResult<()> {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let td = params.text_document;
        let uri = td.uri.clone();
        let entry = self
            .documents
            .open(td.uri, td.text, td.version, Some(td.language_id.as_str()));
        self.publish_diagnostics(&uri, &entry).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        // We negotiated FULL sync; the client sends one change with the
        // entire document body.
        if let Some(change) = params.content_changes.into_iter().next() {
            if let Some(entry) = self.documents.replace(
                &params.text_document.uri,
                change.text,
                params.text_document.version,
            ) {
                self.publish_diagnostics(&params.text_document.uri, &entry)
                    .await;
            }
        }
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> LspResult<Option<GotoDefinitionResponse>> {
        let uri = params
            .text_document_position_params
            .text_document
            .uri
            .clone();
        let position = params.text_document_position_params.position;
        let Some(entry) = self.documents.get(&uri) else {
            return Ok(None);
        };
        Ok(
            crate::definition::definition(entry.language, &uri, &entry.text, position)
                .map(GotoDefinitionResponse::Scalar),
        )
    }

    async fn hover(&self, params: HoverParams) -> LspResult<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let Some(entry) = self.documents.get(uri) else {
            return Ok(None);
        };
        Ok(crate::hover::hover(entry.language, &entry.text, position))
    }

    async fn completion(&self, params: CompletionParams) -> LspResult<Option<CompletionResponse>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let Some(entry) = self.documents.get(uri) else {
            return Ok(None);
        };
        let items = crate::completion::complete(entry.language, &entry.text, position);
        if items.is_empty() {
            Ok(None)
        } else {
            Ok(Some(CompletionResponse::Array(items)))
        }
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.documents.close(&params.text_document.uri);
        // Clear diagnostics for the closed document.
        self.client
            .publish_diagnostics(params.text_document.uri, Vec::new(), None)
            .await;
    }
}

impl ChioLanguageServer {
    /// Run validation on a cached document and publish the resulting
    /// diagnostics to the client. Other diagnostic providers (manifest,
    /// guard DSL) hook in via `crate::diagnostics::validate`.
    pub async fn publish_diagnostics(
        &self,
        uri: &tower_lsp::lsp_types::Url,
        entry: &crate::document::DocumentEntry,
    ) {
        let diags = crate::diagnostics::validate(entry.language, uri, &entry.text);
        self.client
            .publish_diagnostics(uri.clone(), diags, Some(entry.version))
            .await;
    }
}

/// Run the server over stdio. Used by `chio-lsp` and `chio lsp`.
pub async fn run_stdio() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) =
        tower_lsp::LspService::new(|client| Arc::new(ChioLanguageServer::new(client)));
    tower_lsp::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_snapshot_advertises_core_capabilities() {
        let snap = ChioLanguageServer::capabilities_snapshot();
        assert!(snap.text_document_sync_full);
        assert!(snap.definition);
    }
}
