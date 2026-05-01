//! Chio language server.
//!
//! Hosts the tower-lsp server skeleton and the dashmap-backed document
//! cache that the diagnostics, completion, hover, and go-to-definition
//! subsystems share. The server stops at the chio.yaml / manifest /
//! guard-DSL document boundary; it does not run the kernel.
//!
//! Schema sources (loaded read-only):
//!
//! - wire schemas under `spec/schemas/chio-wire/v1/`
//! - guard-bundle schema (consumed by the guard-DSL diagnostics)
//!
//! Diagnostics carry `urn:chio:error:*` codes via the `code` field of
//! `lsp_types::Diagnostic` so editor extensions surface registry codes
//! directly.

#![forbid(unsafe_code)]

pub mod completion;
pub mod definition;
pub mod diagnostics;
pub mod document;
pub mod hover;
pub mod position;
pub mod server;

pub use document::{DocumentCache, DocumentEntry, DocumentLanguage};
pub use server::{ChioLanguageServer, ServerCapabilitiesSnapshot};
