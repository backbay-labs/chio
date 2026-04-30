//! Chio language server.
//!
//! Hosts the tower-lsp server skeleton and the dashmap-backed document
//! cache that the diagnostics, completion, hover, and go-to-definition
//! subsystems share. The server stops at the chio.yaml / manifest /
//! guard-DSL document boundary; it does not run the kernel.
//!
//! Schema sources (loaded read-only):
//!
//! - trajectory-1 M01 wire schemas under `spec/schemas/chio-wire/v1/`
//! - trajectory-1 M06 guard-bundle schema (consumed by the guard-DSL
//!   diagnostics in P4.T6)
//!
//! Diagnostics carry `urn:chio:error:*` codes via the `code` field of
//! `lsp_types::Diagnostic` so the editor extensions in P5 surface
//! registry codes directly.

#![forbid(unsafe_code)]

pub mod completion;
pub mod diagnostics;
pub mod document;
pub mod server;

pub use document::{DocumentCache, DocumentEntry, DocumentLanguage};
pub use server::{ChioLanguageServer, ServerCapabilitiesSnapshot};
