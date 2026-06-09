//! Document cache for chio-lsp.
//!
//! Documents live in a `dashmap::DashMap` keyed by `lsp_types::Url`.
//! The cache stores the raw text plus a coarse language tag so the
//! diagnostics, completion, hover, and definition subsystems can pick
//! the right schema without re-parsing the URI on every request.

use std::sync::Arc;

use dashmap::DashMap;
use tower_lsp::lsp_types::Url;

/// Coarse language classification used to dispatch to the right diagnostics provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocumentLanguage {
    /// Top-level project config (`chio.yaml`).
    ChioYaml,
    /// Tool / capability manifest documents
    /// (`*.chio-manifest.yaml`).
    Manifest,
    /// Guard DSL documents (`*.chio-guard.yaml`).
    GuardDsl,
    /// Anything else; the server keeps the text but emits no
    /// diagnostics.
    Other,
}

impl DocumentLanguage {
    /// Classify a document by URI path suffix and reported language id.
    /// The reported language id wins when present.
    #[must_use]
    pub fn detect(uri: &Url, language_id: Option<&str>) -> Self {
        if let Some(id) = language_id {
            match id {
                "chio-yaml" | "chio.yaml" => return Self::ChioYaml,
                "chio-manifest" => return Self::Manifest,
                "chio-guard" => return Self::GuardDsl,
                _ => {}
            }
        }
        let path = uri.path();
        if path.ends_with("chio.yaml") || path.ends_with("chio.yml") {
            Self::ChioYaml
        } else if path.ends_with(".chio-manifest.yaml") || path.ends_with(".chio-manifest.yml") {
            Self::Manifest
        } else if path.ends_with(".chio-guard.yaml") || path.ends_with(".chio-guard.yml") {
            Self::GuardDsl
        } else {
            Self::Other
        }
    }
}

/// Cached document state.
#[derive(Debug, Clone)]
pub struct DocumentEntry {
    pub text: Arc<String>,
    pub version: i32,
    pub language: DocumentLanguage,
}

impl DocumentEntry {
    #[must_use]
    pub fn new(text: String, version: i32, language: DocumentLanguage) -> Self {
        Self {
            text: Arc::new(text),
            version,
            language,
        }
    }
}

/// Thread-safe document cache.
///
/// `DashMap` gives us read-mostly concurrency without the per-key lock
/// contention a single `RwLock<HashMap>` would impose under fan-out
/// requests (completion + hover + diagnostics fired on the same
/// keystroke).
#[derive(Debug, Default, Clone)]
pub struct DocumentCache {
    inner: Arc<DashMap<Url, DocumentEntry>>,
}

impl DocumentCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn open(
        &self,
        uri: Url,
        text: String,
        version: i32,
        language_id: Option<&str>,
    ) -> DocumentEntry {
        let language = DocumentLanguage::detect(&uri, language_id);
        let entry = DocumentEntry::new(text, version, language);
        self.inner.insert(uri, entry.clone());
        entry
    }

    pub fn replace(&self, uri: &Url, text: String, version: i32) -> Option<DocumentEntry> {
        let language = self.inner.get(uri).map(|e| e.language)?;
        let entry = DocumentEntry::new(text, version, language);
        self.inner.insert(uri.clone(), entry.clone());
        Some(entry)
    }

    pub fn close(&self, uri: &Url) -> Option<DocumentEntry> {
        self.inner.remove(uri).map(|(_, v)| v)
    }

    #[must_use]
    pub fn get(&self, uri: &Url) -> Option<DocumentEntry> {
        self.inner.get(uri).map(|r| r.value().clone())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn detect_classifies_uris_and_language_ids() {
        let uri = Url::parse("file:///tmp/proj/chio.yaml").unwrap();
        assert_eq!(
            DocumentLanguage::detect(&uri, None),
            DocumentLanguage::ChioYaml
        );

        let uri = Url::parse("file:///tmp/proj/tools.chio-manifest.yaml").unwrap();
        assert_eq!(
            DocumentLanguage::detect(&uri, None),
            DocumentLanguage::Manifest
        );

        let uri = Url::parse("file:///tmp/proj/policy.chio-guard.yaml").unwrap();
        assert_eq!(
            DocumentLanguage::detect(&uri, None),
            DocumentLanguage::GuardDsl
        );

        let uri = Url::parse("file:///tmp/proj/random.txt").unwrap();
        assert_eq!(
            DocumentLanguage::detect(&uri, None),
            DocumentLanguage::Other
        );

        // Reported language id wins.
        let uri = Url::parse("file:///tmp/random.txt").unwrap();
        assert_eq!(
            DocumentLanguage::detect(&uri, Some("chio-yaml")),
            DocumentLanguage::ChioYaml
        );
    }

    #[test]
    fn cache_open_replace_close_round_trip() {
        let cache = DocumentCache::new();
        let uri = Url::parse("file:///tmp/proj/chio.yaml").unwrap();
        let entry = cache.open(uri.clone(), "version: 1\n".to_string(), 1, None);
        assert_eq!(entry.version, 1);
        assert_eq!(entry.language, DocumentLanguage::ChioYaml);
        assert_eq!(cache.len(), 1);

        let updated = cache
            .replace(&uri, "version: 2\n".to_string(), 2)
            .expect("replace returns updated entry");
        assert_eq!(updated.version, 2);
        assert_eq!(updated.language, DocumentLanguage::ChioYaml);

        let closed = cache.close(&uri).expect("close returns prior entry");
        assert_eq!(closed.version, 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn replace_unknown_document_does_not_insert() {
        let cache = DocumentCache::new();
        let uri = Url::parse("file:///tmp/proj/chio.yaml").unwrap();

        let updated = cache.replace(&uri, "version: 2\n".to_string(), 2);

        assert!(updated.is_none());
        assert!(cache.get(&uri).is_none());
        assert!(cache.is_empty());
    }
}
