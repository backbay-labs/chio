//! Lifecycle tests.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//!
//! Drives the document cache directly and pins the
//! `ServerCapabilitiesSnapshot` contract. The full
//! `tower_lsp::LspService` stdio dance lives behind a `#[ignore]`d
//! integration smoke harness; this file asserts the contract surface
//! (cache shape + capabilities).

use chio_lsp::{ChioLanguageServer, DocumentCache, DocumentLanguage};
use tower_lsp::lsp_types::Url;

#[test]
fn server_advertises_text_document_sync_full() {
    let snap = ChioLanguageServer::capabilities_snapshot();
    assert!(
        snap.text_document_sync_full,
        "P4.T1 negotiates FULL text document sync"
    );
    // Definition and completion are advertised in the capability snapshot.
    assert!(snap.definition);
}

#[test]
fn document_cache_round_trip_preserves_language_classification() {
    let cache = DocumentCache::new();
    let chio_yaml = Url::parse("file:///proj/chio.yaml").expect("valid url");
    let manifest = Url::parse("file:///proj/tools.chio-manifest.yaml").expect("valid url");
    let guard = Url::parse("file:///proj/policy.chio-guard.yaml").expect("valid url");

    cache.open(chio_yaml.clone(), "version: 1\n".to_string(), 1, None);
    cache.open(manifest.clone(), "tools: []\n".to_string(), 1, None);
    cache.open(guard.clone(), "guards: []\n".to_string(), 1, None);

    assert_eq!(cache.len(), 3);
    assert_eq!(
        cache.get(&chio_yaml).expect("chio.yaml entry").language,
        DocumentLanguage::ChioYaml
    );
    assert_eq!(
        cache.get(&manifest).expect("manifest entry").language,
        DocumentLanguage::Manifest
    );
    assert_eq!(
        cache.get(&guard).expect("guard entry").language,
        DocumentLanguage::GuardDsl
    );

    cache.replace(&chio_yaml, "version: 2\n".to_string(), 2);
    assert_eq!(cache.get(&chio_yaml).expect("entry").version, 2);

    cache.close(&chio_yaml);
    assert!(cache.get(&chio_yaml).is_none());
    assert_eq!(cache.len(), 2);
}
