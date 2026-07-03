use std::collections::HashMap;
use std::sync::Mutex;

use super::formatting::fingerprint;

// ---------------------------------------------------------------------------
// Tokenize store: opaque-id -> original mapping.
// ---------------------------------------------------------------------------

/// Shared token vault used by the `Tokenize` redaction strategy.
#[derive(Debug, Default)]
pub struct TokenVault {
    inner: Mutex<TokenVaultInner>,
}

#[derive(Debug, Default)]
struct TokenVaultInner {
    counter: u64,
    map: HashMap<String, String>,
}

impl TokenVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, value: &str) -> String {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.counter = inner.counter.saturating_add(1);
        let fp = fingerprint(value);
        let id = format!("tok_{}_{}", inner.counter, fp);
        inner.map.insert(id.clone(), value.to_string());
        id
    }

    pub fn get(&self, token: &str) -> Option<String> {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.map.get(token).cloned()
    }

    pub fn len(&self) -> usize {
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
