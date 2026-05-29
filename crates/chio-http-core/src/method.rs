//! HTTP method enumeration for Chio request evaluation.

use serde::{Deserialize, Serialize};

/// HTTP method. Used to determine default policy (GET = session-scoped allow,
/// POST/PUT/PATCH/DELETE = deny without capability).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl HttpMethod {
    /// Whether this method is considered side-effect-free by default.
    /// Side-effect-free methods get session-scoped allow; others require
    /// explicit capability grants.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options)
    }

    /// Whether this method requires an explicit capability grant by default.
    #[must_use]
    pub fn requires_capability(&self) -> bool {
        !self.is_safe()
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Head => write!(f, "HEAD"),
            Self::Options => write!(f, "OPTIONS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chio_test_support::prelude::*;

    #[test]
    fn safe_methods() {
        assert!(HttpMethod::Get.is_safe());
        assert!(HttpMethod::Head.is_safe());
        assert!(HttpMethod::Options.is_safe());
    }

    #[test]
    fn unsafe_methods_require_capability() {
        assert!(HttpMethod::Post.requires_capability());
        assert!(HttpMethod::Put.requires_capability());
        assert!(HttpMethod::Patch.requires_capability());
        assert!(HttpMethod::Delete.requires_capability());
    }

    #[test]
    fn display_uppercase() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
    }

    #[test]
    fn serde_roundtrip() {
        let method = HttpMethod::Post;
        let json = serde_json::to_string(&method).test_unwrap();
        assert_eq!(json, "\"POST\"");
        let back: HttpMethod = serde_json::from_str(&json).test_unwrap();
        assert_eq!(back, method);
    }
}
