//! Request metadata parsing for Tower HTTP enforcement.

use std::collections::HashMap;

const CHIO_CAPABILITY_QUERY_PARAM: &str = "chio_capability";

/// Invalid capability marker used to force fail-closed authority evaluation
/// when the transport presented an ambiguous query capability.
pub(crate) const DUPLICATE_QUERY_CAPABILITY_PRESENTATION: &str =
    "duplicate chio_capability query parameters";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestMetadata {
    query: HashMap<String, String>,
    has_duplicate_query_capability: bool,
}

impl RequestMetadata {
    pub(crate) fn parse(raw_query: Option<&str>) -> Self {
        let Some(raw_query) = raw_query else {
            return Self {
                query: HashMap::new(),
                has_duplicate_query_capability: false,
            };
        };

        let mut query = HashMap::new();
        let mut capability_count = 0usize;

        for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
            if key == CHIO_CAPABILITY_QUERY_PARAM {
                capability_count = capability_count.saturating_add(1);
            }
            query.insert(key.into_owned(), value.into_owned());
        }

        Self {
            query,
            has_duplicate_query_capability: capability_count > 1,
        }
    }

    pub(crate) fn query(&self) -> &HashMap<String, String> {
        &self.query
    }

    pub(crate) fn presented_capability_override(&self) -> Option<&'static str> {
        self.has_duplicate_query_capability
            .then_some(DUPLICATE_QUERY_CAPABILITY_PRESENTATION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_absent_query_has_empty_map_and_no_override() {
        let metadata = RequestMetadata::parse(None);

        assert!(metadata.query().is_empty());
        assert_eq!(metadata.presented_capability_override(), None);
    }

    #[test]
    fn parse_single_capability_query_has_no_override() {
        let metadata = RequestMetadata::parse(Some("chio_capability=cap-a&other=value"));

        assert_eq!(
            metadata.query().get(CHIO_CAPABILITY_QUERY_PARAM),
            Some(&"cap-a".to_string())
        );
        assert_eq!(metadata.presented_capability_override(), None);
    }

    #[test]
    fn parse_duplicate_capability_query_sets_override() {
        let metadata = RequestMetadata::parse(Some("chio_capability=cap-a&chio_capability=cap-b"));

        assert_eq!(
            metadata.presented_capability_override(),
            Some(DUPLICATE_QUERY_CAPABILITY_PRESENTATION)
        );
    }

    #[test]
    fn parse_duplicate_percent_encoded_capability_key_sets_override() {
        let metadata =
            RequestMetadata::parse(Some("chio%5Fcapability=cap-a&chio_capability=cap-b"));

        assert_eq!(
            metadata.presented_capability_override(),
            Some(DUPLICATE_QUERY_CAPABILITY_PRESENTATION)
        );
    }

    #[test]
    fn parse_duplicate_non_capability_query_does_not_set_override() {
        let metadata = RequestMetadata::parse(Some("tag=a&tag=b"));

        assert_eq!(metadata.presented_capability_override(), None);
        assert_eq!(metadata.query().get("tag"), Some(&"b".to_string()));
    }
}
