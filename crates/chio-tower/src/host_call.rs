//! Host-call metric label helpers for guard observability.

pub const HOST_CALL_LOG: &str = "log";
pub const HOST_CALL_GET_CONFIG: &str = "get_config";
pub const HOST_CALL_GET_TIME_UNIX_SECS: &str = "get_time_unix_secs";
pub const HOST_CALL_FETCH_BLOB: &str = "fetch_blob";

pub const HOST_CALL_METRIC_LABEL_VALUES: &[&str] = &[
    HOST_CALL_LOG,
    HOST_CALL_GET_CONFIG,
    HOST_CALL_GET_TIME_UNIX_SECS,
    HOST_CALL_FETCH_BLOB,
];

#[must_use]
pub fn normalize_host_call_metric_label(host_fn: &str) -> Option<&'static str> {
    canonical_host_call_metric_label(host_fn)
}

fn canonical_host_call_metric_label(host_fn: &str) -> Option<&'static str> {
    HOST_CALL_METRIC_LABEL_VALUES
        .iter()
        .copied()
        .find(|label| *label == host_fn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_host_call_metric_label_accepts_declared_labels_only() {
        for label in HOST_CALL_METRIC_LABEL_VALUES {
            assert_eq!(canonical_host_call_metric_label(label), Some(*label));
        }
        assert_eq!(canonical_host_call_metric_label("unknown"), None);
    }
}
