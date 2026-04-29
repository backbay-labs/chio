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
    match host_fn {
        HOST_CALL_LOG => Some(HOST_CALL_LOG),
        HOST_CALL_GET_CONFIG => Some(HOST_CALL_GET_CONFIG),
        HOST_CALL_GET_TIME_UNIX_SECS => Some(HOST_CALL_GET_TIME_UNIX_SECS),
        HOST_CALL_FETCH_BLOB => Some(HOST_CALL_FETCH_BLOB),
        _ => None,
    }
}
