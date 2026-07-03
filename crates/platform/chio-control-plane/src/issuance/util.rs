use std::time::{SystemTime, UNIX_EPOCH};

pub(in crate::issuance) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
