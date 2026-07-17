//! Fail-open detector emission. The counter instance lives in chio-metrics-spec
//! so serving surfaces can render it without a chio-tower dependency; this
//! module is the tower-side producer.

use std::sync::Once;

use chio_metrics_spec::runtime::{families, preregister_known_label_sets};

static SEED: Once = Once::new();

/// Seed the fail-open series (and its sibling alert-pack series) at zero once,
/// before the layer serves, so the absent_over_time backstop only fires on a
/// true scrape gap, not on a deployment that has never failed open.
pub(crate) fn seed_fail_open_series() {
    SEED.call_once(preregister_known_label_sets);
}

/// +1 on the fail-open detector for `surface`. Called from every
/// unenforced-forward site (currently only the tower layer).
pub(crate) fn record_fail_open_suspected(surface: &str) {
    families::FAIL_OPEN_SUSPECTED.incr(&[surface]);
}
