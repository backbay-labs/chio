// Shared integration-test helpers: a given helper is used by some test binaries
// but not all, so the binaries that do not call it would otherwise trip
// `-D dead-code` under the MSRV lane (-D warnings). allow(dead_code) is the
// standard treatment for a shared test-support tree. (Pre-existing on main;
// surfaced by CI while validating this branch.)
#[allow(dead_code)]
pub(crate) mod receipt_query;
#[allow(dead_code)]
pub(crate) mod receipt_query_capital_authority;
#[allow(dead_code)]
pub(crate) mod receipt_query_helpers;
