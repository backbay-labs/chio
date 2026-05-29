//! Threat-intel external guards.
//!
//! Three adapters that implement [`super::ExternalGuard`] and plug into
//! [`super::AsyncGuardAdapter`]:
//!
//! * [`virustotal::VirusTotalGuard`] - queries the VirusTotal v3 API for
//!   URL / file-hash reputation.
//! * [`safe_browsing::SafeBrowsingGuard`] - queries Google Safe Browsing
//!   v4 `threatMatches:find`.
//! * [`snyk::SnykGuard`] - queries the Snyk REST API for package
//!   vulnerabilities.
//!
//! Each module carries its own config struct (with API keys wrapped in
//! [`zeroize::Zeroizing`]) and returns [`chio_kernel::Verdict::Deny`] when
//! the remote service reports a hit at or above the configured threshold.
//!
//! Argument schema (via [`super::GuardCallContext::arguments_json`]):
//!
//! * VirusTotal expects either `{"hash": "<sha256>"}` or
//!   `{"url": "<absolute-url>"}`.
//! * Safe Browsing expects `{"url": "<absolute-url>"}`.
//! * Snyk expects `{"package": "<name>", "version": "<semver>",
//!   "ecosystem": "<npm|pip|maven|...>"}`.
//!
//! The accepted shapes are intentionally minimal - callers can synthesize
//! them from a richer kernel `GuardContext` at the integration layer.

pub mod safe_browsing;
pub mod snyk;
pub mod virustotal;

pub use safe_browsing::{SafeBrowsingConfig, SafeBrowsingGuard};
pub use snyk::{SnykConfig, SnykGuard, SnykSeverity};
pub use virustotal::{VirusTotalConfig, VirusTotalGuard};
