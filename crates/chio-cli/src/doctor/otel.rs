//! OTEL endpoint resolution probe.
//!
//! Resolves the OpenTelemetry OTLP endpoint via
//! `OTEL_EXPORTER_OTLP_ENDPOINT` (and the receipts-specific
//! `CHIO_OTEL_RECEIPT_EXPORTER_ENDPOINT` override). Reports only the
//! resolution status: it does not POST any spans. Network reach is left
//! to the kernel runtime probe.

use super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

const OTLP_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const RECEIPT_OTLP_ENV: &str = "CHIO_OTEL_RECEIPT_EXPORTER_ENDPOINT";

#[derive(Debug, Default, Clone)]
pub struct OtelProbe {
    endpoint_override: Option<String>,
}

impl OtelProbe {
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_override = Some(endpoint.into());
        self
    }

    fn resolve_endpoint(&self) -> Option<(String, &'static str)> {
        if let Some(endpoint) = &self.endpoint_override {
            return Some((endpoint.clone(), "override"));
        }
        if let Ok(value) = std::env::var(RECEIPT_OTLP_ENV) {
            if !value.is_empty() {
                return Some((value, RECEIPT_OTLP_ENV));
            }
        }
        if let Ok(value) = std::env::var(OTLP_ENV) {
            if !value.is_empty() {
                return Some((value, OTLP_ENV));
            }
        }
        None
    }

    fn validate_url(raw: &str) -> Result<(), String> {
        if raw.trim() != raw {
            return Err("endpoint must not have surrounding whitespace".to_string());
        }
        let normalized = if raw.starts_with("http://") || raw.starts_with("https://") {
            raw.to_string()
        } else {
            format!("http://{raw}")
        };
        url::Url::parse(&normalized)
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}

impl Probe for OtelProbe {
    fn name(&self) -> &'static str {
        "otel"
    }

    fn run(&self, _config: &ProbeConfig) -> ProbeReport {
        match self.resolve_endpoint() {
            None => ProbeReport {
                probe: self.name(),
                severity: ProbeSeverity::Info,
                code: "urn:chio:error:cli:other",
                message: "No OTLP endpoint configured. Skipping OTEL probe.".to_string(),
                help: Some(format!(
                    "Set {OTLP_ENV} (or the receipt-specific {RECEIPT_OTLP_ENV}) to enable the probe."
                )),
                context: Vec::new(),
                repaired: false,
            },
            Some((endpoint, source)) => match Self::validate_url(&endpoint) {
                Ok(()) => ProbeReport::ok(
                    self.name(),
                    format!("OTLP endpoint {endpoint} resolved (source: {source})."),
                )
                .with_context("endpoint", endpoint)
                .with_context("source", source),
                Err(err) => ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Warning,
                    "urn:chio:error:cli:doctor-otel-unresolved",
                    format!("OTLP endpoint {endpoint} is not a valid URL: {err}"),
                )
                .with_context("endpoint", endpoint)
                .with_context("source", source)
                .with_help(format!(
                    "Set {OTLP_ENV} to a valid http(s) URL of the form scheme://host[:port]/path."
                )),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_override_resolves() {
        let probe = OtelProbe::default().with_endpoint("https://otel.example/v1/traces");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Ok);
    }

    #[test]
    fn invalid_url_warns() {
        let probe = OtelProbe::default().with_endpoint("::not a url::");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Warning);
        assert_eq!(report.code, "urn:chio:error:cli:doctor-otel-unresolved");
    }

    #[test]
    fn padded_endpoint_warns() {
        let probe = OtelProbe::default().with_endpoint("https://otel.example/v1/traces ");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Warning);
        assert_eq!(report.code, "urn:chio:error:cli:doctor-otel-unresolved");
    }
}
