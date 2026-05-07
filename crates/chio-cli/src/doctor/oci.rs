//! OCI registry reachability probe.
//!
//! Resolves the configured guard registry endpoint and surfaces a
//! reachability report. The probe consumes `chio-guard-registry`
//! read-only: it reads the configured registry reference but never
//! duplicates the pull path.
//!
//! Test mode and `CHIO_DOCTOR_SKIP_NETWORK=1` short-circuit any actual
//! network reach, returning an info-level report instead. The probe is
//! warning-severity on reachability failures (not fatal) so a green
//! workspace can still pass the gate when a developer is offline.

use std::path::PathBuf;

use super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

const REGISTRY_ENV: &str = "CHIO_GUARD_REGISTRY";
const ALT_REGISTRY_ENV: &str = "CHIO_GUARD_REGISTRY_REFERENCE";

#[derive(Debug, Default, Clone)]
pub struct OciProbe {
    registry_override: Option<String>,
    workdir_override: Option<PathBuf>,
}

impl OciProbe {
    #[must_use]
    pub fn with_registry(mut self, registry: impl Into<String>) -> Self {
        self.registry_override = Some(registry.into());
        self
    }

    #[must_use]
    pub fn with_workdir(mut self, dir: PathBuf) -> Self {
        self.workdir_override = Some(dir);
        self
    }

    fn resolve_registry(&self, config: &ProbeConfig) -> Option<String> {
        if let Some(reg) = &self.registry_override {
            return Some(reg.clone());
        }
        if let Ok(value) = std::env::var(REGISTRY_ENV) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        if let Ok(value) = std::env::var(ALT_REGISTRY_ENV) {
            if !value.is_empty() {
                return Some(value);
            }
        }
        // Fall back to a chio.yaml `registry:` line in the workspace.
        let root = self
            .workdir_override
            .clone()
            .or_else(|| config.workdir.clone())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let body = std::fs::read_to_string(root.join("chio.yaml")).ok()?;
        for line in body.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("registry:") {
                let value = rest.trim().trim_matches('"').trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }
}

impl Probe for OciProbe {
    fn name(&self) -> &'static str {
        "oci"
    }

    fn run(&self, config: &ProbeConfig) -> ProbeReport {
        let registry = match self.resolve_registry(config) {
            Some(r) => r,
            None => {
                return ProbeReport {
                    probe: self.name(),
                    severity: ProbeSeverity::Info,
                    code: "urn:chio:error:cli:other",
                    message: "No guard OCI registry configured. Skipping reachability probe."
                        .to_string(),
                    help: Some(
                        "Set CHIO_GUARD_REGISTRY or add a `registry:` line to chio.yaml \
                         to enable the OCI reachability probe."
                            .to_string(),
                    ),
                    context: Vec::new(),
                    repaired: false,
                };
            }
        };

        if config.skip_network || std::env::var("CHIO_DOCTOR_SKIP_NETWORK").is_ok() {
            return ProbeReport::ok(
                self.name(),
                format!("Registry endpoint {registry} resolved. Network probe skipped."),
            )
            .with_context("registry", registry);
        }

        // Best-effort reachability via reqwest blocking. Treat any
        // failure as a warning, never a hard error: the probe is read-
        // only and a transient network blip should not block CI.
        // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: diagnostic OCI reachability
        // probes target a user-configured registry and are skipped by
        // CHIO_DOCTOR_SKIP_NETWORK, outside substrate tool egress.
        match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(client) => {
                let url = if registry.starts_with("http") {
                    registry.clone()
                } else {
                    format!("https://{registry}/v2/")
                };
                // CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST: diagnostic OCI reachability
                // probe, outside substrate tool egress.
                match client.head(&url).send() {
                    Ok(response) => {
                        if response.status().is_success()
                            || response.status().as_u16() == 401
                            || response.status().as_u16() == 404
                        {
                            ProbeReport::ok(
                                self.name(),
                                format!("Registry {registry} reachable ({}).", response.status()),
                            )
                            .with_context("registry", registry)
                        } else {
                            ProbeReport::fail(
                                self.name(),
                                ProbeSeverity::Warning,
                                "urn:chio:error:cli:doctor-oci-unreachable",
                                format!(
                                    "Registry {registry} returned status {}.",
                                    response.status()
                                ),
                            )
                            .with_context("registry", registry)
                        }
                    }
                    Err(err) => ProbeReport::fail(
                        self.name(),
                        ProbeSeverity::Warning,
                        "urn:chio:error:cli:doctor-oci-unreachable",
                        format!("Registry {registry} unreachable: {err}"),
                    )
                    .with_context("registry", registry),
                }
            }
            Err(err) => ProbeReport::fail(
                self.name(),
                ProbeSeverity::Warning,
                "urn:chio:error:cli:doctor-oci-unreachable",
                format!("Could not build HTTP client: {err}"),
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn no_registry_returns_info() {
        let probe = OciProbe::default();
        let config = ProbeConfig {
            skip_network: true,
            workdir: Some(tempfile::tempdir().unwrap().path().to_path_buf()),
            ..Default::default()
        };
        let report = probe.run(&config);
        assert_eq!(report.severity, ProbeSeverity::Info);
    }

    #[test]
    fn skip_network_returns_ok_when_registry_configured() {
        let probe = OciProbe::default().with_registry("ghcr.io/example/chio");
        let config = ProbeConfig {
            skip_network: true,
            ..Default::default()
        };
        let report = probe.run(&config);
        assert_eq!(report.severity, ProbeSeverity::Ok);
        assert_eq!(report.code, "urn:chio:error:cli:other");
        assert!(report
            .context
            .iter()
            .any(|ctx| ctx.key == "registry" && ctx.value == "ghcr.io/example/chio"));
    }
}
