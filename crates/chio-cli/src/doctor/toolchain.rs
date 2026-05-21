//! Toolchain probe.
//!
//! Reads `cargo --version`, the workspace MSRV from the root `Cargo.toml`,
//! and `rust-toolchain.toml` if present. Reports a mismatch as a failing
//! probe keyed to `urn:chio:error:cli:doctor-toolchain-mismatch`.
//!
//! The probe is fail-closed: an unparseable cargo version, missing root
//! manifest, or unreadable rust-toolchain.toml all yield a failing
//! report. Network is never touched.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::probe::{Probe, ProbeConfig, ProbeReport, ProbeSeverity};

/// Toolchain probe. Default constructor probes the workspace root via
/// the current working directory; tests inject an override via `with_root`.
#[derive(Debug, Default, Clone)]
pub struct ToolchainProbe {
    root_override: Option<PathBuf>,
    cargo_version_override: Option<String>,
}

impl ToolchainProbe {
    #[must_use]
    pub fn with_root(mut self, root: PathBuf) -> Self {
        self.root_override = Some(root);
        self
    }

    /// Inject a fake `cargo --version` string. Test-only.
    #[must_use]
    pub fn with_cargo_version(mut self, version: impl Into<String>) -> Self {
        self.cargo_version_override = Some(version.into());
        self
    }

    fn workspace_root(&self, config: &ProbeConfig) -> PathBuf {
        if let Some(root) = &self.root_override {
            return root.clone();
        }
        if let Some(workdir) = &config.workdir {
            return workdir.clone();
        }
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    fn cargo_version_string(&self) -> Option<String> {
        if let Some(injected) = &self.cargo_version_override {
            return Some(injected.clone());
        }
        let output = Command::new("cargo").arg("--version").output().ok()?;
        if !output.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn parse_cargo_version(raw: &str) -> Option<(u64, u64, u64)> {
        // cargo prints e.g. "cargo 1.93.0 (083ac5135 2025-12-15)"
        let mut parts = raw.split_whitespace();
        let _ = parts.next()?;
        let semver = parts.next()?;
        let mut nums = semver.split('.');
        let major: u64 = nums.next()?.parse().ok()?;
        let minor: u64 = nums.next()?.parse().ok()?;
        let patch_str = nums.next().unwrap_or("0");
        // patch may include suffix like "0-nightly"; strip non-digits.
        let patch_digits: String = patch_str.chars().take_while(char::is_ascii_digit).collect();
        let patch: u64 = patch_digits.parse().unwrap_or(0);
        Some((major, minor, patch))
    }

    fn read_msrv(root: &Path) -> Option<String> {
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
        for line in manifest.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("rust-version") {
                let rest = rest.trim_start();
                let rest = rest.strip_prefix('=')?.trim();
                let value = rest.trim_matches('"').trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn read_pinned_toolchain(root: &Path) -> Option<String> {
        let path = root.join("rust-toolchain.toml");
        let body = std::fs::read_to_string(&path).ok()?;
        for line in body.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("channel") {
                let rest = rest.trim_start();
                let rest = rest.strip_prefix('=')?.trim();
                let value = rest.trim_matches('"').trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn parse_minor(raw: &str) -> Option<(u64, u64)> {
        let mut nums = raw.split('.');
        let major: u64 = nums.next()?.parse().ok()?;
        let minor: u64 = nums.next()?.parse().ok()?;
        Some((major, minor))
    }
}

impl Probe for ToolchainProbe {
    fn name(&self) -> &'static str {
        "toolchain"
    }

    fn run(&self, config: &ProbeConfig) -> ProbeReport {
        let root = self.workspace_root(config);

        let raw_version = match self.cargo_version_string() {
            Some(v) => v,
            None => {
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-toolchain-mismatch",
                    "Failed to invoke `cargo --version`.",
                )
                .with_help("Install a Rust toolchain that exposes `cargo` on PATH and rerun.");
            }
        };

        let parsed = match Self::parse_cargo_version(&raw_version) {
            Some(v) => v,
            None => {
                return ProbeReport::fail(
                    self.name(),
                    ProbeSeverity::Error,
                    "urn:chio:error:cli:doctor-toolchain-mismatch",
                    format!("Could not parse cargo version output: {raw_version}"),
                );
            }
        };

        let mut report = ProbeReport::ok(
            self.name(),
            format!(
                "Rust toolchain {}.{}.{} satisfies workspace MSRV.",
                parsed.0, parsed.1, parsed.2
            ),
        )
        .with_context("cargo_version", raw_version.clone());

        if let Some(msrv) = Self::read_msrv(&root) {
            report = report.with_context("msrv", msrv.clone());
            if let Some((m_major, m_minor)) = Self::parse_minor(&msrv) {
                if (parsed.0, parsed.1) < (m_major, m_minor) {
                    return ProbeReport::fail(
                        self.name(),
                        ProbeSeverity::Error,
                        "urn:chio:error:cli:doctor-toolchain-mismatch",
                        format!(
                            "Rust toolchain {}.{}.{} is older than workspace MSRV {}.",
                            parsed.0, parsed.1, parsed.2, msrv
                        ),
                    )
                    .with_context("cargo_version", raw_version)
                    .with_context("msrv", msrv)
                    .with_help("Upgrade Rust to at least the workspace MSRV before running chio.");
                }
            }
        }

        if let Some(pinned) = Self::read_pinned_toolchain(&root) {
            report = report.with_context("pinned_channel", pinned.clone());
            if let Some((p_major, p_minor)) = Self::parse_minor(&pinned) {
                if (parsed.0, parsed.1) != (p_major, p_minor) {
                    return ProbeReport::fail(
                        self.name(),
                        ProbeSeverity::Error,
                        "urn:chio:error:cli:doctor-toolchain-mismatch",
                        format!(
                            "Active cargo {}.{} does not match rust-toolchain.toml channel {}.",
                            parsed.0, parsed.1, pinned
                        ),
                    )
                    .with_context("cargo_version", raw_version)
                    .with_context("pinned_channel", pinned)
                    .with_help(
                        "Run `rustup show` and align the active toolchain with the pinned channel.",
                    );
                }
            }
        }

        report
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_temp_workspace(msrv: Option<&str>, channel: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut manifest = fs::File::create(dir.path().join("Cargo.toml")).expect("manifest");
        writeln!(manifest, "[workspace]").expect("write");
        if let Some(msrv) = msrv {
            writeln!(manifest, "[workspace.package]").expect("write");
            writeln!(manifest, "rust-version = \"{msrv}\"").expect("write");
        }
        if let Some(channel) = channel {
            let mut tc = fs::File::create(dir.path().join("rust-toolchain.toml")).expect("tc");
            writeln!(tc, "[toolchain]").expect("write");
            writeln!(tc, "channel = \"{channel}\"").expect("write");
        }
        dir
    }

    #[test]
    fn parses_cargo_version_with_metadata() {
        let parsed =
            ToolchainProbe::parse_cargo_version("cargo 1.93.0 (083ac5135 2025-12-15)").unwrap();
        assert_eq!(parsed, (1, 93, 0));
    }

    #[test]
    fn ok_when_cargo_meets_msrv() {
        let dir = write_temp_workspace(Some("1.80"), None);
        let probe = ToolchainProbe::default()
            .with_root(dir.path().to_path_buf())
            .with_cargo_version("cargo 1.93.0 (abc 2025-12-15)");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Ok);
    }

    #[test]
    fn fails_when_cargo_below_msrv() {
        let dir = write_temp_workspace(Some("1.95"), None);
        let probe = ToolchainProbe::default()
            .with_root(dir.path().to_path_buf())
            .with_cargo_version("cargo 1.93.0 (abc 2025-12-15)");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Error);
        assert_eq!(report.code, "urn:chio:error:cli:doctor-toolchain-mismatch");
    }

    #[test]
    fn fails_when_pinned_channel_disagrees() {
        let dir = write_temp_workspace(None, Some("1.94.0"));
        let probe = ToolchainProbe::default()
            .with_root(dir.path().to_path_buf())
            .with_cargo_version("cargo 1.93.0 (abc 2025-12-15)");
        let report = probe.run(&ProbeConfig::default());
        assert_eq!(report.severity, ProbeSeverity::Error);
        assert_eq!(report.code, "urn:chio:error:cli:doctor-toolchain-mismatch");
    }
}
