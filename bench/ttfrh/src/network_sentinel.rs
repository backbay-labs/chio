//! Telemetry-free first-run network sentinel.
//!
//! The sentinel inspects every outbound hostname captured during a
//! TTFRH bench run against an allowlist. If any hostname falls outside
//! the per-template (or global) allowlist, the sentinel reports the
//! offending host and the gate fails.
//!
//! Two paths are supported:
//!
//! - The container lane wraps the bench in an iptables-style packet
//!   capture that streams hostnames into a temp file. The sentinel
//!   parses that file with [`SentinelReport::parse_capture_lines`].
//! - The in-process lane verifies the allowlist itself loads, the
//!   templates declare zero unsanctioned hostnames, and the per-template
//!   allowlist is empty by default (telemetry-free).
//!
//! No network I/O happens here; this module is pure logic over byte
//! buffers so the bench remains hermetic on hosts without `iptables`.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crate::TemplateRunner;

/// Allowlist parsed from `bench/ttfrh/sentinel/allowlist.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    pub global_hosts: BTreeSet<String>,
    pub per_template: Vec<TemplateAllowlist>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateAllowlist {
    pub template: TemplateRunner,
    pub hosts: BTreeSet<String>,
}

impl Allowlist {
    /// Allowlist embedded at compile time so the bench can run without
    /// reading the on-disk TOML. Any drift between this constant and
    /// the TOML manifest is caught by [`Self::matches_manifest`].
    pub fn embedded() -> Self {
        let mut global = BTreeSet::new();
        global.insert("127.0.0.1".to_owned());
        global.insert("localhost".to_owned());
        global.insert("::1".to_owned());
        Self {
            global_hosts: global,
            per_template: vec![
                TemplateAllowlist {
                    template: TemplateRunner::NextAiSdkReceipts,
                    hosts: BTreeSet::new(),
                },
                TemplateAllowlist {
                    template: TemplateRunner::FastapiLangchain,
                    hosts: BTreeSet::new(),
                },
                TemplateAllowlist {
                    template: TemplateRunner::CloudflareWorker,
                    hosts: BTreeSet::new(),
                },
            ],
        }
    }

    /// Crude TOML-presence check that the on-disk manifest still names
    /// every loopback host listed in the embedded constant. Avoids a
    /// full TOML parser dependency in the bench crate.
    pub fn matches_manifest(&self, manifest: &str) -> bool {
        let manifest = strip_toml_comments(manifest);
        for host in &self.global_hosts {
            if !manifest.contains(&format!("\"{host}\"")) {
                return false;
            }
        }
        for entry in &self.per_template {
            let header = format!("[templates.{}]", entry.template.slug());
            if !manifest.contains(&header) {
                return false;
            }
        }
        true
    }

    pub fn allows(&self, template: TemplateRunner, host: &str) -> bool {
        if self.global_hosts.contains(host) {
            return true;
        }
        self.per_template
            .iter()
            .find(|entry| entry.template == template)
            .is_some_and(|entry| entry.hosts.contains(host))
    }

    pub fn template_hosts(&self, template: TemplateRunner) -> Option<&BTreeSet<String>> {
        self.per_template
            .iter()
            .find(|entry| entry.template == template)
            .map(|entry| &entry.hosts)
    }
}

fn strip_toml_comments(manifest: &str) -> String {
    const BASIC_MULTILINE_DELIMITER: &str = "\"\"\"";
    const LITERAL_MULTILINE_DELIMITER: &str = "'''";

    let mut stripped = String::with_capacity(manifest.len());
    let mut mode = TomlStringMode::Bare;
    let mut index = 0;
    while index < manifest.len() {
        let Some(rest) = manifest.get(index..) else {
            break;
        };
        match mode {
            TomlStringMode::Bare => {
                if rest.starts_with(BASIC_MULTILINE_DELIMITER) {
                    stripped.push_str(BASIC_MULTILINE_DELIMITER);
                    index += BASIC_MULTILINE_DELIMITER.len();
                    mode = TomlStringMode::MultilineBasic { escaped: false };
                    continue;
                }
                if rest.starts_with(LITERAL_MULTILINE_DELIMITER) {
                    stripped.push_str(LITERAL_MULTILINE_DELIMITER);
                    index += LITERAL_MULTILINE_DELIMITER.len();
                    mode = TomlStringMode::MultilineLiteral;
                    continue;
                }
                let Some((ch, width)) = next_toml_char(rest) else {
                    break;
                };
                match ch {
                    '"' => {
                        stripped.push(ch);
                        index += width;
                        mode = TomlStringMode::Basic { escaped: false };
                    }
                    '\'' => {
                        stripped.push(ch);
                        index += width;
                        mode = TomlStringMode::Literal;
                    }
                    '#' => {
                        while let Some((comment_ch, comment_width)) =
                            manifest.get(index..).and_then(next_toml_char)
                        {
                            if comment_ch == '\n' {
                                break;
                            }
                            index += comment_width;
                        }
                    }
                    _ => {
                        stripped.push(ch);
                        index += width;
                    }
                }
            }
            TomlStringMode::Basic { escaped } => {
                let Some((ch, width)) = next_toml_char(rest) else {
                    break;
                };
                stripped.push(ch);
                index += width;
                mode = if ch == '\n' || (!escaped && ch == '"') {
                    TomlStringMode::Bare
                } else if !escaped && ch == '\\' {
                    TomlStringMode::Basic { escaped: true }
                } else {
                    TomlStringMode::Basic { escaped: false }
                };
            }
            TomlStringMode::Literal => {
                let Some((ch, width)) = next_toml_char(rest) else {
                    break;
                };
                stripped.push(ch);
                index += width;
                if ch == '\n' || ch == '\'' {
                    mode = TomlStringMode::Bare;
                }
            }
            TomlStringMode::MultilineBasic { escaped } => {
                if !escaped {
                    match multiline_quote_prefix(rest, '"') {
                        MultilineQuotePrefix::ClosingDelimiter(count) => {
                            stripped.extend(std::iter::repeat_n('"', count));
                            index += count;
                            mode = TomlStringMode::Bare;
                            continue;
                        }
                        MultilineQuotePrefix::ContentQuotes(count) => {
                            stripped.extend(std::iter::repeat_n('"', count));
                            index += count;
                            continue;
                        }
                        MultilineQuotePrefix::None => {}
                    }
                }
                let Some((ch, width)) = next_toml_char(rest) else {
                    break;
                };
                stripped.push(ch);
                index += width;
                mode = if escaped {
                    TomlStringMode::MultilineBasic { escaped: false }
                } else if ch == '\\' {
                    TomlStringMode::MultilineBasic { escaped: true }
                } else {
                    TomlStringMode::MultilineBasic { escaped: false }
                };
            }
            TomlStringMode::MultilineLiteral => {
                match multiline_quote_prefix(rest, '\'') {
                    MultilineQuotePrefix::ClosingDelimiter(count) => {
                        stripped.extend(std::iter::repeat_n('\'', count));
                        index += count;
                        mode = TomlStringMode::Bare;
                        continue;
                    }
                    MultilineQuotePrefix::ContentQuotes(count) => {
                        stripped.extend(std::iter::repeat_n('\'', count));
                        index += count;
                        continue;
                    }
                    MultilineQuotePrefix::None => {}
                }
                let Some((ch, width)) = next_toml_char(rest) else {
                    break;
                };
                stripped.push(ch);
                index += width;
            }
        }
    }

    stripped
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultilineQuotePrefix {
    None,
    ContentQuotes(usize),
    ClosingDelimiter(usize),
}

fn multiline_quote_prefix(rest: &str, quote: char) -> MultilineQuotePrefix {
    let quote_count = rest.chars().take_while(|ch| *ch == quote).count();
    match quote_count {
        0..=2 => MultilineQuotePrefix::None,
        3 => MultilineQuotePrefix::ClosingDelimiter(3),
        4 | 5 => MultilineQuotePrefix::ContentQuotes(quote_count - 3),
        _ => MultilineQuotePrefix::ClosingDelimiter(quote_count),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TomlStringMode {
    Bare,
    Basic { escaped: bool },
    Literal,
    MultilineBasic { escaped: bool },
    MultilineLiteral,
}

fn next_toml_char(input: &str) -> Option<(char, usize)> {
    input.chars().next().map(|ch| (ch, ch.len_utf8()))
}

/// Result of running the sentinel against a captured hostname stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelReport {
    pub template: TemplateRunner,
    pub allowed: BTreeSet<String>,
    pub offending: BTreeSet<String>,
}

impl SentinelReport {
    pub fn passed(&self) -> bool {
        self.offending.is_empty()
    }

    /// Parse `host:port` (or bare `host`) lines from a packet capture
    /// stream and classify each entry against the allowlist.
    pub fn parse_capture_lines<'a, I: IntoIterator<Item = &'a str>>(
        template: TemplateRunner,
        allowlist: &Allowlist,
        lines: I,
    ) -> Self {
        let mut allowed = BTreeSet::new();
        let mut offending = BTreeSet::new();
        for raw in lines {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let host = split_host_port(line);
            if host.is_empty() {
                continue;
            }
            if allowlist.allows(template, host) {
                allowed.insert(host.to_owned());
            } else {
                offending.insert(host.to_owned());
            }
        }
        Self {
            template,
            allowed,
            offending,
        }
    }
}

/// Strip an optional trailing `:port` from a capture line while preserving
/// IPv6 literals.
///
/// IPv6 addresses contain colons, so a naive `split_once(':')` strips the
/// host down to an empty string and silently bypasses the sentinel
/// (allowing arbitrary IPv6 endpoints to evade the allowlist). Three forms
/// are supported:
///
/// - `[::1]:8787`   - bracketed IPv6 with port; brackets and port stripped.
/// - `[::1]`        - bracketed IPv6 without port.
/// - `127.0.0.1:80` - IPv4 or hostname with port; port stripped.
/// - `::1`          - bare IPv6 literal (no port; preserved as-is).
/// - `127.0.0.1`    - bare IPv4/hostname.
fn split_host_port(line: &str) -> &str {
    let line = line.trim();
    // Bracketed form unambiguously delimits the host.
    if let Some(rest) = line.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            return &rest[..close];
        }
        // Mismatched bracket: treat the whole rest as the host literal.
        return rest;
    }
    // A bare line containing two or more colons is an IPv6 literal with no
    // port, e.g. `::1` or `fe80::1`. Preserve it verbatim.
    if line.matches(':').count() >= 2 {
        return line;
    }
    // Otherwise (IPv4 or hostname, optionally `:port`), strip a single port.
    match line.split_once(':') {
        Some((host, _)) => host.trim(),
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_allowlist_covers_loopback() {
        let allowlist = Allowlist::embedded();
        assert!(allowlist.global_hosts.contains("127.0.0.1"));
        assert!(allowlist.global_hosts.contains("localhost"));
        assert!(allowlist.global_hosts.contains("::1"));
    }

    #[test]
    fn loopback_is_always_allowed() {
        let allowlist = Allowlist::embedded();
        assert!(allowlist.allows(TemplateRunner::NextAiSdkReceipts, "127.0.0.1"));
        assert!(allowlist.allows(TemplateRunner::FastapiLangchain, "localhost"));
        assert!(allowlist.allows(TemplateRunner::CloudflareWorker, "::1"));
    }

    #[test]
    fn unsanctioned_host_is_not_allowed() {
        let allowlist = Allowlist::embedded();
        assert!(!allowlist.allows(TemplateRunner::NextAiSdkReceipts, "telemetry.example"));
    }

    #[test]
    fn parse_capture_flags_only_offending_hosts() {
        let allowlist = Allowlist::embedded();
        let lines = [
            "# trace start",
            "127.0.0.1:3000",
            "telemetry.example:443",
            "localhost",
            "",
        ];
        let report = SentinelReport::parse_capture_lines(
            TemplateRunner::NextAiSdkReceipts,
            &allowlist,
            lines.iter().copied(),
        );
        assert!(!report.passed());
        assert!(report.allowed.contains("127.0.0.1"));
        assert!(report.allowed.contains("localhost"));
        assert!(report.offending.contains("telemetry.example"));
    }

    #[test]
    fn split_host_port_handles_ipv6_forms() {
        // Bare IPv6 literals: preserved as-is so they can match the
        // loopback allowlist (`::1`, etc).
        assert_eq!(split_host_port("::1"), "::1");
        assert_eq!(split_host_port("fe80::1"), "fe80::1");
        // Bracketed IPv6 with and without port.
        assert_eq!(split_host_port("[::1]:8787"), "::1");
        assert_eq!(split_host_port("[fe80::1]"), "fe80::1");
        // IPv4 with port.
        assert_eq!(split_host_port("127.0.0.1:3000"), "127.0.0.1");
        // Hostname with port.
        assert_eq!(
            split_host_port("telemetry.example:443"),
            "telemetry.example"
        );
        // Bare hostname.
        assert_eq!(split_host_port("localhost"), "localhost");
    }

    #[test]
    fn parse_capture_does_not_silently_drop_ipv6_addresses() {
        let allowlist = Allowlist::embedded();
        let lines = ["[::1]:8787", "[2001:db8::1]:443", "fe80::1"];
        let report = SentinelReport::parse_capture_lines(
            TemplateRunner::CloudflareWorker,
            &allowlist,
            lines.iter().copied(),
        );
        // ::1 is in the loopback allowlist; the other IPv6 addresses must
        // surface as offending instead of being silently dropped.
        assert!(report.allowed.contains("::1"));
        assert!(report.offending.contains("2001:db8::1"));
        assert!(report.offending.contains("fe80::1"));
        assert!(!report.passed());
    }

    #[test]
    fn empty_capture_passes() {
        let allowlist = Allowlist::embedded();
        let report = SentinelReport::parse_capture_lines(
            TemplateRunner::FastapiLangchain,
            &allowlist,
            std::iter::empty(),
        );
        assert!(report.passed());
        assert!(report.offending.is_empty());
    }

    #[test]
    fn manifest_matches_embedded_when_in_sync() {
        let manifest = include_str!("../sentinel/allowlist.toml");
        let allowlist = Allowlist::embedded();
        assert!(allowlist.matches_manifest(manifest));
    }

    #[test]
    fn manifest_match_ignores_commented_hosts() {
        let manifest = r#"
# "127.0.0.1"
global_hosts = ["localhost", "::1"]

[templates.next-ai-sdk-receipts]
hosts = []

[templates.fastapi-langchain]
hosts = []

[templates.cloudflare-worker]
hosts = []
"#;
        let allowlist = Allowlist::embedded();
        assert!(!allowlist.matches_manifest(manifest));
    }

    #[test]
    fn manifest_match_preserves_hash_inside_quoted_hosts() {
        let manifest = r#"
global_hosts = ["127.0.0.1", "localhost", "::1", "server#1.example.com"] # comment

[templates.next-ai-sdk-receipts]
hosts = []

[templates.fastapi-langchain]
hosts = []

[templates.cloudflare-worker]
hosts = []
"#;
        let mut allowlist = Allowlist::embedded();
        allowlist
            .global_hosts
            .insert("server#1.example.com".to_string());

        assert!(allowlist.matches_manifest(manifest));
    }

    #[test]
    fn comment_stripping_preserves_hash_inside_multiline_strings() {
        let manifest = concat!(
            "note = \"\"\"\n",
            "basic # not a comment\n",
            "\"\"\"\n",
            "literal = '''\n",
            "literal # not a comment\n",
            "'''\n",
            "# real comment\n",
        );

        let stripped = strip_toml_comments(manifest);

        assert!(stripped.contains("basic # not a comment"));
        assert!(stripped.contains("literal # not a comment"));
        assert!(!stripped.contains("# real comment"));
    }

    #[test]
    fn comment_stripping_handles_basic_quote_next_to_multiline_delimiter() {
        let manifest = concat!(
            "quote = \"\"\"\"quoted # not a comment\"\"\"\" # trailing comment\n",
            "# real comment\n",
        );

        let stripped = strip_toml_comments(manifest);

        assert!(stripped.contains("quoted # not a comment"));
        assert!(!stripped.contains("# trailing comment"));
        assert!(!stripped.contains("# real comment"));
    }

    #[test]
    fn comment_stripping_handles_literal_quote_next_to_multiline_delimiter() {
        let manifest = concat!(
            "quote = ''''quoted # not a comment'''' # trailing comment\n",
            "# real comment\n",
        );

        let stripped = strip_toml_comments(manifest);

        assert!(stripped.contains("quoted # not a comment"));
        assert!(!stripped.contains("# trailing comment"));
        assert!(!stripped.contains("# real comment"));
    }

    #[test]
    fn comment_stripping_consumes_oversized_basic_multiline_quote_runs() {
        for quote_count in [6, 7] {
            let closing = "\"".repeat(quote_count);
            let manifest = format!(
                "quote = \"\"\"quoted{closing} # trailing comment\n\
                 next = \"hash # not a comment\"\n\
                 # real comment\n"
            );

            let stripped = strip_toml_comments(&manifest);

            assert!(stripped.contains("quoted"), "{stripped}");
            assert!(
                stripped.contains("hash # not a comment"),
                "{quote_count}: {stripped}"
            );
            assert!(
                !stripped.contains("# trailing comment"),
                "{quote_count}: {stripped}"
            );
            assert!(
                !stripped.contains("# real comment"),
                "{quote_count}: {stripped}"
            );
        }
    }

    #[test]
    fn comment_stripping_consumes_oversized_literal_multiline_quote_runs() {
        for quote_count in [6, 7] {
            let closing = "'".repeat(quote_count);
            let manifest = format!(
                "quote = '''quoted{closing} # trailing comment\n\
                 next = 'hash # not a comment'\n\
                 # real comment\n"
            );

            let stripped = strip_toml_comments(&manifest);

            assert!(stripped.contains("quoted"), "{stripped}");
            assert!(
                stripped.contains("hash # not a comment"),
                "{quote_count}: {stripped}"
            );
            assert!(
                !stripped.contains("# trailing comment"),
                "{quote_count}: {stripped}"
            );
            assert!(
                !stripped.contains("# real comment"),
                "{quote_count}: {stripped}"
            );
        }
    }

    #[test]
    fn telemetry_free_first_run_per_template() {
        let allowlist = Allowlist::embedded();
        for template in TemplateRunner::ALL {
            match allowlist.template_hosts(template) {
                Some(hosts) => assert!(
                    hosts.is_empty(),
                    "{} default allowlist must be empty (telemetry-free)",
                    template
                ),
                None => panic!("{} missing allowlist entry", template),
            }
        }
    }
}
