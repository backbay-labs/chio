//! CHIO_BLESS gate logic for the replay-gate `--bless` flow.
//!
//! `--bless` is the only sanctioned way to overwrite a blessed golden
//! under `tests/replay/goldens/**`. The flow is fail-closed: every one
//! of the seven programmatic clauses below must hold, evaluated up
//! front, before any byte is written. The eighth doc-level clause
//! (CODEOWNERS review on `tests/replay/goldens/**`) is enforced by
//! branch protection on the PR side and is therefore not part of the
//! in-process gate.
//!
//! The seven programmatic clauses:
//!
//! 1. `CHIO_BLESS=1` is set in the environment.
//! 2. `BLESS_REASON` is set and non-empty (recorded in the audit
//!    entry).
//! 3. The current branch is not `main` and not `release/*`.
//! 4. The working tree is clean except for paths under
//!    `tests/replay/goldens/` and the file `docs/replay-compat.md`.
//! 5. `stderr` is a TTY (human-attended terminal).
//! 6. The `CI` env var is unset or set to `false` / `0` / empty
//!    string (CI cannot bless). Any other non-empty value (including
//!    `true`, `1`, `yes`, or arbitrary build-system markers) is
//!    treated as "running under CI" and refused.
//! 7. The bless writes a one-line audit entry to
//!    `tests/replay/.bless-audit.log` and the same commit must include
//!    that audit-log line; the gate refuses if the audit log is dirty
//!    while the goldens are clean (or vice versa).
//!
//! All filesystem, process, and env access is routed through the
//! [`EnvProvider`], [`GitProvider`], and [`FsProvider`] traits so each
//! clause is unit-testable in isolation. Production code wires the
//! real providers in [`evaluate_gate_real`]; tests construct the
//! [`StubEnv`] / [`StubGit`] / [`StubFs`] doubles below.

use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use thiserror::Error;

/// Path (relative to the workspace root) of the bless audit log.
///
/// The bless flow appends a single line to this file per invocation
/// and the same commit must include the appended line. The file is
/// committed to the repository; the gate compares the working-tree
/// status of this path against the goldens-tree status to enforce the
/// "audit log moves in lockstep with the goldens" invariant of clause 7.
pub const AUDIT_LOG_RELATIVE_PATH: &str = "tests/replay/.bless-audit.log";

/// Placeholder written into the `<sha>` audit-log column at bless time.
///
/// At bless time the goldens, audit-log line, and (optionally)
/// `docs/replay-compat.md` have been staged but not committed, so
/// `git rev-parse HEAD` does NOT yet reflect the SHA the audit-log
/// entry will be embedded in. The bless flow writes this placeholder
/// instead and the operator runs `scripts/seal-bless-audit.sh` (or
/// the equivalent post-merge script) to rewrite the placeholder rows
/// to the real merge SHA on a follow-up commit. The audit-log file
/// header documents the same convention. Sealing is operator-initiated
/// (rather than hooked off `post-commit`) so a single audit-trail row
/// records exactly one commit SHA.
pub const PENDING_SHA_MARKER: &str = "<commit-sha-pending>";

/// Working-tree path prefix that is allowed to be dirty during bless.
///
/// Anything under `tests/replay/goldens/` is the legitimate output of
/// the bless flow.
pub const GOLDENS_DIR_PREFIX: &str = "tests/replay/goldens/";

/// Working-tree path that is allowed to be dirty during bless.
///
/// `docs/replay-compat.md` is updated alongside goldens to document
/// cross-version compatibility shifts.
pub const REPLAY_COMPAT_DOC_PATH: &str = "docs/replay-compat.md";

/// Errors emitted by the CHIO_BLESS gate.
///
/// Each variant maps 1:1 to one of the seven gate clauses; on any
/// error the gate refuses to bless and the caller must abort before
/// touching the goldens tree.
#[derive(Debug, Error)]
pub enum BlessGateError {
    /// Clause 1: `CHIO_BLESS` env var must be exactly `"1"`.
    #[error("CHIO_BLESS env var must be exactly \"1\" (was {0:?})")]
    ChioBlessNotSet(Option<String>),

    /// Clause 2: `BLESS_REASON` must be set and non-empty.
    #[error("BLESS_REASON env var must be set and non-empty")]
    BlessReasonEmpty,

    /// Clause 3: branch must not be `main` or `release/*`.
    #[error("current branch {0:?} is forbidden (main or release/*)")]
    ForbiddenBranch(String),

    /// Clause 4: working tree dirty outside the bless allowlist.
    #[error("working tree has unexpected changes outside the bless allowlist: {0}")]
    DirtyWorkingTree(String),

    /// Clause 5: stderr must be a TTY.
    #[error("stderr is not a TTY; bless requires a human-attended terminal")]
    StderrNotTty,

    /// Clause 6: a non-empty / non-falsey `CI` env var is forbidden.
    /// The contained value is the observed `CI` value for diagnostics.
    #[error("CI env var is set to {0:?}; CI cannot bless")]
    RunningUnderCi(String),

    /// Clause 7: audit log and goldens must move together.
    ///
    /// The audit log line is written by the bless flow itself
    /// ([`append_audit_line`]); this error fires when the gate
    /// observes pre-bless that the audit log path is already dirty
    /// while no goldens are dirty (or vice versa).
    #[error(
        "audit-log / goldens skew: audit log dirty={audit_dirty}, goldens dirty={goldens_dirty}"
    )]
    AuditLogSkew {
        /// Whether `tests/replay/.bless-audit.log` was dirty pre-bless.
        audit_dirty: bool,
        /// Whether anything under `tests/replay/goldens/` was dirty
        /// pre-bless.
        goldens_dirty: bool,
    },

    /// I/O failure while shelling out to `git` or running a provider.
    #[error("git command failed: {0}")]
    Git(String),

    /// I/O failure while writing the audit-log line.
    #[error("audit log line could not be written to {path}: {source}")]
    AuditLogWriteFailure {
        /// Path of the audit log that the bless flow was writing to.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Read-only view onto the process environment.
///
/// All env-var reads in the gate go through this trait so unit tests
/// can stub them without touching the actual process env (which would
/// race with parallel test workers).
pub trait EnvProvider {
    /// Return the value of `key`, or `None` if unset.
    fn var(&self, key: &str) -> Option<String>;
}

/// Read-only view onto the local git repository.
///
/// All `git` invocations in the gate go through this trait so unit
/// tests can stub them without forking actual `git` processes.
pub trait GitProvider {
    /// Return the current branch (`git rev-parse --abbrev-ref HEAD`).
    fn current_branch(&self) -> Result<String, BlessGateError>;

    /// Return the current commit SHA (`git rev-parse HEAD`).
    fn head_sha(&self) -> Result<String, BlessGateError>;

    /// Return the configured user name (`git config user.name`).
    fn user_name(&self) -> Result<String, BlessGateError>;

    /// Return the configured user email (`git config user.email`).
    fn user_email(&self) -> Result<String, BlessGateError>;

    /// Return the list of working-tree paths reported by
    /// `git status --porcelain` (one path per entry; rename arrows are
    /// pre-resolved by the implementation).
    fn dirty_paths(&self) -> Result<Vec<String>, BlessGateError>;
}

/// Filesystem-side I/O surface used by the bless flow.
///
/// Today this is only used by [`append_audit_line`] (clause 7 audit
/// entry write). It exists as a trait so future bless flows can stub
/// it or layer in atomic-write semantics without touching call sites.
pub trait FsProvider {
    /// Append `line` (terminated by `\n`) to `path`, creating the file
    /// if it does not yet exist.
    fn append_line(&self, path: &Path, line: &str) -> std::io::Result<()>;
}

/// Successful gate output: everything an audit-log writer needs.
///
/// Returned only when all seven clauses pass. Subsequent code calls
/// [`append_audit_line`] with this context to satisfy clause 7's
/// audit-log line.
#[derive(Debug, Clone)]
pub struct BlessContext {
    /// Branch the bless was invoked from.
    pub branch: String,
    /// SHA of `HEAD` at the time of the gate evaluation.
    pub sha: String,
    /// Configured `git config user.name`.
    pub user_name: String,
    /// Configured `git config user.email`.
    pub user_email: String,
    /// UTC timestamp at which the gate was evaluated.
    pub timestamp: DateTime<Utc>,
    /// Free-form rationale read from `BLESS_REASON`.
    pub bless_reason: String,
    /// Fixture path the bless targets (caller-provided).
    pub fixture_path: PathBuf,
}

/// Evaluate the seven CHIO_BLESS gate clauses.
///
/// Returns a [`BlessContext`] when all clauses pass; the caller then
/// passes that context to [`append_audit_line`] before writing any
/// goldens. Returns [`BlessGateError`] on the first clause that
/// fails; callers are expected to surface the error to stderr and
/// abort.
///
/// # Parameters
///
/// - `env`: env-var read provider (production: [`SystemEnv`]).
/// - `git`: git-state read provider (production: [`SystemGit`]).
/// - `tty_stderr`: result of `std::io::IsTerminal::is_terminal()` on
///   `stderr`. Hoisted as a parameter (rather than read inside the
///   function) so unit tests can drive it directly without depending
///   on the runtime stderr handle.
/// - `fixture_path`: path the caller intends to bless (recorded in
///   the audit context).
/// - `now`: timestamp to embed in the audit context. Hoisted as a
///   parameter so tests can pin a deterministic clock.
pub fn evaluate_gate(
    env: &dyn EnvProvider,
    git: &dyn GitProvider,
    tty_stderr: bool,
    fixture_path: PathBuf,
    now: DateTime<Utc>,
) -> Result<BlessContext, BlessGateError> {
    // Clause 6 first: CI is the loudest refusal and we want to surface
    // it before anything else even if CHIO_BLESS happens to be unset.
    //
    // Fail-closed contract: the gate only treats `CI` as "absent" when
    // the env var is unset, the empty string, or one of the standard
    // false-y tokens (`false`, `0`, `no`, `off`, case-insensitive). Any
    // other non-empty value is taken as "running under CI" and refused.
    // This keeps the gate from passing in CI environments that signal
    // their presence with `1`, `yes`, `TRUE`, or arbitrary build-system
    // markers (the original `CI=="true"` check failed open on those).
    if let Some(ci) = env.var("CI") {
        if !is_ci_falsey(&ci) {
            return Err(BlessGateError::RunningUnderCi(ci));
        }
    }

    // Clause 1: CHIO_BLESS=1.
    let chio_bless = env.var("CHIO_BLESS");
    if chio_bless.as_deref() != Some("1") {
        return Err(BlessGateError::ChioBlessNotSet(chio_bless));
    }

    // Clause 2: BLESS_REASON non-empty.
    let bless_reason = match env.var("BLESS_REASON") {
        Some(v) if !v.trim().is_empty() => v,
        _ => return Err(BlessGateError::BlessReasonEmpty),
    };

    // Clause 5: stderr must be a TTY.
    if !tty_stderr {
        return Err(BlessGateError::StderrNotTty);
    }

    // Clause 3: branch not main / release/*.
    let branch = git.current_branch()?;
    if branch_is_forbidden(&branch) {
        return Err(BlessGateError::ForbiddenBranch(branch));
    }

    // Clause 4 + clause 7: working-tree allowlist + audit-log lockstep.
    let dirty = git.dirty_paths()?;
    let mut unexpected: Vec<String> = Vec::new();
    let mut audit_dirty = false;
    let mut goldens_dirty = false;
    for path in &dirty {
        if path == AUDIT_LOG_RELATIVE_PATH {
            audit_dirty = true;
            continue;
        }
        if path.starts_with(GOLDENS_DIR_PREFIX) {
            goldens_dirty = true;
            continue;
        }
        if path == REPLAY_COMPAT_DOC_PATH {
            continue;
        }
        unexpected.push(path.clone());
    }
    if !unexpected.is_empty() {
        return Err(BlessGateError::DirtyWorkingTree(unexpected.join(", ")));
    }
    // Clause 7 (pre-bless skew check): the gate refuses if the audit
    // log is already dirty without any goldens dirty (someone wrote
    // an audit line without touching goldens) or vice versa (someone
    // staged goldens without recording an audit entry). The bless
    // flow itself appends one audit line and writes goldens together;
    // running the gate twice in a row is fine because both halves
    // stay in lockstep.
    if audit_dirty != goldens_dirty {
        return Err(BlessGateError::AuditLogSkew {
            audit_dirty,
            goldens_dirty,
        });
    }

    // All seven clauses cleared: collect identity bits for the audit
    // entry. The SHA column is intentionally a placeholder
    // (`<commit-sha-pending>`) because at bless time the staged goldens
    // and audit line are not yet committed; the post-bless sealing
    // step (`scripts/seal-bless-audit.sh`) rewrites the placeholder
    // rows to the actual merge SHA on a follow-up commit. We still
    // confirm `git rev-parse HEAD` succeeds so a broken repo state
    // surfaces here rather than later.
    let _ = git.head_sha()?;
    let sha = PENDING_SHA_MARKER.to_string();
    let user_name = git.user_name()?;
    let user_email = git.user_email()?;

    Ok(BlessContext {
        branch,
        sha,
        user_name,
        user_email,
        timestamp: now,
        bless_reason,
        fixture_path,
    })
}

/// Append a one-line audit entry to the bless audit log.
///
/// Format (single line, terminated by `\n`):
/// `<iso8601>\t<user_name> <<user_email>>\t<branch>\t<sha>\t<fixture>\t<reason>`
///
/// Tab-separated and explicitly fixed-order so a future tooling layer
/// can trivially `awk -F'\t'` over the log. The line is appended via
/// the supplied [`FsProvider`] so callers can swap in atomic-write
/// implementations later.
pub fn append_audit_line(
    fs: &dyn FsProvider,
    audit_log_path: &Path,
    ctx: &BlessContext,
) -> Result<(), BlessGateError> {
    let line = format!(
        "{}\t{} <{}>\t{}\t{}\t{}\t{}",
        ctx.timestamp.to_rfc3339_opts(SecondsFormat::Secs, true),
        sanitize_audit_field(&ctx.user_name),
        sanitize_audit_field(&ctx.user_email),
        sanitize_audit_field(&ctx.branch),
        sanitize_audit_field(&ctx.sha),
        sanitize_audit_field(&ctx.fixture_path.to_string_lossy()),
        sanitize_audit_field(&ctx.bless_reason),
    );
    fs.append_line(audit_log_path, &line)
        .map_err(|source| BlessGateError::AuditLogWriteFailure {
            path: audit_log_path.to_path_buf(),
            source,
        })
}

/// Replace tab and newline characters in audit fields with spaces.
///
/// The audit log is tab-separated and one entry per line; embedded
/// tabs / newlines would corrupt the format. Sanitization is
/// fail-open (replace with space) rather than fail-closed (refuse)
/// because audit entries are advisory: the security-critical path is
/// the gate, not the log.
fn sanitize_audit_field(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

/// Return `true` if `branch` is `main` or matches `release/*`.
fn branch_is_forbidden(branch: &str) -> bool {
    branch == "main" || branch.starts_with("release/")
}

/// Return `true` if `value` is one of the falsey tokens that the bless
/// gate treats as "CI not present".
///
/// The accepted falsey tokens are the empty string and (case-insensitive)
/// `false`, `0`, `no`, `off`. Every other non-empty value, including
/// `true`, `1`, `yes`, `on`, and arbitrary CI marker strings (e.g. a
/// build-system name), is treated as "running under CI" and refused.
/// Whitespace surrounding the value is trimmed before comparison so a
/// stray leading or trailing space does not flip the classification.
fn is_ci_falsey(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "false" | "0" | "no" | "off"
    )
}

// ---------------------------------------------------------------------------
// Production providers
// ---------------------------------------------------------------------------

/// Real env-var provider backed by `std::env::var_os`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnv;

impl EnvProvider for SystemEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Real git provider backed by `std::process::Command` invocations.
///
/// Each call shells out to `git` (which must be on `PATH`); failures
/// are mapped to [`BlessGateError::Git`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemGit;

impl SystemGit {
    fn run(args: &[&str]) -> Result<String, BlessGateError> {
        let output = std::process::Command::new("git")
            .args(args)
            .output()
            .map_err(|e| BlessGateError::Git(format!("spawning git {}: {}", args.join(" "), e)))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BlessGateError::Git(format!(
                "git {} failed: {}",
                args.join(" "),
                stderr.trim()
            )));
        }
        let stdout = String::from_utf8(output.stdout).map_err(|e| {
            BlessGateError::Git(format!(
                "git {} produced non-utf8 output: {}",
                args.join(" "),
                e
            ))
        })?;
        Ok(stdout.trim_end_matches('\n').to_string())
    }
}

impl GitProvider for SystemGit {
    fn current_branch(&self) -> Result<String, BlessGateError> {
        Self::run(&["rev-parse", "--abbrev-ref", "HEAD"])
    }

    fn head_sha(&self) -> Result<String, BlessGateError> {
        Self::run(&["rev-parse", "HEAD"])
    }

    fn user_name(&self) -> Result<String, BlessGateError> {
        Self::run(&["config", "user.name"])
    }

    fn user_email(&self) -> Result<String, BlessGateError> {
        Self::run(&["config", "user.email"])
    }

    fn dirty_paths(&self) -> Result<Vec<String>, BlessGateError> {
        // `git status --porcelain` produces lines like:
        //   " M path/to/file"
        //   "?? path/to/untracked"
        //   "R  oldpath -> newpath"
        //   "C  oldpath -> newpath"
        // The first two characters are the status code (X for index, Y
        // for working tree) followed by a space, then the path. The
        // ` -> ` arrow is only meaningful on rename (`R`) or copy (`C`)
        // entries; ordinary modified / added / untracked paths must be
        // taken verbatim even if their name happens to contain ` -> `
        // (a literal `evil -> tests/replay/goldens/sneak` modified file
        // must be reported as the unsplit path so the clause 4 / 7
        // allowlist logic treats it as out-of-allowlist, not as a
        // legitimate goldens-tree edit).
        let raw = Self::run(&["status", "--porcelain"])?;
        Ok(parse_porcelain_paths(&raw))
    }
}

/// Parse `git status --porcelain` (v1) output into a list of
/// working-tree paths.
///
/// Hoisted out of [`SystemGit::dirty_paths`] so it can be unit-tested
/// without forking a `git` subprocess. The rules:
///
/// - Lines shorter than the canonical `XY path` shape (3 chars
///   minimum past the status code) are dropped.
/// - The two-character status code is inspected to decide whether the
///   line is a rename / copy entry. Only when either the index status
///   or the worktree status is `R` (rename) or `C` (copy) is the
///   ` -> ` arrow split applied; for all other status codes the path
///   substring is taken verbatim.
/// - For rename / copy entries the destination (right of ` -> `) is
///   kept, matching the existing allowlist semantics that target the
///   committed final path.
///
/// Quoted paths (`-z`-style or porcelain v2) are out of scope: this
/// gate runs in non-bare working trees we control, so the v1 plain
/// format is sufficient.
fn parse_porcelain_paths(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        // Need at least "XY p" (status code + space + 1-char path).
        if line.len() < 4 {
            continue;
        }
        let bytes = line.as_bytes();
        // Status code is the first two bytes; path starts after the
        // single separator space at byte index 2 (so path begins at
        // byte index 3).
        let xy = &line[..2];
        let path = &line[3..];
        // Rename / copy entries: split on ` -> ` and keep the
        // destination. Anything else: take the path verbatim.
        let is_rename_or_copy = bytes[0] == b'R'
            || bytes[0] == b'C'
            || xy.as_bytes()[1] == b'R'
            || xy.as_bytes()[1] == b'C';
        if is_rename_or_copy {
            if let Some((_, new)) = path.split_once(" -> ") {
                out.push(new.to_string());
            } else {
                out.push(path.to_string());
            }
        } else {
            out.push(path.to_string());
        }
    }
    out
}

/// Real filesystem-write provider used by [`append_audit_line`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemFs;

impl FsProvider for SystemFs {
    fn append_line(&self, path: &Path, line: &str) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")
    }
}

/// Convenience wrapper that wires real env / git / fs providers and
/// reads `tty_stderr` from the live stderr handle.
///
/// Returns the same `Result` shape as [`evaluate_gate`].
pub fn evaluate_gate_real(
    fixture_path: PathBuf,
    now: DateTime<Utc>,
) -> Result<BlessContext, BlessGateError> {
    use std::io::IsTerminal;
    let env = SystemEnv;
    let git = SystemGit;
    let tty_stderr = std::io::stderr().is_terminal();
    evaluate_gate(&env, &git, tty_stderr, fixture_path, now)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;

    use chrono::TimeZone;
    use tempfile::TempDir;

    use super::*;

    /// Stub env provider backed by an in-memory map.
    struct StubEnv {
        vars: HashMap<String, String>,
    }

    impl StubEnv {
        fn new() -> Self {
            Self {
                vars: HashMap::new(),
            }
        }

        fn with(mut self, key: &str, value: &str) -> Self {
            self.vars.insert(key.to_string(), value.to_string());
            self
        }

        /// Build the all-clauses-pass env: `CHIO_BLESS=1`,
        /// `BLESS_REASON=<reason>`, no `CI`.
        fn happy() -> Self {
            Self::new()
                .with("CHIO_BLESS", "1")
                .with("BLESS_REASON", "fix corpus drift after kernel bump")
        }
    }

    impl EnvProvider for StubEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
    }

    /// Stub git provider with configurable values per method.
    struct StubGit {
        branch: String,
        sha: String,
        user_name: String,
        user_email: String,
        dirty: Vec<String>,
        fail_on_branch: bool,
    }

    impl StubGit {
        fn happy() -> Self {
            Self {
                branch: "wave/W2/m04/p2.t1-bless-gate-logic".to_string(),
                sha: "deadbeefcafebabe1234567890abcdef12345678".to_string(),
                user_name: "Jane Tester".to_string(),
                user_email: "jane@example.com".to_string(),
                dirty: Vec::new(),
                fail_on_branch: false,
            }
        }

        fn with_branch(mut self, branch: &str) -> Self {
            self.branch = branch.to_string();
            self
        }

        fn with_dirty(mut self, paths: &[&str]) -> Self {
            self.dirty = paths.iter().map(|s| s.to_string()).collect();
            self
        }

        fn failing_branch_lookup() -> Self {
            let mut g = Self::happy();
            g.fail_on_branch = true;
            g
        }
    }

    impl GitProvider for StubGit {
        fn current_branch(&self) -> Result<String, BlessGateError> {
            if self.fail_on_branch {
                Err(BlessGateError::Git("simulated git failure".into()))
            } else {
                Ok(self.branch.clone())
            }
        }

        fn head_sha(&self) -> Result<String, BlessGateError> {
            Ok(self.sha.clone())
        }

        fn user_name(&self) -> Result<String, BlessGateError> {
            Ok(self.user_name.clone())
        }

        fn user_email(&self) -> Result<String, BlessGateError> {
            Ok(self.user_email.clone())
        }

        fn dirty_paths(&self) -> Result<Vec<String>, BlessGateError> {
            Ok(self.dirty.clone())
        }
    }

    /// Stub fs provider backed by an in-memory `Vec<String>` log.
    struct StubFs {
        log: RefCell<Vec<String>>,
        force_error: bool,
    }

    impl StubFs {
        fn new() -> Self {
            Self {
                log: RefCell::new(Vec::new()),
                force_error: false,
            }
        }

        fn failing() -> Self {
            Self {
                log: RefCell::new(Vec::new()),
                force_error: true,
            }
        }
    }

    impl FsProvider for StubFs {
        fn append_line(&self, _path: &Path, line: &str) -> std::io::Result<()> {
            if self.force_error {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated fs failure",
                ));
            }
            self.log.borrow_mut().push(line.to_string());
            Ok(())
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 4, 26, 12, 0, 0) {
            chrono::LocalResult::Single(dt) => dt,
            _ => panic!("fixed_now construction must be unambiguous"),
        }
    }

    fn fixture() -> PathBuf {
        PathBuf::from("tests/replay/goldens/allow_simple/00")
    }

    // -----------------------------------------------------------------
    // Happy path: all seven clauses pass.
    // -----------------------------------------------------------------

    #[test]
    fn all_clauses_pass_returns_context() {
        let env = StubEnv::happy();
        let git = StubGit::happy();
        let result = evaluate_gate(&env, &git, true, fixture(), fixed_now());
        let ctx = match result {
            Ok(ctx) => ctx,
            Err(e) => panic!("expected Ok, got {e:?}"),
        };
        assert_eq!(ctx.branch, "wave/W2/m04/p2.t1-bless-gate-logic");
        // SHA column is the pending-bless placeholder; the actual commit SHA
        // is filled in by `scripts/seal-bless-audit.sh`. The stub git
        // provider's `head_sha` is still consulted (so a broken repo
        // surfaces here), but its value is not propagated into the audit
        // context.
        assert_eq!(ctx.sha, PENDING_SHA_MARKER);
        assert_eq!(ctx.user_name, "Jane Tester");
        assert_eq!(ctx.user_email, "jane@example.com");
        assert_eq!(ctx.bless_reason, "fix corpus drift after kernel bump");
        assert_eq!(ctx.timestamp, fixed_now());
    }

    // -----------------------------------------------------------------
    // Clause 1: CHIO_BLESS not set / not exactly "1".
    // -----------------------------------------------------------------

    #[test]
    fn clause_1_chio_bless_unset_refuses() {
        let env = StubEnv::new().with("BLESS_REASON", "rationale");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse without CHIO_BLESS");
        assert!(
            matches!(err, BlessGateError::ChioBlessNotSet(None)),
            "got {err:?}"
        );
    }

    #[test]
    fn clause_1_chio_bless_zero_refuses() {
        let env = StubEnv::new()
            .with("CHIO_BLESS", "0")
            .with("BLESS_REASON", "rationale");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse with CHIO_BLESS=0");
        match err {
            BlessGateError::ChioBlessNotSet(Some(v)) => {
                assert_eq!(v, "0");
            }
            other => panic!("got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // Clause 2: BLESS_REASON empty.
    // -----------------------------------------------------------------

    #[test]
    fn clause_2_bless_reason_unset_refuses() {
        let env = StubEnv::new().with("CHIO_BLESS", "1");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse without BLESS_REASON");
        assert!(
            matches!(err, BlessGateError::BlessReasonEmpty),
            "got {err:?}"
        );
    }

    #[test]
    fn clause_2_bless_reason_blank_refuses() {
        let env = StubEnv::new()
            .with("CHIO_BLESS", "1")
            .with("BLESS_REASON", "   \t  ");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse with whitespace BLESS_REASON");
        assert!(
            matches!(err, BlessGateError::BlessReasonEmpty),
            "got {err:?}"
        );
    }

    // -----------------------------------------------------------------
    // Clause 3: branch is main / release/*.
    // -----------------------------------------------------------------

    #[test]
    fn clause_3_main_branch_refuses() {
        let env = StubEnv::happy();
        let git = StubGit::happy().with_branch("main");
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse on main");
        match err {
            BlessGateError::ForbiddenBranch(b) => assert_eq!(b, "main"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_3_release_branch_refuses() {
        let env = StubEnv::happy();
        let git = StubGit::happy().with_branch("release/v3.0");
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse on release/*");
        match err {
            BlessGateError::ForbiddenBranch(b) => {
                assert_eq!(b, "release/v3.0");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_3_git_lookup_failure_propagates() {
        let env = StubEnv::happy();
        let git = StubGit::failing_branch_lookup();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must surface git failure");
        assert!(matches!(err, BlessGateError::Git(_)), "got {err:?}");
    }

    // -----------------------------------------------------------------
    // Clause 4: working tree dirty outside the bless allowlist.
    // -----------------------------------------------------------------

    #[test]
    fn clause_4_dirty_unrelated_path_refuses() {
        let env = StubEnv::happy();
        let git = StubGit::happy().with_dirty(&["crates/chio-kernel/src/lib.rs"]);
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse dirty unrelated path");
        match err {
            BlessGateError::DirtyWorkingTree(paths) => {
                assert!(paths.contains("crates/chio-kernel/src/lib.rs"));
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_4_dirty_goldens_and_audit_ok() {
        // Working tree dirty in both goldens AND the audit log: the
        // legitimate mid-bless state. Plus replay-compat doc allowed.
        let env = StubEnv::happy();
        let git = StubGit::happy().with_dirty(&[
            "tests/replay/goldens/allow_simple/00/receipts.ndjson",
            "tests/replay/.bless-audit.log",
            "docs/replay-compat.md",
        ]);
        let result = evaluate_gate(&env, &git, true, fixture(), fixed_now());
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn clause_4_replay_compat_doc_allowed() {
        let env = StubEnv::happy();
        let git = StubGit::happy().with_dirty(&["docs/replay-compat.md"]);
        let result = evaluate_gate(&env, &git, true, fixture(), fixed_now());
        assert!(result.is_ok(), "got {result:?}");
    }

    // -----------------------------------------------------------------
    // Clause 5: stderr is not a TTY.
    // -----------------------------------------------------------------

    #[test]
    fn clause_5_no_tty_refuses() {
        let env = StubEnv::happy();
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, false, fixture(), fixed_now())
            .expect_err("must refuse without TTY");
        assert!(matches!(err, BlessGateError::StderrNotTty), "got {err:?}");
    }

    // -----------------------------------------------------------------
    // Clause 6: CI=true.
    // -----------------------------------------------------------------

    #[test]
    fn clause_6_ci_true_refuses() {
        let env = StubEnv::happy().with("CI", "true");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse under CI=true");
        match err {
            BlessGateError::RunningUnderCi(v) => assert_eq!(v, "true"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_6_ci_true_takes_precedence_over_other_failures() {
        // CI=true must refuse even if CHIO_BLESS / BLESS_REASON are
        // unset; we want the loudest signal first so operators know
        // CI cannot bless under any circumstance.
        let env = StubEnv::new().with("CI", "true");
        let git = StubGit::happy().with_branch("main");
        let err =
            evaluate_gate(&env, &git, false, fixture(), fixed_now()).expect_err("must refuse");
        assert!(
            matches!(err, BlessGateError::RunningUnderCi(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn clause_6_ci_false_allowed() {
        let env = StubEnv::happy().with("CI", "false");
        let git = StubGit::happy();
        let result = evaluate_gate(&env, &git, true, fixture(), fixed_now());
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn clause_6_ci_one_refuses() {
        // The original gate failed open on `CI=1` (a common CI marker
        // outside the literal `true` convention). The fix treats any
        // non-falsey value as "running under CI".
        let env = StubEnv::happy().with("CI", "1");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse under CI=1");
        match err {
            BlessGateError::RunningUnderCi(v) => assert_eq!(v, "1"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_6_ci_yes_refuses() {
        let env = StubEnv::happy().with("CI", "yes");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse under CI=yes");
        match err {
            BlessGateError::RunningUnderCi(v) => assert_eq!(v, "yes"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_6_ci_arbitrary_marker_refuses() {
        // Some CI systems set `CI=GitHubActions` or similar. The gate
        // must treat any non-falsey marker as CI present.
        let env = StubEnv::happy().with("CI", "GitHubActions");
        let git = StubGit::happy();
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse under CI=GitHubActions");
        assert!(
            matches!(err, BlessGateError::RunningUnderCi(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn clause_6_ci_zero_allowed() {
        let env = StubEnv::happy().with("CI", "0");
        let git = StubGit::happy();
        let result = evaluate_gate(&env, &git, true, fixture(), fixed_now());
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn clause_6_ci_empty_allowed() {
        // Some shells set `CI=` (empty) when unsetting; treat the empty
        // string as "CI unset" rather than a non-falsey marker.
        let env = StubEnv::happy().with("CI", "");
        let git = StubGit::happy();
        let result = evaluate_gate(&env, &git, true, fixture(), fixed_now());
        assert!(result.is_ok(), "got {result:?}");
    }

    // -----------------------------------------------------------------
    // Clause 7: audit-log / goldens skew.
    // -----------------------------------------------------------------

    #[test]
    fn clause_7_audit_dirty_without_goldens_refuses() {
        let env = StubEnv::happy();
        let git = StubGit::happy().with_dirty(&["tests/replay/.bless-audit.log"]);
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse audit-log skew");
        match err {
            BlessGateError::AuditLogSkew {
                audit_dirty,
                goldens_dirty,
            } => {
                assert!(audit_dirty);
                assert!(!goldens_dirty);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn clause_7_goldens_dirty_without_audit_refuses() {
        let env = StubEnv::happy();
        let git =
            StubGit::happy().with_dirty(&["tests/replay/goldens/allow_simple/00/receipts.ndjson"]);
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("must refuse goldens-without-audit skew");
        match err {
            BlessGateError::AuditLogSkew {
                audit_dirty,
                goldens_dirty,
            } => {
                assert!(!audit_dirty);
                assert!(goldens_dirty);
            }
            other => panic!("got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // append_audit_line.
    // -----------------------------------------------------------------

    #[test]
    fn append_audit_line_writes_tab_separated_entry() {
        let fs = StubFs::new();
        let ctx = BlessContext {
            branch: "wave/W2/m04/p2.t1-bless-gate-logic".to_string(),
            // This test pins a literal SHA to keep field-parsing assertions tight.
            sha: "deadbeefcafebabe1234567890abcdef12345678".to_string(),
            user_name: "Jane Tester".to_string(),
            user_email: "jane@example.com".to_string(),
            timestamp: fixed_now(),
            bless_reason: "fix corpus drift after kernel bump".to_string(),
            fixture_path: fixture(),
        };
        let result = append_audit_line(&fs, Path::new("audit.log"), &ctx);
        assert!(result.is_ok(), "got {result:?}");
        let log = fs.log.borrow();
        assert_eq!(log.len(), 1);
        let line = &log[0];
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "line was: {line:?}");
        assert_eq!(fields[0], "2026-04-26T12:00:00Z");
        assert_eq!(fields[1], "Jane Tester <jane@example.com>");
        assert_eq!(fields[2], "wave/W2/m04/p2.t1-bless-gate-logic");
        assert_eq!(fields[3], "deadbeefcafebabe1234567890abcdef12345678");
        assert_eq!(fields[4], "tests/replay/goldens/allow_simple/00");
        assert_eq!(fields[5], "fix corpus drift after kernel bump");
    }

    #[test]
    fn append_audit_line_sanitizes_embedded_tabs_and_newlines() {
        let fs = StubFs::new();
        let ctx = BlessContext {
            branch: "feature".to_string(),
            sha: "abc".to_string(),
            user_name: "Jane\tTester".to_string(),
            user_email: "jane@example.com".to_string(),
            timestamp: fixed_now(),
            bless_reason: "line one\nline two".to_string(),
            fixture_path: fixture(),
        };
        let result = append_audit_line(&fs, Path::new("audit.log"), &ctx);
        assert!(result.is_ok(), "got {result:?}");
        let log = fs.log.borrow();
        let line = &log[0];
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "line was: {line:?}");
        assert!(!fields[1].contains('\t'));
        assert!(!fields[5].contains('\n'));
        assert!(fields[1].contains("Jane Tester"));
        assert!(fields[5].contains("line one line two"));
    }

    #[test]
    fn append_audit_line_propagates_io_failure() {
        let fs = StubFs::failing();
        let ctx = BlessContext {
            branch: "feature".to_string(),
            sha: "abc".to_string(),
            user_name: "Jane".to_string(),
            user_email: "j@example.com".to_string(),
            timestamp: fixed_now(),
            bless_reason: "rationale".to_string(),
            fixture_path: fixture(),
        };
        let err = append_audit_line(&fs, Path::new("audit.log"), &ctx)
            .expect_err("must propagate fs failure");
        match err {
            BlessGateError::AuditLogWriteFailure { path, .. } => {
                assert_eq!(path, PathBuf::from("audit.log"));
            }
            other => panic!("got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // SystemFs round-trip (uses tempfile, no env / network).
    // -----------------------------------------------------------------

    #[test]
    fn system_fs_appends_to_real_file() {
        let dir = match TempDir::new() {
            Ok(d) => d,
            Err(e) => panic!("tempdir: {e}"),
        };
        let path = dir.path().join("audit.log");
        let fs = SystemFs;
        let r1 = fs.append_line(&path, "first line");
        assert!(r1.is_ok(), "got {r1:?}");
        let r2 = fs.append_line(&path, "second line");
        assert!(r2.is_ok(), "got {r2:?}");
        let contents = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => panic!("read_to_string: {e}"),
        };
        assert_eq!(contents, "first line\nsecond line\n");
    }

    // -----------------------------------------------------------------
    // branch_is_forbidden helper.
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // parse_porcelain_paths helper.
    // -----------------------------------------------------------------

    #[test]
    fn porcelain_keeps_modified_path_with_arrow_in_name_verbatim() {
        // Modified files are NOT rename entries; the ` -> ` substring
        // in the path must be preserved verbatim, not split.
        let raw = " M evil -> tests/replay/goldens/sneak\n";
        let got = parse_porcelain_paths(raw);
        assert_eq!(got, vec!["evil -> tests/replay/goldens/sneak".to_string()]);
    }

    #[test]
    fn porcelain_keeps_untracked_path_with_arrow_verbatim() {
        let raw = "?? evil -> tests/replay/goldens/sneak\n";
        let got = parse_porcelain_paths(raw);
        assert_eq!(got, vec!["evil -> tests/replay/goldens/sneak".to_string()]);
    }

    #[test]
    fn porcelain_splits_actual_rename_entries() {
        let raw = "R  oldpath -> tests/replay/goldens/newpath\n";
        let got = parse_porcelain_paths(raw);
        assert_eq!(got, vec!["tests/replay/goldens/newpath".to_string()]);
    }

    #[test]
    fn porcelain_splits_actual_copy_entries() {
        let raw = "C  oldpath -> tests/replay/goldens/copy\n";
        let got = parse_porcelain_paths(raw);
        assert_eq!(got, vec!["tests/replay/goldens/copy".to_string()]);
    }

    #[test]
    fn porcelain_splits_when_worktree_status_is_rename() {
        // The worktree status (second column) can also be R when the
        // index is clean but the worktree carries a rename.
        let raw = " R old -> tests/replay/goldens/new\n";
        let got = parse_porcelain_paths(raw);
        assert_eq!(got, vec!["tests/replay/goldens/new".to_string()]);
    }

    #[test]
    fn porcelain_classifies_dirty_arrow_path_as_unexpected() {
        // End-to-end through evaluate_gate: a hostile filename
        // containing ` -> ` must NOT pass the allowlist.
        let env = StubEnv::happy();
        let git = StubGit::happy().with_dirty(&["evil -> tests/replay/goldens/sneak"]);
        let err = evaluate_gate(&env, &git, true, fixture(), fixed_now())
            .expect_err("crafted arrow path must NOT pass the allowlist");
        match err {
            BlessGateError::DirtyWorkingTree(paths) => {
                assert!(
                    paths.contains("evil -> tests/replay/goldens/sneak"),
                    "got {paths:?}"
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // is_ci_falsey helper.
    // -----------------------------------------------------------------

    #[test]
    fn ci_falsey_helper_recognises_known_false_tokens() {
        for v in ["", "  ", "false", "FALSE", "False", "0", "no", "NO", "off"] {
            assert!(is_ci_falsey(v), "expected {v:?} to be falsey");
        }
    }

    #[test]
    fn ci_falsey_helper_rejects_truthy_tokens() {
        for v in ["true", "1", "yes", "on", "github", "GitHubActions", "y"] {
            assert!(!is_ci_falsey(v), "expected {v:?} to be truthy");
        }
    }

    #[test]
    fn branch_helper_recognises_main_and_release() {
        assert!(branch_is_forbidden("main"));
        assert!(branch_is_forbidden("release/v3.0"));
        assert!(branch_is_forbidden("release/0.1.0"));
        assert!(!branch_is_forbidden("feature/foo"));
        assert!(!branch_is_forbidden("wave/W2/m04/p2.t1"));
        // "release" with no slash is NOT forbidden (matches doc:
        // `release/*`, not `release` exact). A literal `release`
        // branch would be unusual; we err on the side of allowing it
        // because the doc only blocks the prefix form.
        assert!(!branch_is_forbidden("release"));
    }
}
