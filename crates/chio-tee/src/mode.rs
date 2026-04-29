//! TEE shadow-runner mode lattice and resolver.
//!
//! The mode determines how the TEE side participates in kernel decisions:
//!
//! - [`Mode::VerdictOnly`]: capture verdicts only; no replay-side enforcement.
//! - [`Mode::Shadow`]: replay decisions in the TEE for attestation but do not
//!   block; divergences are logged for offline review.
//! - [`Mode::Enforce`]: replay decisions and reject when the TEE-side replay
//!   disagrees with the kernel verdict (fail-closed).
//!
//! Mode selection follows the precedence specified in
//! `.planning/trajectory/10-tee-replay-harness.md` lines 42-62:
//!
//! 1. Process env `CHIO_TEE_MODE` (highest)
//! 2. Sidecar TOML config under `[tee] mode = "..."`
//! 3. Per-tenant manifest default (`tenant.tee.mode`)
//! 4. Implicit default: [`Mode::VerdictOnly`] when no layer sets a value.
//!
//! SIGUSR1 is wired in [`MoteState`] as a runtime hot-toggle: the resolved
//! mode lives behind an [`ArcSwap<Mode>`] so readers see lock-free atomic
//! transitions, while the toggle lattice (`enforce -> shadow -> verdict-only`
//! is unconditional, upgrades require an explicit capability) is enforced in
//! [`MoteState::transition`].

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// TEE shadow-runner operating modes.
///
/// Ordered by escalation level from least to most enforcement:
/// [`Mode::VerdictOnly`] < [`Mode::Shadow`] < [`Mode::Enforce`]. The numeric
/// representation is intentional: it lets the lattice computation in
/// [`MoteState::transition`] use a simple comparison instead of a match table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Capture verdicts only. No replay-side enforcement runs.
    VerdictOnly,
    /// Replay decisions in the TEE; record divergences but do not block.
    Shadow,
    /// Replay decisions and reject on divergence. Fail-closed.
    Enforce,
}

impl Mode {
    /// String tag used in env vars, TOML, manifests, and receipts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::VerdictOnly => "verdict-only",
            Mode::Shadow => "shadow",
            Mode::Enforce => "enforce",
        }
    }

    /// Implicit default when no precedence layer sets a value.
    pub const fn default_mode() -> Self {
        Mode::VerdictOnly
    }
}

impl Default for Mode {
    fn default() -> Self {
        Mode::default_mode()
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Mode {
    type Err = ParseModeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "verdict-only" => Ok(Mode::VerdictOnly),
            "shadow" => Ok(Mode::Shadow),
            "enforce" => Ok(Mode::Enforce),
            other => Err(ParseModeError {
                value: other.to_string(),
            }),
        }
    }
}

/// Error returned by [`Mode::from_str`] when the input is not a known tag.
#[derive(Debug, thiserror::Error)]
#[error("unknown tee mode: {value:?} (expected verdict-only, shadow, or enforce)")]
pub struct ParseModeError {
    /// The unrecognised tag.
    pub value: String,
}

/// Identifies which precedence layer supplied the resolved mode.
///
/// Mirrors the layer list logged at startup as `tee.mode_resolved`. The
/// [`Source::Default`] variant covers the no-layer-set case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `CHIO_TEE_MODE` process env (highest priority).
    Env,
    /// `[tee] mode = "..."` from sidecar TOML.
    Toml,
    /// `tenant.tee.mode` from chio-manifest.
    TenantManifest,
    /// Implicit fallback ([`Mode::default_mode`]) when no layer is set.
    Default,
}

impl Source {
    /// Diagnostic tag used in `tee.mode_resolved` log output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::Toml => "toml",
            Source::TenantManifest => "tenant_manifest",
            Source::Default => "default",
        }
    }
}

/// Inputs to the precedence resolver.
///
/// Each layer is optional: callers populate whichever layers are available at
/// resolve time. The resolver applies env > toml > tenant manifest > default.
#[derive(Debug, Clone, Default)]
pub struct ModeInputs {
    /// Mode parsed from `CHIO_TEE_MODE`, if set and valid.
    pub env: Option<Mode>,
    /// Mode parsed from sidecar TOML `[tee] mode`, if present.
    pub toml: Option<Mode>,
    /// Mode supplied by the tenant manifest, if present.
    pub tenant_manifest: Option<Mode>,
}

/// Result of running the resolver. Holds the resolved [`Mode`], the [`Source`]
/// that won precedence, and the per-layer values (for `tee.mode_resolved`
/// diagnostic logging).
#[derive(Debug, Clone)]
pub struct ResolvedMode {
    /// The mode that won precedence.
    pub mode: Mode,
    /// Which layer supplied the winning mode.
    pub source: Source,
    /// Per-layer values, for diagnostic logging at startup.
    pub inputs: ModeInputs,
}

impl ResolvedMode {
    /// Run the precedence resolver: env > toml > tenant manifest > default.
    pub fn resolve(inputs: ModeInputs) -> Self {
        if let Some(mode) = inputs.env {
            return ResolvedMode {
                mode,
                source: Source::Env,
                inputs,
            };
        }
        if let Some(mode) = inputs.toml {
            return ResolvedMode {
                mode,
                source: Source::Toml,
                inputs,
            };
        }
        if let Some(mode) = inputs.tenant_manifest {
            return ResolvedMode {
                mode,
                source: Source::TenantManifest,
                inputs,
            };
        }
        ResolvedMode {
            mode: Mode::default_mode(),
            source: Source::Default,
            inputs,
        }
    }
}

/// Reason why a SIGUSR1 transition was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// Upgrade attempted (e.g. `verdict-only -> shadow`) but no
    /// `chio:tee/upgrade@1` capability token was supplied.
    #[error("upgrade {from} -> {to} requires chio:tee/upgrade@1 capability")]
    MissingUpgradeCapability {
        /// Mode the runtime was in before the request.
        from: Mode,
        /// Mode the requester asked for.
        to: Mode,
    },
}

/// Whether a transition from `from` to `to` is a downgrade or an upgrade.
///
/// Downgrades reduce blast radius (`enforce -> shadow -> verdict-only`) and
/// are unconditional. Upgrades require a capability token. Equal modes are
/// treated as no-op downgrades so the toggle is idempotent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Same mode: no-op.
    NoOp,
    /// Lower-enforcement target. Always allowed.
    Downgrade,
    /// Higher-enforcement target. Requires capability.
    Upgrade,
}

impl Direction {
    /// Classify a transition request.
    pub fn classify(from: Mode, to: Mode) -> Self {
        match from.cmp(&to) {
            std::cmp::Ordering::Equal => Direction::NoOp,
            std::cmp::Ordering::Greater => Direction::Downgrade,
            std::cmp::Ordering::Less => Direction::Upgrade,
        }
    }
}

/// Mutable, lock-free shared mode state.
///
/// Wraps [`ArcSwap<Mode>`] so any number of reader tasks can call
/// [`MoteState::current`] without blocking, while the SIGUSR1 handler (and
/// its in-test stand-in [`MoteState::transition`]) updates the cell
/// atomically. The lattice (downgrade always allowed, upgrade requires
/// capability) is enforced inside [`MoteState::transition`] so the live
/// signal handler and tests share one code path.
#[derive(Debug)]
pub struct MoteState {
    inner: Arc<ArcSwap<Mode>>,
}

impl MoteState {
    /// Construct a state cell initialised to `initial`.
    pub fn new(initial: Mode) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    /// Read the current mode without blocking.
    pub fn current(&self) -> Mode {
        **self.inner.load()
    }

    /// Apply a transition. Downgrades and no-ops succeed unconditionally.
    /// Upgrades require `upgrade_capability` to be `Some` (the caller is
    /// responsible for verifying the token's freshness against the
    /// `chio-control-plane` capability service before invoking this method).
    ///
    /// On success, returns the previous mode for receipt-log emission of the
    /// `tee.mode_changed { from, to }` event.
    pub fn transition(
        &self,
        target: Mode,
        upgrade_capability: Option<&str>,
    ) -> Result<Mode, TransitionError> {
        let from = self.current();
        match Direction::classify(from, target) {
            Direction::NoOp | Direction::Downgrade => {
                self.inner.store(Arc::new(target));
                Ok(from)
            }
            Direction::Upgrade => {
                if upgrade_capability.is_some() {
                    self.inner.store(Arc::new(target));
                    Ok(from)
                } else {
                    Err(TransitionError::MissingUpgradeCapability { from, to: target })
                }
            }
        }
    }

    /// Clone the inner `ArcSwap` so signal handlers spawned on background
    /// threads can read and update the same cell.
    pub fn handle(&self) -> Arc<ArcSwap<Mode>> {
        Arc::clone(&self.inner)
    }
}

impl Clone for MoteState {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn mode_round_trip_str() {
        for m in [Mode::VerdictOnly, Mode::Shadow, Mode::Enforce] {
            let parsed: Mode = m.as_str().parse().unwrap();
            assert_eq!(parsed, m);
        }
    }

    #[test]
    fn mode_default_is_verdict_only() {
        assert_eq!(Mode::default(), Mode::VerdictOnly);
    }

    #[test]
    fn mode_lattice_ordering() {
        assert!(Mode::VerdictOnly < Mode::Shadow);
        assert!(Mode::Shadow < Mode::Enforce);
    }

    #[test]
    fn unknown_tag_is_rejected() {
        assert!("monitor".parse::<Mode>().is_err());
    }

    #[test]
    fn resolver_default_when_empty() {
        let r = ResolvedMode::resolve(ModeInputs::default());
        assert_eq!(r.mode, Mode::VerdictOnly);
        assert_eq!(r.source, Source::Default);
    }

    #[test]
    fn downgrade_is_unconditional() {
        let s = MoteState::new(Mode::Enforce);
        let prev = s.transition(Mode::Shadow, None).unwrap();
        assert_eq!(prev, Mode::Enforce);
        assert_eq!(s.current(), Mode::Shadow);
        let prev = s.transition(Mode::VerdictOnly, None).unwrap();
        assert_eq!(prev, Mode::Shadow);
        assert_eq!(s.current(), Mode::VerdictOnly);
    }

    #[test]
    fn upgrade_requires_capability() {
        let s = MoteState::new(Mode::VerdictOnly);
        let err = s.transition(Mode::Shadow, None).unwrap_err();
        assert!(matches!(
            err,
            TransitionError::MissingUpgradeCapability { .. }
        ));
        assert_eq!(s.current(), Mode::VerdictOnly);
        s.transition(Mode::Shadow, Some("cap-token")).unwrap();
        assert_eq!(s.current(), Mode::Shadow);
    }

    #[test]
    fn no_op_transition_succeeds() {
        let s = MoteState::new(Mode::Shadow);
        let prev = s.transition(Mode::Shadow, None).unwrap();
        assert_eq!(prev, Mode::Shadow);
        assert_eq!(s.current(), Mode::Shadow);
    }
}
