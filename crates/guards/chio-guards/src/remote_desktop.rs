//! RemoteDesktopSideChannelGuard - per-channel enable/disable with
//! transfer-size limits for remote desktop / RDP / VNC style sessions.
//!
//! Implements Chio's synchronous [`chio_kernel::Guard`] trait.
//!
//! Handles six named side channels, each with an independent toggle:
//!
//! | Channel        | Action type              | Config field              |
//! |----------------|--------------------------|---------------------------|
//! | Clipboard      | `remote.clipboard`       | `clipboard_enabled`       |
//! | File transfer  | `remote.file_transfer`   | `file_transfer_enabled`   |
//! | Session share  | `remote.session_share`   | `session_share_enabled`   |
//! | Audio          | `remote.audio`           | `audio_enabled`           |
//! | Drive mapping  | `remote.drive_mapping`   | `drive_mapping_enabled`   |
//! | Printing       | `remote.printing`        | `printing_enabled`        |
//!
//! Additional controls:
//!
//! - `max_transfer_size_bytes`: when set, `remote.file_transfer` actions
//!   must include a `transfer_size` / `transferSize` `u64` argument.
//!   Missing, non-integer, or oversized values are denied.
//! - **Unknown `remote.*` channels are denied** - the default branch is
//!   fail-closed so new side channels are not silently permitted.
//!
//! Session-lifecycle actions (`remote.session.connect`,
//! `remote.session.disconnect`, `remote.session.reconnect`) are **not**
//! claimed by this guard; they are the job of [`crate::ComputerUseGuard`]
//! at the coarse layer.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use chio_kernel::{Guard, GuardContext, GuardDecision, KernelError, Verdict};

/// Configuration for [`RemoteDesktopSideChannelGuard`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDesktopSideChannelConfig {
    /// Enable/disable the guard entirely.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Allow clipboard operations.
    #[serde(default = "default_true")]
    pub clipboard_enabled: bool,
    /// Allow file transfer operations.
    #[serde(default = "default_true")]
    pub file_transfer_enabled: bool,
    /// Allow session sharing.
    #[serde(default = "default_true")]
    pub session_share_enabled: bool,
    /// Allow remote audio channel.
    #[serde(default = "default_true")]
    pub audio_enabled: bool,
    /// Allow remote drive mapping.
    #[serde(default = "default_true")]
    pub drive_mapping_enabled: bool,
    /// Allow remote printing.
    #[serde(default = "default_true")]
    pub printing_enabled: bool,
    /// Maximum file-transfer size in bytes.  `None` disables the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transfer_size_bytes: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl Default for RemoteDesktopSideChannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            clipboard_enabled: true,
            file_transfer_enabled: true,
            session_share_enabled: true,
            audio_enabled: true,
            drive_mapping_enabled: true,
            printing_enabled: true,
            max_transfer_size_bytes: None,
        }
    }
}

/// Guard that enforces per-channel toggles and transfer-size limits for
/// remote desktop side channels.
pub struct RemoteDesktopSideChannelGuard {
    config: RemoteDesktopSideChannelConfig,
}

impl RemoteDesktopSideChannelGuard {
    /// Build a guard with default configuration (all channels enabled,
    /// no transfer limit).
    pub fn new() -> Self {
        Self::with_config(RemoteDesktopSideChannelConfig::default())
    }

    /// Build a guard with explicit configuration.
    pub fn with_config(config: RemoteDesktopSideChannelConfig) -> Self {
        Self { config }
    }

    /// Return the side-channel `remote.*` action type this call targets,
    /// if any.  Checks `tool_name` first, then falls back to
    /// `action_type` / `custom_type` arguments.
    fn channel_action_type(tool_name: &str, arguments: &Value) -> Option<String> {
        if is_side_channel(tool_name) {
            return Some(tool_name.to_string());
        }
        for key in ["action_type", "actionType", "custom_type", "customType"] {
            if let Some(v) = arguments.get(key).and_then(|v| v.as_str()) {
                if is_side_channel(v) {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    /// Parse a `transfer_size` / `transferSize` argument into a byte
    /// count.  Returns:
    ///
    /// - `Ok(Some(u64))` when a valid value is present;
    /// - `Ok(None)` when the field is absent;
    /// - `Err(())` when the field is present but not a `u64`.
    #[allow(clippy::result_unit_err)]
    fn read_transfer_size(arguments: &Value) -> Result<Option<u64>, ()> {
        let value = match arguments
            .get("transfer_size")
            .or_else(|| arguments.get("transferSize"))
        {
            Some(v) => v,
            None => return Ok(None),
        };
        match value.as_u64() {
            Some(n) => Ok(Some(n)),
            None => Err(()),
        }
    }
}

impl Default for RemoteDesktopSideChannelGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for RemoteDesktopSideChannelGuard {
    fn name(&self) -> &str {
        "remote-desktop-side-channel"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if !self.config.enabled {
            return Ok(GuardDecision::allow());
        }

        let channel =
            match Self::channel_action_type(&ctx.request.tool_name, &ctx.request.arguments) {
                Some(c) => c,
                None => return Ok(GuardDecision::allow()),
            };

        let verdict = match channel.as_str() {
            "remote.clipboard" => {
                if self.config.clipboard_enabled {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            }
            "remote.file_transfer" => {
                if !self.config.file_transfer_enabled {
                    return Ok(GuardDecision::deny(Vec::new()));
                }
                if let Some(max) = self.config.max_transfer_size_bytes {
                    match Self::read_transfer_size(&ctx.request.arguments) {
                        Ok(Some(n)) => {
                            if n > max {
                                return Ok(GuardDecision::deny(Vec::new()));
                            }
                        }
                        // Missing or non-integer transfer_size with a
                        // configured max → fail-closed.
                        Ok(None) | Err(()) => return Ok(GuardDecision::deny(Vec::new())),
                    }
                }
                return Ok(GuardDecision::allow());
            }
            "remote.session_share" => {
                if self.config.session_share_enabled {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            }
            "remote.audio" => {
                if self.config.audio_enabled {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            }
            "remote.drive_mapping" => {
                if self.config.drive_mapping_enabled {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            }
            "remote.printing" => {
                if self.config.printing_enabled {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            }
            // Unknown `remote.*` channel → fail-closed.
            _ => Verdict::Deny,
        };
        Ok(GuardDecision::from_verdict(verdict))
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, ctx: &GuardContext) -> Result<(), KernelError> {
        crate::revalidate_non_consuming_guard(self, ctx)
    }
}

/// Return `true` when `s` is a `remote.*` side-channel action type
/// (excluding the session-lifecycle trio owned by [`crate::ComputerUseGuard`]).
fn is_side_channel(s: &str) -> bool {
    if !s.starts_with("remote.") {
        return false;
    }
    !matches!(
        s,
        "remote.session.connect" | "remote.session.disconnect" | "remote.session.reconnect"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_side_channel_classifies_correctly() {
        assert!(is_side_channel("remote.clipboard"));
        assert!(is_side_channel("remote.file_transfer"));
        assert!(is_side_channel("remote.webrtc")); // unknown but still `remote.*`
        assert!(!is_side_channel("remote.session.connect"));
        assert!(!is_side_channel("input.inject"));
        assert!(!is_side_channel("filesystem"));
    }

    #[test]
    fn read_transfer_size_variants() {
        let ok = serde_json::json!({"transfer_size": 1024});
        assert_eq!(
            RemoteDesktopSideChannelGuard::read_transfer_size(&ok),
            Ok(Some(1024))
        );
        let camel = serde_json::json!({"transferSize": 2048});
        assert_eq!(
            RemoteDesktopSideChannelGuard::read_transfer_size(&camel),
            Ok(Some(2048))
        );
        let missing = serde_json::json!({});
        assert_eq!(
            RemoteDesktopSideChannelGuard::read_transfer_size(&missing),
            Ok(None)
        );
        let bad = serde_json::json!({"transfer_size": "1024"});
        assert_eq!(
            RemoteDesktopSideChannelGuard::read_transfer_size(&bad),
            Err(())
        );
    }
}
