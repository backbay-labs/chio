//! Cross-platform resident-set-size sampling with no external dependencies.

/// Current resident set size of this process in bytes, or `None` when the
/// platform sampler is unavailable or returns an unparseable value.
///
/// Linux reads `VmRSS` from `/proc/self/status` (reported in kibibytes, so no
/// page-size assumption is needed); other Unix platforms shell out to
/// `ps -o rss=`.
#[must_use]
pub fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        rss_from_proc_status()
    }
    #[cfg(not(target_os = "linux"))]
    {
        rss_from_ps()
    }
}

#[cfg(target_os = "linux")]
fn rss_from_proc_status() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let kibibytes: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return kibibytes.checked_mul(1024);
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn rss_from_ps() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let kibibytes: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    kibibytes.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::current_rss_bytes;

    #[test]
    fn rss_current_rss_bytes_reports_positive_on_supported_platforms() {
        let sampled = current_rss_bytes();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        match sampled {
            Some(bytes) => assert!(
                bytes > 0,
                "resident set on {} must be positive, got {bytes}",
                std::env::consts::OS
            ),
            None => panic!(
                "current_rss_bytes must report Some on {}",
                std::env::consts::OS
            ),
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // Unsupported platforms must return without panicking; the value may
            // legitimately be None.
            let _ = sampled;
        }
    }
}
