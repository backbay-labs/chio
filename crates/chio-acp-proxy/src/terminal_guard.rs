/// Terminal command execution guard.
///
/// Fail-closed: only commands explicitly on the allowlist may execute.
/// Arguments are checked for common shell injection patterns.
#[derive(Debug, Clone)]
pub struct TerminalGuard {
    allowed_commands: Vec<String>,
}

impl TerminalGuard {
    /// Create a new guard with an explicit command allowlist.
    pub fn new(allowed_commands: Vec<String>) -> Self {
        Self { allowed_commands }
    }

    /// Check whether `command` with the given `args` is permitted.
    ///
    /// The shell-metacharacter check on arguments is **defense-in-depth**.
    /// In normal operation, arguments are passed to the subprocess via
    /// `execve` (through `std::process::Command::args`), not through a
    /// shell, so metacharacters like `|`, `;`, and backticks have no
    /// special meaning to the kernel. However, some agent runtimes or
    /// user configurations may invoke commands through a shell wrapper.
    /// The guard rejects suspicious arguments as a secondary safety
    /// layer to catch misuse even in those scenarios.
    pub fn check_command(&self, command: &str, args: &[String]) -> Result<(), AcpProxyError> {
        // Fail-closed: empty allowlist means deny everything.
        if self.allowed_commands.is_empty() {
            return Err(AcpProxyError::AccessDenied(
                "terminal denied: no allowed commands configured".to_string(),
            ));
        }

        if command.is_empty() {
            return Err(AcpProxyError::AccessDenied(
                "terminal denied: empty command".to_string(),
            ));
        }

        let allowed = self.allowed_commands.iter().any(|c| c == command);

        if !allowed {
            return Err(AcpProxyError::AccessDenied(format!(
                "terminal denied: command not allowed: {command}"
            )));
        }

        // Check arguments for shell injection patterns.
        for arg in args {
            if contains_shell_metachar(arg) {
                return Err(AcpProxyError::AccessDenied(format!(
                    "terminal denied: suspicious argument: {arg}"
                )));
            }
        }

        Ok(())
    }
}

/// Return true if the argument contains characters commonly used for
/// shell injection.
fn contains_shell_metachar(arg: &str) -> bool {
    // Flag backticks, $(), pipes, semicolons, and newlines.
    arg.contains('`')
        || arg.contains("$(")
        || arg.contains('|')
        || arg.contains(';')
        || arg.contains('\n')
        || arg.contains('\r')
}
