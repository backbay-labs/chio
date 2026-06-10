use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

/// Manages the stdio transport to a spawned ACP agent subprocess.
///
/// Messages are exchanged as newline-delimited JSON over the child
/// process's stdin/stdout.
pub struct AcpTransport {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

impl AcpTransport {
    /// Spawn the ACP agent as a subprocess and return a transport
    /// handle for bidirectional JSON-RPC communication.
    pub fn spawn(
        command: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<Self, AcpProxyError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn().map_err(|e| {
            AcpProxyError::Transport(format!("failed to spawn agent process '{command}': {e}"))
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            AcpProxyError::Transport("agent process stdout not captured".to_string())
        })?;

        let reader = BufReader::new(stdout);

        Ok(Self { child, reader })
    }

    /// Send a JSON-RPC message to the agent's stdin.
    pub fn send(&mut self, message: &serde_json::Value) -> Result<(), AcpProxyError> {
        let stdin = self.child.stdin.as_mut().ok_or_else(|| {
            AcpProxyError::Transport("agent process stdin not available".to_string())
        })?;

        let serialized = serde_json::to_string(message).map_err(|e| {
            AcpProxyError::Protocol(format!("failed to serialize message: {e}"))
        })?;

        stdin.write_all(serialized.as_bytes()).map_err(|e| {
            AcpProxyError::Transport(format!("failed to write to agent stdin: {e}"))
        })?;
        stdin.write_all(b"\n").map_err(|e| {
            AcpProxyError::Transport(format!("failed to write newline to agent stdin: {e}"))
        })?;
        stdin.flush().map_err(|e| {
            AcpProxyError::Transport(format!("failed to flush agent stdin: {e}"))
        })?;

        Ok(())
    }

    /// Read the next JSON-RPC message from the agent's stdout.
    ///
    /// Returns `Ok(None)` when the agent has closed its stdout (EOF).
    pub fn recv(&mut self) -> Result<Option<serde_json::Value>, AcpProxyError> {
        let mut line = String::new();
        let bytes_read = self.reader.read_line(&mut line).map_err(|e| {
            AcpProxyError::Transport(format!("failed to read from agent stdout: {e}"))
        })?;

        if bytes_read == 0 {
            return Ok(None);
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            AcpProxyError::Protocol(format!("invalid JSON from agent: {e}"))
        })?;

        Ok(Some(value))
    }

    /// Attempt to kill the agent subprocess.
    pub fn kill(&mut self) -> Result<(), AcpProxyError> {
        self.child.kill().map_err(|e| {
            AcpProxyError::Transport(format!("failed to kill agent process: {e}"))
        })
    }

    /// Wait for the agent subprocess to exit and return its status code.
    pub fn wait(&mut self) -> Result<Option<i32>, AcpProxyError> {
        let status = self.child.wait().map_err(|e| {
            AcpProxyError::Transport(format!("failed to wait on agent process: {e}"))
        })?;
        Ok(status.code())
    }
}
