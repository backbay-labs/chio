/// Configuration for the ACP security proxy.
///
/// Use the builder methods to customise the proxy before passing the
/// config to the interceptor or transport layer.
#[derive(Debug, Clone)]
pub struct AcpProxyConfig {
    /// Command used to spawn the ACP agent subprocess.
    agent_command: String,
    /// Arguments passed to the agent subprocess.
    agent_args: Vec<String>,
    /// Additional environment variables set on the agent subprocess.
    agent_env: Vec<(String, String)>,
    /// Filesystem path prefixes the agent is allowed to access.
    allowed_path_prefixes: Vec<String>,
    /// Terminal commands the agent is allowed to execute.
    allowed_commands: Vec<String>,
    /// Public key used for receipt verification (hex-encoded).
    public_key: String,
    /// Chio server identity string included in receipts.
    server_id: String,
}

impl AcpProxyConfig {
    /// Create a new proxy configuration with the required fields.
    ///
    /// All guard lists start empty (deny-all).
    #[must_use]
    pub fn new(agent_command: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            agent_command: agent_command.into(),
            agent_args: Vec::new(),
            agent_env: Vec::new(),
            allowed_path_prefixes: Vec::new(),
            allowed_commands: Vec::new(),
            public_key: public_key.into(),
            server_id: "chio-acp-proxy".to_string(),
        }
    }

    /// Append arguments to the agent subprocess command line.
    #[must_use]
    pub fn with_agent_args(mut self, args: Vec<String>) -> Self {
        self.agent_args = args;
        self
    }

    /// Set extra environment variables for the agent subprocess.
    #[must_use]
    pub fn with_agent_env(mut self, env: Vec<(String, String)>) -> Self {
        self.agent_env = env;
        self
    }

    /// Add a filesystem path prefix that the agent is allowed to access.
    #[must_use]
    pub fn with_allowed_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_path_prefixes.push(prefix.into());
        self
    }

    /// Add a terminal command to the allowlist.
    #[must_use]
    pub fn with_allowed_command(mut self, command: impl Into<String>) -> Self {
        self.allowed_commands.push(command.into());
        self
    }

    /// Override the default Chio server ID embedded in receipts.
    #[must_use]
    pub fn with_server_id(mut self, server_id: impl Into<String>) -> Self {
        self.server_id = server_id.into();
        self
    }

    // -- accessors --

    /// The command to spawn the ACP agent.
    pub fn agent_command(&self) -> &str {
        &self.agent_command
    }

    /// Arguments for the agent subprocess.
    pub fn agent_args(&self) -> &[String] {
        &self.agent_args
    }

    /// Environment variables for the agent subprocess.
    pub fn agent_env(&self) -> &[(String, String)] {
        &self.agent_env
    }

    /// Path prefixes the agent may read/write.
    pub fn allowed_path_prefixes(&self) -> &[String] {
        &self.allowed_path_prefixes
    }

    /// Commands the agent may execute.
    pub fn allowed_commands(&self) -> &[String] {
        &self.allowed_commands
    }

    /// Public key for receipt signing.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Chio server ID.
    pub fn server_id(&self) -> &str {
        &self.server_id
    }
}
