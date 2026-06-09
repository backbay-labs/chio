/// Filesystem access guard that enforces path-scoped capabilities.
///
/// The guard is fail-closed: if no allowed prefix matches, access is
/// denied. Path traversal attacks using `..` components are rejected
/// before prefix checking.
///
/// By default the guard resolves existing path components through the
/// filesystem before prefix matching. This catches symlinks inside an
/// allowed tree that point outside that tree, including writes to new
/// files below an existing symlink.
#[derive(Debug, Clone)]
pub struct FsGuard {
    allowed_prefixes: Vec<String>,
    /// When true, resolve existing filesystem components before prefix
    /// matching. Falls back to textual canonicalization if no component
    /// can be resolved.
    resolve_symlinks: bool,
}

impl FsGuard {
    /// Create a new guard with the given set of allowed path prefixes.
    pub fn new(allowed_prefixes: Vec<String>) -> Self {
        Self {
            allowed_prefixes,
            resolve_symlinks: true,
        }
    }

    /// Enable or disable filesystem-level symlink resolution.
    ///
    /// When enabled, the guard resolves existing path components before
    /// checking prefixes. If no component can be resolved on disk, the
    /// guard falls back to textual canonicalization.
    #[must_use]
    pub fn with_resolve_symlinks(mut self, resolve: bool) -> Self {
        self.resolve_symlinks = resolve;
        self
    }

    /// Check whether a read operation on `path` is permitted.
    pub fn check_read(&self, path: &str) -> Result<(), AcpProxyError> {
        self.check_path(path, "read")
    }

    /// Check whether a write operation on `path` is permitted.
    pub fn check_write(&self, path: &str) -> Result<(), AcpProxyError> {
        self.check_path(path, "write")
    }

    /// Check whether a terminal working directory is permitted.
    pub fn check_cwd(&self, path: &str) -> Result<(), AcpProxyError> {
        self.check_path(path, "cwd")
    }

    fn check_path(&self, path: &str, operation: &str) -> Result<(), AcpProxyError> {
        // Reject empty paths immediately.
        if path.is_empty() {
            return Err(AcpProxyError::AccessDenied(format!(
                "fs {operation} denied: empty path"
            )));
        }

        // Reject relative paths -- all allowed prefixes are absolute.
        if !path.starts_with('/') {
            return Err(AcpProxyError::AccessDenied(format!(
                "fs {operation} denied: relative path not allowed: {path}"
            )));
        }

        // Reject path traversal attempts.
        if contains_traversal(&canonicalize_path(path)) {
            return Err(AcpProxyError::PathTraversal(path.to_string()));
        }

        // Resolve the canonical path (optionally through the filesystem).
        let canonical = self.resolve_path(path);

        // Fail-closed: deny if no prefix matches.
        if self.allowed_prefixes.is_empty() {
            return Err(AcpProxyError::AccessDenied(format!(
                "fs {operation} denied: no allowed path prefixes configured"
            )));
        }

        for prefix in &self.allowed_prefixes {
            let prefix = self.resolve_prefix(prefix);
            if prefix.is_empty() || contains_traversal(&prefix) {
                continue;
            }
            if canonical.starts_with(prefix.as_str()) {
                // Ensure the match is on a path boundary, not a substring.
                // e.g. prefix "/home/user/project" must NOT match
                // "/home/user/project_evil/secret.txt".
                let is_exact = canonical.len() == prefix.len();
                let has_boundary = canonical
                    .as_bytes()
                    .get(prefix.len())
                    .map(|&b| b == b'/')
                    .unwrap_or(false);
                if is_exact || has_boundary {
                    return Ok(());
                }
            }
        }

        Err(AcpProxyError::AccessDenied(format!(
            "fs {operation} denied for path: {path}"
        )))
    }

    fn resolve_path(&self, path: &str) -> String {
        if self.resolve_symlinks {
            if let Some(real) = resolve_existing_prefix(path) {
                return real;
            }
        }
        canonicalize_path(path)
    }

    fn resolve_prefix(&self, prefix: &str) -> String {
        let normalized = canonicalize_path(prefix);
        if !self.resolve_symlinks {
            return normalized;
        }
        resolve_existing_prefix(prefix).unwrap_or(normalized)
    }
}

fn resolve_existing_prefix(path: &str) -> Option<String> {
    use std::path::PathBuf;

    let mut original = PathBuf::new();
    let mut resolved = PathBuf::new();

    for component in std::path::Path::new(path).components() {
        original.push(component.as_os_str());
        if original.exists() {
            let real = std::fs::canonicalize(&original).ok()?;
            resolved = real;
        } else {
            resolved.push(component.as_os_str());
        }
    }

    Some(canonicalize_path(&resolved.to_string_lossy()))
}

/// Normalize a path string for comparison.
///
/// This performs basic textual normalization (collapsing separators,
/// trimming trailing slashes) without touching the filesystem, so it
/// works in unit tests without real files.
fn canonicalize_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                // We still collect ".." but `contains_traversal` will
                // reject the path later.
                parts.push("..");
            }
            other => parts.push(other),
        }
    }
    if path.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// Return true if the path contains parent-directory traversal.
fn contains_traversal(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}
