use std::fmt;

use serde::{Deserialize, Serialize};

use crate::_generated::error_codes::{lookup_error_code, ErrorCodeSpec};
use crate::{Code, Domain, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    code: Code,
    domain: Domain,
    severity: Severity,
    message: String,
    help: Option<String>,
}

impl Diagnostic {
    #[must_use]
    pub fn new(
        code: impl Into<Code>,
        domain: Domain,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            domain,
            severity,
            message: message.into(),
            help: None,
        }
    }

    #[must_use]
    pub fn from_spec(spec: &ErrorCodeSpec, message: impl Into<String>) -> Self {
        Self::new(spec.urn, spec.domain, spec.severity, message).with_help(spec.help)
    }

    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    #[must_use]
    pub fn code(&self) -> &Code {
        &self.code
    }

    #[must_use]
    pub const fn domain(&self) -> Domain {
        self.domain
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn help(&self) -> Option<&str> {
        self.help.as_deref()
    }

    #[must_use]
    pub fn registry_spec(&self) -> Option<&'static ErrorCodeSpec> {
        let spec = lookup_error_code(self.code.as_str())?;
        (self.domain == spec.domain && self.severity == spec.severity).then_some(spec)
    }

    #[must_use]
    pub fn into_error(self) -> ChioError {
        ChioError { diagnostic: self }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.help() {
            Some(help) => write!(
                f,
                "{} [{}:{}]: {} ({})",
                self.code, self.domain, self.severity, self.message, help
            ),
            None => write!(
                f,
                "{} [{}:{}]: {}",
                self.code, self.domain, self.severity, self.message
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{diagnostic}")]
pub struct ChioError {
    diagnostic: Diagnostic,
}

impl ChioError {
    #[must_use]
    pub fn new(
        code: impl Into<Code>,
        domain: Domain,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Diagnostic::new(code, domain, severity, message).into_error()
    }

    #[must_use]
    pub fn from_spec(spec: &ErrorCodeSpec, message: impl Into<String>) -> Self {
        Diagnostic::from_spec(spec, message).into_error()
    }

    #[must_use]
    pub fn diagnostic(&self) -> &Diagnostic {
        &self.diagnostic
    }

    #[must_use]
    pub fn code(&self) -> &Code {
        self.diagnostic.code()
    }

    #[must_use]
    pub const fn domain(&self) -> Domain {
        self.diagnostic.domain()
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.diagnostic.severity()
    }

    #[must_use]
    pub fn message(&self) -> &str {
        self.diagnostic.message()
    }

    #[must_use]
    pub fn help(&self) -> Option<&str> {
        self.diagnostic.help()
    }

    #[must_use]
    pub fn registry_spec(&self) -> Option<&'static ErrorCodeSpec> {
        self.diagnostic.registry_spec()
    }
}

impl From<Diagnostic> for ChioError {
    fn from(diagnostic: Diagnostic) -> Self {
        diagnostic.into_error()
    }
}

#[must_use]
pub fn diagnostic(
    code: impl Into<Code>,
    domain: Domain,
    severity: Severity,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(code, domain, severity, message)
}

#[must_use]
pub fn diagnostic_from_spec(spec: &ErrorCodeSpec, message: impl Into<String>) -> Diagnostic {
    Diagnostic::from_spec(spec, message)
}

#[must_use]
pub fn error(
    code: impl Into<Code>,
    domain: Domain,
    severity: Severity,
    message: impl Into<String>,
) -> ChioError {
    ChioError::new(code, domain, severity, message)
}

#[must_use]
pub fn error_from_spec(spec: &ErrorCodeSpec, message: impl Into<String>) -> ChioError {
    ChioError::from_spec(spec, message)
}
