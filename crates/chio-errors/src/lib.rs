mod code;
mod diagnostic;
mod domain;
mod severity;

pub use code::Code;
pub use diagnostic::{diagnostic, error, ChioError, Diagnostic};
pub use domain::{Domain, UnknownDomain};
pub use severity::{Severity, UnknownSeverity};

pub type Result<T> = std::result::Result<T, ChioError>;
