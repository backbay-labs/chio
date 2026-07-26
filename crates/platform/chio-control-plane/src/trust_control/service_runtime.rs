#[path = "service_runtime/admission_authority.rs"]
mod admission_authority;
#[path = "service_runtime/budget.rs"]
pub mod budget;
#[path = "service_runtime/client.rs"]
pub mod client;
#[path = "service_runtime/errors.rs"]
mod errors;
#[path = "service_runtime/init.rs"]
mod init;
#[path = "service_runtime/issuance.rs"]
pub mod issuance;
#[path = "service_runtime/public_registry.rs"]
pub mod public_registry;
#[path = "service_runtime/remote_admission.rs"]
pub(crate) mod remote_admission;
#[path = "service_runtime/remote_authority.rs"]
pub mod remote_authority;
#[path = "service_runtime/remote_stores.rs"]
pub mod remote_stores;
#[path = "service_runtime/reputation.rs"]
pub mod reputation;
#[path = "service_runtime/router.rs"]
mod router;

#[cfg(test)]
#[path = "service_runtime/tests/mod.rs"]
mod tests;

use super::*;

pub(crate) use init::serve_async;
