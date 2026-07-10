//! Skill and Workflow Authority for Chio.
//!
//! This crate extends the Chio capability model with multi-step skill
//! composition. A *skill* is an ordered sequence of tool invocations with
//! declared I/O contracts, dependency relationships, and budget envelopes.
//!
//! # Core concepts
//!
//! - [`SkillGrant`] -- extends capability model for ordered tool sequences
//! - [`SkillManifest`] -- describes tool dependencies, I/O contracts, budget
//! - [`WorkflowReceipt`] -- captures complete execution trace as single artifact
//! - [`WorkflowAuthority`] -- validates each step against declared scope and budget
//!
//! # Example
//!
//! ```ignore
//! let manifest = SkillManifest { ... };
//! let authority = WorkflowAuthority::new(signing_key);
//! let execution = authority.begin(&manifest, &capability)?;
//!
//! for step in &manifest.steps {
//!     authority.validate_step(&execution, step, &arguments)?;
//!     // ... invoke tool ...
//!     authority.record_step_result(&mut execution, step, result)?;
//! }
//!
//! let receipt = authority.finalize(execution)?;
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod authority;
pub mod grant;
pub mod manifest;
pub mod receipt;

pub mod preflight {
    pub use chio_workflow_preflight::*;
}

pub use authority::{WorkflowAuthority, WorkflowError, WorkflowExecution};
pub use grant::SkillGrant;
pub use manifest::{IoContract, SkillManifest, SkillStep};
pub use preflight::{
    evaluate_workflow_preflight, WorkflowPreflightError, WorkflowPreflightPlan,
    WorkflowPreflightReport, WorkflowPreflightVerdict,
};
pub use receipt::{
    StepRecord, VendorSignatureRequirement, WorkflowReceipt, WorkflowReceiptBody,
    WorkflowReceiptError, WorkflowVendorSignature,
};
