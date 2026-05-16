//! Live Chiodos runtime admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::ChioReceipt;
use chio_core_types::{PublicKey, SignedExportEnvelope};
use chio_kernel::{
    KernelError, RuntimeAdmissionContext as KernelRuntimeAdmissionContext,
    RuntimeAdmissionDecision as KernelRuntimeAdmissionDecision, RuntimeAdmissionHook,
    ToolCallRequest,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

mod admission;
mod admission_hook;
mod buyer;
mod error;
mod hash;
mod ops;
mod orchestration;
mod pheromone_policy;
mod schema;
mod serde_io;
mod store;
pub(crate) mod treaty;
mod types;
mod validation;

pub use admission::*;
pub(crate) use admission::{trust_floor_identity, validate_runtime_trust_floor_transition};
pub use admission_hook::*;
pub use buyer::*;
pub use error::ChiodosRuntimeError;
pub(crate) use hash::canonical_sha256;
pub use hash::*;
pub use ops::*;
pub use orchestration::*;
pub use schema::*;
pub use serde_io::*;
pub use store::*;
pub use treaty::{
    bilateral_invocation_binding_sha256, compute_ladder_intersection,
    cross_boundary_admission_report_json, evaluate_cross_boundary_admission,
    governance_ladder_manifest_from_json, governance_ladder_manifest_sha256,
    ladder_intersection_from_json, ladder_intersection_json, ladder_intersection_semantic_sha256,
    ladder_intersection_sha256, receipt_lineage_bundle_from_json,
    receipt_lineage_statement_from_json, receipt_lineage_statement_sha256, treaty_scope_from_json,
    treaty_scope_semantic_intersection_sha256, treaty_scope_sha256,
    validate_cross_boundary_admission_report, validate_governance_ladder_manifest,
    validate_ladder_intersection, validate_treaty_scope,
};
pub use types::*;
pub use validation::*;
pub(crate) use validation::{
    ensure_sha256_hash, is_sha256_hex, rejected, validate_runtime_orchestration_step_state,
};
