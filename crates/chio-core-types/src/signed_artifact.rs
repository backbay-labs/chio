//! Signed-artifact schema registry and fail-closed compatibility gate.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::capability::{
    CHIO_CAPABILITIES_SCHEMA, CHIO_CAPABILITY_V1_SCHEMA, CHIO_CAPABILITY_V2_SCHEMA,
};
use crate::error::{Error, Result};
use crate::oracle::CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA;
use crate::receipt::{
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_V2_SCHEMA,
    CHIO_RECEIPT_V2_SCHEMA,
};
use crate::runtime_attestation::{
    AWS_NITRO_ATTESTATION_SCHEMA, AZURE_MAA_ATTESTATION_SCHEMA,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA, GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
};
use crate::session::{CHIO_REQUEST_LINEAGE_RECORD_SCHEMA, CHIO_SESSION_ANCHOR_SCHEMA};

/// Anchor-batch signed artifact schema. Defined here so non-anchor verifiers
/// can reject unknown signed artifacts before loading the `chio-anchor` crate.
pub const CHIO_ANCHOR_BATCH_V1_SCHEMA: &str = "chio.anchor_batch.v1";
pub const CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA: &str = "chio.bilateral-signature-slice.v1";

/// Known signed artifacts accepted by the core compatibility gate.
pub const KNOWN_SIGNED_ARTIFACT_SCHEMAS: &[&str] = &[
    CHIO_CAPABILITIES_SCHEMA,
    CHIO_CAPABILITY_V1_SCHEMA,
    CHIO_CAPABILITY_V2_SCHEMA,
    "chio.receipt.v1",
    CHIO_RECEIPT_V2_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_V2_SCHEMA,
    CHIO_ANCHOR_BATCH_V1_SCHEMA,
    CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA,
    CHIO_SESSION_ANCHOR_SCHEMA,
    CHIO_REQUEST_LINEAGE_RECORD_SCHEMA,
    CHIO_ORACLE_CONVERSION_EVIDENCE_SCHEMA,
    AZURE_MAA_ATTESTATION_SCHEMA,
    AWS_NITRO_ATTESTATION_SCHEMA,
    GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA,
    ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA,
];

/// Lightweight registry entry for schema-aware verifiers and reports.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedArtifactSchemaEntry {
    pub schema: String,
    pub artifact_kind: String,
    pub introduced_by: String,
}

/// Return whether a schema ID is known to this verifier build.
#[must_use]
pub fn is_supported_signed_artifact_schema(schema: &str) -> bool {
    KNOWN_SIGNED_ARTIFACT_SCHEMAS.contains(&schema)
}

/// Fail closed on unknown signed-artifact schema IDs.
pub fn validate_signed_artifact_schema(schema: &str) -> Result<()> {
    if is_supported_signed_artifact_schema(schema) {
        Ok(())
    } else {
        Err(Error::CanonicalJson(format!(
            "unsupported signed-artifact schema: {schema}"
        )))
    }
}

/// Built-in registry entries mirrored by `spec/schemas/registry.json`.
#[must_use]
pub fn built_in_signed_artifact_registry() -> Vec<SignedArtifactSchemaEntry> {
    [
        (
            CHIO_CAPABILITIES_SCHEMA,
            "capability_negotiation",
            "schema-registry/v1/capability-negotiation",
        ),
        (
            CHIO_CAPABILITY_V1_SCHEMA,
            "capability_token",
            "schema-registry/v1/capability-token-v1",
        ),
        (
            CHIO_CAPABILITY_V2_SCHEMA,
            "capability_token",
            "schema-registry/v1/capability-token-v2",
        ),
        (
            "chio.receipt.v1",
            "receipt",
            "schema-registry/v1/receipt-v1",
        ),
        (
            CHIO_RECEIPT_V2_SCHEMA,
            "receipt",
            "schema-registry/v1/receipt-v2-body-hash",
        ),
        (
            CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
            "receipt_lineage",
            "schema-registry/v1/receipt-lineage-v1",
        ),
        (
            CHIO_RECEIPT_LINEAGE_STATEMENT_V2_SCHEMA,
            "receipt_lineage",
            "schema-registry/v1/receipt-lineage-v2",
        ),
        (
            CHIO_ANCHOR_BATCH_V1_SCHEMA,
            "anchor_batch",
            "schema-registry/v1/anchor-batch-v1",
        ),
        (
            CHIO_BILATERAL_SIGNATURE_SLICE_V1_SCHEMA,
            "bilateral_dsse_signature_slice",
            "federation-dsse-slice",
        ),
    ]
    .into_iter()
    .map(
        |(schema, artifact_kind, introduced_by)| SignedArtifactSchemaEntry {
            schema: schema.to_string(),
            artifact_kind: artifact_kind.to_string(),
            introduced_by: introduced_by.to_string(),
        },
    )
    .collect()
}
