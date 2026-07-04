//! Relay alert assurance package, export, replay, and retention reporting.

use crate::{
    canonical_sha256, contains_secret_marker, is_bounded_code, is_bounded_route_token,
    is_sha256_hex, reject_downstream_source_secrets, validate_delivery_evidence_shape,
    PheromoneRelayError, RelayAlertAcknowledgementReport, RelayAlertCheck,
    RelayAlertDeliveryDriftReport, RelayAlertDeliveryEvidence, RelayAlertDeliveryReport,
    RelayAlertHandoffReport, RelayAlertNormalizationReport, RelayAlertReport,
    RelayAlertRouteReviewPacket, RelayTrendReport,
    PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA, PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA,
    PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use chio_core_types::{Keypair, PublicKey, Signature};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

mod export;
mod generation;
mod reporting;
mod types;

pub use self::export::{
    sign_relay_alert_assurance_export_bundle, verify_relay_alert_assurance_export_bundle,
};
pub use self::generation::generate_relay_alert_assurance_package;
pub use self::reporting::{
    generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
};
pub use self::types::{
    RelayAlertAssuranceExportArtifact, RelayAlertAssuranceExportBuildInput,
    RelayAlertAssuranceExportBundle, RelayAlertAssuranceExportFile,
    RelayAlertAssuranceExportManifest, RelayAlertAssuranceExportManifestBody,
    RelayAlertAssuranceExportReport, RelayAlertAssuranceInput, RelayAlertAssurancePackage,
    RelayAlertAssuranceRecoveryDrill, RelayAlertAssuranceRecoveryDrillInput,
    RelayAlertAssuranceRecoveryDrillReport, RelayAlertAssuranceReplayInput,
    RelayAlertAssuranceReplayReport, RelayAlertAssuranceRetentionEntry,
    RelayAlertAssuranceRetentionInput, RelayAlertAssuranceRetentionProfileDocument,
    RelayAlertAssuranceRetentionReport, RelayAlertAssuranceRetentionRule,
    RelayAlertAssuranceRetentionState, RelayAlertAssuranceTrustedExporter,
    RelayAlertAssuranceTrustedExportersDocument,
};

pub(crate) use self::export::{
    export_artifact_from_json, validate_export_bundle_manifest, validate_export_identity,
    validate_export_path,
};
pub(crate) use self::generation::{
    validate_assurance_package_sources, validate_assurance_source_chain,
};
pub(crate) use self::reporting::validate_retention_profile;
