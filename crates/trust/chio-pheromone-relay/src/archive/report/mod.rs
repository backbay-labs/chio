//! Relay alert assurance archive, closeout, and retention report generators.

use super::*;
use crate::{
    canonical_sha256, contains_secret_marker, generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    is_sha256_hex, validate_export_path, validate_retention_profile,
    verify_relay_alert_assurance_export_bundle, PheromoneRelayError,
    RelayAlertAssuranceExportBundle, RelayAlertAssuranceRecoveryDrillInput,
    RelayAlertAssuranceRecoveryDrillReport, RelayAlertAssuranceReplayInput,
    RelayAlertAssuranceRetentionInput, RelayAlertAssuranceRetentionProfileDocument,
    RelayAlertAssuranceTrustedExportersDocument, RelayAlertCheck, RelayOperatorRecommendation,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
};
use std::collections::BTreeSet;

mod external_retention;
mod generators;
mod helpers;
mod validators;

pub use self::generators::{
    generate_relay_alert_assurance_archive_report,
    generate_relay_alert_assurance_archive_restore_drill_report,
    generate_relay_alert_assurance_closeout_report,
    generate_relay_alert_assurance_external_retention_review_report,
    generate_relay_alert_assurance_physical_archive_drill_report,
    generate_relay_alert_assurance_retention_handoff_report,
    relay_alert_assurance_external_retention_profile_from_json,
};

pub(crate) use self::external_retention::{
    external_retention_check, external_retention_fail, external_retention_fresh,
    external_retention_handoffs, external_retention_physical_reports,
    external_retention_report_status, external_retention_restore_status,
    external_retention_sample_coverage, ExternalRetentionEvidence,
};
pub(crate) use self::helpers::{
    closeout_review_from_archive, has_matching_physical_readback, has_matching_retention_handoff,
    review_archive_candidate,
};
pub(crate) use self::validators::{
    validate_archive_candidates, validate_archive_input_roots, validate_archive_profile,
    validate_archive_restore_profile, validate_closeout_profile,
    validate_external_retention_profile, validate_external_retention_schema_token,
    validate_physical_archive_evidence, validate_retention_handoff_evidence,
    validate_retention_handoff_profile,
};
