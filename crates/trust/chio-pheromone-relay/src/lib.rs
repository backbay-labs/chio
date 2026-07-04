//! Live Chio pheromone relay service and durable relay state.

#![forbid(unsafe_code)]

mod alerts;
mod archive;
mod assurance;
mod client;
mod delivery;
mod directory;
mod error;
mod http_signing;
mod metrics;
mod schema;
mod service;
mod store;
mod validation;

pub const PHEROMONE_RELAY_ALERT_DEDUPE_PREFIX: &str = "chio-relay";
pub const PHEROMONE_RELAY_SERVICE_LABEL: &str = "chio-pheromone-relay";

pub(crate) use alerts::{
    contains_secret_marker, delivery_receiver_map, handoff_route_map, is_bounded_code,
    is_bounded_route_token, relay_alert_severity_from_str, validate_alert_profile,
    validate_handoff_profile, validate_suppression_state,
};
pub use alerts::{
    evaluate_relay_alert_handoff, evaluate_relay_alerts, generate_relay_trend_report, RelayAlert,
    RelayAlertCheck, RelayAlertDrill, RelayAlertDrillReport, RelayAlertEvaluationInput,
    RelayAlertHandoffEscalation, RelayAlertHandoffInput, RelayAlertHandoffProfileDocument,
    RelayAlertHandoffReceiver, RelayAlertHandoffReport, RelayAlertHandoffRouteReadiness,
    RelayAlertHandoffSinkKind, RelayAlertReport, RelayAlertRoute, RelayAlertRouteKind,
    RelayAlertRoutingProfileDocument, RelayAlertRule, RelayAlertSeverity,
    RelayAlertSuppressionEntry, RelayAlertSuppressionStateDocument, RelayEventReport,
    RelayTrendInput, RelayTrendPoint, RelayTrendReport,
};
pub use archive::{
    build_relay_alert_assurance_archive_extraction_report,
    generate_relay_alert_assurance_archive_report,
    generate_relay_alert_assurance_archive_restore_drill_report,
    generate_relay_alert_assurance_closeout_report,
    generate_relay_alert_assurance_external_retention_review_report,
    generate_relay_alert_assurance_physical_archive_drill_report,
    generate_relay_alert_assurance_retention_handoff_report,
    relay_alert_assurance_external_retention_profile_from_json,
    sign_relay_alert_assurance_archive_package,
    validate_relay_alert_assurance_archive_package_report,
    verify_relay_alert_assurance_archive_package, RelayAlertAssuranceArchiveBundleCandidate,
    RelayAlertAssuranceArchiveBundleReview, RelayAlertAssuranceArchiveExtractionReport,
    RelayAlertAssuranceArchiveInput, RelayAlertAssuranceArchivePackage,
    RelayAlertAssuranceArchivePackageBuildInput, RelayAlertAssuranceArchivePackageBundle,
    RelayAlertAssuranceArchivePackageFile, RelayAlertAssuranceArchivePackageManifest,
    RelayAlertAssuranceArchivePackageManifestBody, RelayAlertAssuranceArchivePackageMember,
    RelayAlertAssuranceArchivePackageReport, RelayAlertAssuranceArchivePackageVerifyInput,
    RelayAlertAssuranceArchiveProfileDocument, RelayAlertAssuranceArchiveReport,
    RelayAlertAssuranceArchiveRestoreDrillInput, RelayAlertAssuranceArchiveRestoreDrillReport,
    RelayAlertAssuranceArchiveRestorePackageReview,
    RelayAlertAssuranceArchiveRestoreProfileDocument, RelayAlertAssuranceCloseoutBundleReview,
    RelayAlertAssuranceCloseoutInput, RelayAlertAssuranceCloseoutProfileDocument,
    RelayAlertAssuranceCloseoutReport, RelayAlertAssuranceExternalRetentionPackageReview,
    RelayAlertAssuranceExternalRetentionProfileDocument,
    RelayAlertAssuranceExternalRetentionReviewInput,
    RelayAlertAssuranceExternalRetentionReviewReport, RelayAlertAssurancePhysicalArchiveDrillInput,
    RelayAlertAssurancePhysicalArchiveDrillReport, RelayAlertAssurancePhysicalArchiveEvidence,
    RelayAlertAssuranceRetentionHandoffEvidence, RelayAlertAssuranceRetentionHandoffInput,
    RelayAlertAssuranceRetentionHandoffProfileDocument, RelayAlertAssuranceRetentionHandoffReport,
    RelayAlertAssuranceTrustedArchivePackager, RelayAlertAssuranceTrustedArchivePackagersDocument,
};
pub use assurance::{
    generate_relay_alert_assurance_package, generate_relay_alert_assurance_recovery_drill_report,
    generate_relay_alert_assurance_replay_report, generate_relay_alert_assurance_retention_report,
    sign_relay_alert_assurance_export_bundle, verify_relay_alert_assurance_export_bundle,
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
pub(crate) use assurance::{validate_export_path, validate_retention_profile};
pub use client::PheromoneRelayClient;
pub use delivery::{
    evaluate_relay_alert_acknowledgement, evaluate_relay_alert_delivery,
    generate_relay_alert_delivery_drift_report, generate_relay_alert_handoff_drift_report,
    generate_relay_alert_route_review_packet, normalize_relay_alert_delivery_evidence,
    relay_alert_delivery_evidence_from_json, relay_alert_delivery_profile_from_json,
    relay_alert_handoff_profile_from_json, relay_alert_routing_profile_from_json,
    relay_alert_suppression_state_from_json, RelayAlertAcknowledgement,
    RelayAlertAcknowledgementInput, RelayAlertAcknowledgementReport, RelayAlertDeliveryDrift,
    RelayAlertDeliveryDriftInput, RelayAlertDeliveryDriftReport, RelayAlertDeliveryEvidence,
    RelayAlertDeliveryInput, RelayAlertDeliveryProfileDocument, RelayAlertDeliveryReceiver,
    RelayAlertDeliveryReport, RelayAlertDeliveryResult, RelayAlertDeliveryStatus,
    RelayAlertHandoffDrift, RelayAlertHandoffDriftInput, RelayAlertHandoffDriftReport,
    RelayAlertNormalizationInput, RelayAlertNormalizationProfileDocument,
    RelayAlertNormalizationReport, RelayAlertRouteOwner, RelayAlertRouteOwnerProfileDocument,
    RelayAlertRouteReview, RelayAlertRouteReviewInput, RelayAlertRouteReviewPacket,
};
pub(crate) use delivery::{reject_downstream_source_secrets, validate_delivery_evidence_shape};
pub use directory::{
    peer_directory_from_json, peer_directory_from_json_with_profile,
    peer_directory_state_from_json, promote_peer_directory_candidate,
    reject_peer_directory_candidate, sign_peer_directory_bundle, PeerDirectory,
    PeerDirectoryBundleBody, PeerDirectoryBundleDocument, PeerDirectoryBundleSigningInput,
    PeerDirectoryBundleTrust, PeerDirectoryDocument, PeerDirectoryEntry,
    PeerDirectoryRejectedEntry, PeerDirectoryRotationReport, PeerDirectoryStateDocument,
    PeerDirectoryStateEntry, RelayLadderRef, RelayProfile, RelayProfileLimits, RelayRole,
    TrustedPeerDirectoryIssuer,
};
pub use error::PheromoneRelayError;
pub use http_signing::{
    sign_relay_http_request, PheromoneRelayHttpRequest, RelayHttpSigningInput,
    RelayHttpVerificationContext,
};
pub(crate) use metrics::{
    count_outbox_statuses, count_rows, count_stale_leases, oldest_pending_queued_at,
    push_queue_depth_sample, recent_failure_summaries, relay_directory_summary,
    relay_queue_summary,
};
pub use metrics::{
    RelayDirectorySummary, RelayFailureSummary, RelayMetricSample, RelayMetricsFormat,
    RelayMetricsSnapshot, RelayObservabilityInput, RelayObservabilityReport,
    RelayOperatorRecommendation, RelayQueueSummary,
};
pub use schema::{
    PHEROMONE_BATCH_RELAY_PATH, PHEROMONE_CATCHUP_RELAY_PATH, PHEROMONE_CATCHUP_REQUEST_SCHEMA,
    PHEROMONE_CATCHUP_RESPONSE_SCHEMA, PHEROMONE_HEALTH_PATH,
    PHEROMONE_PEER_DIRECTORY_BUNDLE_SCHEMA, PHEROMONE_PEER_DIRECTORY_ROTATION_REPORT_SCHEMA,
    PHEROMONE_PEER_DIRECTORY_SCHEMA, PHEROMONE_PEER_DIRECTORY_STATE_SCHEMA, PHEROMONE_READY_PATH,
    PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_EXTRACTION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PACKAGE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_ARCHIVE_RESTORE_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_CLOSEOUT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_MANIFEST_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXPORT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_EXTERNAL_RETENTION_REVIEW_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PACKAGE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_PHYSICAL_ARCHIVE_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RECOVERY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_REPLAY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_RETENTION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_ARCHIVE_PACKAGERS_SCHEMA,
    PHEROMONE_RELAY_ALERT_ASSURANCE_TRUSTED_EXPORTERS_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA, PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DRILL_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_PROFILE_SCHEMA, PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA, PHEROMONE_RELAY_ALERT_ROUTING_PROFILE_SCHEMA,
    PHEROMONE_RELAY_CONFIG_SCHEMA, PHEROMONE_RELAY_DRILL_REPORT_SCHEMA,
    PHEROMONE_RELAY_EVENT_REPORT_SCHEMA, PHEROMONE_RELAY_HEALTH_REPORT_SCHEMA,
    PHEROMONE_RELAY_HTTP_REQUEST_SCHEMA, PHEROMONE_RELAY_METRICS_PATH,
    PHEROMONE_RELAY_METRICS_SNAPSHOT_SCHEMA, PHEROMONE_RELAY_NEGATIVE_CORPUS_SCHEMA,
    PHEROMONE_RELAY_OBSERVABILITY_PATH, PHEROMONE_RELAY_OBSERVABILITY_REPORT_SCHEMA,
    PHEROMONE_RELAY_OPERATOR_REPORT_SCHEMA, PHEROMONE_RELAY_PATH_PREFIX,
    PHEROMONE_RELAY_SUPERVISOR_PROFILE_SCHEMA, PHEROMONE_RELAY_SUPPRESSION_STATE_SCHEMA,
    PHEROMONE_RELAY_TICK_REPORT_SCHEMA, PHEROMONE_RELAY_TREND_REPORT_SCHEMA,
};
pub use service::{
    deliver_due_batches, enforce_outbound_peer_batch_directory_scope,
    enforce_peer_batch_directory_scope, lint_relay_supervisor_profile,
    relay_supervisor_profile_from_json, ExtraMetricsHook, PheromoneRelayConfig,
    PheromoneRelayService, RelayBatchReceiver, RelayDrillCheck, RelayDrillReport,
    RelayReverseProxyProfile, RelaySupervisorProfileDocument,
};
pub(crate) use store::i64_from_u64;
pub use store::{
    CatchupRequest, CatchupResponse, InboxRecordResult, InboxReserveResult, PheromoneRelayStore,
    RelayDeliveryReport, RelayHealthCheck, RelayHealthReport, RelayNonceRecorder, RelayNonceSet,
    RelayOperatorReport, RelayOutboxBatch, RelayTickReport, SqlitePheromoneRelayStore,
};
pub(crate) use validation::{
    canonical_sha256, is_sha256_hex, u64_from_i64, validate_endpoint,
    validate_peer_directory_profile,
};
