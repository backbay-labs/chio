use crate::{
    canonical_sha256, contains_secret_marker, delivery_receiver_map, handoff_route_map,
    is_bounded_code, is_bounded_route_token, is_sha256_hex, relay_alert_severity_from_str,
    validate_alert_profile, validate_handoff_profile, validate_suppression_state,
    PheromoneRelayError, RelayAlertCheck, RelayAlertHandoffProfileDocument,
    RelayAlertHandoffReport, RelayAlertHandoffSinkKind, RelayAlertRoutingProfileDocument,
    RelayAlertSeverity, RelayAlertSuppressionStateDocument,
    PHEROMONE_RELAY_ALERT_ACKNOWLEDGEMENT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_DRIFT_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_EVIDENCE_SCHEMA, PHEROMONE_RELAY_ALERT_DELIVERY_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_DELIVERY_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_HANDOFF_DRIFT_REPORT_SCHEMA, PHEROMONE_RELAY_ALERT_HANDOFF_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_NORMALIZATION_REPORT_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_OWNER_PROFILE_SCHEMA,
    PHEROMONE_RELAY_ALERT_ROUTE_REVIEW_PACKET_SCHEMA, PHEROMONE_RELAY_SERVICE_LABEL,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

mod evaluators;
mod helpers;
mod types;
mod validators;

pub use evaluators::{
    evaluate_relay_alert_acknowledgement, evaluate_relay_alert_delivery,
    generate_relay_alert_delivery_drift_report, generate_relay_alert_handoff_drift_report,
    generate_relay_alert_route_review_packet, normalize_relay_alert_delivery_evidence,
    relay_alert_delivery_evidence_from_json, relay_alert_delivery_profile_from_json,
    relay_alert_handoff_profile_from_json, relay_alert_routing_profile_from_json,
    relay_alert_suppression_state_from_json,
};
pub use types::{
    RelayAlertAcknowledgement, RelayAlertAcknowledgementInput, RelayAlertAcknowledgementReport,
    RelayAlertDeliveryDrift, RelayAlertDeliveryDriftInput, RelayAlertDeliveryDriftReport,
    RelayAlertDeliveryEvidence, RelayAlertDeliveryInput, RelayAlertDeliveryProfileDocument,
    RelayAlertDeliveryReceiver, RelayAlertDeliveryReport, RelayAlertDeliveryResult,
    RelayAlertDeliveryStatus, RelayAlertHandoffDrift, RelayAlertHandoffDriftInput,
    RelayAlertHandoffDriftReport, RelayAlertNormalizationInput,
    RelayAlertNormalizationProfileDocument, RelayAlertNormalizationReport, RelayAlertRouteOwner,
    RelayAlertRouteOwnerProfileDocument, RelayAlertRouteReview, RelayAlertRouteReviewInput,
    RelayAlertRouteReviewPacket,
};

#[allow(unused_imports)]
pub(crate) use helpers::{
    json_labels, json_string, json_u64, normalization_receiver_map, normalize_downstream_source,
    reject_downstream_source_secrets, relay_alert_delivery_status_from_str, route_owner_map,
    validate_evidence_matches_receiver, validate_normalized_evidence,
};
#[allow(unused_imports)]
pub(crate) use validators::{
    validate_delivery_evidence_shape, validate_delivery_handoff_report, validate_delivery_labels,
    validate_delivery_profile, validate_delivery_receiver, validate_delivery_report,
    validate_delivery_result, validate_delivery_token, validate_normalization_profile,
    validate_review_source_chain, validate_route_owner_profile,
};
