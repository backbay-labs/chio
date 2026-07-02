/// Maximum number of budget rows returned in a single operator report.
pub const MAX_OPERATOR_BUDGET_LIMIT: usize = 200;
/// Maximum number of shared-evidence reference rows returned in one query.
pub const MAX_SHARED_EVIDENCE_LIMIT: usize = 200;
/// Maximum number of settlement backlog rows returned in one report.
pub const MAX_SETTLEMENT_BACKLOG_LIMIT: usize = 200;
/// Maximum number of receipt detail rows returned in one behavioral feed.
pub const MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT: usize = 200;
/// Maximum number of metered-billing reconciliation rows returned in one report.
pub const MAX_METERED_BILLING_LIMIT: usize = 200;
/// Maximum number of authorization-context rows returned in one report.
pub const MAX_AUTHORIZATION_CONTEXT_LIMIT: usize = 200;
/// Maximum number of economic projection rows returned in one report.
pub const MAX_ECONOMIC_RECEIPT_LIMIT: usize = 200;
/// Stable schema identifier for Chio's normative OAuth-family authorization profile.
pub const CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA: &str = "chio.oauth.authorization-profile.v1";
/// Stable schema identifier for Chio's sender-constraint profile.
pub const CHIO_OAUTH_SENDER_CONSTRAINT_SCHEMA: &str = "chio.oauth.sender-constraint.v1";
/// Stable schema identifier for Chio authorization-context reports.
pub const CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA: &str =
    "chio.oauth.authorization-context-report.v1";
/// Stable schema identifier for the deterministic economic completion flow bundle.
pub const ECONOMIC_COMPLETION_FLOW_SCHEMA: &str = "chio.economic-completion-flow.v1";
/// Stable schema identifier for Chio authorization-profile metadata artifacts.
pub const CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA: &str = "chio.oauth.authorization-metadata.v1";
/// Stable schema identifier for Chio enterprise IAM reviewer packs.
pub const CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA: &str =
    "chio.oauth.authorization-review-pack.v1";
/// Stable identifier for Chio's first governed authorization-details profile.
pub const CHIO_OAUTH_AUTHORIZATION_PROFILE_ID: &str = "chio-governed-rar-v1";
/// Detail type for the primary governed tool action.
pub const CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE: &str = "chio_governed_tool";
/// Detail type for governed commerce scope.
pub const CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE: &str = "chio_governed_commerce";
/// Detail type for governed metered-billing scope.
pub const CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE: &str =
    "chio_governed_metered_billing";
/// Stable label for Chio's capability-subject sender binding.
pub const CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT: &str = "capability_subject";
/// Stable label for Chio's Chio-native DPoP proof requirement.
pub const CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP: &str = "chio_dpop_v1";
/// Stable label for Chio's bounded mTLS-thumbprint sender adapter.
pub const CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS: &str = "chio_mtls_thumbprint_v1";
/// Stable label for Chio's bounded attestation-bound sender adapter.
pub const CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION: &str = "chio_attestation_binding_v1";
/// Stable request-time parameter for Chio governed authorization details.
pub const CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER: &str = "authorization_details";
/// Stable request-time parameter for Chio governed transaction context.
pub const CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER: &str = "chio_transaction_context";
/// Stable access-token claim for Chio governed authorization details.
pub const CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM: &str = "authorization_details";
/// Stable access-token claim for Chio governed transaction context.
pub const CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM: &str = "chio_transaction_context";

/// Stable schema identifier for insurer-facing behavioral feed exports.
pub const BEHAVIORAL_FEED_SCHEMA: &str = "chio.behavioral-feed.v1";
