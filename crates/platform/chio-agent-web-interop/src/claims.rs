pub(super) const CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND: &str =
    "claim.agent_web.external_subject_digest_bound";
pub(super) const CLAIM_PROJECTION_MANIFEST_BOUND: &str =
    "claim.agent_web.projection_manifest_bound";
pub(super) const CLAIM_UNSUPPORTED_CLAIMS_LIMITED: &str =
    "claim.agent_web.unsupported_claims_limited";
pub(super) const CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY: &str =
    "claim.agent_web.sidecar_not_native_authority";
pub(super) const CLAIM_EXTERNAL_WEBHOOK_SIGNATURE_IS_CHIO_AUTHORITY: &str =
    "claim.external.webhook_signature_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_CLOUDEVENTS_EVENT_IS_CHIO_AUTHORITY: &str =
    "claim.external.cloudevents_event_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_GRAPHQL_HTTP_SUBSCRIPTION_COVERAGE: &str =
    "claim.external.graphql_http_subscription_coverage";
pub(super) const CLAIM_EXTERNAL_GRAPHQL_HTTP_OPERATION_IS_CHIO_AUTHORITY: &str =
    "claim.external.graphql_http_operation_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_MCP_TOOL_CALL_IS_CHIO_AUTHORITY: &str =
    "claim.external.mcp_tool_call_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_A2A_TASK_IS_CHIO_AUTHORITY: &str =
    "claim.external.a2a_task_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_OAUTH2_TOKEN_IS_CHIO_AUTHORITY: &str =
    "claim.external.oauth2_token_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_OPENID_CONNECT_IDENTITY_IS_CHIO_AUTHORITY: &str =
    "claim.external.openid_connect_identity_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_SPIFFE_WORKLOAD_IDENTITY_IS_CHIO_AUTHORITY: &str =
    "claim.external.spiffe_workload_identity_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_KUBERNETES_ADMISSION_IS_CHIO_AUTHORITY: &str =
    "claim.external.kubernetes_admission_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_OCI_REF_IS_CHIO_AUTHORITY: &str =
    "claim.external.oci_ref_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_VC_IS_CHIO_AUTHORITY: &str = "claim.external.vc_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_SIGSTORE_BUNDLE_IS_CHIO_AUTHORITY: &str =
    "claim.external.sigstore_bundle_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_ACP_CLIENT_PERMISSION_IS_CHIO_AUTHORITY: &str =
    "claim.external.acp_client_permission_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_ACP_COMMERCE_PAYMENT_IS_CHIO_AUTHORITY: &str =
    "claim.external.acp_commerce_payment_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_AG_UI_EVENT_IS_CHIO_AUTHORITY: &str =
    "claim.external.ag_ui_event_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_BROWSER_AUTOMATION_IS_CHIO_AUTHORITY: &str =
    "claim.external.browser_automation_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_RPA_TRANSCRIPT_IS_CHIO_AUTHORITY: &str =
    "claim.external.rpa_transcript_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_EMAIL_ACTION_IS_CHIO_AUTHORITY: &str =
    "claim.external.email_action_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_CALENDAR_ACTION_IS_CHIO_AUTHORITY: &str =
    "claim.external.calendar_action_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_SLACK_ACTION_IS_CHIO_AUTHORITY: &str =
    "claim.external.slack_action_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_SCIM_LIFECYCLE_IS_CHIO_AUTHORITY: &str =
    "claim.external.scim_lifecycle_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_SD_JWT_VC_IS_CHIO_AUTHORITY: &str =
    "claim.external.sd_jwt_vc_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_BBS_PROOF_IS_CHIO_AUTHORITY: &str =
    "claim.external.bbs_proof_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_VC_DI_BBS_INTEROP_VERIFIED: &str =
    "claim.external.vc_di_bbs_interop_verified";
pub(super) const CLAIM_EXTERNAL_IN_TOTO_STATEMENT_IS_CHIO_AUTHORITY: &str =
    "claim.external.in_toto_statement_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_DSSE_ENVELOPE_IS_CHIO_AUTHORITY: &str =
    "claim.external.dsse_envelope_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_SLSA_PROVENANCE_IS_CHIO_AUTHORITY: &str =
    "claim.external.slsa_provenance_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_OPENAPI_OPERATION_IS_CHIO_AUTHORITY: &str =
    "claim.external.openapi_operation_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_ASYNCAPI_MESSAGE_IS_CHIO_AUTHORITY: &str =
    "claim.external.asyncapi_message_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_AP2_MANDATE_IS_CHIO_AUTHORITY: &str =
    "claim.external.ap2_mandate_is_chio_authority";
pub(super) const CLAIM_EXTERNAL_X402_PAYMENT_IS_CHIO_AUTHORITY: &str =
    "claim.external.x402_payment_is_chio_authority";

pub(super) fn push_claim_once(verified_claims: &mut Vec<String>, claim: &str) {
    if !verified_claims.iter().any(|verified| verified == claim) {
        verified_claims.push(claim.to_string());
    }
}
