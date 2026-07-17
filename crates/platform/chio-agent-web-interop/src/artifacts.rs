use serde::{Deserialize, Serialize};

use chio_core_types::{
    canonical_json_bytes, sha256_hex, PublicKey, Signature,
    CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA, CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA,
};
use chio_transaction_passport::{TransactionPassport, TransactionPassportError};

use super::{
    evidence::{validate_bundle_relative_path, validate_sha256_hex},
    protocols, AgentWebReplayEntry, AgentWebVerifierTrust,
};

mod a2a;
mod acp_client;
mod acp_commerce;
mod ag_ui;
mod ap2;
mod asyncapi;
mod browser_automation;
mod calendar;
mod cloudevents;
mod email;
mod graphql_http;
mod mcp;
mod oauth2;
mod openapi;
mod openid_connect;
mod rpa;
mod scim;
mod slack;
mod spiffe;
mod standard_webhooks;
mod x402;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentWebProofEnvelope {
    schema: String,
    pub(super) envelope_id: String,
    transaction_passport_ref: String,
    #[serde(default)]
    agent_web_passport_scope_sha256: Option<String>,
    pub(super) source_protocol: String,
    pub(super) source_protocol_version: String,
    external_subject: String,
    pub(super) external_subject_path: String,
    pub(super) external_subject_digest: String,
    external_subject_signature_ref: String,
    pub(super) projection_manifest_ref: String,
    pub(super) projection_manifest_sha256: String,
    pub(super) chio_claim_refs: Vec<String>,
    pub(super) receipt_refs: Vec<String>,
    disclosure_capsule_refs: Vec<String>,
    settlement_refs: Vec<String>,
    risk_refs: Vec<String>,
    pub(super) limitations: Vec<String>,
    signature: String,
}

impl AgentWebProofEnvelope {
    pub(super) fn is_scope_bound_v2(&self) -> bool {
        self.schema == CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectionManifest {
    schema: String,
    pub(super) projection_id: String,
    pub(super) source_protocol: String,
    pub(super) source_version: String,
    external_fields_used: Vec<String>,
    external_fields_not_used: Vec<String>,
    sidecar_fields: Vec<String>,
    digest_algorithm: String,
    signature_algorithm: String,
    requires_external_signature: bool,
    pub(super) claim_mapping: Vec<ClaimMapping>,
    pub(super) unsupported_claims: Vec<String>,
    pub(super) copy_limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClaimMapping {
    pub(super) claim_ref: String,
    pub(super) evidence_class: String,
}

pub(super) fn validate_envelope(
    passport: &TransactionPassport,
    passport_scope_sha256: &str,
    envelope: &AgentWebProofEnvelope,
    trust: &AgentWebVerifierTrust,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &envelope.schema),
        ("envelope_id", &envelope.envelope_id),
        (
            "transaction_passport_ref",
            &envelope.transaction_passport_ref,
        ),
        ("source_protocol", &envelope.source_protocol),
        ("source_protocol_version", &envelope.source_protocol_version),
        ("external_subject", &envelope.external_subject),
        ("external_subject_path", &envelope.external_subject_path),
        ("external_subject_digest", &envelope.external_subject_digest),
        ("projection_manifest_ref", &envelope.projection_manifest_ref),
        (
            "projection_manifest_sha256",
            &envelope.projection_manifest_sha256,
        ),
        ("signature", &envelope.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if envelope.transaction_passport_ref != passport.id {
        return Err(claim_failed("Agent Web envelope passport mismatch"));
    }
    match envelope.schema.as_str() {
        CHIO_AGENT_WEB_PROOF_ENVELOPE_V1_SCHEMA => {
            if envelope.agent_web_passport_scope_sha256.is_some() {
                return Err(claim_failed(
                    "Agent Web v1 envelope must not include passport scope digest",
                ));
            }
        }
        CHIO_AGENT_WEB_PROOF_ENVELOPE_V2_SCHEMA => {
            let scope_sha256 = envelope
                .agent_web_passport_scope_sha256
                .as_deref()
                .ok_or_else(|| {
                    claim_failed("Agent Web v2 envelope missing passport scope digest")
                })?;
            validate_sha256_hex(scope_sha256)
                .map_err(|_| claim_failed("invalid Agent Web passport scope digest"))?;
            if scope_sha256 != passport_scope_sha256 {
                return Err(claim_failed("Agent Web envelope passport scope mismatch"));
            }
        }
        schema => {
            return Err(claim_failed(format!(
                "unsupported Agent Web proof envelope schema: {schema}"
            )));
        }
    }
    validate_content_addressed_envelope_id(envelope)?;
    verify_envelope_signature(envelope, trust)?;
    validate_source_protocol(&envelope.source_protocol)?;
    validate_bundle_relative_path(&envelope.external_subject_path).map_err(|_| {
        TransactionPassportError::InvalidAgentWebArtifact {
            path: envelope.external_subject_path.clone(),
            message: "unsafe external subject path".to_string(),
        }
    })?;
    validate_sha256_hex(&envelope.external_subject_digest)
        .map_err(|_| claim_failed("invalid external subject digest"))?;
    validate_sha256_hex(&envelope.projection_manifest_sha256)
        .map_err(|_| claim_failed("invalid projection manifest digest"))?;
    if envelope.chio_claim_refs.is_empty() {
        return Err(claim_failed("Agent Web envelope must include claim refs"));
    }
    if envelope.receipt_refs.is_empty() {
        return Err(claim_failed("Agent Web envelope must include receipt refs"));
    }
    for claim in &envelope.chio_claim_refs {
        require_non_empty(claim, "chio_claim_refs")?;
    }
    let mut unique_receipt_refs = envelope
        .is_scope_bound_v2()
        .then(std::collections::BTreeSet::new);
    for receipt_ref in &envelope.receipt_refs {
        require_non_empty(receipt_ref, "receipt_refs")?;
        if unique_receipt_refs
            .as_mut()
            .is_some_and(|refs| !refs.insert(receipt_ref))
        {
            return Err(claim_failed(format!(
                "duplicate Agent Web receipt ref: {receipt_ref}"
            )));
        }
    }
    if !envelope.disclosure_capsule_refs.is_empty() {
        return Err(claim_failed(
            "Agent Web disclosure capsule refs are not verifier-bound",
        ));
    }
    if !envelope.settlement_refs.is_empty() {
        return Err(claim_failed(
            "Agent Web settlement refs are not verifier-bound",
        ));
    }
    if !envelope.risk_refs.is_empty() {
        return Err(claim_failed("Agent Web risk refs are not verifier-bound"));
    }
    for limitation in &envelope.limitations {
        require_non_empty(limitation, "limitations")?;
    }
    let _ = &envelope.external_subject_signature_ref;
    Ok(())
}

#[derive(Serialize)]
struct AgentWebProofEnvelopeIdInputV1<'a> {
    schema: &'a str,
    transaction_passport_ref: &'a str,
    source_protocol: &'a str,
    source_protocol_version: &'a str,
    external_subject: &'a str,
    external_subject_path: &'a str,
    external_subject_digest: &'a str,
    external_subject_signature_ref: &'a str,
    projection_manifest_ref: &'a str,
    projection_manifest_sha256: &'a str,
    chio_claim_refs: &'a [String],
    receipt_refs: &'a [String],
    disclosure_capsule_refs: &'a [String],
    settlement_refs: &'a [String],
    risk_refs: &'a [String],
    limitations: &'a [String],
}

#[derive(Serialize)]
struct AgentWebProofEnvelopeIdInputV2<'a> {
    #[serde(flatten)]
    v1: AgentWebProofEnvelopeIdInputV1<'a>,
    agent_web_passport_scope_sha256: &'a str,
}

#[derive(Serialize)]
struct AgentWebProofEnvelopeSignaturePayloadV1<'a> {
    envelope_id: &'a str,
    #[serde(flatten)]
    id_input: AgentWebProofEnvelopeIdInputV1<'a>,
}

#[derive(Serialize)]
struct AgentWebProofEnvelopeSignaturePayloadV2<'a> {
    envelope_id: &'a str,
    #[serde(flatten)]
    id_input: AgentWebProofEnvelopeIdInputV2<'a>,
}

fn envelope_id_input_v1(envelope: &AgentWebProofEnvelope) -> AgentWebProofEnvelopeIdInputV1<'_> {
    AgentWebProofEnvelopeIdInputV1 {
        schema: &envelope.schema,
        transaction_passport_ref: &envelope.transaction_passport_ref,
        source_protocol: &envelope.source_protocol,
        source_protocol_version: &envelope.source_protocol_version,
        external_subject: &envelope.external_subject,
        external_subject_path: &envelope.external_subject_path,
        external_subject_digest: &envelope.external_subject_digest,
        external_subject_signature_ref: &envelope.external_subject_signature_ref,
        projection_manifest_ref: &envelope.projection_manifest_ref,
        projection_manifest_sha256: &envelope.projection_manifest_sha256,
        chio_claim_refs: &envelope.chio_claim_refs,
        receipt_refs: &envelope.receipt_refs,
        disclosure_capsule_refs: &envelope.disclosure_capsule_refs,
        settlement_refs: &envelope.settlement_refs,
        risk_refs: &envelope.risk_refs,
        limitations: &envelope.limitations,
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum AgentWebProofEnvelopeIdInput<'a> {
    V1(AgentWebProofEnvelopeIdInputV1<'a>),
    V2(AgentWebProofEnvelopeIdInputV2<'a>),
}

#[derive(Serialize)]
#[serde(untagged)]
enum AgentWebProofEnvelopeSignaturePayload<'a> {
    V1(AgentWebProofEnvelopeSignaturePayloadV1<'a>),
    V2(AgentWebProofEnvelopeSignaturePayloadV2<'a>),
}

fn envelope_id_input(
    envelope: &AgentWebProofEnvelope,
) -> Result<AgentWebProofEnvelopeIdInput<'_>, TransactionPassportError> {
    let v1 = envelope_id_input_v1(envelope);
    if !envelope.is_scope_bound_v2() {
        return Ok(AgentWebProofEnvelopeIdInput::V1(v1));
    }
    let scope_sha256 = envelope
        .agent_web_passport_scope_sha256
        .as_deref()
        .ok_or_else(|| claim_failed("Agent Web v2 envelope missing passport scope digest"))?;
    Ok(AgentWebProofEnvelopeIdInput::V2(
        AgentWebProofEnvelopeIdInputV2 {
            v1,
            agent_web_passport_scope_sha256: scope_sha256,
        },
    ))
}

fn envelope_signature_payload(
    envelope: &AgentWebProofEnvelope,
) -> Result<AgentWebProofEnvelopeSignaturePayload<'_>, TransactionPassportError> {
    let id_input = envelope_id_input(envelope)?;
    Ok(match id_input {
        AgentWebProofEnvelopeIdInput::V1(id_input) => {
            AgentWebProofEnvelopeSignaturePayload::V1(AgentWebProofEnvelopeSignaturePayloadV1 {
                envelope_id: &envelope.envelope_id,
                id_input,
            })
        }
        AgentWebProofEnvelopeIdInput::V2(id_input) => {
            AgentWebProofEnvelopeSignaturePayload::V2(AgentWebProofEnvelopeSignaturePayloadV2 {
                envelope_id: &envelope.envelope_id,
                id_input,
            })
        }
    })
}

fn validate_content_addressed_envelope_id(
    envelope: &AgentWebProofEnvelope,
) -> Result<(), TransactionPassportError> {
    let expected = content_addressed_envelope_id(envelope)?;
    if envelope.envelope_id != expected {
        return Err(claim_failed(
            "Agent Web envelope id is not content-addressed",
        ));
    }
    Ok(())
}

fn content_addressed_envelope_id(
    envelope: &AgentWebProofEnvelope,
) -> Result<String, TransactionPassportError> {
    let payload = envelope_id_input(envelope)?;
    let canonical = canonical_json_bytes(&payload)
        .map_err(|_| claim_failed("Agent Web envelope id is not content-addressed"))?;
    Ok(sha256_hex(&canonical))
}

fn verify_envelope_signature(
    envelope: &AgentWebProofEnvelope,
    trust: &AgentWebVerifierTrust,
) -> Result<(), TransactionPassportError> {
    let Some(signature_ref) = envelope.signature.strip_prefix("sig-ed25519:") else {
        return Err(claim_failed("Agent Web envelope signature invalid"));
    };
    let mut parts = signature_ref.split(':');
    let Some(public_key_ref) = parts.next() else {
        return Err(claim_failed("Agent Web envelope signature invalid"));
    };
    let Some(signature_ref) = parts.next() else {
        return Err(claim_failed("Agent Web envelope signature invalid"));
    };
    if parts.next().is_some() {
        return Err(claim_failed("Agent Web envelope signature invalid"));
    }

    let public_key = PublicKey::from_hex(public_key_ref)
        .map_err(|_| claim_failed("Agent Web envelope signature invalid"))?;
    if !trust.trusts_envelope_sidecar_key(&public_key) {
        return Err(claim_failed("Agent Web envelope signer untrusted"));
    }
    let signature = Signature::from_hex(signature_ref)
        .map_err(|_| claim_failed("Agent Web envelope signature invalid"))?;
    let payload = envelope_signature_payload(envelope)?;
    let canonical = chio_core_types::canonical_json_bytes(&payload)
        .map_err(|_| claim_failed("Agent Web envelope signature invalid"))?;
    if !public_key.verify(&canonical, &signature) {
        return Err(claim_failed("Agent Web envelope signature invalid"));
    }
    Ok(())
}

pub(super) fn validate_projection_manifest(
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &manifest.schema),
        ("projection_id", &manifest.projection_id),
        ("source_protocol", &manifest.source_protocol),
        ("source_version", &manifest.source_version),
        ("digest_algorithm", &manifest.digest_algorithm),
        ("signature_algorithm", &manifest.signature_algorithm),
    ] {
        require_non_empty(value, field)?;
    }
    validate_source_protocol(&manifest.source_protocol)?;
    if manifest.source_protocol == "graphql-http" && !manifest.source_version.starts_with("draft-")
    {
        return Err(claim_failed(
            "GraphQL over HTTP version must be draft-labeled",
        ));
    }
    if !protocols::is_supported_source_version(&manifest.source_protocol, &manifest.source_version)
    {
        return Err(claim_failed(protocols::unsupported_source_version_message(
            &manifest.source_protocol,
        )));
    }
    if manifest.digest_algorithm != "sha256" {
        return Err(claim_failed("unsupported Agent Web digest algorithm"));
    }
    validate_signature_algorithm(manifest)?;
    if manifest.external_fields_used.is_empty() {
        return Err(claim_failed("projection manifest missing external fields"));
    }
    if manifest.sidecar_fields.is_empty() {
        return Err(claim_failed("projection manifest missing sidecar fields"));
    }
    if manifest.claim_mapping.is_empty() {
        return Err(claim_failed("projection manifest missing claim mapping"));
    }
    for mapping in &manifest.claim_mapping {
        require_non_empty(&mapping.claim_ref, "claim_ref")?;
        validate_evidence_class(&mapping.evidence_class)?;
    }
    for unsupported_claim in &manifest.unsupported_claims {
        require_non_empty(unsupported_claim, "unsupported_claims")?;
    }
    for limitation in &manifest.copy_limitations {
        require_non_empty(limitation, "copy_limitations")?;
    }
    let _ = &manifest.external_fields_not_used;
    Ok(())
}

fn validate_signature_algorithm(
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_protocol == "standard-webhooks" && !manifest.requires_external_signature {
        return Err(claim_failed(
            "Standard Webhooks projection requires external signature",
        ));
    }
    if manifest.requires_external_signature {
        if manifest.signature_algorithm == "none" {
            return Err(claim_failed(
                "Agent Web required signature cannot use none algorithm",
            ));
        }
        if !supported_signature_algorithm(&manifest.source_protocol, &manifest.signature_algorithm)
        {
            return Err(claim_failed("unsupported Agent Web signature algorithm"));
        }
        return Ok(());
    }
    if manifest.signature_algorithm != "none" {
        return Err(claim_failed(
            "Agent Web signature algorithm present without external signature requirement",
        ));
    }
    Ok(())
}

fn supported_signature_algorithm(source_protocol: &str, signature_algorithm: &str) -> bool {
    matches!(
        (source_protocol, signature_algorithm),
        ("standard-webhooks", "standard-webhooks")
    )
}

pub(super) fn validate_external_subject(
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
    bytes: &[u8],
    trust: &AgentWebVerifierTrust,
) -> Result<Option<AgentWebReplayEntry>, TransactionPassportError> {
    let actual_digest = chio_core_types::sha256_hex(bytes);
    if actual_digest != envelope.external_subject_digest {
        return Err(claim_failed("external subject digest mismatch"));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidAgentWebArtifact {
            path: envelope.external_subject_path.clone(),
            message: error.to_string(),
        }
    })?;
    let subject_id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TransactionPassportError::InvalidAgentWebArtifact {
            path: envelope.external_subject_path.clone(),
            message: "missing external subject id".to_string(),
        })?;
    if subject_id != envelope.external_subject {
        return Err(claim_failed("external subject id mismatch"));
    }
    validate_external_subject_kind(&value, manifest)?;
    if manifest.requires_external_signature {
        require_non_empty(
            &envelope.external_subject_signature_ref,
            "external_subject_signature_ref",
        )
        .map_err(|_| claim_failed("missing external signature"))?;
    }
    let replay_entry = match manifest.source_protocol.as_str() {
        "standard-webhooks" => standard_webhooks::validate_subject(
            &value,
            &envelope.external_subject_signature_ref,
            trust,
        )
        .map(Some),
        "cloudevents" => cloudevents::validate_subject(&value, manifest).map(|()| None),
        "graphql-http" => graphql_http::validate_subject(&value, manifest).map(|()| None),
        "mcp" => mcp::validate_subject(&value, envelope, manifest).map(|()| None),
        "a2a" => a2a::validate_subject(&value, envelope, manifest).map(|()| None),
        "acp-client" => acp_client::validate_subject(&value, envelope, manifest).map(|()| None),
        "acp-commerce" => acp_commerce::validate_subject(&value, envelope).map(|()| None),
        "ag-ui" => ag_ui::validate_subject(&value, envelope, manifest).map(|()| None),
        "browser-automation" => {
            browser_automation::validate_subject(&value, envelope, manifest).map(|()| None)
        }
        "rpa" => rpa::validate_subject(&value, envelope, manifest).map(|()| None),
        "gmail-api" => email::validate_subject(&value, envelope, manifest).map(|()| None),
        "google-calendar-api" => {
            calendar::validate_subject(&value, envelope, manifest).map(|()| None)
        }
        "slack" => slack::validate_subject(&value, envelope, manifest).map(|()| None),
        "oauth2" => oauth2::validate_subject(&value, envelope, manifest).map(|()| None),
        "openid-connect" => {
            openid_connect::validate_subject(&value, envelope, manifest).map(|()| None)
        }
        "scim" => scim::validate_subject(&value, envelope, manifest).map(|()| None),
        "spiffe" => spiffe::validate_subject(&value, envelope, manifest).map(|()| None),
        "kubernetes-admission" => {
            validate_kubernetes_admission_subject(&value, envelope, manifest).map(|()| None)
        }
        "oci" => validate_oci_ref_subject(&value, envelope, manifest).map(|()| None),
        "vc" => validate_vc_subject(&value, envelope, manifest).map(|()| None),
        "sd-jwt-vc" => {
            validate_sd_jwt_vc_presentation_subject(&value, envelope, manifest).map(|()| None)
        }
        "bbs" => validate_bbs_receipt_disclosure_subject(&value, envelope, manifest).map(|()| None),
        "sigstore" => validate_sigstore_bundle_subject(&value, envelope, manifest).map(|()| None),
        "in-toto" => validate_in_toto_statement_subject(&value, envelope, manifest).map(|()| None),
        "dsse" => validate_dsse_envelope_subject(&value, envelope, manifest).map(|()| None),
        "slsa-provenance" => {
            validate_slsa_provenance_subject(&value, envelope, manifest).map(|()| None)
        }
        "openapi" => openapi::validate_subject(&value, envelope, manifest).map(|()| None),
        "asyncapi" => asyncapi::validate_subject(&value, envelope, manifest).map(|()| None),
        "ap2" => ap2::validate_subject(&value, envelope, manifest).map(|()| None),
        "x402" => x402::validate_subject(&value, envelope, manifest).map(|()| None),
        _ => Err(claim_failed(format!(
            "unsupported Agent Web source protocol: {}",
            manifest.source_protocol
        ))),
    }?;
    Ok(replay_entry)
}

fn validate_external_subject_kind(
    value: &serde_json::Value,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    let Some((expected, mismatch_message)) =
        expected_external_subject_kind(&manifest.source_protocol)
    else {
        return Ok(());
    };
    validate_object_kind(value, expected, mismatch_message)
}

fn expected_external_subject_kind(source_protocol: &str) -> Option<(&'static str, &'static str)> {
    match source_protocol {
        "standard-webhooks" => Some((
            "standard_webhooks_delivery",
            "Standard Webhooks external subject kind mismatch",
        )),
        "graphql-http" => Some((
            "graphql_http_operation",
            "GraphQL HTTP external subject kind mismatch",
        )),
        "mcp" => Some(("mcp_tool_call", "MCP external subject kind mismatch")),
        "a2a" => Some(("a2a_task", "A2A external subject kind mismatch")),
        "openapi" => Some((
            "openapi_operation",
            "OpenAPI external subject kind mismatch",
        )),
        "acp-client" => Some((
            "acp_client_permission_request",
            "ACP client external subject kind mismatch",
        )),
        "acp-commerce" => Some((
            "acp_commerce_checkout",
            "ACP commerce external subject kind mismatch",
        )),
        "ag-ui" => Some(("ag_ui_event", "AG-UI external subject kind mismatch")),
        "browser-automation" => Some((
            "browser_automation_command",
            "Browser automation external subject kind mismatch",
        )),
        "rpa" => Some(("rpa_transcript", "RPA external subject kind mismatch")),
        "gmail-api" => Some((
            "email_connector_action",
            "Gmail API external subject kind mismatch",
        )),
        "google-calendar-api" => Some((
            "calendar_connector_action",
            "Google Calendar API external subject kind mismatch",
        )),
        "slack" => Some((
            "slack_connector_action",
            "Slack external subject kind mismatch",
        )),
        "oauth2" => Some((
            "oauth2_authorization",
            "OAuth2 external subject kind mismatch",
        )),
        "openid-connect" => Some((
            "openid_connect_identity",
            "OpenID Connect external subject kind mismatch",
        )),
        "scim" => Some((
            "scim_lifecycle_event",
            "SCIM external subject kind mismatch",
        )),
        "spiffe" => Some((
            "spiffe_workload_identity",
            "SPIFFE external subject kind mismatch",
        )),
        "kubernetes-admission" => Some((
            "kubernetes_admission_review",
            "Kubernetes admission external subject kind mismatch",
        )),
        "oci" => Some(("oci_artifact_ref", "OCI external subject kind mismatch")),
        "vc" => Some(("verifiable_credential", "VC external subject kind mismatch")),
        "sd-jwt-vc" => Some((
            "sd_jwt_vc_presentation",
            "SD-JWT VC external subject kind mismatch",
        )),
        "bbs" => Some((
            "bbs_receipt_disclosure",
            "BBS external subject kind mismatch",
        )),
        "sigstore" => Some(("sigstore_bundle", "Sigstore external subject kind mismatch")),
        "in-toto" => Some((
            "in_toto_statement",
            "in-toto external subject kind mismatch",
        )),
        "dsse" => Some(("dsse_envelope", "DSSE external subject kind mismatch")),
        "slsa-provenance" => Some((
            "slsa_provenance",
            "SLSA provenance external subject kind mismatch",
        )),
        "asyncapi" => Some((
            "asyncapi_message",
            "AsyncAPI external subject kind mismatch",
        )),
        "ap2" => Some(("ap2_mandate_chain", "AP2 external subject kind mismatch")),
        "x402" => Some(("x402_payment", "x402 external subject kind mismatch")),
        _ => None,
    }
}

fn validate_object_kind(
    value: &serde_json::Value,
    expected: &str,
    mismatch_message: &'static str,
) -> Result<(), TransactionPassportError> {
    let object_kind = required_json_str(value, "object_kind", mismatch_message)?;
    if object_kind != expected {
        return Err(claim_failed(mismatch_message));
    }
    Ok(())
}

fn validate_kubernetes_admission_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("Kubernetes admission source version mismatch"));
    }
    if manifest.source_version != "admissionreview-v1" {
        return Err(claim_failed(
            "unsupported Kubernetes admission source version",
        ));
    }
    for (field, message) in [
        ("cluster_id_digest", "missing Kubernetes cluster digest"),
        ("user_info_digest", "missing Kubernetes user info digest"),
        ("object_digest", "missing Kubernetes object digest"),
        (
            "admission_webhook_configuration_digest",
            "missing Kubernetes webhook configuration digest",
        ),
        (
            "chio_capability_token_digest",
            "missing Kubernetes capability token digest",
        ),
        ("patch_digest", "missing Kubernetes patch digest"),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid Kubernetes digest: {field}")))?;
    }
    for (field, message) in [
        ("api_group", "missing Kubernetes API group"),
        ("api_version", "missing Kubernetes API version"),
        ("resource", "missing Kubernetes resource"),
        ("kind", "missing Kubernetes kind"),
        ("namespace", "missing Kubernetes namespace"),
    ] {
        required_json_str(value, field, message)?;
    }
    let operation = required_json_str(value, "operation", "missing Kubernetes operation")?;
    if !matches!(operation, "CREATE" | "UPDATE" | "DELETE" | "CONNECT") {
        return Err(claim_failed("unsupported Kubernetes admission operation"));
    }
    let request_uid = required_json_str(value, "request_uid", "missing Kubernetes request UID")?;
    let response_uid = required_json_str(value, "response_uid", "missing Kubernetes response UID")?;
    if request_uid != response_uid {
        return Err(claim_failed("Kubernetes admission response UID mismatch"));
    }
    let allowed = required_json_bool(value, "allowed", "missing Kubernetes allowed decision")?;
    if !allowed {
        return Err(claim_failed("Kubernetes admission was not allowed"));
    }
    let warning_digests = value
        .get("warning_digests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing Kubernetes warning digests"))?;
    for warning_digest in warning_digests {
        let warning_digest = warning_digest
            .as_str()
            .ok_or_else(|| claim_failed("invalid Kubernetes warning digest"))?;
        validate_sha256_hex(warning_digest)
            .map_err(|_| claim_failed("invalid Kubernetes digest: warning_digests"))?;
    }
    let receipt_ref = required_json_str(
        value,
        "chio_admission_receipt_ref",
        "missing Kubernetes admission receipt ref",
    )?;
    if !envelope
        .receipt_refs
        .iter()
        .any(|bound| bound == receipt_ref)
    {
        return Err(claim_failed(
            "Kubernetes admission receipt ref is not bound",
        ));
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing Kubernetes Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "Kubernetes admission was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn validate_oci_ref_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("OCI source version mismatch"));
    }
    if manifest.source_version != "image-spec-v1" {
        return Err(claim_failed("unsupported OCI source version"));
    }
    required_json_str(value, "registry", "missing OCI registry")?;
    required_json_str(value, "repository", "missing OCI repository")?;
    let digest = required_json_str(value, "digest", "missing OCI digest")?;
    validate_oci_sha256_digest(digest, "OCI reference must be digest-pinned")?;
    let descriptor_digest =
        required_json_str(value, "descriptor_digest", "missing OCI descriptor digest")?;
    validate_oci_sha256_digest(descriptor_digest, "invalid OCI descriptor digest")?;
    let subject_digest = required_json_str(value, "subject_digest", "missing OCI subject digest")?;
    validate_oci_sha256_digest(subject_digest, "invalid OCI subject digest")?;
    let descriptor_size =
        required_json_u64(value, "descriptor_size", "missing OCI descriptor size")?;
    if descriptor_size == 0 {
        return Err(claim_failed("OCI descriptor size missing"));
    }
    let media_type = required_json_str(value, "media_type", "missing OCI media type")?;
    if !media_type.starts_with("application/vnd.oci.") {
        return Err(claim_failed("unsupported OCI media type"));
    }
    required_json_str(value, "artifact_type", "missing OCI artifact type")?;
    let sigstore_bundle_digest = required_json_str(
        value,
        "sigstore_bundle_digest",
        "missing OCI Sigstore bundle digest",
    )?;
    validate_sha256_hex(sigstore_bundle_digest)
        .map_err(|_| claim_failed("invalid OCI digest: sigstore_bundle_digest"))?;
    let rekor_inclusion_status = required_json_str(
        value,
        "rekor_inclusion_status",
        "missing OCI Rekor inclusion status",
    )?;
    if rekor_inclusion_status == "verified" {
        return Err(claim_failed(
            "OCI Rekor inclusion must not be self-asserted as verified",
        ));
    }
    if !matches!(
        rekor_inclusion_status,
        "advisory" | "claimed" | "unverified"
    ) {
        return Err(claim_failed("unsupported OCI Rekor inclusion status"));
    }
    let cache_admission_report_digest = required_json_str(
        value,
        "cache_admission_report_digest",
        "missing OCI cache admission report digest",
    )?;
    validate_sha256_hex(cache_admission_report_digest)
        .map_err(|_| claim_failed("invalid OCI digest: cache_admission_report_digest"))?;
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing OCI receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing OCI receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid OCI receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("OCI receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing OCI Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed("OCI ref was not mediated by Chio receipt"));
    }
    Ok(())
}

fn validate_vc_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("VC source version mismatch"));
    }
    if !matches!(
        manifest.source_version.as_str(),
        "vc-data-model-1.1" | "vc-data-model-2.0"
    ) {
        return Err(claim_failed("unsupported VC source version"));
    }
    let media_type = required_json_str(value, "media_type", "missing VC media type")?;
    if !matches!(media_type, "application/vc+ld+json" | "application/vc+jwt") {
        return Err(claim_failed("unsupported VC media type"));
    }
    for (field, message) in [
        ("credential_digest", "missing VC credential digest"),
        ("issuer_digest", "missing VC issuer digest"),
        ("subject_digest", "missing VC subject digest"),
        ("credential_schema_digest", "missing VC schema digest"),
        ("credential_status_digest", "missing VC status digest"),
        ("proof_digest", "missing VC proof digest"),
        (
            "verifier_policy_digest",
            "missing VC verifier policy digest",
        ),
        (
            "authorization_context_digest",
            "missing VC authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid VC digest: {field}")))?;
    }
    let proof_type = required_json_str(value, "proof_type", "missing VC proof type")?;
    if !matches!(
        proof_type,
        "DataIntegrityProof" | "JsonWebSignature2020" | "Ed25519Signature2020"
    ) {
        return Err(claim_failed("unsupported VC proof type"));
    }
    let proof_purpose = required_json_str(value, "proof_purpose", "missing VC proof purpose")?;
    if proof_purpose != "assertionMethod" {
        return Err(claim_failed("unsupported VC proof purpose"));
    }
    let credential_status =
        required_json_str(value, "credential_status", "missing VC credential status")?;
    if credential_status != "valid" {
        return Err(claim_failed("unsupported VC credential status"));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing VC receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing VC receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid VC receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("VC receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing VC Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "VC credential was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn validate_sd_jwt_vc_presentation_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("SD-JWT VC source version mismatch"));
    }
    if manifest.source_version != "v1" {
        return Err(claim_failed("unsupported SD-JWT VC source version"));
    }
    let media_type = required_json_str(value, "media_type", "missing SD-JWT VC media type")?;
    if media_type != "application/dc+sd-jwt" {
        return Err(claim_failed("unsupported SD-JWT VC media type"));
    }
    for (field, message) in [
        ("credential_digest", "missing SD-JWT VC credential digest"),
        (
            "disclosed_claims_digest",
            "missing SD-JWT VC disclosed claims digest",
        ),
        (
            "holder_binding_digest",
            "missing SD-JWT VC holder binding digest",
        ),
        ("issuer_key_digest", "missing SD-JWT VC issuer key digest"),
        (
            "verifier_policy_digest",
            "missing SD-JWT VC verifier policy digest",
        ),
        (
            "presentation_nonce_digest",
            "missing SD-JWT VC presentation nonce digest",
        ),
        ("audience_digest", "missing SD-JWT VC audience digest"),
        (
            "authorization_context_digest",
            "missing SD-JWT VC authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid SD-JWT VC digest: {field}")))?;
    }
    let credential_status = required_json_str(
        value,
        "credential_status",
        "missing SD-JWT VC credential status",
    )?;
    if credential_status != "valid" {
        return Err(claim_failed("unsupported SD-JWT VC credential status"));
    }
    let key_binding_alg = required_json_str(
        value,
        "key_binding_alg",
        "missing SD-JWT VC key binding alg",
    )?;
    if !matches!(key_binding_alg, "ES256" | "ES384" | "ES512" | "EdDSA") {
        return Err(claim_failed("unsupported SD-JWT VC key binding alg"));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing SD-JWT VC receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing SD-JWT VC receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid SD-JWT VC receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("SD-JWT VC receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing SD-JWT VC Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "SD-JWT VC presentation was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn validate_bbs_receipt_disclosure_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("BBS source version mismatch"));
    }
    if manifest.source_version != "chio-receipt-bbs-v1" {
        return Err(claim_failed("unsupported BBS source version"));
    }
    let projection_profile = required_json_str(
        value,
        "projection_profile",
        "missing BBS projection profile",
    )?;
    if projection_profile != "chio-receipt-bbs-v1" {
        return Err(claim_failed("unsupported BBS projection profile"));
    }
    for (field, message) in [
        ("proof_digest", "missing BBS proof digest"),
        (
            "revealed_messages_digest",
            "missing BBS revealed messages digest",
        ),
        (
            "hidden_messages_digest",
            "missing BBS hidden messages digest",
        ),
        ("issuer_key_digest", "missing BBS issuer key digest"),
        ("nonce_digest", "missing BBS nonce digest"),
        (
            "verifier_policy_digest",
            "missing BBS verifier policy digest",
        ),
        ("receipt_digest", "missing BBS receipt digest"),
        (
            "authorization_context_digest",
            "missing BBS authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid BBS digest: {field}")))?;
    }
    let disclosure_count =
        required_json_u64(value, "disclosure_count", "missing BBS disclosure count")?;
    if disclosure_count == 0 {
        return Err(claim_failed("missing BBS disclosures"));
    }
    required_json_u64(value, "hidden_count", "missing BBS hidden count")?;
    let verification_status = required_json_str(
        value,
        "verification_status",
        "missing BBS verification status",
    )?;
    if verification_status == "verified" {
        return Err(claim_failed(
            "BBS verification status must not be self-asserted as verified",
        ));
    }
    if !matches!(verification_status, "advisory" | "claimed" | "unverified") {
        return Err(claim_failed("unsupported BBS verification status"));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing BBS receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing BBS receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid BBS receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("BBS receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing BBS Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "BBS receipt disclosure was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn validate_sigstore_bundle_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("Sigstore source version mismatch"));
    }
    if manifest.source_version != "bundle-v1" {
        return Err(claim_failed("unsupported Sigstore source version"));
    }
    let media_type = required_json_str(value, "media_type", "missing Sigstore media type")?;
    if media_type != "application/vnd.dev.sigstore.bundle+json" {
        return Err(claim_failed("unsupported Sigstore media type"));
    }
    for (field, message) in [
        ("bundle_digest", "missing Sigstore bundle digest"),
        ("artifact_digest", "missing Sigstore artifact digest"),
        (
            "certificate_identity_digest",
            "missing Sigstore certificate identity digest",
        ),
        (
            "certificate_issuer_digest",
            "missing Sigstore certificate issuer digest",
        ),
        (
            "transparency_log_digest",
            "missing Sigstore transparency log digest",
        ),
        ("rekor_entry_digest", "missing Sigstore Rekor entry digest"),
        ("signature_digest", "missing Sigstore signature digest"),
        (
            "verification_material_digest",
            "missing Sigstore verification material digest",
        ),
        (
            "slsa_provenance_digest",
            "missing Sigstore SLSA provenance digest",
        ),
        (
            "authorization_context_digest",
            "missing Sigstore authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid Sigstore digest: {field}")))?;
    }
    let predicate_type =
        required_json_str(value, "predicate_type", "missing Sigstore predicate type")?;
    if predicate_type != "https://slsa.dev/provenance/v1" {
        return Err(claim_failed("unsupported Sigstore predicate type"));
    }
    let transparency_included = required_json_bool(
        value,
        "transparency_included",
        "missing Sigstore transparency inclusion",
    )?;
    if !transparency_included {
        return Err(claim_failed("missing Sigstore transparency inclusion"));
    }
    let verification_status = required_json_str(
        value,
        "verification_status",
        "missing Sigstore verification status",
    )?;
    if verification_status == "verified" {
        return Err(claim_failed(
            "Sigstore verification status must not be self-asserted as verified",
        ));
    }
    if !matches!(verification_status, "advisory" | "claimed" | "unverified") {
        return Err(claim_failed("unsupported Sigstore verification status"));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing Sigstore receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing Sigstore receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid Sigstore receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("Sigstore receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing Sigstore Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "Sigstore bundle was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn validate_in_toto_statement_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("in-toto source version mismatch"));
    }
    if manifest.source_version != "statement-v1-dsse" {
        return Err(claim_failed("unsupported in-toto source version"));
    }
    let statement_type =
        required_json_str(value, "statement_type", "missing in-toto statement type")?;
    if statement_type != "https://in-toto.io/Statement/v1" {
        return Err(claim_failed("unsupported in-toto statement type"));
    }
    let payload_type = required_json_str(value, "payload_type", "missing DSSE payload type")?;
    if payload_type != "application/vnd.in-toto+json" {
        return Err(claim_failed("unsupported DSSE payload type"));
    }
    let predicate_type =
        required_json_str(value, "predicate_type", "missing in-toto predicate type")?;
    if !matches!(
        predicate_type,
        "https://in-toto.io/attestation/bilateral-cosign-invocation/v1"
            | "chio.bilateral-cosign-invocation.v1"
    ) {
        return Err(claim_failed("unsupported in-toto bilateral predicate type"));
    }
    for (field, message) in [
        ("dsse_envelope_digest", "missing DSSE envelope digest"),
        ("payload_digest", "missing DSSE payload digest"),
        ("subject_digest", "missing in-toto subject digest"),
        ("predicate_digest", "missing in-toto predicate digest"),
        (
            "builder_identity_digest",
            "missing in-toto builder identity digest",
        ),
        (
            "signer_identity_digest",
            "missing DSSE signer identity digest",
        ),
        (
            "verification_material_digest",
            "missing DSSE verification material digest",
        ),
        (
            "authorization_context_digest",
            "missing in-toto authorization context digest",
        ),
        ("peer_pin_digest", "missing in-toto peer pin digest"),
        (
            "policy_summary_digest",
            "missing in-toto policy summary digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid in-toto digest: {field}")))?;
    }
    required_json_str(
        value,
        "capability_lease_ref",
        "missing in-toto capability lease ref",
    )?;
    let signature_count = required_json_u64(value, "signature_count", "missing DSSE signature")?;
    if signature_count < 2 {
        return Err(claim_failed(
            "in-toto statement requires bilateral DSSE signatures",
        ));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing in-toto receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing in-toto receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid in-toto receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("in-toto receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing in-toto Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "in-toto statement was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn validate_dsse_envelope_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("DSSE source version mismatch"));
    }
    if manifest.source_version != "v1" {
        return Err(claim_failed("unsupported DSSE source version"));
    }
    required_json_str(value, "payload_type", "missing DSSE payload type")?;
    for (field, message) in [
        ("payload_digest", "missing DSSE payload digest"),
        ("subject_digest", "missing DSSE subject digest"),
        ("signature_digest", "missing DSSE signature digest"),
        (
            "signer_identity_digest",
            "missing DSSE signer identity digest",
        ),
        (
            "verification_material_digest",
            "missing DSSE verification material digest",
        ),
        (
            "authorization_context_digest",
            "missing DSSE authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid DSSE digest: {field}")))?;
    }
    let signature_count = required_json_u64(value, "signature_count", "missing DSSE signature")?;
    if signature_count < 2 {
        return Err(claim_failed("DSSE envelope requires bilateral signatures"));
    }
    let verification_status = required_json_str(
        value,
        "verification_status",
        "missing DSSE verification status",
    )?;
    if verification_status != "verified" {
        return Err(claim_failed("unsupported DSSE verification status"));
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing DSSE Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "DSSE envelope was not mediated by Chio receipt",
        ));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing DSSE receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing DSSE receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid DSSE receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("DSSE receipt ref is not bound"));
        }
    }
    Ok(())
}

fn validate_slsa_provenance_subject(
    value: &serde_json::Value,
    envelope: &AgentWebProofEnvelope,
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    if manifest.source_version != envelope.source_protocol_version {
        return Err(claim_failed("SLSA source version mismatch"));
    }
    if manifest.source_version != "v1" {
        return Err(claim_failed("unsupported SLSA source version"));
    }
    let predicate_type = required_json_str(value, "predicate_type", "missing SLSA predicate type")?;
    if predicate_type != "https://slsa.dev/provenance/v1" {
        return Err(claim_failed("unsupported SLSA predicate type"));
    }
    required_json_str(value, "build_type", "missing SLSA build type")?;
    for (field, message) in [
        ("builder_id_digest", "missing SLSA builder id digest"),
        (
            "build_invocation_digest",
            "missing SLSA build invocation digest",
        ),
        (
            "resolved_dependencies_digest",
            "missing SLSA resolved dependencies digest",
        ),
        ("materials_digest", "missing SLSA materials digest"),
        ("artifact_digest", "missing SLSA artifact digest"),
        ("provenance_digest", "missing SLSA provenance digest"),
        (
            "verification_material_digest",
            "missing SLSA verification material digest",
        ),
        (
            "authorization_context_digest",
            "missing SLSA authorization context digest",
        ),
    ] {
        let digest = required_json_str(value, field, message)?;
        validate_sha256_hex(digest)
            .map_err(|_| claim_failed(format!("invalid SLSA digest: {field}")))?;
    }
    required_json_str(value, "build_started_on", "missing SLSA build start")?;
    required_json_str(value, "build_finished_on", "missing SLSA build finish")?;
    let verification_status = required_json_str(
        value,
        "verification_status",
        "missing SLSA verification status",
    )?;
    if verification_status != "verified" {
        return Err(claim_failed("unsupported SLSA verification status"));
    }
    let receipt_refs = value
        .get("receipt_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| claim_failed("missing SLSA receipt refs"))?;
    if receipt_refs.is_empty() {
        return Err(claim_failed("missing SLSA receipt refs"));
    }
    for receipt_ref in receipt_refs {
        let receipt_ref = receipt_ref
            .as_str()
            .ok_or_else(|| claim_failed("invalid SLSA receipt ref"))?;
        if !envelope
            .receipt_refs
            .iter()
            .any(|bound| bound == receipt_ref)
        {
            return Err(claim_failed("SLSA receipt ref is not bound"));
        }
    }
    let mediated = required_json_bool(
        value,
        "mediated_by_chio_receipt",
        "missing SLSA Chio receipt mediation",
    )?;
    if !mediated {
        return Err(claim_failed(
            "SLSA provenance was not mediated by Chio receipt",
        ));
    }
    Ok(())
}

fn required_json_str<'a>(
    value: &'a serde_json::Value,
    field: &'static str,
    message: &'static str,
) -> Result<&'a str, TransactionPassportError> {
    let value = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| claim_failed(message))?;
    if value.is_empty() {
        return Err(claim_failed(message));
    }
    Ok(value)
}

fn required_json_u64(
    value: &serde_json::Value,
    field: &'static str,
    message: &'static str,
) -> Result<u64, TransactionPassportError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| claim_failed(message))
}

fn required_json_bool(
    value: &serde_json::Value,
    field: &'static str,
    message: &'static str,
) -> Result<bool, TransactionPassportError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| claim_failed(message))
}

fn validate_oci_sha256_digest(
    value: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| claim_failed(message))?;
    if !digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(claim_failed(message));
    }
    validate_sha256_hex(digest).map_err(|_| claim_failed(message))
}

fn validate_source_protocol(protocol: &str) -> Result<(), TransactionPassportError> {
    if protocols::is_supported_source_protocol(protocol) {
        Ok(())
    } else {
        Err(claim_failed(format!(
            "unsupported Agent Web source protocol: {protocol}"
        )))
    }
}

fn validate_evidence_class(evidence_class: &str) -> Result<(), TransactionPassportError> {
    if matches!(
        evidence_class,
        "native-external-proof"
            | "chio-sidecar-proof"
            | "digest-bound-reference"
            | "advisory-observation"
            | "unsupported"
    ) {
        Ok(())
    } else {
        Err(claim_failed(format!(
            "unsupported Agent Web evidence class: {evidence_class}"
        )))
    }
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(claim_failed(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::AgentWebClaimFailed(message.into())
}
