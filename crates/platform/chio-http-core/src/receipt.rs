//! HTTP receipt: signed proof that an HTTP request was evaluated by Chio.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use chio_core_types::crypto::{Keypair, PublicKey, Signature};
use chio_core_types::receipt::{
    kinds::BoundaryClass, kinds::ObservationOutcome, kinds::ReceiptKind, kinds::RedactionMode,
    kinds::ToolOrigin, kinds::TrustLevel, metadata::ActorRef, metadata::GuardEvidence,
};
use chio_core_types::{canonical_json_bytes, sha256_hex};

use crate::method::HttpMethod;
use crate::verdict::Verdict;

pub const CHIO_HTTP_STATUS_SCOPE_KEY: &str = "chio_http_status_scope";
pub const CHIO_DECISION_RECEIPT_ID_KEY: &str = "chio_decision_receipt_id";
pub const CHIO_KERNEL_RECEIPT_ID_KEY: &str = "chio_kernel_receipt_id";
pub const CHIO_HTTP_STATUS_SCOPE_DECISION: &str = "decision";
pub const CHIO_HTTP_STATUS_SCOPE_FINAL: &str = "final";

/// Signed receipt for an HTTP request evaluation.
/// Binds the request identity, route, method, verdict, and guard evidence
/// under an Ed25519 signature from the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpReceipt {
    /// Authoritative content-addressed receipt id.
    pub id: String,

    /// Unique request ID this receipt covers.
    pub request_id: String,

    /// The matched route pattern (e.g., "/pets/{petId}").
    pub route_pattern: String,

    /// HTTP method of the evaluated request.
    pub method: HttpMethod,

    /// SHA-256 hash of the caller identity.
    pub caller_identity_hash: String,

    /// Session ID the request belonged to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// The kernel's verdict.
    pub verdict: Verdict,

    /// Signed semantic class for this HTTP receipt.
    pub receipt_kind: ReceiptKind,

    /// Signed boundary class for this HTTP receipt.
    pub boundary_class: BoundaryClass,

    /// Observation outcome. Mediated HTTP receipts must omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,

    /// Where the protected effect executes relative to Chio.
    pub tool_origin: ToolOrigin,

    /// Redaction mode applied to signed receipt details.
    pub redaction_mode: RedactionMode,

    /// Actor chain associated with the HTTP decision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,

    /// Per-guard evidence collected during evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,

    /// HTTP status Chio associated with the evaluation outcome at receipt-signing
    /// time.
    ///
    /// For deny receipts this is the concrete error status Chio will emit.
    /// For allow receipts produced before an upstream or inner response exists,
    /// this is evaluation-time status metadata rather than guaranteed
    /// downstream response evidence.
    pub response_status: u16,

    /// Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,

    /// SHA-256 hash binding the request content to this receipt.
    pub content_hash: String,

    /// SHA-256 hash of the policy that was applied.
    pub policy_hash: String,

    /// Trust level of the signed decision.
    pub trust_level: TrustLevel,

    /// Capability ID that was exercised, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,

    /// Optional metadata for extensibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// The kernel's public key (for verification without out-of-band lookup).
    pub kernel_key: PublicKey,

    /// Ed25519 signature over canonical JSON of the body fields.
    pub signature: Signature,
}

/// The body of an HTTP receipt (everything except the signature).
/// Used for signing and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpReceiptBody {
    pub id: String,
    pub request_id: String,
    pub route_pattern: String,
    pub method: HttpMethod,
    pub caller_identity_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub verdict: Verdict,
    pub receipt_kind: ReceiptKind,
    pub boundary_class: BoundaryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,
    pub tool_origin: ToolOrigin,
    pub redaction_mode: RedactionMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    pub response_status: u16,
    pub timestamp: u64,
    pub content_hash: String,
    pub policy_hash: String,
    pub trust_level: TrustLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
}

impl HttpReceiptBody {
    fn validate_authority_semantics(&self) -> chio_core_types::Result<()> {
        if self.receipt_kind != ReceiptKind::MediatedDecision {
            return Err(chio_core_types::Error::CanonicalJson(
                "HTTP receipts must be mediated_decision receipts".to_string(),
            ));
        }
        if self.boundary_class != BoundaryClass::Prevent {
            return Err(chio_core_types::Error::CanonicalJson(
                "HTTP receipts must use the prevent boundary class".to_string(),
            ));
        }
        if self.observation_outcome.is_some() {
            return Err(chio_core_types::Error::CanonicalJson(
                "mediated HTTP receipts must not carry observation_outcome".to_string(),
            ));
        }
        if self.trust_level != TrustLevel::Mediated {
            return Err(chio_core_types::Error::CanonicalJson(
                "HTTP receipts must use mediated trust level".to_string(),
            ));
        }
        Ok(())
    }
}

impl HttpReceipt {
    /// Sign a receipt body with the kernel's keypair.
    pub fn sign(mut body: HttpReceiptBody, keypair: &Keypair) -> chio_core_types::Result<Self> {
        body.id = compute_http_receipt_id(&body)?;
        body.validate_authority_semantics()?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            request_id: body.request_id,
            route_pattern: body.route_pattern,
            method: body.method,
            caller_identity_hash: body.caller_identity_hash,
            session_id: body.session_id,
            verdict: body.verdict,
            receipt_kind: body.receipt_kind,
            boundary_class: body.boundary_class,
            observation_outcome: body.observation_outcome,
            tool_origin: body.tool_origin,
            redaction_mode: body.redaction_mode,
            actor_chain: body.actor_chain,
            evidence: body.evidence,
            response_status: body.response_status,
            timestamp: body.timestamp,
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            trust_level: body.trust_level,
            capability_id: body.capability_id,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    /// Extract the body for re-verification.
    #[must_use]
    pub fn body(&self) -> HttpReceiptBody {
        HttpReceiptBody {
            id: self.id.clone(),
            request_id: self.request_id.clone(),
            route_pattern: self.route_pattern.clone(),
            method: self.method,
            caller_identity_hash: self.caller_identity_hash.clone(),
            session_id: self.session_id.clone(),
            verdict: self.verdict.clone(),
            receipt_kind: self.receipt_kind,
            boundary_class: self.boundary_class,
            observation_outcome: self.observation_outcome,
            tool_origin: self.tool_origin,
            redaction_mode: self.redaction_mode,
            actor_chain: self.actor_chain.clone(),
            evidence: self.evidence.clone(),
            response_status: self.response_status,
            timestamp: self.timestamp,
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            trust_level: self.trust_level,
            capability_id: self.capability_id.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the receipt signature against the embedded kernel key.
    pub fn verify_signature(&self) -> chio_core_types::Result<bool> {
        let body = self.body();
        if body.validate_authority_semantics().is_err() {
            return Ok(false);
        }
        if compute_http_receipt_id(&body)? != self.id {
            return Ok(false);
        }
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    /// Recompute the content-addressed HTTP receipt id.
    pub fn recompute_id(&self) -> chio_core_types::Result<String> {
        compute_http_receipt_id(&self.body())
    }

    /// Whether this receipt id matches the canonical body fields.
    pub fn receipt_id_valid(&self) -> chio_core_types::Result<bool> {
        Ok(self.recompute_id()? == self.id)
    }

    /// Whether this receipt records an authoritative allow.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.is_authorized()
    }

    /// Whether this receipt is an authoritative Chio authorization.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.receipt_kind == ReceiptKind::MediatedDecision
            && self.boundary_class == BoundaryClass::Prevent
            && self.observation_outcome.is_none()
            && self.trust_level == TrustLevel::Mediated
            && self.verdict.is_allowed()
    }

    /// Whether this receipt records a deny verdict.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.verdict.is_denied()
    }

    fn chio_receipt_body(
        &self,
    ) -> chio_core_types::Result<chio_core_types::receipt::body::ChioReceiptBody> {
        // A durable receipt store verifies `ToolCallAction::verify_hash()` before
        // accepting a receipt, so `parameter_hash` must be the canonical hash of
        // the action parameters, not the HTTP body content hash. Deriving it from
        // the parameters keeps the converted receipt verifiable end to end; a
        // store that recomputes the hash then accepts the record instead of
        // rejecting it. The HTTP body content hash stays bound to the receipt
        // through the `content_hash` field below.
        let action = chio_core_types::receipt::decision::ToolCallAction::from_parameters(
            serde_json::json!({
                "method": self.method.to_string(),
                "route": self.route_pattern,
                "request_id": self.request_id,
            }),
        )?;

        Ok(chio_core_types::receipt::body::ChioReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            capability_id: self.capability_id.clone().unwrap_or_default(),
            tool_server: "http".to_string(),
            tool_name: format!("{} {}", self.method, self.route_pattern),
            action,
            decision: Some(self.verdict.to_decision()),
            receipt_kind: self.receipt_kind,
            boundary_class: self.boundary_class,
            observation_outcome: self.observation_outcome,
            tool_origin: self.tool_origin,
            redaction_mode: self.redaction_mode,
            actor_chain: self.actor_chain.clone(),
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: self.evidence.clone(),
            metadata: self.metadata.clone(),
            trust_level: self.trust_level,
            tenant_id: None,
            kernel_key: self.kernel_key.clone(),
            bbs_projection_version: None,
        })
    }

    /// Convert this HTTP receipt into a signed core ChioReceipt for unified storage.
    pub fn to_chio_receipt_with_keypair(
        &self,
        keypair: &Keypair,
    ) -> chio_core_types::Result<chio_core_types::receipt::body::ChioReceipt> {
        let mut chio_body = self.chio_receipt_body()?;
        let canonical = canonical_json_bytes(&chio_body)?;
        chio_body.content_hash = sha256_hex(&canonical);
        chio_core_types::receipt::body::ChioReceipt::sign(chio_body, keypair)
    }

    /// Convert this HTTP receipt into a core ChioReceipt for unified storage.
    ///
    /// This method fails closed because a valid ChioReceipt signature cannot be
    /// derived from an HttpReceipt without the kernel signing keypair.
    pub fn to_chio_receipt(
        &self,
    ) -> chio_core_types::Result<chio_core_types::receipt::body::ChioReceipt> {
        Err(chio_core_types::Error::CanonicalJson(
            "cannot convert HttpReceipt into signed ChioReceipt without the kernel keypair"
                .to_string(),
        ))
    }
}

fn compute_http_receipt_id(body: &HttpReceiptBody) -> chio_core_types::Result<String> {
    let mut value = serde_json::to_value(body)?;
    let Some(object) = value.as_object_mut() else {
        return Err(chio_core_types::Error::CanonicalJson(
            "HTTP receipt body did not serialize to an object".to_string(),
        ));
    };
    object.remove("id");
    let canonical = canonical_json_bytes(&value)?;
    Ok(sha256_hex(&canonical))
}

#[must_use]
pub fn http_status_metadata_decision() -> Value {
    let mut map = Map::new();
    map.insert(
        CHIO_HTTP_STATUS_SCOPE_KEY.to_string(),
        Value::String(CHIO_HTTP_STATUS_SCOPE_DECISION.to_string()),
    );
    Value::Object(map)
}

#[must_use]
pub fn http_status_metadata_final(decision_receipt_id: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert(
        CHIO_HTTP_STATUS_SCOPE_KEY.to_string(),
        Value::String(CHIO_HTTP_STATUS_SCOPE_FINAL.to_string()),
    );
    if let Some(id) = decision_receipt_id {
        map.insert(
            CHIO_DECISION_RECEIPT_ID_KEY.to_string(),
            Value::String(id.to_string()),
        );
    }
    Value::Object(map)
}

#[must_use]
pub fn http_status_scope(metadata: Option<&Value>) -> Option<&str> {
    metadata
        .and_then(Value::as_object)
        .and_then(|object| object.get(CHIO_HTTP_STATUS_SCOPE_KEY))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Verdict;

    use chio_test_support::prelude::*;

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn sample_body(keypair: &Keypair) -> HttpReceiptBody {
        HttpReceiptBody {
            id: "receipt-001".to_string(),
            request_id: "req-001".to_string(),
            route_pattern: "/pets/{petId}".to_string(),
            method: HttpMethod::Get,
            caller_identity_hash: "abc123".to_string(),
            session_id: Some("sess-001".to_string()),
            verdict: Verdict::Allow,
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: vec![],
            response_status: 200,
            timestamp: 1700000000,
            content_hash: "deadbeef".to_string(),
            policy_hash: "cafebabe".to_string(),
            trust_level: TrustLevel::Mediated,
            capability_id: None,
            metadata: None,
            kernel_key: keypair.public_key(),
        }
    }

    #[test]
    fn sign_and_verify() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        assert!(receipt.verify_signature().test_unwrap());
        assert!(receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn deny_receipt() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.verdict = Verdict::deny("no capability", "CapabilityGuard");
        body.response_status = 403;
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        assert!(receipt.is_denied());
        assert!(receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn sign_rejects_unsigned_authority_shape_drift() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.receipt_kind = ReceiptKind::TraceObservation;
        body.boundary_class = BoundaryClass::DetectOnly;
        body.observation_outcome = Some(ObservationOutcome::Observed);
        body.trust_level = TrustLevel::Verified;

        let error = HttpReceipt::sign(body, &kp).test_unwrap_err();
        assert!(error
            .to_string()
            .contains("HTTP receipts must be mediated_decision receipts"));
    }

    #[test]
    fn verify_signature_rejects_signed_authority_shape_drift() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let mut receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        receipt.receipt_kind = ReceiptKind::TraceObservation;
        receipt.boundary_class = BoundaryClass::DetectOnly;
        receipt.observation_outcome = Some(ObservationOutcome::Observed);
        receipt.trust_level = TrustLevel::Verified;
        let (signature, _) = kp.sign_canonical(&receipt.body()).test_unwrap();
        receipt.signature = signature;

        assert!(!receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn body_roundtrip() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body.clone(), &kp).test_unwrap();
        let extracted = receipt.body();
        // sign() overwrites body.id with the content-addressed id, so the
        // extracted body carries the signed id rather than the caller-supplied
        // value.
        assert_eq!(extracted.id, receipt.id);
        assert_ne!(extracted.id, body.id);
        assert_eq!(extracted.route_pattern, body.route_pattern);
    }

    #[test]
    fn serde_roundtrip() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        let json = serde_json::to_string(&receipt).test_unwrap();
        let back: HttpReceipt = serde_json::from_str(&json).test_unwrap();
        assert!(back.verify_signature().test_unwrap());
    }

    #[test]
    fn to_chio_receipt_conversion() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        let error = receipt.to_chio_receipt().test_unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot convert HttpReceipt into signed ChioReceipt"));
    }

    #[test]
    fn receipt_with_evidence_entries() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.evidence = vec![
            GuardEvidence {
                guard_name: "PolicyGuard".to_string(),
                verdict: true,
                details: Some("session-scoped allow".to_string()),
            },
            GuardEvidence {
                guard_name: "RateLimitGuard".to_string(),
                verdict: true,
                details: None,
            },
        ];
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        assert!(receipt.verify_signature().test_unwrap());
        assert_eq!(receipt.evidence.len(), 2);
        assert_eq!(receipt.evidence[0].guard_name, "PolicyGuard");
        assert!(receipt.evidence[0].verdict);
    }

    #[test]
    fn receipt_with_metadata() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.metadata = Some(serde_json::json!({
            "trace_id": "abc123",
            "tags": ["production", "v2"]
        }));
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        assert!(receipt.verify_signature().test_unwrap());
        let meta = receipt.metadata.as_ref().test_unwrap();
        assert_eq!(meta["trace_id"], "abc123");
    }

    #[test]
    fn receipt_with_capability_id() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.capability_id = Some("cap-xyz-789".to_string());
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        assert!(receipt.verify_signature().test_unwrap());
        assert_eq!(receipt.capability_id.as_deref(), Some("cap-xyz-789"));
        let chio_receipt = receipt.to_chio_receipt_with_keypair(&kp).test_unwrap();
        assert_eq!(chio_receipt.capability_id, "cap-xyz-789");
        assert!(chio_receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn converted_receipt_has_a_verifiable_action_hash() {
        // A durable receipt store recomputes the action parameter hash and
        // rejects a receipt whose hash does not match its parameters. Signing
        // alone is not enough: a receipt can carry a valid signature yet still be
        // refused for a mismatched action hash, which would fail every durable
        // append closed. The converted core receipt must therefore verify both.
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        let chio_receipt = receipt.to_chio_receipt_with_keypair(&kp).test_unwrap();
        assert!(
            chio_receipt.verify_signature().test_unwrap(),
            "converted receipt signature must verify"
        );
        assert!(
            chio_receipt.action.verify_hash().test_unwrap(),
            "converted receipt action hash must match its parameters so a durable store accepts it"
        );
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let mut receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        // Tamper with the response status
        receipt.response_status = 500;
        assert!(!receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn receipt_metadata_scope_roundtrip_and_signature_verifies() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.metadata = Some(http_status_metadata_final(Some("decision-001")));

        let receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        assert_eq!(
            http_status_scope(receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
        assert!(receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn tampering_with_status_scope_metadata_breaks_signature() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.metadata = Some(http_status_metadata_decision());

        let mut receipt = HttpReceipt::sign(body, &kp).test_unwrap();
        receipt.metadata = Some(http_status_metadata_final(Some("decision-001")));

        assert!(!receipt.verify_signature().test_unwrap());
    }
}
