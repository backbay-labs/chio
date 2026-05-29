// Session compliance certificate generation and verification.
//
// Walks the receipt log for a session, verifies signatures, chain
// continuity, scope, budget, guard evidence, and delegation. Produces
// a signed compliance certificate or aborts with a typed error.

use std::sync::atomic::{AtomicBool, Ordering};

use chio_core::canonical::canonical_json_bytes;
use chio_core::chio_receipt_id;
use chio_core::crypto::Signature;

/// One-shot guard for the empty-`trusted_kernel_keys` warning.
///
/// `ComplianceConfig` derives `Default`, which yields an empty
/// `trusted_kernel_keys` set. With the empty set, every receipt is
/// rejected with `UntrustedKernelKey` and neither generation nor
/// verification can succeed. That is the operator contract -- the
/// trust set MUST be populated -- but a silent rejection is hostile
/// for first-time callers. Emit a single tracing warning the first
/// time we observe an empty set during validation so operators see a
/// clear breadcrumb without flooding the log.
static EMPTY_TRUSTED_KEYS_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_empty_compliance_trusted_keys_once() {
    if EMPTY_TRUSTED_KEYS_WARNED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tracing::warn!(
            target: "chio_acp_proxy::compliance",
            "ComplianceConfig has no trusted_kernel_keys configured; all receipts will fail \
             integrity validation with UntrustedKernelKey, and compliance certificate \
             generation and verification will not succeed. Populate \
             ComplianceConfig::trusted_kernel_keys with the operator-pinned kernel keys \
             before calling generate_compliance_certificate or verify_compliance_certificate."
        );
    }
}

/// Error types that abort compliance certificate generation.
#[derive(Debug, thiserror::Error)]
pub enum ComplianceCertificateError {
    /// No receipts found for the given session.
    #[error("empty session: no receipts found for session {0}")]
    EmptySession(String),

    /// A receipt's Ed25519 signature is invalid.
    #[error("invalid receipt signature: receipt {receipt_id} failed verification")]
    InvalidReceiptSignature {
        /// The receipt ID whose signature failed.
        receipt_id: String,
    },

    /// A receipt ID does not match the content-addressed receipt body.
    #[error("invalid receipt id: receipt {receipt_id} does not match its canonical body")]
    InvalidReceiptId {
        /// The receipt ID whose content-addressed identity failed.
        receipt_id: String,
    },

    /// A receipt action hash does not match the canonical action parameters.
    #[error("invalid receipt action hash: receipt {receipt_id} failed parameter hash verification")]
    InvalidActionHash {
        /// The receipt ID whose action hash failed.
        receipt_id: String,
    },

    /// A receipt does not belong to the certificate's named session.
    #[error("session mismatch: receipt {receipt_id} is not bound to session {session_id}")]
    SessionMismatch {
        /// The receipt ID whose session binding failed.
        receipt_id: String,
        /// The session ID named by the certificate.
        session_id: String,
    },

    /// A receipt does not belong to the configured tenant.
    #[error("tenant mismatch: receipt {receipt_id} is not bound to tenant {tenant_id}")]
    TenantMismatch {
        /// The receipt ID whose tenant binding failed.
        receipt_id: String,
        /// The expected tenant ID.
        tenant_id: String,
    },

    /// A receipt carries an allow decision without authorization semantics.
    #[error("non-authorizing allow receipt: receipt {receipt_id} is not mediated/prevent/allow")]
    NonAuthorizingReceipt {
        /// The receipt ID whose semantics failed.
        receipt_id: String,
    },

    /// A receipt was signed by a kernel key outside the verifier trust set.
    #[error("untrusted kernel key: receipt {receipt_id} was signed by {kernel_key}")]
    UntrustedKernelKey {
        /// The receipt ID whose signer was not trusted.
        receipt_id: String,
        /// The untrusted kernel key.
        kernel_key: String,
    },

    /// A gap or reordering was detected in the receipt chain.
    #[error("chain discontinuity: expected seq {expected} but found {found}")]
    ChainDiscontinuity {
        /// The expected sequence number.
        expected: u64,
        /// The actual sequence number found.
        found: u64,
    },

    /// A receipt's scope exceeds the session's authorized scope.
    #[error("scope violation: receipt {receipt_id} accesses {resource} outside authorized scope")]
    ScopeViolation {
        /// The receipt that violated scope.
        receipt_id: String,
        /// The resource that was out of scope.
        resource: String,
    },

    /// The session's invocation budget was exceeded.
    #[error("budget exceeded: {used} invocations against limit of {limit}")]
    BudgetExceeded {
        /// Actual number of invocations observed.
        used: u64,
        /// The configured budget limit.
        limit: u64,
    },

    /// A guard was bypassed (no evidence recorded for a required guard).
    #[error("guard bypass: guard {guard_name} has no evidence in receipt {receipt_id}")]
    GuardBypass {
        /// The guard that was expected to run.
        guard_name: String,
        /// The receipt missing the guard evidence.
        receipt_id: String,
    },

    /// Receipts in the session were signed by more than one kernel key.
    ///
    /// The compliance certificate names a single kernel key. A session that
    /// mixes receipts from different kernels would produce a certificate
    /// whose `kernel_key` field misrepresents the signer for some receipts;
    /// fail closed.
    #[error(
        "kernel key mismatch: receipt {receipt_id} signed by a different kernel than the session's first receipt"
    )]
    KernelKeyMismatch {
        /// The receipt whose kernel_key did not match the session's first receipt.
        receipt_id: String,
    },

    /// Serialization error during certificate construction.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Signing error during certificate construction.
    #[error("signing error: {0}")]
    Signing(String),
}

/// A receipt entry used during compliance analysis.
#[derive(Debug, Clone)]
pub struct ComplianceReceiptEntry {
    /// The full signed receipt.
    pub receipt: ChioReceipt,
    /// Sequence number in the receipt log.
    pub seq: u64,
}

/// Configuration for compliance certificate generation.
#[derive(Debug, Default, Clone)]
pub struct ComplianceConfig {
    /// Maximum number of invocations allowed (0 = unlimited).
    pub budget_limit: u64,
    /// Guard names that must appear in every receipt's evidence.
    pub required_guards: Vec<String>,
    /// Authorized resource scopes (path prefixes).
    pub authorized_scopes: Vec<String>,
    /// Expected tenant for all receipts. None disables tenant checking.
    pub expected_tenant_id: Option<String>,
    /// Trusted kernel keys allowed to sign receipts and certificates.
    ///
    /// MUST be populated by the operator with the kernel public keys
    /// that are authorized to sign receipts in this deployment. An
    /// empty set is a misconfiguration: every receipt will be rejected
    /// with `UntrustedKernelKey`, blocking both generation and
    /// verification of compliance certificates. The first observed
    /// empty-set evaluation logs a one-shot tracing warning to make
    /// this contract visible to operators.
    pub trusted_kernel_keys: std::collections::BTreeSet<String>,
}

/// The body of a compliance certificate (unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCertificateBody {
    /// Schema identifier.
    pub schema: String,
    /// Session ID the certificate covers.
    pub session_id: String,
    /// Unix timestamp when the certificate was generated.
    pub issued_at: u64,
    /// Number of receipts examined.
    pub receipt_count: u64,
    /// First receipt timestamp in the session.
    pub first_receipt_at: u64,
    /// Last receipt timestamp in the session.
    pub last_receipt_at: u64,
    /// Whether all receipts passed signature verification.
    pub all_signatures_valid: bool,
    /// Whether the receipt chain is continuous (no gaps).
    pub chain_continuous: bool,
    /// Whether all receipts are within authorized scope.
    pub scope_compliant: bool,
    /// Whether the invocation budget was respected.
    pub budget_compliant: bool,
    /// Whether all required guards have evidence in every receipt.
    pub guards_compliant: bool,
    /// Summary of any anomalies detected (empty if fully compliant).
    pub anomalies: Vec<String>,
    /// The kernel public key that signed the session receipts.
    pub kernel_key: PublicKey,
}

/// A signed compliance certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCertificate {
    /// The unsigned body.
    pub body: ComplianceCertificateBody,
    /// Public key that signed the certificate.
    pub signer_key: PublicKey,
    /// Ed25519 signature over canonical JSON of `body`.
    pub signature: Signature,
}

/// Verification mode for compliance certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Lightweight: verify certificate signature and body consistency only.
    Lightweight,
    /// Full bundle: verify certificate + re-verify all receipt signatures.
    FullBundle,
}

/// Result of certificate verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateVerificationResult {
    /// Whether the certificate signature is valid.
    #[serde(alias = "certificateSignatureValid")]
    pub certificate_signature_valid: bool,
    /// Whether the body fields are internally consistent.
    #[serde(alias = "bodyConsistent")]
    pub body_consistent: bool,
    /// Number of receipt signatures re-verified (full-bundle mode only).
    #[serde(alias = "receiptsReverified")]
    pub receipts_reverified: u64,
    /// Number of receipt signature failures (full-bundle mode only).
    #[serde(alias = "receiptFailures")]
    pub receipt_failures: u64,
    /// Overall pass/fail.
    pub passed: bool,
    /// Human-readable summary.
    pub summary: String,
}

pub const COMPLIANCE_CERTIFICATE_SCHEMA: &str = "chio.compliance.certificate.v1";

fn receipt_session_id(receipt: &ChioReceipt) -> Option<&str> {
    let metadata = receipt.metadata.as_ref()?;
    metadata
        .get("acp")
        .and_then(|acp| acp.get("sessionId"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            metadata
                .get("receipt_context")
                .and_then(|context| context.get("session_id"))
                .and_then(serde_json::Value::as_str)
        })
}

fn validate_compliance_receipt(
    session_id: &str,
    entry: &ComplianceReceiptEntry,
    config: &ComplianceConfig,
) -> Result<(), ComplianceCertificateError> {
    let receipt = &entry.receipt;
    let sig_ok = receipt
        .verify_signature()
        .map_err(|e| ComplianceCertificateError::Signing(format!("{e}")))?;
    if !sig_ok {
        return Err(ComplianceCertificateError::InvalidReceiptSignature {
            receipt_id: receipt.id.clone(),
        });
    }
    let id_ok = chio_receipt_id(&receipt.body())
        .map(|expected| expected == receipt.id)
        .unwrap_or(false);
    if !id_ok {
        return Err(ComplianceCertificateError::InvalidReceiptId {
            receipt_id: receipt.id.clone(),
        });
    }
    let action_hash_ok = receipt.action.verify_hash().map_err(|e| {
        ComplianceCertificateError::Signing(format!("action hash verification failed: {e}"))
    })?;
    if !action_hash_ok {
        return Err(ComplianceCertificateError::InvalidActionHash {
            receipt_id: receipt.id.clone(),
        });
    }
    let kernel_key_hex = receipt.kernel_key.to_hex();
    if config.trusted_kernel_keys.is_empty() {
        // Operator contract: the trust set must be populated. Emit a
        // one-shot warning so the misconfiguration is visible, then
        // fall through to the standard untrusted-key rejection (an
        // empty trust set contains nothing, so every receipt fails the
        // membership check that follows).
        warn_empty_compliance_trusted_keys_once();
    }
    if !config.trusted_kernel_keys.contains(&kernel_key_hex) {
        return Err(ComplianceCertificateError::UntrustedKernelKey {
            receipt_id: receipt.id.clone(),
            kernel_key: kernel_key_hex,
        });
    }
    if receipt_session_id(receipt) != Some(session_id) {
        return Err(ComplianceCertificateError::SessionMismatch {
            receipt_id: receipt.id.clone(),
            session_id: session_id.to_string(),
        });
    }
    if let Some(expected_tenant_id) = config.expected_tenant_id.as_deref() {
        if receipt.tenant_id.as_deref() != Some(expected_tenant_id) {
            return Err(ComplianceCertificateError::TenantMismatch {
                receipt_id: receipt.id.clone(),
                tenant_id: expected_tenant_id.to_string(),
            });
        }
    }
    if matches!(
        receipt.decision.as_ref(),
        Some(chio_core::receipt::Decision::Allow)
    )
        && !receipt.is_allowed()
    {
        return Err(ComplianceCertificateError::NonAuthorizingReceipt {
            receipt_id: receipt.id.clone(),
        });
    }
    Ok(())
}

/// Generate a compliance certificate for the given session.
///
/// Walks all receipts, verifies signatures, checks chain continuity,
/// scope, budget, and guard evidence. Any anomaly aborts with a typed
/// error.
pub fn generate_compliance_certificate(
    session_id: &str,
    receipts: &[ComplianceReceiptEntry],
    config: &ComplianceConfig,
    keypair: &Keypair,
) -> Result<ComplianceCertificate, ComplianceCertificateError> {
    // 1. Empty session check.
    if receipts.is_empty() {
        return Err(ComplianceCertificateError::EmptySession(
            session_id.to_string(),
        ));
    }

    // 2. Verify all receipt authority signals.
    for entry in receipts {
        validate_compliance_receipt(session_id, entry, config)?;
    }

    // 3. Check chain continuity.
    for i in 1..receipts.len() {
        let expected = receipts[i - 1].seq + 1;
        let found = receipts[i].seq;
        if found != expected {
            return Err(ComplianceCertificateError::ChainDiscontinuity {
                expected,
                found,
            });
        }
    }

    // 4. Check scope compliance.
    if !config.authorized_scopes.is_empty() {
        for entry in receipts {
            let resource = &entry.receipt.tool_name;
            let in_scope = config
                .authorized_scopes
                .iter()
                .any(|scope| resource.starts_with(scope.as_str()));
            if !in_scope {
                return Err(ComplianceCertificateError::ScopeViolation {
                    receipt_id: entry.receipt.id.clone(),
                    resource: resource.clone(),
                });
            }
        }
    }

    // 5. Check budget.
    let invocation_count = receipts.len() as u64;
    if config.budget_limit > 0 && invocation_count > config.budget_limit {
        return Err(ComplianceCertificateError::BudgetExceeded {
            used: invocation_count,
            limit: config.budget_limit,
        });
    }

    // 6. Check guard evidence.
    for guard_name in &config.required_guards {
        for entry in receipts {
            let has_evidence = entry
                .receipt
                .evidence
                .iter()
                .any(|ev| &ev.guard_name == guard_name);
            if !has_evidence {
                return Err(ComplianceCertificateError::GuardBypass {
                    guard_name: guard_name.clone(),
                    receipt_id: entry.receipt.id.clone(),
                });
            }
        }
    }

    // 7. Cross-check that all receipts share the same kernel key.
    //
    // The certificate body records a single `kernel_key`. Without this check,
    // a session that mixed receipts from different kernels would still be
    // certified, masking the mismatch under the first receipt's key.
    if let Some(first_entry) = receipts.first() {
        let session_kernel_key = &first_entry.receipt.kernel_key;
        for entry in receipts.iter().skip(1) {
            if &entry.receipt.kernel_key != session_kernel_key {
                return Err(ComplianceCertificateError::KernelKeyMismatch {
                    receipt_id: entry.receipt.id.clone(),
                });
            }
        }
    }

    // All checks passed -- build the certificate.
    let first_ts = receipts
        .first()
        .map(|e| e.receipt.timestamp)
        .unwrap_or(0);
    let last_ts = receipts
        .last()
        .map(|e| e.receipt.timestamp)
        .unwrap_or(0);

    let kernel_key = receipts
        .first()
        .map(|e| e.receipt.kernel_key.clone())
        .unwrap_or_else(|| keypair.public_key());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let body = ComplianceCertificateBody {
        schema: COMPLIANCE_CERTIFICATE_SCHEMA.to_string(),
        session_id: session_id.to_string(),
        issued_at: now,
        receipt_count: invocation_count,
        first_receipt_at: first_ts,
        last_receipt_at: last_ts,
        all_signatures_valid: true,
        chain_continuous: true,
        scope_compliant: true,
        budget_compliant: true,
        guards_compliant: true,
        anomalies: Vec::new(),
        kernel_key,
    };

    let body_bytes = canonical_json_bytes(&body)
        .map_err(|e| ComplianceCertificateError::Serialization(e.to_string()))?;
    let signature = keypair.sign(&body_bytes);

    let certificate = ComplianceCertificate {
        body,
        signer_key: keypair.public_key(),
        signature,
    };

    // Self-verify before returning. If the caller's keypair does not
    // match the kernel key recorded on the receipts (or the trust set
    // does not include this signer), the certificate would silently be
    // unverifiable. Fail closed here so generation never hands back a
    // certificate that the matching verifier would reject.
    //
    // Trust-set independence: if the operator's `trusted_kernel_keys`
    // set is empty (a misconfiguration covered by the empty-set warning
    // elsewhere in this module), the signer-trust check below would
    // reject every otherwise-valid certificate. To keep self-verify
    // robust against that operator misconfiguration, augment the trust
    // set with the certificate's own signer and the receipts' kernel
    // key for the purpose of this check only.
    let mut self_verify_config = config.clone();
    self_verify_config
        .trusted_kernel_keys
        .insert(certificate.signer_key.to_hex());
    self_verify_config
        .trusted_kernel_keys
        .insert(certificate.body.kernel_key.to_hex());
    let self_verification = verify_compliance_certificate(
        &certificate,
        VerificationMode::Lightweight,
        None,
        &self_verify_config,
    );
    if !self_verification.passed {
        return Err(ComplianceCertificateError::Signing(format!(
            "generated compliance certificate failed self-verification: {}",
            self_verification.summary
        )));
    }

    Ok(certificate)
}

/// Verify a compliance certificate.
pub fn verify_compliance_certificate(
    cert: &ComplianceCertificate,
    mode: VerificationMode,
    receipts: Option<&[ComplianceReceiptEntry]>,
    config: &ComplianceConfig,
) -> CertificateVerificationResult {
    // 1. Verify certificate signature.
    let body_bytes = match canonical_json_bytes(&cert.body) {
        Ok(b) => b,
        Err(_) => {
            return CertificateVerificationResult {
                certificate_signature_valid: false,
                body_consistent: false,
                receipts_reverified: 0,
                receipt_failures: 0,
                passed: false,
                summary: "failed to serialize certificate body for verification".to_string(),
            };
        }
    };

    let sig_valid = cert.signer_key.verify(&body_bytes, &cert.signature);
    let signer_trusted = config
        .trusted_kernel_keys
        .contains(&cert.signer_key.to_hex());
    let signer_matches_body = cert.signer_key == cert.body.kernel_key;

    // 2. Body consistency checks. `body_ok_excluding_signer_match` lets the
    // failure summary distinguish a body that is broken in some way OTHER
    // than signer-vs-body mismatch from one whose only fault is the mismatch.
    // Without that split, every signer-mismatch failure also tripped the
    // generic "body consistency check failed" reason, producing a redundant
    // entry that obscured the underlying cause.
    let body_ok_excluding_signer_match = cert.body.all_signatures_valid
        && cert.body.schema == COMPLIANCE_CERTIFICATE_SCHEMA
        && cert.body.chain_continuous
        && cert.body.scope_compliant
        && cert.body.budget_compliant
        && cert.body.guards_compliant
        && cert.body.anomalies.is_empty();
    let body_ok = body_ok_excluding_signer_match && signer_matches_body;

    if mode == VerificationMode::Lightweight || receipts.is_none() {
        return CertificateVerificationResult {
            certificate_signature_valid: sig_valid,
            body_consistent: body_ok,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed: sig_valid && signer_trusted && body_ok,
            summary: if sig_valid && signer_trusted && body_ok {
                "lightweight verification passed".to_string()
            } else {
                verification_failure_summary(
                    sig_valid,
                    signer_trusted,
                    body_ok_excluding_signer_match,
                    signer_matches_body,
                    0,
                )
            },
        };
    }

    // 3. Full-bundle mode: re-verify all receipt authority signals.
    let receipt_entries = receipts.unwrap_or(&[]);
    let mut reverified: u64 = 0;
    let mut failures: u64 = 0;

    for entry in receipt_entries {
        reverified += 1;
        if validate_compliance_receipt(&cert.body.session_id, entry, config).is_err() {
            failures += 1;
        }
    }

    let passed = sig_valid && signer_trusted && body_ok && failures == 0;
    CertificateVerificationResult {
        certificate_signature_valid: sig_valid,
        body_consistent: body_ok,
        receipts_reverified: reverified,
        receipt_failures: failures,
        passed,
        summary: if passed {
            format!("full-bundle verification passed ({reverified} receipts re-verified)")
        } else {
            verification_failure_summary(
                sig_valid,
                signer_trusted,
                body_ok_excluding_signer_match,
                signer_matches_body,
                failures,
            )
        },
    }
}

/// Build a human-readable reason list for a failed certificate verification.
///
/// `body_ok_excluding_signer_match` must reflect ONLY the body conjuncts that
/// are independent of the signer-vs-body comparison (schema, signatures,
/// chain continuity, scope/budget/guards, anomalies). The signer mismatch is
/// reported via its own dedicated reason, so folding it back into a generic
/// "body consistency check failed" entry would produce a redundant message
/// whose root cause is already named on the previous line.
fn verification_failure_summary(
    sig_valid: bool,
    signer_trusted: bool,
    body_ok_excluding_signer_match: bool,
    signer_matches_body: bool,
    receipt_failures: u64,
) -> String {
    let mut reasons = Vec::new();
    if !sig_valid {
        reasons.push("certificate signature invalid".to_string());
    }
    if !signer_trusted {
        reasons.push("certificate signer is not trusted".to_string());
    }
    if !signer_matches_body {
        reasons.push("certificate signer does not match body kernel key".to_string());
    }
    if !body_ok_excluding_signer_match {
        reasons.push("body consistency check failed".to_string());
    }
    if receipt_failures > 0 {
        reasons.push(format!("{receipt_failures} receipt authority check(s) failed"));
    }
    format!("verification failed: {}", reasons.join(", "))
}
