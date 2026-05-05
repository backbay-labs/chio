// Session compliance certificate generation and verification.
//
// Walks the receipt log for a session, verifies signatures, chain
// continuity, scope, budget, guard evidence, and delegation. Produces
// a signed compliance certificate or aborts with a typed error.

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Signature;

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
}

/// The body of a compliance certificate (unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCertificateBody {
    /// Schema identifier.
    pub schema: String,
    /// Session ID the certificate covers.
    #[serde(alias = "sessionId")]
    pub session_id: String,
    /// Unix timestamp when the certificate was generated.
    #[serde(alias = "issuedAt")]
    pub issued_at: u64,
    /// Number of receipts examined.
    #[serde(alias = "receiptCount")]
    pub receipt_count: u64,
    /// First receipt timestamp in the session.
    #[serde(alias = "firstReceiptAt")]
    pub first_receipt_at: u64,
    /// Last receipt timestamp in the session.
    #[serde(alias = "lastReceiptAt")]
    pub last_receipt_at: u64,
    /// Whether all receipts passed signature verification.
    #[serde(alias = "allSignaturesValid")]
    pub all_signatures_valid: bool,
    /// Whether the receipt chain is continuous (no gaps).
    #[serde(alias = "chainContinuous")]
    pub chain_continuous: bool,
    /// Whether all receipts are within authorized scope.
    #[serde(alias = "scopeCompliant")]
    pub scope_compliant: bool,
    /// Whether the invocation budget was respected.
    #[serde(alias = "budgetCompliant")]
    pub budget_compliant: bool,
    /// Whether all required guards have evidence in every receipt.
    #[serde(alias = "guardsCompliant")]
    pub guards_compliant: bool,
    /// Summary of any anomalies detected (empty if fully compliant).
    pub anomalies: Vec<String>,
    /// The kernel public key that signed the session receipts.
    #[serde(alias = "kernelKey")]
    pub kernel_key: PublicKey,
}

/// A signed compliance certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCertificate {
    /// The unsigned body.
    pub body: ComplianceCertificateBody,
    /// Public key that signed the certificate.
    #[serde(alias = "signerKey")]
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

    // 2. Verify all receipt signatures.
    for entry in receipts {
        let sig_ok = entry
            .receipt
            .verify_signature()
            .map_err(|e| ComplianceCertificateError::Signing(format!("{e}")))?;
        if !sig_ok {
            return Err(ComplianceCertificateError::InvalidReceiptSignature {
                receipt_id: entry.receipt.id.clone(),
            });
        }
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

    Ok(ComplianceCertificate {
        body,
        signer_key: keypair.public_key(),
        signature,
    })
}

/// Verify a compliance certificate.
pub fn verify_compliance_certificate(
    cert: &ComplianceCertificate,
    mode: VerificationMode,
    receipts: Option<&[ComplianceReceiptEntry]>,
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

    // 2. Body consistency checks.
    let body_ok = cert.body.all_signatures_valid
        && cert.body.chain_continuous
        && cert.body.scope_compliant
        && cert.body.budget_compliant
        && cert.body.guards_compliant
        && cert.body.anomalies.is_empty();

    if mode == VerificationMode::Lightweight || receipts.is_none() {
        return CertificateVerificationResult {
            certificate_signature_valid: sig_valid,
            body_consistent: body_ok,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed: sig_valid && body_ok,
            summary: if sig_valid && body_ok {
                "lightweight verification passed".to_string()
            } else {
                "lightweight verification failed".to_string()
            },
        };
    }

    // 3. Full-bundle mode: re-verify all receipt signatures.
    let receipt_entries = receipts.unwrap_or(&[]);
    let mut reverified: u64 = 0;
    let mut failures: u64 = 0;

    for entry in receipt_entries {
        reverified += 1;
        let ok = entry
            .receipt
            .verify_signature()
            .unwrap_or(false);
        if !ok {
            failures += 1;
        }
    }

    let passed = sig_valid && body_ok && failures == 0;
    CertificateVerificationResult {
        certificate_signature_valid: sig_valid,
        body_consistent: body_ok,
        receipts_reverified: reverified,
        receipt_failures: failures,
        passed,
        summary: if passed {
            format!("full-bundle verification passed ({reverified} receipts re-verified)")
        } else {
            let mut reasons = Vec::new();
            if !sig_valid {
                reasons.push("certificate signature invalid".to_string());
            }
            if !body_ok {
                reasons.push("body consistency check failed".to_string());
            }
            if failures > 0 {
                reasons.push(format!("{failures} receipt signature(s) failed"));
            }
            format!("full-bundle verification failed: {}", reasons.join(", "))
        },
    }
}
