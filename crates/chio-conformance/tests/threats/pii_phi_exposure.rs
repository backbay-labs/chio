//! Threat test for threat ID `pii_phi_exposure`.
//!
//! Coverage strategy: exercise the in-tree response sanitization guard against
//! definite PHI/PII markers and assert both block and redact modes fail closed
//! before raw identifiers reach downstream consumers.

use chio_guards::{ResponseSanitizationGuard, SanitizationAction, ScanResult, SensitivityLevel};

#[test]
fn threat_pii_phi_exposure_is_covered() {
    // covers: pii_phi_exposure
    let payload = serde_json::json!({
        "patient": "Jane Doe",
        "mrn": "MRN 123456789",
        "ssn": "123-45-6789"
    });

    let blocking =
        ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Block);
    match blocking.scan_response(&payload) {
        ScanResult::Blocked(findings) => {
            assert!(findings.iter().any(|(name, _)| name == "MRN"));
            assert!(findings.iter().any(|(name, _)| name == "SSN"));
        }
        other => panic!("PHI payload must block, got {other:?}"),
    }

    let redacting =
        ResponseSanitizationGuard::new(SensitivityLevel::High, SanitizationAction::Redact);
    match redacting.scan_response(&payload) {
        ScanResult::Redacted {
            redacted_text,
            redaction_count,
            ..
        } => {
            assert!(redaction_count >= 2);
            assert!(!redacted_text.contains("123-45-6789"));
            assert!(!redacted_text.contains("MRN 123456789"));
        }
        other => panic!("PHI payload must redact, got {other:?}"),
    }
}
