# TRJ4-044 PII and PHI exposure

- Test: `crates/chio-conformance/tests/threats/pii_phi_exposure.rs`
- Coverage: direct `ResponseSanitizationGuard` exercise.
- Negative case: payload containing SSN and MRN markers blocks in `Block` mode.
- Redaction case: the same payload removes raw identifiers in `Redact` mode.
