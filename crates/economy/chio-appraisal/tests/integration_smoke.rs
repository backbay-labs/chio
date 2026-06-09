use chio_appraisal::{
    RuntimeAttestationAppraisalVerdict, RuntimeAttestationNormalizedClaimVocabulary,
    RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA,
};

#[test]
fn appraisal_vocabulary_uses_public_schema_contract() {
    let vocabulary = RuntimeAttestationNormalizedClaimVocabulary {
        schema: RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA.to_string(),
        entries: Vec::new(),
    };

    assert_eq!(
        vocabulary.schema,
        RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA
    );
    assert_ne!(
        RuntimeAttestationAppraisalVerdict::Accepted,
        RuntimeAttestationAppraisalVerdict::Rejected
    );
}
