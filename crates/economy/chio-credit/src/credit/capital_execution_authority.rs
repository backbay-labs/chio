use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionAuthorityStepProofBody {
    pub schema: String,
    pub role: CapitalExecutionRole,
    pub principal_id: String,
    pub approved_at: u64,
    pub expires_at: u64,
}

pub type SignedCapitalExecutionAuthorityStepProof =
    SignedExportEnvelope<CapitalExecutionAuthorityStepProofBody>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionAuthorityStep {
    pub role: CapitalExecutionRole,
    pub principal_id: String,
    pub approved_at: u64,
    pub expires_at: u64,
    pub authority_proof: SignedCapitalExecutionAuthorityStepProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl CapitalExecutionAuthorityStep {
    pub fn signed(
        role: CapitalExecutionRole,
        principal_keypair: &crate::crypto::Keypair,
        approved_at: u64,
        expires_at: u64,
        note: Option<String>,
    ) -> Result<Self, String> {
        let principal_id = principal_keypair.public_key().to_hex();
        let body = CapitalExecutionAuthorityStepProofBody {
            schema: CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA.to_string(),
            role,
            principal_id: principal_id.clone(),
            approved_at,
            expires_at,
        };
        let authority_proof = SignedCapitalExecutionAuthorityStepProof::sign(body, principal_keypair)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            role,
            principal_id,
            approved_at,
            expires_at,
            authority_proof,
            note,
        })
    }
}

pub fn validate_capital_execution_authority_step_proof(
    step: &CapitalExecutionAuthorityStep,
) -> Result<(), String> {
    if step.authority_proof.body.schema != CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA {
        return Err(format!(
            "capital execution authority proof schema must be {CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA}"
        ));
    }
    if !step
        .authority_proof
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Err("capital execution authority proof signature verification failed".to_string());
    }
    let signer_principal_id = step.authority_proof.signer_key.to_hex();
    if step.principal_id != signer_principal_id {
        return Err("capital execution authority proof signer must match principalId".to_string());
    }
    let proof = &step.authority_proof.body;
    if proof.role != step.role
        || proof.principal_id != step.principal_id
        || proof.approved_at != step.approved_at
        || proof.expires_at != step.expires_at
    {
        return Err(
            "capital execution authority proof body must match authorityChain step".to_string(),
        );
    }
    Ok(())
}
