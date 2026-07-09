//! EVM settlement instruction readiness, binding checks, and digest signing.

use super::*;

pub(super) fn ensure_instruction_ready(
    config: &SettlementChainConfig,
    instruction: &SignedCapitalExecutionInstruction,
    beneficiary_address: &str,
) -> Result<(), SettlementError> {
    let verified = instruction
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "capital execution instruction signature verification failed".to_string(),
        ));
    }
    if instruction.body.action != CapitalExecutionInstructionAction::TransferFunds {
        return Err(SettlementError::InvalidDispatch(
            "only transfer_funds is supported by the official settlement runtime".to_string(),
        ));
    }
    if instruction.body.rail.kind != CapitalExecutionRailKind::Web3 {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction rail.kind must be web3".to_string(),
        ));
    }
    if instruction.body.rail.jurisdiction.as_deref() != Some(config.chain_id.as_str()) {
        return Err(SettlementError::InvalidDispatch(format!(
            "capital instruction jurisdiction {:?} does not match {}",
            instruction.body.rail.jurisdiction, config.chain_id
        )));
    }
    if instruction.body.amount.is_none() {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction amount is required".to_string(),
        ));
    }
    let governed_receipt_id = instruction
        .body
        .governed_receipt_id
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction governed_receipt_id is required".to_string(),
            )
        })?;
    if governed_receipt_id.trim().is_empty() {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction governed_receipt_id cannot be empty".to_string(),
        ));
    }
    let completion_flow_row_id = instruction
        .body
        .completion_flow_row_id
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction completion_flow_row_id is required".to_string(),
            )
        })?;
    ensure_settlement_completion_flow_binding(completion_flow_row_id, governed_receipt_id)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if !instruction
        .body
        .support_boundary
        .automatic_dispatch_supported
    {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction must explicitly enable automatic dispatch".to_string(),
        ));
    }
    let destination = instruction
        .body
        .rail
        .destination_account_ref
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction destination_account_ref is required".to_string(),
            )
        })?;
    let destination_address =
        parse_address(destination, "capital instruction destination_account_ref")?;
    let beneficiary_address = parse_address(beneficiary_address, "beneficiary_address")?;
    if destination_address != beneficiary_address {
        return Err(SettlementError::InvalidDispatch(
            "beneficiary address must match capital instruction destination_account_ref"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_settlement_binding(
    config: &SettlementChainConfig,
    binding: &SignedWeb3IdentityBinding,
    purpose: Web3KeyBindingPurpose,
) -> Result<(), SettlementError> {
    verify_web3_identity_binding(binding)
        .map_err(|error| SettlementError::InvalidBinding(error.to_string()))?;
    if !binding.certificate.purpose.contains(&purpose) {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not include {:?} purpose",
            purpose
        )));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain| chain == &config.chain_id)
    {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not cover {}",
            config.chain_id
        )));
    }
    let binding_settlement_address = parse_address(
        &binding.certificate.settlement_address,
        "binding settlement address",
    )?;
    let config_operator_address =
        parse_address(&config.operator_address, "config.operator_address")?;
    if binding_settlement_address != config_operator_address {
        return Err(SettlementError::InvalidBinding(
            "binding settlement address does not match the configured operator".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn proof_components(
    anchor_proof: &AnchorInclusionProof,
) -> Result<(ChioMerkleProof, B256, B256), SettlementError> {
    let proof = ChioMerkleProof {
        audit_path: anchor_proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(anchor_proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(anchor_proof.receipt_inclusion.proof.tree_size as u64),
    };
    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    let evidence_hash = hash_to_b256(&leaf_hash(&receipt_bytes));
    let root = hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root);
    Ok((proof, root, evidence_hash))
}

pub(super) fn dual_sign_digest(
    config: &SettlementChainConfig,
    escrow_contract: &str,
    escrow_id: &B256,
    receipt_hash: &B256,
    amount_minor_units: u128,
    operator_epoch: u64,
) -> Result<B256, SettlementError> {
    let chain_id = parse_eip155_chain_id(&config.chain_id)?;
    let domain_separator = keccak256(
        (
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    .as_bytes(),
            ),
            keccak256("ChioEscrow".as_bytes()),
            keccak256("1".as_bytes()),
            U256::from(chain_id),
            parse_address(escrow_contract, "escrow_contract")?,
        )
            .abi_encode(),
    );
    let struct_hash = keccak256(
        (
            keccak256(
                "ChioEscrowRelease(bytes32 escrowId,bytes32 receiptHash,uint256 amount,uint64 operatorEpoch)"
                    .as_bytes(),
            ),
            *escrow_id,
            *receipt_hash,
            U256::from(amount_minor_units),
            U256::from(operator_epoch),
        )
            .abi_encode(),
    );
    let mut packed = Vec::with_capacity(66);
    packed.extend_from_slice(b"\x19\x01");
    packed.extend_from_slice(domain_separator.as_slice());
    packed.extend_from_slice(struct_hash.as_slice());
    Ok(keccak256(packed))
}

pub(super) fn sign_digest(
    private_key_hex: &str,
    digest: &B256,
) -> Result<EvmSignature, SettlementError> {
    let secp = Secp256k1::new();
    let secret = parse_secret_key(private_key_hex)?;
    let message = Message::from_digest(*digest.as_ref());
    let signature: RecoverableSignature = secp.sign_ecdsa_recoverable(message, &secret);
    let (recovery_id, bytes) = signature.serialize_compact();
    let v = 27 + i32::from(recovery_id) as u8;
    let r = format!("0x{}", hex::encode(&bytes[..32]));
    let s = format!("0x{}", hex::encode(&bytes[32..]));
    Ok(EvmSignature { v, r, s })
}

pub(super) fn signer_address_from_private_key(
    private_key_hex: &str,
) -> Result<Address, SettlementError> {
    let secp = Secp256k1::new();
    let secret = parse_secret_key(private_key_hex)?;
    let public = SecpPublicKey::from_secret_key(&secp, &secret);
    let encoded = public.serialize_uncompressed();
    let hash = keccak256(&encoded[1..]);
    Ok(Address::from_slice(&hash.as_slice()[12..]))
}

fn parse_secret_key(private_key_hex: &str) -> Result<SecretKey, SettlementError> {
    let raw = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|error| SettlementError::Signature(error.to_string()))?;
    SecretKey::from_byte_array(
        raw.try_into().map_err(|_| {
            SettlementError::Signature("expected a 32-byte private key".to_string())
        })?,
    )
    .map_err(|error| SettlementError::Signature(error.to_string()))
}
