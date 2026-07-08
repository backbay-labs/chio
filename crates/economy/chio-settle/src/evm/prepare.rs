//! EVM settlement call preparation and on-chain read/submit helpers.

use super::*;

pub fn scale_chio_amount_to_token_minor_units(
    amount: &MonetaryAmount,
    config: &SettlementChainConfig,
) -> Result<u128, SettlementError> {
    config.validate()?;
    let chio_decimals = u32::from(config.policy.chio_minor_unit_decimals);
    let token_decimals = u32::from(config.policy.token_minor_unit_decimals);
    let amount_units = u128::from(amount.units);
    if token_decimals >= chio_decimals {
        let scale = 10_u128
            .checked_pow(token_decimals - chio_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        amount_units
            .checked_mul(scale)
            .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))
    } else {
        let divisor = 10_u128
            .checked_pow(chio_decimals - token_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        if amount_units % divisor != 0 {
            return Err(SettlementError::InvalidInput(
                "Chio amount cannot be represented exactly in settlement token units".to_string(),
            ));
        }
        Ok(amount_units / divisor)
    }
}

const ESCROW_PROOF_LEAF_TYPE: &str = "ChioEscrowProof(uint256 chainId,address escrow,bytes32 escrowId,address token,address beneficiary,bytes32 operatorKeyHash,bytes32 receiptHash,uint256 amount,bool partial)";
const BOND_PROOF_LEAF_TYPE: &str = "ChioBondProof(uint256 chainId,address vault,bytes32 vaultId,bytes32 evidenceHash,uint8 action,uint256 slashAmount,bytes32 distributionHash)";
const BOND_ACTION_RELEASE: u8 = 0;
const BOND_ACTION_IMPAIR: u8 = 1;

pub(crate) fn scale_token_minor_units_to_chio_amount(
    units: u128,
    currency: &str,
    config: &SettlementChainConfig,
) -> Result<MonetaryAmount, SettlementError> {
    let chio_decimals = u32::from(config.policy.chio_minor_unit_decimals);
    let token_decimals = u32::from(config.policy.token_minor_unit_decimals);
    let chio_units = if token_decimals >= chio_decimals {
        let divisor = 10_u128
            .checked_pow(token_decimals - chio_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        if !units.is_multiple_of(divisor) {
            return Err(SettlementError::InvalidInput(
                "token amount cannot be represented exactly in Chio units".to_string(),
            ));
        }
        units / divisor
    } else {
        let scale = 10_u128
            .checked_pow(chio_decimals - token_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        units
            .checked_mul(scale)
            .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))?
    };
    let amount = u64::try_from(chio_units)
        .map_err(|_| SettlementError::InvalidInput("Chio amount does not fit u64".to_string()))?;
    Ok(MonetaryAmount {
        units: amount,
        currency: currency.to_string(),
    })
}

pub fn prepare_erc20_approval(
    token_address: &str,
    owner_address: &str,
    spender_address: &str,
    amount_minor_units: u128,
) -> Result<PreparedErc20Approval, SettlementError> {
    let spender = parse_address(spender_address, "spender_address")?;
    let amount = U256::from(amount_minor_units);
    let call = IERC20ApproveOnly::approveCall { spender, amount };
    Ok(PreparedErc20Approval {
        owner_address: owner_address.to_string(),
        token_address: token_address.to_string(),
        spender_address: spender_address.to_string(),
        amount_minor_units,
        call: PreparedEvmCall {
            from_address: owner_address.to_string(),
            to_address: token_address.to_string(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn prepare_web3_escrow_dispatch(
    config: &SettlementChainConfig,
    request: &EscrowDispatchRequest,
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedEscrowCreate, SettlementError> {
    config.validate()?;
    ensure_instruction_ready(
        config,
        &request.capital_instruction,
        &request.beneficiary_address,
    )?;
    ensure_settlement_binding(config, binding, Web3KeyBindingPurpose::Settle)?;

    if request.dispatch_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "dispatch_id is required".to_string(),
        ));
    }
    if request.capability_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "capability_id is required".to_string(),
        ));
    }

    let settlement_amount = request
        .capital_instruction
        .body
        .amount
        .clone()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch("capital instruction amount is required".to_string())
        })?;
    let amount_minor_units = scale_chio_amount_to_token_minor_units(&settlement_amount, config)?;
    // The operator key hash binds an Ed25519 key; reject other algorithms here
    // rather than letting PublicKey::as_bytes panic on a P256/P384/Hybrid key
    // that arrived via a deserialized (untrusted) identity binding.
    if !matches!(
        binding.certificate.chio_public_key.algorithm(),
        chio_core::crypto::SigningAlgorithm::Ed25519
    ) {
        return Err(SettlementError::InvalidBinding(format!(
            "settlement identity binding requires an Ed25519 chio_public_key, got {:?}",
            binding.certificate.chio_public_key.algorithm()
        )));
    }
    let operator_key_hash = keccak256(binding.certificate.chio_public_key.as_bytes());
    let terms = IChioEscrow::EscrowTerms {
        capabilityId: hash_string_id(&request.capability_id),
        depositor: parse_address(&request.depositor_address, "depositor_address")?,
        beneficiary: parse_address(&request.beneficiary_address, "beneficiary_address")?,
        token: parse_address(&config.settlement_token_address, "settlement_token_address")?,
        maxAmount: U256::from(amount_minor_units),
        deadline: U256::from(request.capital_instruction.body.execution_window.not_after),
        operator: parse_address(&config.operator_address, "operator_address")?,
        operatorKeyHash: operator_key_hash,
    };

    let derive_call = IChioEscrow::deriveEscrowIdCall {
        terms: terms.clone(),
    };
    let static_result = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: request.depositor_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(derive_call),
            gas_limit: None,
        },
    )
    .await?;
    let result_bytes = decode_hex_bytes(&static_result)?;
    let expected_escrow_id = IChioEscrow::deriveEscrowIdCall::abi_decode_returns(&result_bytes)
        .map_err(|error| {
            SettlementError::Serialization(format!("deriveEscrowId decode failed: {error}"))
        })?;
    let expected_escrow_id = format_b256(expected_escrow_id);
    let create_call_data = encode_call(IChioEscrow::createEscrowCall { terms });

    let dispatch = Web3SettlementDispatchArtifact {
        schema: CHIO_WEB3_SETTLEMENT_DISPATCH_SCHEMA.to_string(),
        dispatch_id: request.dispatch_id.clone(),
        issued_at: request.issued_at,
        trust_profile_id: request.trust_profile_id.clone(),
        contract_package_id: request.contract_package_id.clone(),
        chain_id: config.chain_id.clone(),
        capital_instruction: request.capital_instruction.clone(),
        bond: None,
        settlement_path: request.settlement_path,
        settlement_amount: settlement_amount.clone(),
        escrow_id: expected_escrow_id.clone(),
        escrow_contract: config.escrow_contract.clone(),
        bond_vault_contract: config.bond_vault_contract.clone(),
        settlement_token_address: config.settlement_token_address.clone(),
        beneficiary_address: request.beneficiary_address.clone(),
        operator_key_hash: format_b256(operator_key_hash),
        support_boundary: Web3SettlementSupportBoundary {
            real_dispatch_supported: true,
            anchor_proof_required: request.settlement_path == Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: request.oracle_evidence_required_for_fx,
            custody_boundary_explicit: true,
            reversal_supported: true,
        },
        note: request.note.clone(),
    };
    validate_web3_settlement_dispatch(&dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;

    Ok(PreparedEscrowCreate {
        expected_escrow_id,
        capability_commitment: format_b256(hash_string_id(&request.capability_id)),
        settlement_amount_minor_units: amount_minor_units,
        dispatch,
        call: PreparedEvmCall {
            from_address: request.depositor_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: create_call_data,
            gas_limit: None,
        },
    })
}

pub fn prepare_merkle_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    anchor_proof: &AnchorInclusionProof,
    amount: EscrowExecutionAmount,
) -> Result<PreparedMerkleRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    validate_merkle_dispatch_config(config, dispatch)?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if let Some(chain_anchor) = anchor_proof.chain_anchor.as_ref() {
        if chain_anchor.chain_id != dispatch.chain_id {
            return Err(SettlementError::InvalidDispatch(
                "anchor proof chain does not match the settlement dispatch".to_string(),
            ));
        }
    }

    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    let leaf = leaf_hash(&receipt_bytes);
    let receipt_hash = keccak256(&receipt_bytes);
    let observed_amount = match amount {
        EscrowExecutionAmount::Full => dispatch.settlement_amount.clone(),
        EscrowExecutionAmount::Partial(amount) => amount,
    };
    let amount_minor_units = scale_chio_amount_to_token_minor_units(&observed_amount, config)?;
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let typed_root = escrow_proof_leaf(
        dispatch,
        escrow_id,
        receipt_hash,
        amount_minor_units,
        observed_amount != dispatch.settlement_amount,
    )?;
    let proof = ChioMerkleProof {
        audit_path: Vec::new(),
        leaf_index: U256::from(0_u8),
        tree_size: U256::from(1_u8),
    };
    let call = if observed_amount == dispatch.settlement_amount {
        IChioEscrow::releaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: typed_root,
            receiptHash: receipt_hash,
            settledAmount: U256::from(amount_minor_units),
        }
        .abi_encode()
    } else {
        IChioEscrow::partialReleaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: typed_root,
            receiptHash: receipt_hash,
            amount: U256::from(amount_minor_units),
        }
        .abi_encode()
    };

    Ok(PreparedMerkleRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_hash: format_b256(receipt_hash),
        receipt_leaf_hash: leaf.to_hex_prefixed(),
        merkle_root: format_b256(typed_root),
        partial: observed_amount != dispatch.settlement_amount,
        settlement_amount_minor_units: amount_minor_units,
        observed_amount,
        call: PreparedEvmCall {
            from_address: dispatch.beneficiary_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: format!("0x{}", hex::encode(call)),
            gas_limit: None,
        },
    })
}

fn validate_merkle_dispatch_config(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
) -> Result<(), SettlementError> {
    if dispatch.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "dispatch chain_id {} does not match config {}",
            dispatch.chain_id, config.chain_id
        )));
    }
    let dispatch_escrow = parse_address(&dispatch.escrow_contract, "dispatch.escrow_contract")?;
    let config_escrow = parse_address(&config.escrow_contract, "config.escrow_contract")?;
    if dispatch_escrow != config_escrow {
        return Err(SettlementError::InvalidDispatch(
            "dispatch escrow_contract does not match config escrow_contract".to_string(),
        ));
    }
    let dispatch_token = parse_address(
        &dispatch.settlement_token_address,
        "dispatch.settlement_token_address",
    )?;
    let config_token = parse_address(
        &config.settlement_token_address,
        "config.settlement_token_address",
    )?;
    if dispatch_token != config_token {
        return Err(SettlementError::InvalidDispatch(
            "dispatch settlement_token_address does not match config settlement_token_address"
                .to_string(),
        ));
    }
    if dispatch.settlement_path != Web3SettlementPath::MerkleProof {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the Merkle settlement path".to_string(),
        ));
    }
    Ok(())
}

pub fn prepare_merkle_release_root_publication(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    release: &PreparedMerkleRelease,
    checkpoint_seq: u64,
    batch_seq: u64,
) -> Result<PreparedEvmCall, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    validate_merkle_dispatch_config(config, dispatch)?;
    if checkpoint_seq == 0 || batch_seq == 0 {
        return Err(SettlementError::InvalidInput(
            "settlement root publication sequence values must be non-zero".to_string(),
        ));
    }
    if release.chain_id != dispatch.chain_id || release.escrow_id != dispatch.escrow_id {
        return Err(SettlementError::InvalidDispatch(
            "settlement root publication release does not match dispatch".to_string(),
        ));
    }
    let call = IChioRootRegistry::publishRootCall {
        operator: parse_address(&config.operator_address, "operator_address")?,
        merkleRoot: parse_b256_hex(&release.merkle_root, "release.merkle_root")?,
        checkpointSeq: checkpoint_seq,
        batchStartSeq: batch_seq,
        batchEndSeq: batch_seq,
        treeSize: 1,
        operatorKeyHash: parse_b256_hex(&dispatch.operator_key_hash, "dispatch.operator_key_hash")?,
    };
    Ok(PreparedEvmCall {
        from_address: config.operator_address.clone(),
        to_address: config.root_registry_contract.clone(),
        data: encode_call(call),
        gas_limit: None,
    })
}

fn escrow_proof_leaf(
    dispatch: &Web3SettlementDispatchArtifact,
    escrow_id: B256,
    receipt_hash: B256,
    amount_minor_units: u128,
    partial: bool,
) -> Result<B256, SettlementError> {
    let chain_id = parse_eip155_chain_id(&dispatch.chain_id)?;
    let encoded = (
        keccak256(ESCROW_PROOF_LEAF_TYPE.as_bytes()),
        U256::from(chain_id),
        parse_address(&dispatch.escrow_contract, "dispatch.escrow_contract")?,
        escrow_id,
        parse_address(
            &dispatch.settlement_token_address,
            "dispatch.settlement_token_address",
        )?,
        parse_address(
            &dispatch.beneficiary_address,
            "dispatch.beneficiary_address",
        )?,
        parse_b256_hex(&dispatch.operator_key_hash, "dispatch.operator_key_hash")?,
        receipt_hash,
        U256::from(amount_minor_units),
        partial,
    )
        .abi_encode();
    Ok(keccak256(encoded))
}

fn ensure_single_leaf_bond_proof(
    anchor_proof: &AnchorInclusionProof,
) -> Result<(), SettlementError> {
    if anchor_proof.receipt_inclusion.proof.tree_size != 1
        || !anchor_proof.receipt_inclusion.proof.audit_path.is_empty()
    {
        return Err(SettlementError::Unsupported(
            "multi-leaf bond proof preparation requires typed bond inclusion data".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn bond_proof_leaf(
    config: &SettlementChainConfig,
    vault_id: B256,
    evidence_hash: B256,
    action: u8,
    slash_amount_minor_units: u128,
    distribution_hash: B256,
) -> Result<B256, SettlementError> {
    let chain_id = parse_eip155_chain_id(&config.chain_id)?;
    let encoded = (
        keccak256(BOND_PROOF_LEAF_TYPE.as_bytes()),
        U256::from(chain_id),
        parse_address(&config.bond_vault_contract, "bond_vault_contract")?,
        vault_id,
        evidence_hash,
        U256::from(action),
        U256::from(slash_amount_minor_units),
        distribution_hash,
    )
        .abi_encode();
    Ok(keccak256(encoded))
}

pub(super) fn bond_distribution_hash(beneficiaries: &[Address], shares: &[U256]) -> B256 {
    let beneficiaries_tail_len = 32 + beneficiaries.len() * 32;
    let shares_offset = 64 + beneficiaries_tail_len;
    let mut encoded = Vec::with_capacity(shares_offset + 32 + shares.len() * 32);
    push_abi_u256(&mut encoded, U256::from(64_u64));
    push_abi_u256(&mut encoded, U256::from(shares_offset as u64));
    push_abi_u256(&mut encoded, U256::from(beneficiaries.len() as u64));
    for beneficiary in beneficiaries {
        encoded.extend_from_slice(&[0_u8; 12]);
        encoded.extend_from_slice(beneficiary.as_slice());
    }
    push_abi_u256(&mut encoded, U256::from(shares.len() as u64));
    for share in shares {
        push_abi_u256(&mut encoded, *share);
    }
    keccak256(encoded)
}

fn push_abi_u256(encoded: &mut Vec<u8>, value: U256) {
    encoded.extend_from_slice(&value.to_be_bytes::<32>());
}

pub fn prepare_dual_sign_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    receipt: &ChioReceipt,
    input: &DualSignReleaseInput,
) -> Result<PreparedDualSignRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if dispatch.settlement_path != Web3SettlementPath::DualSignature {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the dual-signature path".to_string(),
        ));
    }
    let verified = receipt
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "receipt signature verification failed".to_string(),
        ));
    }
    if input.observed_amount != dispatch.settlement_amount {
        return Err(SettlementError::Unsupported(
            "dual-signature release is bounded to full settlement on the official stack"
                .to_string(),
        ));
    }
    let amount_minor_units =
        scale_chio_amount_to_token_minor_units(&input.observed_amount, config)?;
    let receipt_hash = keccak256(
        canonical_json_bytes(&receipt.body())
            .map_err(|error| SettlementError::Serialization(error.to_string()))?,
    );
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let digest = dual_sign_digest(
        config,
        &config.escrow_contract,
        &escrow_id,
        &receipt_hash,
        amount_minor_units,
    )?;
    let signature = sign_digest(&input.operator_private_key_hex, &digest)?;

    let call = IChioEscrow::releaseWithSignatureCall {
        escrowId: escrow_id,
        receiptHash: receipt_hash,
        settledAmount: U256::from(amount_minor_units),
        v: signature.v,
        r: parse_b256_hex(&signature.r, "signature.r")?,
        s: parse_b256_hex(&signature.s, "signature.s")?,
    };

    Ok(PreparedDualSignRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_hash: format_b256(receipt_hash),
        digest: format_b256(digest),
        settlement_amount_minor_units: amount_minor_units,
        observed_amount: input.observed_amount.clone(),
        signature,
        call: PreparedEvmCall {
            from_address: dispatch.beneficiary_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_escrow_refund(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    caller_address: &str,
) -> Result<PreparedEscrowRefund, SettlementError> {
    config.validate()?;
    let call = IChioEscrow::refundCall {
        escrowId: parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?,
    };
    Ok(PreparedEscrowRefund {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: config.chain_id.clone(),
        call: PreparedEvmCall {
            from_address: caller_address.to_string(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn prepare_bond_lock(
    config: &SettlementChainConfig,
    request: &BondLockRequest,
) -> Result<PreparedBondLock, SettlementError> {
    config.validate()?;
    let verified = request
        .bond
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "credit bond signature verification failed".to_string(),
        ));
    }
    if request.bond.body.lifecycle_state != CreditBondLifecycleState::Active {
        return Err(SettlementError::InvalidDispatch(
            "bond lifecycle must be active before on-chain lock".to_string(),
        ));
    }
    let terms = request.bond.body.report.terms.clone().ok_or_else(|| {
        SettlementError::InvalidDispatch("credit bond terms are required".to_string())
    })?;
    let collateral_minor_units =
        scale_chio_amount_to_token_minor_units(&terms.collateral_amount, config)?;
    let reserve_requirement_minor_units =
        scale_chio_amount_to_token_minor_units(&terms.reserve_requirement_amount, config)?;
    let bond_terms = IChioBondVault::BondTerms {
        bondId: hash_string_id(&request.bond.body.bond_id),
        facilityId: hash_string_id(&terms.facility_id),
        principal: parse_address(&request.principal_address, "principal_address")?,
        token: parse_address(&config.settlement_token_address, "settlement_token_address")?,
        collateralAmount: U256::from(collateral_minor_units),
        reserveRequirementAmount: U256::from(reserve_requirement_minor_units),
        expiresAt: U256::from(request.bond.body.expires_at),
        reserveRequirementRatioBps: terms.reserve_ratio_bps,
        operator: parse_address(&config.operator_address, "operator_address")?,
    };
    let derive_call = IChioBondVault::deriveVaultIdCall {
        terms: bond_terms.clone(),
    };
    let static_result = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: request.principal_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(derive_call),
            gas_limit: None,
        },
    )
    .await?;
    let result_bytes = decode_hex_bytes(&static_result)?;
    let vault_id =
        IChioBondVault::deriveVaultIdCall::abi_decode_returns(&result_bytes).map_err(|error| {
            SettlementError::Serialization(format!("deriveVaultId decode failed: {error}"))
        })?;
    let call_data = encode_call(IChioBondVault::lockBondCall { terms: bond_terms });

    Ok(PreparedBondLock {
        vault_id: format_b256(vault_id),
        bond_id_hash: format_b256(hash_string_id(&request.bond.body.bond_id)),
        facility_id_hash: format_b256(hash_string_id(&terms.facility_id)),
        collateral_minor_units,
        reserve_requirement_minor_units,
        call: PreparedEvmCall {
            from_address: request.principal_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: call_data,
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_release(
    config: &SettlementChainConfig,
    vault_id: &str,
    operator_address: &str,
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondRelease, SettlementError> {
    config.validate()?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    ensure_single_leaf_bond_proof(anchor_proof)?;
    let (proof, _anchor_root, evidence_hash) = proof_components(anchor_proof)?;
    let vault_id = parse_b256_hex(vault_id, "vault_id")?;
    let root = bond_proof_leaf(
        config,
        vault_id,
        evidence_hash,
        BOND_ACTION_RELEASE,
        0,
        B256::ZERO,
    )?;
    let call = IChioBondVault::releaseBondDetailedCall {
        vaultId: vault_id,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondRelease {
        vault_id: format_b256(vault_id),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        merkle_root: format_b256(root),
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_impair(
    config: &SettlementChainConfig,
    vault_id: &str,
    operator_address: &str,
    slash_amount: &MonetaryAmount,
    beneficiaries: &[String],
    shares: &[MonetaryAmount],
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondImpair, SettlementError> {
    config.validate()?;
    if beneficiaries.is_empty() || beneficiaries.len() != shares.len() {
        return Err(SettlementError::InvalidInput(
            "beneficiaries and shares must be non-empty and aligned".to_string(),
        ));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    ensure_single_leaf_bond_proof(anchor_proof)?;
    let slash_amount_minor_units = scale_chio_amount_to_token_minor_units(slash_amount, config)?;
    let mut share_units = Vec::with_capacity(shares.len());
    let mut total = 0_u128;
    for share in shares {
        let scaled = scale_chio_amount_to_token_minor_units(share, config)?;
        total = total
            .checked_add(scaled)
            .ok_or_else(|| SettlementError::InvalidInput("slash shares overflowed".to_string()))?;
        share_units.push(U256::from(scaled));
    }
    if total != slash_amount_minor_units {
        return Err(SettlementError::InvalidInput(
            "slash shares must sum to slash_amount".to_string(),
        ));
    }
    let beneficiary_addresses = beneficiaries
        .iter()
        .map(|value| parse_address(value, "beneficiary"))
        .collect::<Result<Vec<_>, _>>()?;
    let (proof, _anchor_root, evidence_hash) = proof_components(anchor_proof)?;
    let vault_id = parse_b256_hex(vault_id, "vault_id")?;
    let distribution_hash = bond_distribution_hash(&beneficiary_addresses, &share_units);
    let root = bond_proof_leaf(
        config,
        vault_id,
        evidence_hash,
        BOND_ACTION_IMPAIR,
        slash_amount_minor_units,
        distribution_hash,
    )?;
    let call = IChioBondVault::impairBondDetailedCall {
        vaultId: vault_id,
        slashAmount: U256::from(slash_amount_minor_units),
        beneficiaries: beneficiary_addresses,
        shares: share_units,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondImpair {
        vault_id: format_b256(vault_id),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        merkle_root: format_b256(root),
        slash_amount_minor_units,
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_proof_root_publication(
    config: &SettlementChainConfig,
    root: &str,
    operator_key_hash: &str,
    checkpoint_seq: u64,
    batch_seq: u64,
) -> Result<PreparedEvmCall, SettlementError> {
    config.validate()?;
    if checkpoint_seq == 0 || batch_seq == 0 {
        return Err(SettlementError::InvalidInput(
            "bond root publication sequence values must be non-zero".to_string(),
        ));
    }
    let call = IChioRootRegistry::publishRootCall {
        operator: parse_address(&config.operator_address, "operator_address")?,
        merkleRoot: parse_b256_hex(root, "root")?,
        checkpointSeq: checkpoint_seq,
        batchStartSeq: batch_seq,
        batchEndSeq: batch_seq,
        treeSize: 1,
        operatorKeyHash: parse_b256_hex(operator_key_hash, "operator_key_hash")?,
    };
    Ok(PreparedEvmCall {
        from_address: config.operator_address.clone(),
        to_address: config.root_registry_contract.clone(),
        data: encode_call(call),
        gas_limit: None,
    })
}

pub fn prepare_bond_expiry(
    config: &SettlementChainConfig,
    vault_id: &str,
    caller_address: &str,
) -> Result<PreparedBondExpiry, SettlementError> {
    config.validate()?;
    let call = IChioBondVault::expireReleaseCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    Ok(PreparedBondExpiry {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        call: PreparedEvmCall {
            from_address: caller_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn static_validate_call(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    eth_call_raw(config, call).await
}

pub async fn estimate_call_gas(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<u64, SettlementError> {
    let result = rpc_call(config, "eth_estimateGas", json!([request_value(call)])).await?;
    parse_hex_u64(
        result.as_str().ok_or_else(|| {
            SettlementError::Rpc("eth_estimateGas returned non-string".to_string())
        })?,
    )
}

pub async fn submit_call(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    let mut request = request_value(call);
    let gas_limit = match call.gas_limit {
        Some(gas_limit) => gas_limit,
        None => estimate_call_gas(config, call)
            .await?
            .saturating_mul(12)
            .saturating_div(10)
            .saturating_add(50_000),
    };
    request["gas"] = Value::String(format!("0x{gas_limit:x}"));
    let result = rpc_call(config, "eth_sendTransaction", json!([request])).await?;
    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| SettlementError::Rpc("eth_sendTransaction returned non-string".to_string()))
}

pub async fn confirm_transaction(
    config: &SettlementChainConfig,
    tx_hash: &str,
) -> Result<EvmTransactionReceipt, SettlementError> {
    for _ in 0..100 {
        let result = rpc_call(config, "eth_getTransactionReceipt", json!([tx_hash])).await?;
        if result.is_null() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        let block_hash = result
            .get("blockHash")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing blockHash".to_string()))?
            .to_string();
        let block_number = parse_hex_u64(
            result
                .get("blockNumber")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("receipt missing blockNumber".to_string()))?,
        )?;
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .map(|value| value == "0x1")
            .unwrap_or(false);
        let gas_used = parse_hex_u64(
            result
                .get("gasUsed")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("receipt missing gasUsed".to_string()))?,
        )?;
        let from_address = result
            .get("from")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing from".to_string()))?
            .to_string();
        let to_address = result
            .get("to")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing to".to_string()))?
            .to_string();
        let logs = result
            .get("logs")
            .and_then(Value::as_array)
            .ok_or_else(|| SettlementError::Rpc("receipt missing logs".to_string()))?
            .iter()
            .map(parse_log_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let block = rpc_call(config, "eth_getBlockByHash", json!([block_hash, false])).await?;
        let observed_at = parse_hex_u64(
            block
                .get("timestamp")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("block missing timestamp".to_string()))?,
        )?;
        return Ok(EvmTransactionReceipt {
            tx_hash: tx_hash.to_string(),
            block_number,
            block_hash,
            status,
            from_address,
            to_address,
            gas_used,
            observed_at,
            logs,
        });
    }
    Err(SettlementError::Rpc(format!(
        "timed out waiting for transaction receipt {tx_hash}"
    )))
}

pub async fn read_escrow_snapshot(
    config: &SettlementChainConfig,
    escrow_id: &str,
) -> Result<EscrowSnapshot, SettlementError> {
    let call = IChioEscrow::getEscrowCall {
        escrowId: parse_b256_hex(escrow_id, "escrow_id")?,
    };
    let raw = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IChioEscrow::getEscrowCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getEscrow decode failed: {error}"))
    })?;
    let deposited_minor_units = u256_to_u128(decoded.deposited, "escrow.deposited")?;
    let released_minor_units = u256_to_u128(decoded.released, "escrow.released")?;
    Ok(EscrowSnapshot {
        escrow_id: escrow_id.to_string(),
        depositor_address: format!("{:?}", decoded.terms.depositor),
        beneficiary_address: format!("{:?}", decoded.terms.beneficiary),
        deadline: decoded.terms.deadline.to::<u64>(),
        deposited_minor_units,
        released_minor_units,
        refunded: decoded.refunded,
        remaining_minor_units: deposited_minor_units.saturating_sub(released_minor_units),
    })
}

pub async fn read_bond_snapshot(
    config: &SettlementChainConfig,
    vault_id: &str,
) -> Result<EvmBondSnapshot, SettlementError> {
    let call = IChioBondVault::getBondCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    let raw = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IChioBondVault::getBondCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getBond decode failed: {error}"))
    })?;
    Ok(EvmBondSnapshot {
        vault_id: vault_id.to_string(),
        principal_address: format!("{:?}", decoded.terms.principal),
        expires_at: decoded.terms.expiresAt.to::<u64>(),
        locked_minor_units: u256_to_u128(decoded.lockedAmount, "bond.lockedAmount")?,
        reserve_requirement_minor_units: u256_to_u128(
            decoded.terms.reserveRequirementAmount,
            "bond.terms.reserveRequirementAmount",
        )?,
        reserve_requirement_ratio_bps: decoded.terms.reserveRequirementRatioBps,
        slashed_minor_units: u256_to_u128(decoded.slashedAmount, "bond.slashedAmount")?,
        released: decoded.released,
        expired: decoded.expired,
    })
}
