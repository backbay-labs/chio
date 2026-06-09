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
        beneficiary_address: request.beneficiary_address.clone(),
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
    if dispatch.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "dispatch chain_id {} does not match config {}",
            dispatch.chain_id, config.chain_id
        )));
    }
    if dispatch.settlement_path != Web3SettlementPath::MerkleProof {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the Merkle settlement path".to_string(),
        ));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if let Some(chain_anchor) = anchor_proof.chain_anchor.as_ref() {
        if chain_anchor.chain_id != dispatch.chain_id {
            return Err(SettlementError::InvalidDispatch(
                "anchor proof chain does not match the settlement dispatch".to_string(),
            ));
        }
    }

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
    let leaf = leaf_hash(&receipt_bytes);
    let observed_amount = match amount {
        EscrowExecutionAmount::Full => dispatch.settlement_amount.clone(),
        EscrowExecutionAmount::Partial(amount) => amount,
    };
    let amount_minor_units = scale_chio_amount_to_token_minor_units(&observed_amount, config)?;
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let call = if observed_amount == dispatch.settlement_amount {
        IChioEscrow::releaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root),
            receiptHash: hash_to_b256(&leaf),
            settledAmount: U256::from(amount_minor_units),
        }
        .abi_encode()
    } else {
        IChioEscrow::partialReleaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root),
            receiptHash: hash_to_b256(&leaf),
            amount: U256::from(amount_minor_units),
        }
        .abi_encode()
    };

    Ok(PreparedMerkleRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_leaf_hash: leaf.to_hex_prefixed(),
        merkle_root: anchor_proof.receipt_inclusion.merkle_root.to_hex_prefixed(),
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
    let (proof, root, evidence_hash) = proof_components(anchor_proof)?;
    let call = IChioBondVault::releaseBondDetailedCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondRelease {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
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
    let (proof, root, evidence_hash) = proof_components(anchor_proof)?;
    let call = IChioBondVault::impairBondDetailedCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
        slashAmount: U256::from(slash_amount_minor_units),
        beneficiaries: beneficiaries
            .iter()
            .map(|value| parse_address(value, "beneficiary"))
            .collect::<Result<Vec<_>, _>>()?,
        shares: share_units,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondImpair {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        slash_amount_minor_units,
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
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
