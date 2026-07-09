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
const BOND_PROOF_LEAF_TYPE: &str = "ChioBondProof(uint256 chainId,address vault,bytes32 vaultId,bytes32 operatorKeyHash,bytes32 evidenceHash,uint8 action,uint256 slashAmount,bytes32 distributionHash)";
const BOND_ACTION_RELEASE: u8 = 0;
const BOND_ACTION_IMPAIR: u8 = 1;
const MAX_IMPAIR_BENEFICIARIES: usize = 16;

#[derive(Debug, Clone, Copy)]
pub enum PreparedBondProofRoot<'a> {
    Release(&'a PreparedBondRelease),
    Impair(&'a PreparedBondImpair),
}

impl PreparedBondProofRoot<'_> {
    fn chain_id(self) -> String {
        match self {
            Self::Release(prepared) => prepared.chain_id.clone(),
            Self::Impair(prepared) => prepared.chain_id.clone(),
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementAnchorContentBinding {
    pub execution_receipt_id: String,
    pub settlement_reference: String,
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
    let operator_key_hash = settlement_operator_key_hash(binding)?;
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

fn settlement_operator_key_hash(
    binding: &SignedWeb3IdentityBinding,
) -> Result<B256, SettlementError> {
    if !matches!(
        binding.certificate.chio_public_key.algorithm(),
        chio_core::crypto::SigningAlgorithm::Ed25519
    ) {
        return Err(SettlementError::InvalidBinding(format!(
            "settlement identity binding requires an Ed25519 chio_public_key, got {:?}",
            binding.certificate.chio_public_key.algorithm()
        )));
    }
    Ok(keccak256(binding.certificate.chio_public_key.as_bytes()))
}

pub fn prepare_merkle_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    anchor_proof: &AnchorInclusionProof,
    anchor_content: &SettlementAnchorContentBinding,
    amount: EscrowExecutionAmount,
) -> Result<PreparedMerkleRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    validate_merkle_dispatch_config(config, dispatch)?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    ensure_escrow_anchor_matches_config(config, dispatch, anchor_proof, anchor_content)?;

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

fn ensure_escrow_anchor_matches_config(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    anchor_proof: &AnchorInclusionProof,
    anchor_content: &SettlementAnchorContentBinding,
) -> Result<(), SettlementError> {
    ensure_anchor_receipt_binds_dispatch(dispatch, anchor_proof, anchor_content)?;
    let chain_anchor = anchor_proof.chain_anchor.as_ref().ok_or_else(|| {
        SettlementError::InvalidDispatch(
            "escrow release anchor proof requires an on-chain chain_anchor".to_string(),
        )
    })?;
    if chain_anchor.chain_id != config.chain_id || chain_anchor.chain_id != dispatch.chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "escrow release chain_anchor.chain_id {} does not match config {} and dispatch {}",
            chain_anchor.chain_id, config.chain_id, dispatch.chain_id
        )));
    }
    let anchor_registry = parse_address(
        &chain_anchor.contract_address,
        "anchor_proof.chain_anchor.contract_address",
    )?;
    let config_registry = parse_address(
        &config.root_registry_contract,
        "config.root_registry_contract",
    )?;
    if anchor_registry != config_registry {
        return Err(SettlementError::InvalidDispatch(
            "escrow release chain_anchor.contract_address does not match config root_registry_contract"
                .to_string(),
        ));
    }
    let anchor_operator = parse_address(
        &chain_anchor.operator_address,
        "anchor_proof.chain_anchor.operator_address",
    )?;
    let config_operator = parse_address(&config.operator_address, "config.operator_address")?;
    if anchor_operator != config_operator {
        return Err(SettlementError::InvalidDispatch(
            "escrow release operator address does not match config operator_address".to_string(),
        ));
    }
    let operator_key_hash = parse_b256_hex(
        &chain_anchor.operator_key_hash,
        "anchor_proof.chain_anchor.operator_key_hash",
    )?;
    if operator_key_hash == B256::ZERO {
        return Err(SettlementError::InvalidDispatch(
            "escrow release operator key hash must not be zero".to_string(),
        ));
    }
    let dispatch_operator_key_hash =
        parse_b256_hex(&dispatch.operator_key_hash, "dispatch.operator_key_hash")?;
    if operator_key_hash != dispatch_operator_key_hash {
        return Err(SettlementError::InvalidDispatch(
            "escrow release operator_key_hash does not match dispatch operator_key_hash"
                .to_string(),
        ));
    }
    Ok(())
}

fn ensure_anchor_receipt_binds_dispatch(
    dispatch: &Web3SettlementDispatchArtifact,
    anchor_proof: &AnchorInclusionProof,
    anchor_content: &SettlementAnchorContentBinding,
) -> Result<(), SettlementError> {
    let governed_receipt_id = dispatch
        .capital_instruction
        .body
        .governed_receipt_id
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "dispatch capital_instruction governed_receipt_id is required".to_string(),
            )
        })?;
    let receipt_nonce = anchor_proof
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.get(chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY)
        })
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "anchor proof receipt must carry signing nonce".to_string(),
            )
        })?;
    if receipt_nonce != governed_receipt_id {
        return Err(SettlementError::InvalidDispatch(
            "anchor proof receipt must match dispatch governed_receipt_id".to_string(),
        ));
    }
    let expected_content_hash = settlement_anchor_receipt_content_hash_parts(
        &anchor_content.execution_receipt_id,
        &anchor_content.settlement_reference,
        &dispatch.dispatch_id,
        governed_receipt_id,
    )
    .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if anchor_proof.receipt.content_hash != expected_content_hash {
        return Err(SettlementError::InvalidDispatch(
            "anchor proof receipt content hash must bind settlement execution".to_string(),
        ));
    }
    Ok(())
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

fn validate_merkle_release_matches_dispatch(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    release: &PreparedMerkleRelease,
) -> Result<B256, SettlementError> {
    if release.chain_id != dispatch.chain_id || release.escrow_id != dispatch.escrow_id {
        return Err(SettlementError::InvalidDispatch(
            "settlement root publication release does not match dispatch".to_string(),
        ));
    }
    let scaled_amount = scale_chio_amount_to_token_minor_units(&release.observed_amount, config)?;
    if scaled_amount != release.settlement_amount_minor_units {
        return Err(SettlementError::InvalidDispatch(
            "release settlement_amount_minor_units does not match observed_amount".to_string(),
        ));
    }
    let partial = release.observed_amount != dispatch.settlement_amount;
    if release.partial != partial {
        return Err(SettlementError::InvalidDispatch(
            "release partial flag does not match observed_amount".to_string(),
        ));
    }

    let escrow_id = parse_b256_hex(&release.escrow_id, "release.escrow_id")?;
    let receipt_hash = parse_b256_hex(&release.receipt_hash, "release.receipt_hash")?;
    parse_b256_hex(&release.receipt_leaf_hash, "release.receipt_leaf_hash")?;
    let expected_root = escrow_proof_leaf(
        dispatch,
        escrow_id,
        receipt_hash,
        release.settlement_amount_minor_units,
        release.partial,
    )?;
    if parse_b256_hex(&release.merkle_root, "release.merkle_root")? != expected_root {
        return Err(SettlementError::InvalidDispatch(
            "release merkle_root does not match dispatch commitment".to_string(),
        ));
    }

    if parse_address(&release.call.from_address, "release.call.from_address")?
        != parse_address(
            &dispatch.beneficiary_address,
            "dispatch.beneficiary_address",
        )?
    {
        return Err(SettlementError::InvalidDispatch(
            "release call from_address does not match dispatch beneficiary".to_string(),
        ));
    }
    if parse_address(&release.call.to_address, "release.call.to_address")?
        != parse_address(&config.escrow_contract, "config.escrow_contract")?
    {
        return Err(SettlementError::InvalidDispatch(
            "release call to_address does not match config escrow_contract".to_string(),
        ));
    }

    let call_data = decode_hex_bytes(&release.call.data)?;
    if release.partial {
        let call = IChioEscrow::partialReleaseWithProofDetailedCall::abi_decode(&call_data)
            .map_err(|error| {
                SettlementError::InvalidDispatch(format!(
                    "partial release call data does not decode: {error}"
                ))
            })?;
        if call.escrowId != escrow_id
            || call.root != expected_root
            || call.receiptHash != receipt_hash
            || call.amount != U256::from(release.settlement_amount_minor_units)
            || call.proof.treeSize != U256::from(1_u8)
            || call.proof.leafIndex != U256::from(0_u8)
            || !call.proof.auditPath.is_empty()
        {
            return Err(SettlementError::InvalidDispatch(
                "partial release call data does not match release commitment".to_string(),
            ));
        }
    } else {
        let call =
            IChioEscrow::releaseWithProofDetailedCall::abi_decode(&call_data).map_err(|error| {
                SettlementError::InvalidDispatch(format!(
                    "release call data does not decode: {error}"
                ))
            })?;
        if call.escrowId != escrow_id
            || call.root != expected_root
            || call.receiptHash != receipt_hash
            || call.settledAmount != U256::from(release.settlement_amount_minor_units)
            || call.proof.treeSize != U256::from(1_u8)
            || call.proof.leafIndex != U256::from(0_u8)
            || !call.proof.auditPath.is_empty()
        {
            return Err(SettlementError::InvalidDispatch(
                "release call data does not match release commitment".to_string(),
            ));
        }
    }

    Ok(expected_root)
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
    let merkle_root = validate_merkle_release_matches_dispatch(config, dispatch, release)?;
    let call = IChioRootRegistry::publishRootCall {
        operator: parse_address(&config.operator_address, "operator_address")?,
        merkleRoot: merkle_root,
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

fn singleton_typed_proof() -> ChioMerkleProof {
    ChioMerkleProof {
        audit_path: Vec::new(),
        leaf_index: U256::from(0_u8),
        tree_size: U256::from(1_u8),
    }
}

fn ensure_bond_anchor_matches_config(
    config: &SettlementChainConfig,
    operator_address: &str,
    bond_snapshot: &EvmBondSnapshot,
    anchor_proof: &AnchorInclusionProof,
) -> Result<B256, SettlementError> {
    let chain_anchor = anchor_proof.chain_anchor.as_ref().ok_or_else(|| {
        SettlementError::InvalidDispatch(
            "bond evidence anchor proof requires an on-chain chain_anchor".to_string(),
        )
    })?;
    if chain_anchor.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond evidence chain_anchor.chain_id {} does not match config {}",
            chain_anchor.chain_id, config.chain_id
        )));
    }
    let anchor_registry = parse_address(
        &chain_anchor.contract_address,
        "anchor_proof.chain_anchor.contract_address",
    )?;
    let config_registry = parse_address(
        &config.root_registry_contract,
        "config.root_registry_contract",
    )?;
    if anchor_registry != config_registry {
        return Err(SettlementError::InvalidDispatch(
            "bond evidence chain_anchor.contract_address does not match config root_registry_contract"
                .to_string(),
        ));
    }
    let anchor_operator = parse_address(
        &chain_anchor.operator_address,
        "anchor_proof.chain_anchor.operator_address",
    )?;
    let config_operator = parse_address(&config.operator_address, "config.operator_address")?;
    let caller_operator = parse_address(operator_address, "operator_address")?;
    if anchor_operator != config_operator || caller_operator != config_operator {
        return Err(SettlementError::InvalidDispatch(
            "bond evidence operator address does not match config operator_address".to_string(),
        ));
    }
    let operator_key_hash = parse_b256_hex(
        &chain_anchor.operator_key_hash,
        "anchor_proof.chain_anchor.operator_key_hash",
    )?;
    if operator_key_hash == B256::ZERO {
        return Err(SettlementError::InvalidDispatch(
            "bond evidence operator key hash must not be zero".to_string(),
        ));
    }
    let expected_operator_key_hash = parse_b256_hex(
        &bond_snapshot.operator_key_hash,
        "bond_snapshot.operator_key_hash",
    )?;
    if operator_key_hash != expected_operator_key_hash {
        return Err(SettlementError::InvalidDispatch(
            "bond evidence operator_key_hash does not match bond operator_key_hash".to_string(),
        ));
    }
    Ok(operator_key_hash)
}

fn ensure_bond_snapshot_live(
    bond_snapshot: &EvmBondSnapshot,
    action: &'static str,
) -> Result<(), SettlementError> {
    if bond_snapshot.released || bond_snapshot.expired {
        return Err(SettlementError::InvalidInput(format!(
            "bond snapshot is already closed for {action}"
        )));
    }
    if bond_snapshot.observed_at == 0 {
        return Err(SettlementError::InvalidInput(format!(
            "bond snapshot has no observed_at timestamp for {action}"
        )));
    }
    if bond_snapshot.observed_at > bond_snapshot.expires_at {
        return Err(SettlementError::InvalidInput(format!(
            "bond snapshot is past expires_at for {action}"
        )));
    }
    if bond_snapshot.locked_minor_units == 0 {
        return Err(SettlementError::InvalidInput(format!(
            "bond snapshot has no locked collateral for {action}"
        )));
    }
    if bond_snapshot.slashed_minor_units > bond_snapshot.locked_minor_units {
        return Err(SettlementError::InvalidInput(format!(
            "bond snapshot slashed amount exceeds locked collateral for {action}"
        )));
    }
    Ok(())
}

fn validate_bond_release_matches_call(
    config: &SettlementChainConfig,
    release: &PreparedBondRelease,
) -> Result<(B256, B256), SettlementError> {
    if release.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(
            "bond release chain_id does not match settlement config".to_string(),
        ));
    }
    if parse_address(&release.call.from_address, "bond release.call.from_address")?
        != parse_address(&config.operator_address, "config.operator_address")?
    {
        return Err(SettlementError::InvalidDispatch(
            "bond release call from_address does not match config operator_address".to_string(),
        ));
    }
    if parse_address(&release.call.to_address, "bond release.call.to_address")?
        != parse_address(&config.bond_vault_contract, "config.bond_vault_contract")?
    {
        return Err(SettlementError::InvalidDispatch(
            "bond release call to_address does not match config bond_vault_contract".to_string(),
        ));
    }

    let vault_id = parse_b256_hex(&release.vault_id, "bond release.vault_id")?;
    let operator_key_hash =
        parse_b256_hex(&release.operator_key_hash, "bond release.operator_key_hash")?;
    let evidence_hash = parse_b256_hex(&release.evidence_hash, "bond release.evidence_hash")?;
    let expected_root = bond_proof_leaf(
        config,
        vault_id,
        operator_key_hash,
        evidence_hash,
        BOND_ACTION_RELEASE,
        0,
        B256::ZERO,
    )?;
    if parse_b256_hex(&release.merkle_root, "bond release.merkle_root")? != expected_root {
        return Err(SettlementError::InvalidDispatch(
            "bond release merkle_root does not match release commitment".to_string(),
        ));
    }

    let call_data = decode_hex_bytes(&release.call.data)?;
    let call =
        IChioBondVault::releaseBondDetailedCall::abi_decode(&call_data).map_err(|error| {
            SettlementError::InvalidDispatch(format!(
                "bond release call data does not decode: {error}"
            ))
        })?;
    if call.vaultId != vault_id
        || call.root != expected_root
        || call.evidenceHash != evidence_hash
        || call.proof.treeSize != U256::from(1_u8)
        || call.proof.leafIndex != U256::from(0_u8)
        || !call.proof.auditPath.is_empty()
    {
        return Err(SettlementError::InvalidDispatch(
            "bond release call data does not match release commitment".to_string(),
        ));
    }
    Ok((expected_root, operator_key_hash))
}

fn validate_bond_impair_matches_call(
    config: &SettlementChainConfig,
    impair: &PreparedBondImpair,
) -> Result<(B256, B256), SettlementError> {
    if impair.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(
            "bond impair chain_id does not match settlement config".to_string(),
        ));
    }
    if parse_address(&impair.call.from_address, "bond impair.call.from_address")?
        != parse_address(&config.operator_address, "config.operator_address")?
    {
        return Err(SettlementError::InvalidDispatch(
            "bond impair call from_address does not match config operator_address".to_string(),
        ));
    }
    if parse_address(&impair.call.to_address, "bond impair.call.to_address")?
        != parse_address(&config.bond_vault_contract, "config.bond_vault_contract")?
    {
        return Err(SettlementError::InvalidDispatch(
            "bond impair call to_address does not match config bond_vault_contract".to_string(),
        ));
    }

    let vault_id = parse_b256_hex(&impair.vault_id, "bond impair.vault_id")?;
    let operator_key_hash =
        parse_b256_hex(&impair.operator_key_hash, "bond impair.operator_key_hash")?;
    let evidence_hash = parse_b256_hex(&impair.evidence_hash, "bond impair.evidence_hash")?;
    let call_data = decode_hex_bytes(&impair.call.data)?;
    let call = IChioBondVault::impairBondDetailedCall::abi_decode(&call_data).map_err(|error| {
        SettlementError::InvalidDispatch(format!("bond impair call data does not decode: {error}"))
    })?;
    if call.vaultId != vault_id
        || call.evidenceHash != evidence_hash
        || call.slashAmount != U256::from(impair.slash_amount_minor_units)
        || call.proof.treeSize != U256::from(1_u8)
        || call.proof.leafIndex != U256::from(0_u8)
        || !call.proof.auditPath.is_empty()
    {
        return Err(SettlementError::InvalidDispatch(
            "bond impair call data does not match impair commitment".to_string(),
        ));
    }

    validate_bond_impair_distribution(
        &call.beneficiaries,
        &call.shares,
        impair.slash_amount_minor_units,
    )?;
    let distribution_hash = bond_distribution_hash(&call.beneficiaries, &call.shares);
    let expected_root = bond_proof_leaf(
        config,
        vault_id,
        operator_key_hash,
        evidence_hash,
        BOND_ACTION_IMPAIR,
        impair.slash_amount_minor_units,
        distribution_hash,
    )?;
    if parse_b256_hex(&impair.merkle_root, "bond impair.merkle_root")? != expected_root
        || call.root != expected_root
    {
        return Err(SettlementError::InvalidDispatch(
            "bond impair merkle_root does not match impair commitment".to_string(),
        ));
    }
    Ok((expected_root, operator_key_hash))
}

fn validate_bond_prepared_root(
    config: &SettlementChainConfig,
    prepared_root: PreparedBondProofRoot<'_>,
) -> Result<(B256, B256), SettlementError> {
    match prepared_root {
        PreparedBondProofRoot::Release(release) => {
            validate_bond_release_matches_call(config, release)
        }
        PreparedBondProofRoot::Impair(impair) => validate_bond_impair_matches_call(config, impair),
    }
}

fn validate_bond_snapshot_matches_prepared_root(
    bond_snapshot: &EvmBondSnapshot,
    prepared_root: PreparedBondProofRoot<'_>,
) -> Result<(), SettlementError> {
    ensure_bond_snapshot_live(bond_snapshot, "root publication")?;
    match prepared_root {
        PreparedBondProofRoot::Release(release) => {
            if parse_b256_hex(&release.vault_id, "bond release.vault_id")?
                != parse_b256_hex(&bond_snapshot.vault_id, "bond_snapshot.vault_id")?
            {
                return Err(SettlementError::InvalidDispatch(
                    "bond release vault_id does not match bond snapshot".to_string(),
                ));
            }
            if parse_b256_hex(&release.operator_key_hash, "bond release.operator_key_hash")?
                != parse_b256_hex(
                    &bond_snapshot.operator_key_hash,
                    "bond_snapshot.operator_key_hash",
                )?
            {
                return Err(SettlementError::InvalidDispatch(
                    "bond release operator_key_hash does not match bond snapshot".to_string(),
                ));
            }
        }
        PreparedBondProofRoot::Impair(impair) => {
            if parse_b256_hex(&impair.vault_id, "bond impair.vault_id")?
                != parse_b256_hex(&bond_snapshot.vault_id, "bond_snapshot.vault_id")?
            {
                return Err(SettlementError::InvalidDispatch(
                    "bond impair vault_id does not match bond snapshot".to_string(),
                ));
            }
            if parse_b256_hex(&impair.operator_key_hash, "bond impair.operator_key_hash")?
                != parse_b256_hex(
                    &bond_snapshot.operator_key_hash,
                    "bond_snapshot.operator_key_hash",
                )?
            {
                return Err(SettlementError::InvalidDispatch(
                    "bond impair operator_key_hash does not match bond snapshot".to_string(),
                ));
            }
            let remaining_collateral = bond_snapshot
                .locked_minor_units
                .checked_sub(bond_snapshot.slashed_minor_units)
                .ok_or_else(|| {
                    SettlementError::InvalidInput(
                        "bond snapshot slashed amount exceeds locked collateral".to_string(),
                    )
                })?;
            if impair.slash_amount_minor_units > remaining_collateral {
                return Err(SettlementError::InvalidInput(
                    "slash_amount exceeds remaining bond collateral".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn bond_proof_leaf(
    config: &SettlementChainConfig,
    vault_id: B256,
    operator_key_hash: B256,
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
        operator_key_hash,
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

fn validate_bond_impair_distribution(
    beneficiaries: &[Address],
    shares: &[U256],
    slash_amount_minor_units: u128,
) -> Result<(), SettlementError> {
    if beneficiaries.is_empty()
        || beneficiaries.len() > MAX_IMPAIR_BENEFICIARIES
        || beneficiaries.len() != shares.len()
        || slash_amount_minor_units == 0
    {
        return Err(SettlementError::InvalidInput(
            "InvalidSlashDistribution".to_string(),
        ));
    }

    let mut total = U256::ZERO;
    for (beneficiary, share) in beneficiaries.iter().zip(shares) {
        if *beneficiary == Address::ZERO {
            return Err(SettlementError::InvalidInput(
                "InvalidSlashDistribution".to_string(),
            ));
        }
        total = total
            .checked_add(*share)
            .ok_or_else(|| SettlementError::InvalidInput("InvalidSlashDistribution".to_string()))?;
    }
    if total != U256::from(slash_amount_minor_units) {
        return Err(SettlementError::InvalidInput(
            "InvalidSlashDistribution".to_string(),
        ));
    }
    Ok(())
}

fn push_abi_u256(encoded: &mut Vec<u8>, value: U256) {
    encoded.extend_from_slice(&value.to_be_bytes::<32>());
}

pub async fn prepare_dual_sign_release(
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
    let registry_evidence = read_identity_operator_record_at_block(config).await?;
    let operator_key_hash = parse_b256_hex(
        &registry_evidence.operator_key_hash,
        "identity_registry_evidence.operator_key_hash",
    )?;
    let settlement_key = parse_address(
        &registry_evidence.settlement_key,
        "identity_registry_evidence.settlement_key",
    )?;
    if !registry_evidence.active {
        return Err(SettlementError::InvalidInput(
            "identity registry operator is not active".to_string(),
        ));
    }
    if registry_evidence.operator_epoch == 0 {
        return Err(SettlementError::InvalidInput(
            "operator_epoch must be nonzero".to_string(),
        ));
    }
    let expected_key_hash =
        parse_b256_hex(&dispatch.operator_key_hash, "dispatch.operator_key_hash")?;
    if operator_key_hash != expected_key_hash {
        return Err(SettlementError::InvalidDispatch(
            "identity registry operator key hash does not match dispatch operator_key_hash"
                .to_string(),
        ));
    }
    let signer_address = signer_address_from_private_key(&input.operator_private_key_hex)?;
    if settlement_key != signer_address {
        return Err(SettlementError::InvalidInput(
            "operator signing key does not match identity registry settlement key".to_string(),
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
        registry_evidence.operator_epoch,
    )?;
    let signature = sign_digest(&input.operator_private_key_hex, &digest)?;

    let call = IChioEscrow::releaseWithSignatureCall {
        escrowId: escrow_id,
        receiptHash: receipt_hash,
        settledAmount: U256::from(amount_minor_units),
        operatorEpoch: registry_evidence.operator_epoch,
        v: signature.v,
        r: parse_b256_hex(&signature.r, "signature.r")?,
        s: parse_b256_hex(&signature.s, "signature.s")?,
    };

    Ok(PreparedDualSignRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_hash: format_b256(receipt_hash),
        digest: format_b256(digest),
        operator_epoch: registry_evidence.operator_epoch,
        identity_registry_evidence_binding: DualSignRegistryEvidenceBinding {
            identity_registry_contract: config.identity_registry_contract.clone(),
            operator_address: config.operator_address.clone(),
            settlement_key: format!("{signer_address:?}"),
        },
        identity_registry_evidence: registry_evidence,
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

async fn read_identity_operator_record_at_block(
    config: &SettlementChainConfig,
) -> Result<DualSignRegistryEvidence, SettlementError> {
    let block = latest_block_header(config).await?;
    let block_tag = format!("0x{:x}", block.number);
    let call = IChioIdentityRegistry::getOperatorCall {
        operator: parse_address(&config.operator_address, "config.operator_address")?,
    };
    let raw = eth_call_raw_at_block(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.identity_registry_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
        &block_tag,
    )
    .await?;
    let checked_block = block_header_by_number(config, block.number).await?;
    if checked_block.hash != block.hash {
        return Err(SettlementError::Rpc(
            "identity registry block hash changed before signing".to_string(),
        ));
    }
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IChioIdentityRegistry::getOperatorCall::abi_decode_returns(&bytes)
        .map_err(|error| SettlementError::Rpc(format!("decode getOperator: {error}")))?;
    Ok(DualSignRegistryEvidence {
        chain_id: config.chain_id.clone(),
        identity_registry_contract: config.identity_registry_contract.clone(),
        operator_address: config.operator_address.clone(),
        block_number: block.number,
        block_hash: block.hash,
        observed_at: block.timestamp,
        operator_key_hash: format_b256(decoded.edKeyHash),
        settlement_key: format!("{:?}", decoded.settlementKey),
        registered_at: decoded.registeredAt,
        operator_epoch: decoded.operatorEpoch,
        active: decoded.active,
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
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedBondLock, SettlementError> {
    config.validate()?;
    ensure_settlement_binding(config, binding, Web3KeyBindingPurpose::Settle)?;
    let operator_key_hash = settlement_operator_key_hash(binding)?;
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
        operatorKeyHash: operator_key_hash,
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
        operator_key_hash: format_b256(operator_key_hash),
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
    operator_address: &str,
    bond_snapshot: &EvmBondSnapshot,
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondRelease, SettlementError> {
    config.validate()?;
    ensure_bond_snapshot_live(bond_snapshot, "release")?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    let operator_key_hash =
        ensure_bond_anchor_matches_config(config, operator_address, bond_snapshot, anchor_proof)?;
    let (_anchor_proof, _anchor_root, evidence_hash) = proof_components(anchor_proof)?;
    let proof = singleton_typed_proof();
    let vault_id = parse_b256_hex(&bond_snapshot.vault_id, "bond_snapshot.vault_id")?;
    let root = bond_proof_leaf(
        config,
        vault_id,
        operator_key_hash,
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
        operator_key_hash: format_b256(operator_key_hash),
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
    operator_address: &str,
    bond_snapshot: &EvmBondSnapshot,
    slash_amount: &MonetaryAmount,
    beneficiaries: &[String],
    shares: &[MonetaryAmount],
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondImpair, SettlementError> {
    config.validate()?;
    ensure_bond_snapshot_live(bond_snapshot, "impair")?;
    if beneficiaries.is_empty() || beneficiaries.len() != shares.len() {
        return Err(SettlementError::InvalidInput(
            "beneficiaries and shares must be non-empty and aligned".to_string(),
        ));
    }
    if beneficiaries.len() > MAX_IMPAIR_BENEFICIARIES {
        return Err(SettlementError::InvalidInput(format!(
            "bond impair beneficiary count must not exceed {MAX_IMPAIR_BENEFICIARIES}"
        )));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    let operator_key_hash =
        ensure_bond_anchor_matches_config(config, operator_address, bond_snapshot, anchor_proof)?;
    let slash_amount_minor_units = scale_chio_amount_to_token_minor_units(slash_amount, config)?;
    if slash_amount_minor_units == 0 {
        return Err(SettlementError::InvalidInput(
            "slash_amount must be greater than zero".to_string(),
        ));
    }
    let remaining_collateral = bond_snapshot
        .locked_minor_units
        .checked_sub(bond_snapshot.slashed_minor_units)
        .ok_or_else(|| {
            SettlementError::InvalidInput(
                "bond snapshot slashed amount exceeds locked collateral".to_string(),
            )
        })?;
    if slash_amount_minor_units > remaining_collateral {
        return Err(SettlementError::InvalidInput(
            "slash_amount exceeds remaining bond collateral".to_string(),
        ));
    }
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
    validate_bond_impair_distribution(
        &beneficiary_addresses,
        &share_units,
        slash_amount_minor_units,
    )?;
    let (_anchor_proof, _anchor_root, evidence_hash) = proof_components(anchor_proof)?;
    let proof = singleton_typed_proof();
    let vault_id = parse_b256_hex(&bond_snapshot.vault_id, "bond_snapshot.vault_id")?;
    let distribution_hash = bond_distribution_hash(&beneficiary_addresses, &share_units);
    let root = bond_proof_leaf(
        config,
        vault_id,
        operator_key_hash,
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
        operator_key_hash: format_b256(operator_key_hash),
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
    bond_snapshot: &EvmBondSnapshot,
    prepared_root: PreparedBondProofRoot<'_>,
    checkpoint_seq: u64,
    batch_seq: u64,
) -> Result<PreparedEvmCall, SettlementError> {
    config.validate()?;
    if prepared_root.chain_id() != config.chain_id {
        return Err(SettlementError::InvalidInput(
            "prepared bond proof chain_id does not match settlement config".to_string(),
        ));
    }
    if checkpoint_seq == 0 || batch_seq == 0 {
        return Err(SettlementError::InvalidInput(
            "bond root publication sequence values must be non-zero".to_string(),
        ));
    }
    validate_bond_snapshot_matches_prepared_root(bond_snapshot, prepared_root)?;
    let (merkle_root, operator_key_hash) = validate_bond_prepared_root(config, prepared_root)?;
    if operator_key_hash == B256::ZERO {
        return Err(SettlementError::InvalidInput(
            "operator_key_hash must not be zero".to_string(),
        ));
    }
    let call = IChioRootRegistry::publishRootCall {
        operator: parse_address(&config.operator_address, "operator_address")?,
        merkleRoot: merkle_root,
        checkpointSeq: checkpoint_seq,
        batchStartSeq: batch_seq,
        batchEndSeq: batch_seq,
        treeSize: 1,
        operatorKeyHash: operator_key_hash,
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

struct EvmBlockHeader {
    number: u64,
    hash: String,
    timestamp: u64,
}

async fn latest_block_header(
    config: &SettlementChainConfig,
) -> Result<EvmBlockHeader, SettlementError> {
    block_header_by_tag(config, "latest").await
}

async fn block_header_by_number(
    config: &SettlementChainConfig,
    block_number: u64,
) -> Result<EvmBlockHeader, SettlementError> {
    block_header_by_tag(config, &format!("0x{block_number:x}")).await
}

async fn block_header_by_tag(
    config: &SettlementChainConfig,
    block_tag: &str,
) -> Result<EvmBlockHeader, SettlementError> {
    let block = rpc_call(config, "eth_getBlockByNumber", json!([block_tag, false])).await?;
    let number = parse_hex_u64(
        block
            .get("number")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc(format!("{block_tag} block missing number")))?,
    )?;
    let hash = block
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc(format!("{block_tag} block missing hash")))?
        .to_string();
    parse_b256_hex(&hash, "block.hash")?;
    let timestamp = parse_hex_u64(
        block
            .get("timestamp")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc(format!("{block_tag} block missing timestamp")))?,
    )?;
    Ok(EvmBlockHeader {
        number,
        hash,
        timestamp,
    })
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
    let block = latest_block_header(config).await?;
    let block_number = block.number;
    let observed_at = block.timestamp;
    let block_tag = format!("0x{block_number:x}");
    let call = IChioBondVault::getBondCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    let raw = eth_call_raw_at_block(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
        &block_tag,
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IChioBondVault::getBondCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getBond decode failed: {error}"))
    })?;
    Ok(EvmBondSnapshot {
        vault_id: vault_id.to_string(),
        principal_address: format!("{:?}", decoded.terms.principal),
        operator_key_hash: format_b256(decoded.terms.operatorKeyHash),
        expires_at: decoded.terms.expiresAt.to::<u64>(),
        observed_at,
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
