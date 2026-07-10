use alloy_primitives::keccak256;

use super::*;

pub(super) fn validate_identity_registry_operator_snapshot(
    bundle: &PublicSettlementProofBundle,
    snapshot: &PublicSettlementIdentityRegistryOperatorSnapshot,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &snapshot.identity_registry_contract,
        "public_settlement.chain_snapshot.identity_registry_operator.identity_registry_contract",
    )?;
    ensure_non_empty(
        &snapshot.operator_address,
        "public_settlement.chain_snapshot.identity_registry_operator.operator_address",
    )?;
    ensure_non_empty(
        &snapshot.operator_key_hash,
        "public_settlement.chain_snapshot.identity_registry_operator.operator_key_hash",
    )?;
    ensure_non_empty(
        &snapshot.settlement_key,
        "public_settlement.chain_snapshot.identity_registry_operator.settlement_key",
    )?;
    ensure_non_empty(
        &snapshot.block_hash,
        "public_settlement.chain_snapshot.identity_registry_operator.block_hash",
    )?;
    ensure_evm_address(
        &snapshot.identity_registry_contract,
        "public_settlement.chain_snapshot.identity_registry_operator.identity_registry_contract",
    )?;
    ensure_evm_address(
        &snapshot.operator_address,
        "public_settlement.chain_snapshot.identity_registry_operator.operator_address",
    )?;
    ensure_evm_address(
        &snapshot.settlement_key,
        "public_settlement.chain_snapshot.identity_registry_operator.settlement_key",
    )?;
    Hash::from_hex(&snapshot.operator_key_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&snapshot.block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if snapshot.operator_epoch == 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot epoch must be non-zero"
                .to_string(),
        ));
    }
    if !snapshot.active {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot must be active".to_string(),
        ));
    }
    let provenance = bundle.deployment_provenance.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof(
            "public settlement deployment provenance missing".to_string(),
        )
    })?;
    if !evm_addresses_match(
        &snapshot.identity_registry_contract,
        &provenance.identity_registry_address,
    )? {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot contract mismatch".to_string(),
        ));
    }
    let chain_anchor = required_chain_anchor(bundle)?;
    if !evm_addresses_match(&snapshot.operator_address, &chain_anchor.operator_address)? {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot address mismatch".to_string(),
        ));
    }
    if !hashes_match(&snapshot.operator_key_hash, &chain_anchor.operator_key_hash)? {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot key mismatch".to_string(),
        ));
    }
    if snapshot.operator_epoch != chain_anchor.operator_epoch {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot epoch mismatch".to_string(),
        ));
    }
    if snapshot.block_number > chain_anchor.block_number
        || snapshot.block_number > bundle.chain_snapshot.observed_block_number
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot block exceeds observed chain state"
                .to_string(),
        ));
    }
    if snapshot.block_number == chain_anchor.block_number
        && snapshot.block_hash != chain_anchor.block_hash
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement identity registry operator snapshot block hash mismatch".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_release_event(
    bundle: &PublicSettlementProofBundle,
    escrow: &PublicSettlementEscrowSnapshot,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    let release_event = escrow.release_event.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof(
            "public settlement escrow release event missing".to_string(),
        )
    })?;
    if release_event.escrow_id != escrow.escrow_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event escrow id mismatch".to_string(),
        ));
    }
    Hash::from_hex(&release_event.release_tx_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&release_event.receipt_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if release_event.release_tx_hash
        != bundle
            .settlement_receipt
            .observed_execution
            .external_reference_id
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event tx hash mismatch".to_string(),
        ));
    }
    let expected_partial =
        bundle.settlement_receipt.lifecycle_state == Web3SettlementLifecycleState::PartiallySettled;
    if release_event.partial != expected_partial {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event partial flag mismatch".to_string(),
        ));
    }
    let Some(anchor_proof) = bundle.settlement_receipt.reconciled_anchor_proof.as_ref() else {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release event requires reconciled anchor proof".to_string(),
        ));
    };
    let receipt_hash = keccak256(
        canonical_json_bytes(&anchor_proof.receipt.body())
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?,
    );
    let mut receipt_hash_bytes = [0_u8; 32];
    receipt_hash_bytes.copy_from_slice(receipt_hash.as_slice());
    let expected_receipt_hash = Hash::from_bytes(receipt_hash_bytes).to_hex_prefixed();
    if release_event.receipt_hash != expected_receipt_hash {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event receipt hash mismatch".to_string(),
        ));
    }
    validate_release_event_block(&release_event.block, bundle)?;
    if !release_event
        .block
        .transaction_hashes
        .iter()
        .any(|tx_hash| tx_hash == &release_event.release_tx_hash)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release tx hash not included in event block".to_string(),
        ));
    }
    if !trust.trusted_release_event_blocks.iter().any(|block| {
        block.block_number == release_event.block.block_number
            && block.block_hash == release_event.block.block_hash
            && block
                .transaction_hashes
                .iter()
                .any(|tx_hash| tx_hash == &release_event.release_tx_hash)
    }) {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release tx hash not included in trusted release event block"
                .to_string(),
        ));
    }
    let trusted_log = required_trusted_release_event_log(release_event, escrow, trust)?;
    validate_trusted_release_event_log(trusted_log, release_event, escrow, expected_partial)?;
    if release_event.amount != trusted_log.amount {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event amount mismatch against trusted log".to_string(),
        ));
    }
    if trusted_log.amount != bundle.settlement_receipt.settled_amount {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement trusted release event amount mismatch".to_string(),
        ));
    }
    let _prior_released = escrow
        .released_amount
        .units
        .checked_sub(trusted_log.amount.units)
        .ok_or_else(|| {
            Web3ContractError::InvalidSettlement(
                "public settlement release event amount exceeds released amount".to_string(),
            )
        })?;
    validate_release_event_remaining_amount(release_event, trusted_log, escrow, expected_partial)?;
    Ok(())
}

fn required_trusted_release_event_log<'a>(
    release_event: &PublicSettlementReleaseEvent,
    escrow: &PublicSettlementEscrowSnapshot,
    trust: &'a PublicSettlementVerifierTrust,
) -> Result<&'a PublicSettlementReleaseEventLog, Web3ContractError> {
    trust
        .trusted_release_event_logs
        .iter()
        .find(|log| {
            log.release_tx_hash == release_event.release_tx_hash
                && log.block_number == release_event.block.block_number
                && log.block_hash == release_event.block.block_hash
                && log.escrow_id == escrow.escrow_id
        })
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "public settlement trusted release event log evidence missing".to_string(),
            )
        })
}

fn validate_trusted_release_event_log(
    trusted_log: &PublicSettlementReleaseEventLog,
    release_event: &PublicSettlementReleaseEvent,
    escrow: &PublicSettlementEscrowSnapshot,
    expected_partial: bool,
) -> Result<(), Web3ContractError> {
    ensure_evm_address(
        &trusted_log.contract_address,
        "public_settlement.trust.trusted_release_event_logs.contract_address",
    )?;
    if !evm_addresses_match(&trusted_log.contract_address, &escrow.escrow_contract)? {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement trusted release event contract mismatch".to_string(),
        ));
    }
    Hash::from_hex(&trusted_log.release_tx_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&trusted_log.receipt_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&trusted_log.block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if trusted_log.escrow_id != release_event.escrow_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement trusted release event escrow id mismatch".to_string(),
        ));
    }
    if trusted_log.receipt_hash != release_event.receipt_hash {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement trusted release event receipt hash mismatch".to_string(),
        ));
    }
    let expected_kind = if expected_partial {
        PublicSettlementReleaseEventKind::EscrowPartialRelease
    } else {
        PublicSettlementReleaseEventKind::EscrowReleased
    };
    if trusted_log.event != expected_kind {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement trusted release event kind mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_release_event_remaining_amount(
    release_event: &PublicSettlementReleaseEvent,
    trusted_log: &PublicSettlementReleaseEventLog,
    escrow: &PublicSettlementEscrowSnapshot,
    expected_partial: bool,
) -> Result<(), Web3ContractError> {
    if !expected_partial {
        if release_event.remaining_amount.is_some() || trusted_log.remaining_amount.is_some() {
            return Err(Web3ContractError::InvalidSettlement(
                "public settlement full release event must not carry remaining amount".to_string(),
            ));
        }
        return Ok(());
    }
    let event_remaining = release_event.remaining_amount.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof(
            "public settlement partial release event remaining amount missing".to_string(),
        )
    })?;
    let log_remaining = trusted_log.remaining_amount.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof(
            "public settlement partial release trusted log remaining amount missing".to_string(),
        )
    })?;
    if event_remaining != log_remaining {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event remaining amount mismatch against trusted log"
                .to_string(),
        ));
    }
    if event_remaining.currency != escrow.locked_amount.currency {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event remaining currency mismatch".to_string(),
        ));
    }
    let remaining = escrow
        .locked_amount
        .units
        .checked_sub(escrow.released_amount.units)
        .ok_or_else(|| {
            Web3ContractError::InvalidSettlement(
                "public settlement release event remaining amount underflow".to_string(),
            )
        })?;
    if event_remaining.units != remaining {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement release event remaining amount mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_release_event_block(
    block: &PublicSettlementBlockSnapshot,
    bundle: &PublicSettlementProofBundle,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &block.block_hash,
        "public_settlement.chain_snapshot.escrow.release_event.block.block_hash",
    )?;
    Hash::from_hex(&block.block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    let chain_anchor = required_chain_anchor(bundle)?;
    if block.block_number < chain_anchor.block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release event block predates anchor block".to_string(),
        ));
    }
    if block.block_number > bundle.chain_snapshot.latest_block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release event block exceeds latest block".to_string(),
        ));
    }
    let confirmations = bundle
        .chain_snapshot
        .latest_block_number
        .saturating_sub(block.block_number)
        .saturating_add(1);
    if confirmations < u64::from(bundle.required_confirmations) {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release event block lacks required confirmations".to_string(),
        ));
    }
    if block.transaction_hashes.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement release event block transaction list is empty".to_string(),
        ));
    }
    for transaction_hash in &block.transaction_hashes {
        ensure_non_empty(
            transaction_hash,
            "public_settlement.chain_snapshot.escrow.release_event.block.transaction_hashes",
        )?;
        Hash::from_hex(transaction_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    }
    Ok(())
}

pub(super) fn validate_dispute_event_blocks(
    bundle: &PublicSettlementProofBundle,
    dispute: &PublicSettlementDisputeSnapshot,
    trusted_blocks: &[PublicSettlementBlockSnapshot],
) -> Result<(), Web3ContractError> {
    for tx_hash in &dispute.chain_event_tx_hashes {
        ensure_non_empty(tx_hash, "public_settlement.dispute.chain_event_tx_hashes")?;
        Hash::from_hex(tx_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    }
    if dispute.chain_event_tx_hashes.is_empty() {
        if dispute.posture != PublicSettlementDisputePosture::Undisputed {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event evidence missing".to_string(),
            ));
        }
        if !dispute.chain_event_blocks.is_empty() {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event block without tx hash".to_string(),
            ));
        }
        return Ok(());
    }
    if dispute.chain_event_blocks.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute event block evidence missing".to_string(),
        ));
    }
    if trusted_blocks.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute event trusted block evidence missing".to_string(),
        ));
    }
    let chain_anchor = required_chain_anchor(bundle)?;
    for block in &dispute.chain_event_blocks {
        validate_dispute_event_block(block, chain_anchor.block_number, bundle)?;
        let Some(trusted_block) = trusted_blocks.iter().find(|trusted_block| {
            trusted_block.block_number == block.block_number
                && trusted_block.block_hash == block.block_hash
        }) else {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event block is not trusted".to_string(),
            ));
        };
        validate_dispute_event_block(trusted_block, chain_anchor.block_number, bundle)?;
    }
    for tx_hash in &dispute.chain_event_tx_hashes {
        if !dispute.chain_event_blocks.iter().any(|block| {
            block
                .transaction_hashes
                .iter()
                .any(|block_tx_hash| block_tx_hash == tx_hash)
        }) {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event tx hash not included in event block".to_string(),
            ));
        }
        if !trusted_blocks.iter().any(|block| {
            dispute.chain_event_blocks.iter().any(|bundle_block| {
                bundle_block.block_number == block.block_number
                    && bundle_block.block_hash == block.block_hash
            }) && block
                .transaction_hashes
                .iter()
                .any(|block_tx_hash| block_tx_hash == tx_hash)
        }) {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event tx hash not included in trusted event block"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_dispute_event_block(
    block: &PublicSettlementBlockSnapshot,
    anchor_block_number: u64,
    bundle: &PublicSettlementProofBundle,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &block.block_hash,
        "public_settlement.dispute.chain_event_blocks.block_hash",
    )?;
    Hash::from_hex(&block.block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if block.block_number < anchor_block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute event block predates anchor block".to_string(),
        ));
    }
    if block.block_number > bundle.chain_snapshot.latest_block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute event block exceeds latest block".to_string(),
        ));
    }
    let confirmations = bundle
        .chain_snapshot
        .latest_block_number
        .saturating_sub(block.block_number)
        .saturating_add(1);
    if confirmations < u64::from(bundle.required_confirmations) {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute event block below finality threshold".to_string(),
        ));
    }
    if block.transaction_hashes.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute event block transaction list is empty".to_string(),
        ));
    }
    for tx_hash in &block.transaction_hashes {
        ensure_non_empty(
            tx_hash,
            "public_settlement.dispute.chain_event_blocks.transaction_hashes",
        )?;
        Hash::from_hex(tx_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    }
    Ok(())
}
