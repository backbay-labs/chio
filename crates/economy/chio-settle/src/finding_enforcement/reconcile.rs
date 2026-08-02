//! Reconciliation of what the vault reported against the frozen intent.

use alloy_primitives::U256;
use alloy_sol_types::SolCall;
use chio_web3_bindings::IChioBondVault;

use super::plan::FindingImpairmentIntent;
use super::{decode_call_data, parse_chain_hash, parse_evm_address};
use crate::{EvmTransactionReceipt, SettlementFinalityStatus};

/// One raw transaction the durable publisher stored for an intent, plus what
/// it later observed for that transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredImpairmentTransaction {
    /// Authenticated chain on which the publisher observed the transaction.
    pub chain_id: String,
    /// Hash of the transaction the publisher broadcast.
    pub tx_hash: String,
    /// Address the transaction was sent to.
    pub to_address: String,
    /// Raw call input as broadcast.
    ///
    /// `None` when the publisher holds only an observation. The vault keeps
    /// its consumed-evidence map private and its impairment event does not
    /// carry the distribution, so nothing on chain can reconstruct the input,
    /// and the match cannot be proved from the contract surface alone.
    pub input_data: Option<String>,
    /// Receipt observed for `tx_hash`, once one exists.
    pub receipt: Option<EvmTransactionReceipt>,
    /// Finality assessed for that receipt, once one was taken.
    pub finality: Option<SettlementFinalityStatus>,
}

/// Closed vault rejection vocabulary this choke point distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingVaultRejection {
    /// The vault has already consumed this evidence hash. Alone this says
    /// nothing about which call consumed it.
    EvidenceAlreadyUsed,
    /// The vault holds no live bond for the target vault id.
    BondNotLive,
    /// The proof did not verify against the published root.
    InvalidEvidence,
    /// The distribution violated the vault's beneficiary and share rules.
    InvalidSlashDistribution,
    /// The identity registry does not qualify the calling operator.
    OperatorNotQualified,
    /// The vault is paused.
    VaultPaused,
    /// A payout token transfer failed, reverting the whole call.
    TransferFailed,
}

/// Why an external observation parks the liability instead of resolving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingImpairmentQuarantine {
    /// The vault refused the evidence as already consumed and the publisher
    /// holds no transaction for this intent.
    StoredTransactionMissing,
    /// The stored transaction has no receipt yet.
    ReceiptMissing,
    /// The receipt has not reached finality under the chain policy.
    ReceiptNotFinalized,
    /// The receipt records a reverted transaction.
    ReceiptReverted,
    /// The receipt does not belong to the stored transaction.
    ReceiptTransactionMismatch,
    /// The stored transaction was observed on another chain.
    ChainMismatch,
    /// The stored transaction did not target the frozen bond vault.
    TargetMismatch,
    /// The publisher recorded no call input, and the vault exposes no
    /// surface that would prove the match without one.
    EvidenceProvenanceUnavailable,
    /// The stored input does not decode as the vault impairment call.
    UndecodableInput,
    /// The decoded input does not match the frozen intent.
    DecodedInputMismatch,
}

/// What the publisher came back with for one intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingImpairmentAttempt {
    /// The publisher stored a transaction for this intent and observed it.
    Observed {
        /// The stored transaction and its observation.
        stored: StoredImpairmentTransaction,
    },
    /// The vault rejected the prepared call.
    Rejected {
        /// Why the vault rejected it.
        rejection: FindingVaultRejection,
        /// Any transaction the publisher had already stored for this intent.
        stored: Option<StoredImpairmentTransaction>,
    },
}

/// Closed reconciliation outcome for one impairment intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingImpairmentOutcome {
    /// A finalized transaction proved to be exactly this intent.
    Confirmed {
        /// Transaction that carried it.
        tx_hash: String,
    },
    /// External state is ambiguous. The liability stays open for operator
    /// reconciliation; this is not an impairment and must never be reported
    /// as one.
    Quarantined {
        /// Why the match could not be proved.
        reason: FindingImpairmentQuarantine,
    },
    /// The vault rejected the call outright and nothing was impaired.
    Failed {
        /// The vault's rejection.
        reason: FindingVaultRejection,
    },
}

/// Reconcile one publisher attempt against the frozen intent.
///
/// The rule this exists for: `EvidenceAlreadyUsed` is success only when a
/// stored raw transaction, a finalized receipt, and a decoded input all match
/// the frozen intent exactly. The vault consumes an evidence hash globally
/// and keeps that map private, so the bare error is equally consistent with
/// "this impairment already landed" and with "some other call burned this
/// evidence hash". Treating it as success in the second case would record a
/// slash that never paid the harmed buyers and would release the liability on
/// a false terminal. Every insufficient variant therefore quarantines: a
/// parked liability keeps purchases blocked and is recoverable, whereas an
/// assumed slash is not.
#[must_use]
pub fn reconcile_finding_impairment(
    intent: &FindingImpairmentIntent,
    attempt: &FindingImpairmentAttempt,
) -> FindingImpairmentOutcome {
    match attempt {
        FindingImpairmentAttempt::Observed { stored }
        | FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: Some(stored),
        } => match match_stored_transaction(intent, stored) {
            Ok(tx_hash) => FindingImpairmentOutcome::Confirmed { tx_hash },
            Err(reason) => FindingImpairmentOutcome::Quarantined { reason },
        },
        FindingImpairmentAttempt::Rejected {
            rejection: FindingVaultRejection::EvidenceAlreadyUsed,
            stored: None,
        } => FindingImpairmentOutcome::Quarantined {
            reason: FindingImpairmentQuarantine::StoredTransactionMissing,
        },
        FindingImpairmentAttempt::Rejected { rejection, .. } => {
            FindingImpairmentOutcome::Failed { reason: *rejection }
        }
    }
}

/// Prove a stored transaction is exactly the frozen intent, or say why not.
fn match_stored_transaction(
    intent: &FindingImpairmentIntent,
    stored: &StoredImpairmentTransaction,
) -> Result<String, FindingImpairmentQuarantine> {
    if stored.chain_id != intent.chain_id {
        return Err(FindingImpairmentQuarantine::ChainMismatch);
    }
    let receipt = stored
        .receipt
        .as_ref()
        .ok_or(FindingImpairmentQuarantine::ReceiptMissing)?;
    if stored.finality != Some(SettlementFinalityStatus::Finalized) {
        return Err(FindingImpairmentQuarantine::ReceiptNotFinalized);
    }
    if !receipt.status {
        return Err(FindingImpairmentQuarantine::ReceiptReverted);
    }
    if !hashes_match(&receipt.tx_hash, &stored.tx_hash) {
        return Err(FindingImpairmentQuarantine::ReceiptTransactionMismatch);
    }

    let target = parse_evm_address(&intent.target_contract, "intent.target_contract")
        .map_err(|_| FindingImpairmentQuarantine::TargetMismatch)?;
    for address in [&stored.to_address, &receipt.to_address] {
        if parse_evm_address(address, "stored transaction to_address")
            .map_err(|_| FindingImpairmentQuarantine::TargetMismatch)?
            != target
        {
            return Err(FindingImpairmentQuarantine::TargetMismatch);
        }
    }

    let input_data = stored
        .input_data
        .as_deref()
        .ok_or(FindingImpairmentQuarantine::EvidenceProvenanceUnavailable)?;
    let bytes = decode_call_data(input_data, "stored transaction input")
        .map_err(|_| FindingImpairmentQuarantine::UndecodableInput)?;
    let call = IChioBondVault::impairBondDetailedCall::abi_decode(&bytes)
        .map_err(|_| FindingImpairmentQuarantine::UndecodableInput)?;

    let vault_id = parse_chain_hash(&intent.vault_id, "intent.vault_id")
        .map_err(|_| FindingImpairmentQuarantine::DecodedInputMismatch)?;
    let evidence_hash = parse_chain_hash(&intent.evidence_hash, "intent.evidence_hash")
        .map_err(|_| FindingImpairmentQuarantine::DecodedInputMismatch)?;
    let merkle_root = parse_chain_hash(&intent.merkle_root, "intent.merkle_root")
        .map_err(|_| FindingImpairmentQuarantine::DecodedInputMismatch)?;
    if call.vaultId != vault_id
        || call.evidenceHash != evidence_hash
        || call.root != merkle_root
        || call.slashAmount != U256::from(intent.slash_amount_minor_units)
    {
        return Err(FindingImpairmentQuarantine::DecodedInputMismatch);
    }
    if call.beneficiaries.len() != intent.destinations.len()
        || call.shares.len() != intent.destinations.len()
    {
        return Err(FindingImpairmentQuarantine::DecodedInputMismatch);
    }
    for (index, destination) in intent.destinations.iter().enumerate() {
        let expected = parse_evm_address(&destination.destination, "intent destination")
            .map_err(|_| FindingImpairmentQuarantine::DecodedInputMismatch)?;
        if call.beneficiaries.get(index) != Some(&expected)
            || call.shares.get(index) != Some(&U256::from(destination.share_minor_units))
        {
            return Err(FindingImpairmentQuarantine::DecodedInputMismatch);
        }
    }

    Ok(stored.tx_hash.clone())
}

fn hashes_match(left: &str, right: &str) -> bool {
    left.trim_start_matches("0x")
        .eq_ignore_ascii_case(right.trim_start_matches("0x"))
}
