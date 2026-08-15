//! Cost facets: `metered_exposure_backing` and `settled_spend_backing`.
//!
//! Two non-interchangeable floors on KERNEL-ACCOUNTED amounts. Neither
//! proves paid honest work, physical compute burn, total effort, or the
//! truth of the finding. Metered exposure requires an admitted kernel,
//! mediated reconciled spend semantics, and a matching signed execution
//! nonce per receipt; settled spend additionally requires finalized
//! settlement evidence on the same receipts. Amounts add with checked
//! arithmetic after exact currency equality; the advisory saturating
//! rollup elsewhere in the tree is never authority.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::authoritative_spend::{
    is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, PresentedNonceView,
};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::economics::SettlementStatus;

/// Resolves the presented execution nonce for one evidence receipt.
/// Verification that may run more than once must resolve WITHOUT
/// consuming; a consuming resolver would self-deny on the second pass.
pub trait FindingNonceResolver {
    /// The nonce presented alongside this receipt, if any was resolved.
    fn nonce_for(&self, receipt: &ChioReceipt) -> Option<&dyn PresentedNonceView>;
}

/// A resolver with no nonce evidence: every metered facet evaluation
/// under it reports unavailable rather than verified.
pub struct NoNonceEvidence;

impl FindingNonceResolver for NoNonceEvidence {
    fn nonce_for(&self, _receipt: &ChioReceipt) -> Option<&dyn PresentedNonceView> {
        None
    }
}

/// Outcome of a cost-facet evaluation, before report mapping.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CostFacetOutcome {
    /// The floor is established: every receipt authoritative, exact
    /// currencies, checked sum at least the asserted evidence cost.
    Verified { accounted_units: u64 },
    /// A required input (nonce evidence, settlement evidence) was not
    /// supplied; deny wherever the facet is required.
    Unavailable { reason: &'static str },
    /// Supplied evidence positively fails the check.
    Failed { reason: String },
}

/// Evaluate `metered_exposure_backing`: every evidence receipt must be an
/// authoritative mediated-spend receipt under an ADMITTED kernel key with
/// its presented nonce, and the checked sum of reconciled spend in the
/// exact evidence-cost currency must reach the asserted rollup. An empty
/// admitted-key set denies everything by construction.
pub(crate) fn evaluate_metered_exposure(
    receipts: &[&ChioReceipt],
    admitted_kernel_keys: &[PublicKey],
    nonce_resolver: &dyn FindingNonceResolver,
    evidence_cost: &MonetaryAmount,
) -> CostFacetOutcome {
    if receipts.is_empty() {
        return CostFacetOutcome::Unavailable {
            reason: "no evidence receipts resolved",
        };
    }
    let mut accounted_units: u64 = 0;
    for receipt in receipts {
        let Some(nonce) = nonce_resolver.nonce_for(receipt) else {
            return CostFacetOutcome::Unavailable {
                reason: "execution nonce evidence not supplied",
            };
        };
        if let Err(reason) = is_authoritative_spend_receipt(receipt, admitted_kernel_keys, nonce) {
            return CostFacetOutcome::Failed {
                reason: format!("receipt {} not authoritative: {reason:?}", receipt.id),
            };
        }
        let Some(authority) = BudgetAuthorityReceiptRef::from_receipt(receipt) else {
            return CostFacetOutcome::Failed {
                reason: format!("receipt {} lacks budget authority metadata", receipt.id),
            };
        };
        let Some(financial) = receipt.financial_metadata() else {
            return CostFacetOutcome::Failed {
                reason: format!("receipt {} lacks financial metadata", receipt.id),
            };
        };
        if financial.currency != evidence_cost.currency {
            return CostFacetOutcome::Failed {
                reason: format!(
                    "receipt {} currency {} does not match evidence cost currency {}",
                    receipt.id, financial.currency, evidence_cost.currency
                ),
            };
        }
        let Some(total) = accounted_units.checked_add(authority.realized_units) else {
            return CostFacetOutcome::Failed {
                reason: "accounted spend overflow".to_string(),
            };
        };
        accounted_units = total;
    }
    if accounted_units < evidence_cost.units {
        return CostFacetOutcome::Failed {
            reason: format!(
                "kernel-accounted spend {accounted_units} below asserted evidence cost {}",
                evidence_cost.units
            ),
        };
    }
    CostFacetOutcome::Verified { accounted_units }
}

/// Evaluate `settled_spend_backing` on top of a verified metered floor:
/// every receipt must additionally carry finalized settlement evidence
/// (`settlement_status == settled`). `pending` and `not_applicable` never
/// satisfy the facet.
pub(crate) fn evaluate_settled_spend(
    receipts: &[&ChioReceipt],
    metered: &CostFacetOutcome,
) -> CostFacetOutcome {
    let CostFacetOutcome::Verified { accounted_units } = metered else {
        return CostFacetOutcome::Unavailable {
            reason: "metered exposure floor not established",
        };
    };
    for receipt in receipts {
        let Some(financial) = receipt.financial_metadata() else {
            return CostFacetOutcome::Failed {
                reason: format!("receipt {} lacks financial metadata", receipt.id),
            };
        };
        match financial.settlement_status {
            SettlementStatus::Settled => {}
            // A failed settlement is evidence that spend did NOT occur,
            // not absent evidence.
            SettlementStatus::Failed => {
                return CostFacetOutcome::Failed {
                    reason: format!("receipt {} settlement failed", receipt.id),
                };
            }
            SettlementStatus::Pending | SettlementStatus::NotApplicable => {
                return CostFacetOutcome::Unavailable {
                    reason: "receipt settlement not finalized",
                };
            }
        }
    }
    CostFacetOutcome::Verified {
        accounted_units: *accounted_units,
    }
}
