use super::*;

use chio_core::capability::GovernedProvenanceEvidenceClass;
use chio_kernel::evidence_export::EvidenceLineageReferences;
use chio_kernel::operator_report::GovernedTransactionDiagnostics;
use chio_kernel::receipt_query::{ReceiptReadBoundary, ReceiptReadContext};

// Report generation for `SqliteReceiptStore`. The shared governed-transaction
// projection helpers live here; each report family lives in its own submodule
// under `reports/`, contributing methods to `impl SqliteReceiptStore`. The
// submodules reach these helpers and the receipt_store-scope imports through
// `use super::*`, mirroring the `support/` submodule tree.
#[path = "reports/analytics.rs"]
mod analytics;
#[path = "reports/authorization.rs"]
mod authorization;
#[path = "reports/behavioral.rs"]
mod behavioral;
#[path = "reports/billing.rs"]
mod billing;
#[path = "reports/compliance.rs"]
mod compliance;
#[path = "reports/cost_attribution.rs"]
mod cost_attribution;
#[path = "reports/economic.rs"]
mod economic;
#[path = "reports/reconciliation.rs"]
mod reconciliation;
#[path = "reports/settlement.rs"]
mod settlement;
#[path = "reports/shared_evidence.rs"]
mod shared_evidence;

#[derive(Debug, Clone)]
struct GovernedTransactionProjection {
    strong: GovernedTransactionReceiptMetadata,
    diagnostics: Option<GovernedTransactionDiagnostics>,
}

#[derive(Debug, Clone, Default)]
struct PersistedLineageReferences {
    statement_id: Option<String>,
    session_anchor_id: Option<String>,
}

fn extract_governed_transaction_diagnostics(
    receipt: &ChioReceipt,
) -> Option<GovernedTransactionDiagnostics> {
    let diagnostics = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction_diagnostics"))
        .cloned()
        .and_then(|value| serde_json::from_value::<GovernedTransactionDiagnostics>(value).ok())
        .unwrap_or_default();

    (!diagnostics.is_empty()).then_some(diagnostics)
}

fn sanitize_governed_transaction_projection(
    receipt: &ChioReceipt,
    governed: &GovernedTransactionReceiptMetadata,
) -> GovernedTransactionProjection {
    let mut strong = governed.clone();
    let mut diagnostics = extract_governed_transaction_diagnostics(receipt).unwrap_or_default();

    if let Some(call_chain) = strong
        .call_chain
        .clone()
        .filter(|call_chain| call_chain.evidence_class == GovernedProvenanceEvidenceClass::Asserted)
    {
        strong.call_chain = None;
        if diagnostics.asserted_call_chain.is_none() {
            diagnostics.asserted_call_chain = Some(call_chain);
        }
    }

    if diagnostics.lineage_references.session_anchor_id.is_none() {
        diagnostics.lineage_references.session_anchor_id = strong
            .call_chain
            .as_ref()
            .and_then(|call_chain| call_chain.session_anchor_id.clone())
            .or_else(|| {
                diagnostics
                    .asserted_call_chain
                    .as_ref()
                    .and_then(|call_chain| call_chain.session_anchor_id.clone())
            });
    }
    if diagnostics
        .lineage_references
        .receipt_lineage_statement_id
        .is_none()
    {
        diagnostics.lineage_references.receipt_lineage_statement_id = strong
            .call_chain
            .as_ref()
            .and_then(|call_chain| call_chain.receipt_lineage_statement_id.clone())
            .or_else(|| {
                diagnostics
                    .asserted_call_chain
                    .as_ref()
                    .and_then(|call_chain| call_chain.receipt_lineage_statement_id.clone())
            });
    }

    GovernedTransactionProjection {
        strong,
        diagnostics: (!diagnostics.is_empty()).then_some(diagnostics),
    }
}

fn apply_persisted_lineage_references(
    projection: &mut GovernedTransactionProjection,
    persisted: &PersistedLineageReferences,
) {
    if persisted.statement_id.is_none() && persisted.session_anchor_id.is_none() {
        return;
    }

    if let Some(call_chain) = projection.strong.call_chain.as_mut() {
        if call_chain.session_anchor_id.is_none() {
            call_chain.session_anchor_id = persisted.session_anchor_id.clone();
        }
        if call_chain.receipt_lineage_statement_id.is_none() {
            call_chain.receipt_lineage_statement_id = persisted.statement_id.clone();
        }
    }

    let diagnostics = projection
        .diagnostics
        .get_or_insert_with(GovernedTransactionDiagnostics::default);
    if let Some(call_chain) = diagnostics.asserted_call_chain.as_mut() {
        if call_chain.session_anchor_id.is_none() {
            call_chain.session_anchor_id = persisted.session_anchor_id.clone();
        }
        if call_chain.receipt_lineage_statement_id.is_none() {
            call_chain.receipt_lineage_statement_id = persisted.statement_id.clone();
        }
    }
    if diagnostics.lineage_references.session_anchor_id.is_none() {
        diagnostics.lineage_references.session_anchor_id = persisted.session_anchor_id.clone();
    }
    if diagnostics
        .lineage_references
        .receipt_lineage_statement_id
        .is_none()
    {
        diagnostics.lineage_references.receipt_lineage_statement_id =
            persisted.statement_id.clone();
    }
    if diagnostics.is_empty() {
        projection.diagnostics = None;
    }
}

fn call_chain_evidence_class(
    projection: &GovernedTransactionProjection,
) -> Option<GovernedProvenanceEvidenceClass> {
    projection
        .strong
        .call_chain
        .as_ref()
        .map(|call_chain| call_chain.evidence_class)
        .or_else(|| {
            projection
                .diagnostics
                .as_ref()
                .and_then(|diagnostics| diagnostics.asserted_call_chain.as_ref())
                .map(|call_chain| call_chain.evidence_class)
        })
}

fn lineage_references_from_projection(
    projection: &GovernedTransactionProjection,
) -> Option<&EvidenceLineageReferences> {
    projection
        .diagnostics
        .as_ref()
        .map(|diagnostics| &diagnostics.lineage_references)
        .filter(|references| !references.is_empty())
}

fn authorization_transaction_context_from_projection(
    projection: &GovernedTransactionProjection,
) -> chio_kernel::operator_report::GovernedAuthorizationTransactionContext {
    let mut transaction_context =
        authorization_transaction_context_from_governed_metadata(&projection.strong);
    if transaction_context.call_chain.is_none() {
        transaction_context.call_chain = projection
            .diagnostics
            .as_ref()
            .and_then(|diagnostics| diagnostics.asserted_call_chain.clone());
    }
    transaction_context
}

fn require_admin_receipt_read_context(
    context: Option<&ReceiptReadContext>,
    surface: &str,
) -> Result<(), ReceiptStoreError> {
    match context {
        Some(ReceiptReadContext {
            boundary: ReceiptReadBoundary::AdminAll,
            ..
        }) => Ok(()),
        Some(ReceiptReadContext {
            boundary: ReceiptReadBoundary::TenantScoped { .. },
            ..
        }) => Err(ReceiptStoreError::ReadBoundary(format!(
            "{surface} requires admin receipt read authority until tenant-scoped report filtering is implemented"
        ))),
        None => Err(ReceiptStoreError::ReadBoundary(format!(
            "{surface} requires an explicit receipt read context"
        ))),
    }
}
