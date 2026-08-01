//! Insurance flow tests: a claim filed against a policy with receipt
//! evidence is processed through the settlement flow.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_fiscal::{
    FiscalActivationHistory, FiscalAuthorityState, FiscalBootstrapState, FiscalCharterRegistry,
    FiscalContinuitySnapshot, FiscalGenesisPolicy, FiscalResolver, FiscalRuntimeAdapter,
    FiscalRuntimeAdapterRegistry, SignedFiscalCharter, SignedFiscalContinuityCheckpoint,
    SignedFiscalRuntimeReadiness, VerifiedFiscalCharter, VerifiedFiscalContinuityCheckpoint,
    VerifiedFiscalRuntimeReadiness, FISCAL_RUNTIME_ADAPTER_COUNT,
};
use chio_market::{
    quote_and_bind, BoundPolicy, ClaimDecision, ClaimDenialReason, ClaimEvidence,
    ClaimSettlementRequest, ClaimSettlementSink, InsuranceFlowError, PolicyStatus,
    ReceiptEvidenceSource, ReceiptFingerprint, ResolvedReceiptEvidence, StaticPremiumSource,
};
use chio_underwriting::{LookbackWindow, PremiumInputs};

fn window() -> LookbackWindow {
    LookbackWindow::new(1_000_000, 1_000_600).expect("valid lookback window")
}

fn static_source(score: u32) -> StaticPremiumSource {
    StaticPremiumSource::new(PremiumInputs::new(Some(score), None, 1_000, "USD"))
}

fn with_fiscal<T>(run: impl FnOnce(&FiscalResolver<'_>) -> T) -> T {
    let fixture = |name: &str| {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
        ));
        std::fs::read(path).expect("read fiscal fixture")
    };
    let policy: FiscalGenesisPolicy =
        serde_json::from_slice(&fixture("genesis-policy")).expect("genesis policy");
    let charter = VerifiedFiscalCharter::verify(
        serde_json::from_slice::<SignedFiscalCharter>(&fixture("charter")).expect("charter"),
    )
    .expect("verified charter");
    let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])
        .expect("fiscal charter registry");
    let registry = FiscalRuntimeAdapterRegistry::new(
        "build-1".to_owned(),
        "chio.fiscal.runtime.v1".to_owned(),
        (0..FISCAL_RUNTIME_ADAPTER_COUNT)
            .map(|index| {
                FiscalRuntimeAdapter::new(format!("adapter-{index}"), format!("1.{index}"))
                    .expect("runtime adapter")
            })
            .collect(),
    )
    .expect("runtime registry");
    let readiness = VerifiedFiscalRuntimeReadiness::verify(
        serde_json::from_slice::<SignedFiscalRuntimeReadiness>(&fixture("consumer-readiness"))
            .expect("consumer readiness"),
        &policy,
        registry,
    )
    .expect("verified consumer readiness");
    let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
        serde_json::from_slice::<SignedFiscalContinuityCheckpoint>(&fixture(
            "continuity-checkpoint",
        ))
        .expect("continuity checkpoint"),
        &policy,
        &charters,
    )
    .expect("verified continuity checkpoint");
    let authority = FiscalAuthorityState::from_checkpoint(
        &policy,
        &checkpoint,
        FiscalBootstrapState::CharterPinned,
    )
    .expect("fiscal authority state");
    let history = FiscalActivationHistory::new(Vec::new()).expect("empty activation history");
    run(&FiscalResolver {
        continuity: FiscalContinuitySnapshot::Verified(&checkpoint),
        policy: &policy,
        readiness: &readiness,
        activation_history: &history,
        authority: &authority,
        charters: &charters,
        schedules: &[],
        verify_at: checkpoint.body().trusted_clock_high_water,
    })
}

struct InMemoryReceipts {
    entries: BTreeMap<String, ResolvedReceiptEvidence>,
}

impl ReceiptEvidenceSource for InMemoryReceipts {
    fn resolve(&self, receipt_id: &str) -> Result<ResolvedReceiptEvidence, String> {
        self.entries
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| format!("receipt `{receipt_id}` not found"))
    }
}

struct CapturingSink {
    events: Mutex<Vec<ClaimSettlementRequest>>,
}

impl CapturingSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<ClaimSettlementRequest> {
        self.events.lock().expect("lock").clone()
    }
}

impl ClaimSettlementSink for CapturingSink {
    fn submit(&self, request: ClaimSettlementRequest) -> Result<String, String> {
        let mut events = self.events.lock().map_err(|error| error.to_string())?;
        let reference = format!("settle-ref-{}", events.len());
        events.push(request);
        Ok(reference)
    }
}

fn make_receipt(
    keypair: &Keypair,
    receipt_id: &str,
) -> (ReceiptFingerprint, ResolvedReceiptEvidence) {
    let body = ("chio.receipt.fixture.v1", receipt_id, 1_000_000u64);
    let canonical = canonical_json_bytes(&body).expect("canonical JSON");
    let body_sha256 = sha256_hex(&canonical);
    let signature = keypair.sign(&canonical);
    let signer_key = keypair.public_key();
    (
        ReceiptFingerprint {
            receipt_id: receipt_id.to_string(),
            body_sha256: body_sha256.clone(),
        },
        ResolvedReceiptEvidence {
            body_sha256,
            signer_key,
            signature,
            canonical_body: canonical,
        },
    )
}

#[test]
fn bind_then_file_claim_reaches_settlement_flow() {
    let keypair = Keypair::generate();
    let policy: BoundPolicy = with_fiscal(|resolver| {
        quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            resolver,
            1_000_600,
            60 * 60 * 24 * 30,
        )
    })
    .expect("clean agent should receive a quote and bind");
    assert_eq!(policy.status, PolicyStatus::Active);

    let (fingerprint, resolved) = make_receipt(&keypair, "rcpt-42");
    let receipts = InMemoryReceipts {
        entries: BTreeMap::from([(fingerprint.receipt_id.clone(), resolved)]),
    };
    let sink = CapturingSink::new();
    let evidence = ClaimEvidence {
        claim_id: "claim-42".to_string(),
        policy_id: policy.policy_id.clone(),
        requested_amount: MonetaryAmount {
            units: 500_000,
            currency: "USD".to_string(),
        },
        incident_description: "covered incident with verified receipt evidence".to_string(),
        supporting_receipts: vec![fingerprint],
        settlement_chain_id: "ethereum-mainnet".to_string(),
    };

    let decision = policy
        .file_claim(&evidence, 1_001_000, &receipts, &sink)
        .expect("file_claim should not error with valid evidence");
    match &decision {
        ClaimDecision::Approved {
            payable_amount,
            settlement,
            ..
        } => {
            assert_eq!(payable_amount.currency, "USD");
            assert!(payable_amount.units > 0);
            assert_eq!(settlement.request.capability_commitment, policy.policy_id);
            assert_eq!(settlement.request.lane_kind, "chio.insurance.claim.v1");
            assert_eq!(settlement.settlement_reference, "settle-ref-0");
        }
        ClaimDecision::Denied { reason, .. } => {
            panic!("expected approval, got denial reason {reason:?}")
        }
    }

    let events = sink.events();
    assert_eq!(events.len(), 1, "settlement must be submitted exactly once");
    assert_eq!(events[0].chain_id, "ethereum-mainnet");
}

#[test]
fn claim_without_receipts_is_denied_and_settlement_is_not_called() {
    let policy = with_fiscal(|resolver| {
        quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            resolver,
            1_000_600,
            60 * 60 * 24 * 30,
        )
    })
    .expect("clean agent binds");
    let receipts = InMemoryReceipts {
        entries: BTreeMap::new(),
    };
    let sink = CapturingSink::new();
    let evidence = ClaimEvidence {
        claim_id: "claim-empty".to_string(),
        policy_id: policy.policy_id.clone(),
        requested_amount: MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        },
        incident_description: "no evidence".to_string(),
        supporting_receipts: Vec::new(),
        settlement_chain_id: "ethereum-mainnet".to_string(),
    };
    let decision = policy
        .file_claim(&evidence, 1_001_000, &receipts, &sink)
        .expect("file_claim should not error");
    match decision {
        ClaimDecision::Denied { reason, .. } => {
            assert_eq!(reason, ClaimDenialReason::InsufficientEvidence);
        }
        ClaimDecision::Approved { .. } => panic!("expected denial with no receipts"),
    }
    assert!(sink.events().is_empty());
}

#[test]
fn denied_premium_prevents_binding() {
    let err = with_fiscal(|resolver| {
        quote_and_bind(
            "agent-denials",
            "tool:exec",
            window(),
            &static_source(300),
            resolver,
            1_000_600,
            60 * 60 * 24 * 30,
        )
    })
    .expect_err("score below floor should produce a decline");
    assert!(matches!(err, InsuranceFlowError::PremiumDeclined(_)));
}
