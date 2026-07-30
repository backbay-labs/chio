use std::fs;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::sha256_hex;
use chio_finding::{
    compute_allocation_id, FindingBondBacking, FindingBondClass, FindingCollateralVault,
    FINDING_BOND_BACKING_SCHEMA_V1,
};
use tempfile::TempDir;

use super::*;
use crate::finding_market_store::SqliteFindingMarketStore;
use crate::finding_purchase_store::{
    FindingPurchaseDeliveryInput, FindingPurchaseDenyInput, FindingPurchaseReservationInput,
    FindingPurchaseStoreError, SqliteFindingPurchaseStore,
};
use crate::SqliteAuthorityStore;

const LISTING_ID: &str = "challenge-listing-01";
const OTHER_LISTING_ID: &str = "challenge-listing-02";
const NOW: u64 = 1_750_000_000;
const RETRY_DEADLINE: u64 = NOW + 3_600;
/// The exposure cap `backing_body` registers for every fixture allocation.
const REGISTERED_EXPOSURE_CAP: u64 = 450;

struct Fixture {
    _temp: TempDir,
    _authority: SqliteAuthorityStore,
    _market: SqliteFindingMarketStore,
    purchases: SqliteFindingPurchaseStore,
    store: SqliteFindingChallengeStore,
    allocation_id: String,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    secure_temp_directory(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let market = authority.finding_market_store();
    let purchases = authority.finding_purchase_store();
    let store = authority.finding_challenge_store();
    let allocation_id = consume_allocation(&market, "vault:finding-collateral", LISTING_ID);
    Fixture {
        _temp: temp,
        _authority: authority,
        _market: market,
        purchases,
        store,
        allocation_id,
    }
}

fn secure_temp_directory(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("secure temp directory");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn hex64(character: char) -> String {
    character.to_string().repeat(64)
}

fn digest(tag: &str) -> String {
    sha256_hex(tag.as_bytes())
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn envelope_string<T: serde::Serialize + Clone>(body: &T, signer: &Keypair) -> String {
    let signed = SignedExportEnvelope::sign(body.clone(), signer).expect("sign envelope");
    String::from_utf8(canonical_json_bytes(&signed).expect("canonical envelope"))
        .expect("utf8 envelope")
}

/// Collateral backing the fixture finding on one listing, mirroring the
/// purchase store's fixture so a reservation opened here is backed the
/// same way the sale path backs it.
fn backing_body(ledger_account: &str, listing_id: &str) -> FindingBondBacking {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: keypair(21).public_key(),
        seller: keypair(22).public_key(),
        authorization_envelope_sha256: hex64('1'),
        finding_id: hex64('a'),
        listing_id: listing_id.to_string(),
        terms_envelope_sha256: hex64('2'),
        profile_envelope_sha256: hex64('3'),
        fee_requirement_sha256: hex64('4'),
        fee_schedule_envelope_sha256: hex64('5'),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(500),
        maximum_sale_exposure: usd(REGISTERED_EXPOSURE_CAP),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: ledger_account.to_string(),
            operator_epoch: 1,
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    backing.allocation_id = compute_allocation_id(&backing).expect("allocation id");
    backing
}

fn consume_allocation(
    market: &SqliteFindingMarketStore,
    ledger_account: &str,
    listing_id: &str,
) -> String {
    let backing = backing_body(ledger_account, listing_id);
    let envelope = envelope_string(&backing, &keypair(21));
    market
        .register_allocation(&envelope, &backing, NOW)
        .expect("register allocation");
    market
        .consume_allocation(&backing.allocation_id)
        .expect("consume allocation");
    backing.allocation_id
}

/// One challenge's identifiers, owned so the borrowed submission can
/// point at them.
struct Challenge {
    challenge_id: String,
    finding_id: String,
    listing_id: String,
    envelope_sha256: String,
    branch: FindingChallengeAuthorizationBranch,
    class: FindingChallengeEvidenceClass,
    challenger_hex: Option<String>,
    submitted_at: u64,
}

impl Challenge {
    fn buyer(tag: &str) -> Self {
        Self {
            challenge_id: format!("challenge-{tag}"),
            finding_id: hex64('a'),
            listing_id: LISTING_ID.to_owned(),
            envelope_sha256: digest(&format!("challenge-envelope-{tag}")),
            branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(hex64('b')),
            submitted_at: NOW,
        }
    }

    fn audit(tag: &str) -> Self {
        Self {
            branch: FindingChallengeAuthorizationBranch::VenueAudit,
            challenger_hex: None,
            ..Self::buyer(tag)
        }
    }

    fn on_listing(mut self, listing_id: &str) -> Self {
        self.listing_id = listing_id.to_owned();
        self
    }

    fn in_class(mut self, class: FindingChallengeEvidenceClass) -> Self {
        self.class = class;
        self
    }

    fn input(&self) -> FindingChallengeSubmission<'_> {
        FindingChallengeSubmission {
            challenge_id: &self.challenge_id,
            finding_id: &self.finding_id,
            listing_id: &self.listing_id,
            challenge_envelope_sha256: &self.envelope_sha256,
            authorization_branch: self.branch,
            evidence_class: self.class,
            challenger_hex: self.challenger_hex.as_deref(),
            submitted_at: self.submitted_at,
        }
    }
}

/// One liability head's keys, owned so the borrowed input can point at
/// them.
struct Liability {
    liability_key: String,
    defect_key: String,
    finding_id: String,
    listing_id: String,
    allocation_id: String,
    venue_id: String,
}

impl Liability {
    fn new(tag: &str, listing_id: &str, allocation_id: &str) -> Self {
        Self {
            liability_key: digest(&format!("liability-{tag}")),
            defect_key: digest(&format!("defect-{tag}")),
            finding_id: hex64('a'),
            listing_id: listing_id.to_owned(),
            allocation_id: allocation_id.to_owned(),
            venue_id: "venue-01".to_owned(),
        }
    }

    fn input(&self) -> FindingLiabilityInput<'_> {
        FindingLiabilityInput {
            liability_key: &self.liability_key,
            defect_key: &self.defect_key,
            finding_id: &self.finding_id,
            listing_id: &self.listing_id,
            allocation_id: &self.allocation_id,
            venue_id: &self.venue_id,
            chain_id: "eip155:8453",
            vault_contract: "0xvault",
            vault_id: "vault-01",
            opened_at: NOW,
        }
    }
}

fn submit(fixture: &Fixture, challenge: &Challenge) -> FindingChallengeWriteOutcome {
    fixture
        .store
        .submit_challenge(&challenge.input())
        .expect("submit challenge")
}

/// Drive one challenge from submission to its terminal verdict.
fn close_challenge(
    fixture: &Fixture,
    challenge: &Challenge,
    verdict: FindingChallengeVerdict,
    now: u64,
) -> FindingChallengeState {
    submit(fixture, challenge);
    fixture
        .store
        .begin_evaluation(&challenge.challenge_id, now)
        .expect("begin evaluation");
    fixture
        .store
        .record_verdict(
            &challenge.challenge_id,
            verdict,
            &digest(&format!("outcome-{}", challenge.challenge_id)),
            now + 1,
        )
        .expect("record verdict")
}

fn challenge_state(fixture: &Fixture, challenge_id: &str) -> FindingChallengeState {
    fixture
        .store
        .get_challenge(challenge_id)
        .expect("get challenge")
        .expect("challenge present")
        .state
}

fn liability(fixture: &Fixture, liability_key: &str) -> FindingLiabilityRecord {
    fixture
        .store
        .get_liability(liability_key)
        .expect("get liability")
        .expect("liability present")
}

fn open_liability(fixture: &Fixture, liability: &Liability) -> FindingChallengeWriteOutcome {
    fixture
        .store
        .open_liability(&liability.input())
        .expect("open liability")
}

fn lock_input<'a>(
    tag: &'a str,
    challenge_id: &'a str,
    owner_hex: &'a str,
    schedule: &'a str,
) -> FindingDisputeLockInput<'a> {
    FindingDisputeLockInput {
        lock_id: tag,
        challenge_id,
        owner_hex,
        schedule_envelope_sha256: schedule,
        amount_units: 25,
        currency: "USD",
        expires_at: NOW + 86_400,
        locked_at: NOW,
    }
}

/// One reservation on the fixture listing, taken through to a reserved
/// slot so the cutoff line has something on it.
fn reserve_slot(fixture: &Fixture, tag: &str, listing_id: &str, allocation_id: &str) -> u64 {
    let reservation_id = format!("reservation-{tag}");
    let purchase_intent_id = format!("intent-{tag}");
    let payment_operation_id = format!("payment-{tag}");
    let encumbrance_id = format!("encumbrance-{tag}");
    let bid = digest(&format!("bid-{tag}"));
    let ask = digest(&format!("ask-{tag}"));
    let payer = hex64('b');
    let finding_id = hex64('a');
    let admission = hex64('c');
    fixture
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: &reservation_id,
            purchase_intent_id: &purchase_intent_id,
            authoritative_payment_operation_id: &payment_operation_id,
            payer_hex: &payer,
            agent_id: "agent-buyer-01",
            finding_id: &finding_id,
            listing_id,
            bid_envelope_sha256: &bid,
            ask_digest: &ask,
            admission_envelope_sha256: &admission,
            amount_units: 10,
            currency: "USD",
            expires_at: NOW + 3_600,
            encumbrance_id: &encumbrance_id,
            allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: NOW,
        })
        .expect("open reservation");
    fixture
        .purchases
        .reserve_slot(&reservation_id, NOW + 1)
        .expect("reserve slot")
}

fn settle_slot(fixture: &Fixture, tag: &str, purchase_key: &str, now: u64) {
    let reservation_id = format!("reservation-{tag}");
    let bytes = format!("{{\"schema\":\"chio.finding.purchase-record.v1\",\"tag\":\"{tag}\"}}")
        .into_bytes();
    let record_sha256 = sha256_hex(&bytes);
    fixture
        .purchases
        .close_slot_with_record(&FindingPurchaseDeliveryInput {
            reservation_id: &reservation_id,
            purchase_key,
            record_json: &bytes,
            record_sha256: &record_sha256,
            delivery_receipt_id: "receipt-delivery",
            retention_expires_at: NOW + 100_000,
            now,
        })
        .expect("settle purchase");
}

fn deny_slot(fixture: &Fixture, tag: &str, now: u64) {
    let reservation_id = format!("reservation-{tag}");
    let bytes = format!("{{\"schema\":\"chio.finding.failed-delivery.v1\",\"tag\":\"{tag}\"}}")
        .into_bytes();
    let record_sha256 = sha256_hex(&bytes);
    fixture
        .purchases
        .close_slot_with_deny(&FindingPurchaseDenyInput {
            reservation_id: &reservation_id,
            failed_delivery_id: &format!("failed-delivery-{tag}"),
            record_json: &bytes,
            record_sha256: &record_sha256,
            deny_receipt_id: "receipt-deny",
            now,
        })
        .expect("deny delivery");
}

#[test]
fn submit_challenge_inserts_replays_and_rejects_conflicts() {
    let fixture = fixture();
    let challenge = Challenge::buyer("alpha");
    assert_eq!(
        submit(&fixture, &challenge),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .get_challenge(&challenge.challenge_id)
            .expect("get challenge")
            .expect("challenge present"),
        FindingChallengeRecord {
            challenge_id: challenge.challenge_id.clone(),
            finding_id: challenge.finding_id.clone(),
            listing_id: LISTING_ID.to_string(),
            challenge_envelope_sha256: challenge.envelope_sha256.clone(),
            authorization_branch: FindingChallengeAuthorizationBranch::BuyerSubmission,
            evidence_class: FindingChallengeEvidenceClass::EvidenceInvalid,
            challenger_hex: Some(hex64('b')),
            state: FindingChallengeState::Submitted,
            retry_count: 0,
            retry_deadline: None,
            outcome_envelope_sha256: None,
            submitted_at: NOW,
            updated_at: NOW,
        },
        "every challenge column must round-trip, so a column-index swap fails here"
    );

    assert_eq!(
        submit(&fixture, &challenge),
        FindingChallengeWriteOutcome::ExistingSame,
        "an identical replay must not open a second adjudication"
    );

    // A retry carries the clock it retries from, so the submission time
    // must not decide whether it is the same challenge.
    let mut later = challenge.input();
    later.submitted_at = NOW + 30;
    assert_eq!(
        fixture
            .store
            .submit_challenge(&later)
            .expect("replay from a later clock"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        fixture
            .store
            .get_challenge(&challenge.challenge_id)
            .expect("get challenge")
            .expect("challenge present")
            .submitted_at,
        NOW,
        "a replay never moves the submission time the first call committed"
    );

    let mut conflicting = challenge.input();
    conflicting.evidence_class = FindingChallengeEvidenceClass::DigestMismatch;
    assert!(
        matches!(
            fixture.store.submit_challenge(&conflicting),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "conflicting parameters under an existing challenge id must reject"
    );

    let mut duplicate_envelope = Challenge::buyer("beta");
    duplicate_envelope
        .envelope_sha256
        .clone_from(&challenge.envelope_sha256);
    assert!(
        matches!(
            fixture.store.submit_challenge(&duplicate_envelope.input()),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one signed challenge envelope cannot open two adjudications"
    );

    let mut audit_with_challenger = Challenge::audit("gamma");
    audit_with_challenger.challenger_hex = Some(hex64('b'));
    assert!(
        matches!(
            fixture
                .store
                .submit_challenge(&audit_with_challenger.input()),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "a venue audit must not name a challenger"
    );
    let mut buyer_without_challenger = Challenge::buyer("delta");
    buyer_without_challenger.challenger_hex = None;
    assert!(
        matches!(
            fixture
                .store
                .submit_challenge(&buyer_without_challenger.input()),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "a buyer submission must name its challenger"
    );

    let audit = Challenge::audit("epsilon").in_class(FindingChallengeEvidenceClass::DigestMismatch);
    assert_eq!(
        submit(&fixture, &audit),
        FindingChallengeWriteOutcome::Inserted
    );
    let listed = fixture
        .store
        .list_challenges(&hex64('a'), LISTING_ID)
        .expect("list challenges");
    assert_eq!(listed.len(), 2);
    assert!(fixture
        .store
        .get_challenge("challenge-absent")
        .expect("absent challenge lookup")
        .is_none());
}

#[test]
fn challenge_lifecycle_admits_only_its_legal_edges() {
    let fixture = fixture();
    let upheld = Challenge::buyer("alpha");
    submit(&fixture, &upheld);
    let outcome = digest("outcome-alpha");
    assert!(
        matches!(
            fixture.store.record_verdict(
                &upheld.challenge_id,
                FindingChallengeVerdict::Upheld,
                &outcome,
                NOW + 1
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a verdict without an evaluation in progress must reject"
    );
    assert_eq!(
        fixture
            .store
            .begin_evaluation(&upheld.challenge_id, NOW + 1)
            .expect("begin evaluation"),
        FindingChallengeEvaluationStart::Started
    );
    assert_eq!(
        fixture
            .store
            .begin_evaluation(&upheld.challenge_id, NOW + 2)
            .expect("idempotent begin"),
        FindingChallengeEvaluationStart::AlreadyEvaluating
    );
    assert_eq!(
        fixture
            .store
            .record_verdict(
                &upheld.challenge_id,
                FindingChallengeVerdict::Upheld,
                &outcome,
                NOW + 3
            )
            .expect("record upheld"),
        FindingChallengeState::Upheld
    );
    assert_eq!(
        fixture
            .store
            .record_verdict(
                &upheld.challenge_id,
                FindingChallengeVerdict::Upheld,
                &outcome,
                NOW + 4
            )
            .expect("replay upheld"),
        FindingChallengeState::Upheld
    );
    assert!(
        matches!(
            fixture.store.record_verdict(
                &upheld.challenge_id,
                FindingChallengeVerdict::Rejected,
                &outcome,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a closed challenge cannot be reopened under a different verdict"
    );
    assert!(
        matches!(
            fixture.store.record_verdict(
                &upheld.challenge_id,
                FindingChallengeVerdict::Upheld,
                &digest("outcome-other"),
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a closed challenge cannot be rebound to a different outcome"
    );
    assert!(
        matches!(
            fixture
                .store
                .begin_evaluation(&upheld.challenge_id, NOW + 6),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a terminal challenge cannot re-enter evaluation"
    );

    let rejected = Challenge::buyer("beta");
    assert_eq!(
        close_challenge(
            &fixture,
            &rejected,
            FindingChallengeVerdict::Rejected,
            NOW + 1
        ),
        FindingChallengeState::Rejected
    );
    assert!(
        matches!(
            fixture.store.begin_evaluation("challenge-absent", NOW),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "an unknown challenge cannot be evaluated"
    );
    assert!(
        matches!(
            fixture.store.record_verdict(
                "challenge-absent",
                FindingChallengeVerdict::Upheld,
                &outcome,
                NOW
            ),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "an unknown challenge has no verdict to record"
    );
}

#[test]
fn bounded_retry_reaches_indeterminate_closed() {
    let fixture = fixture();

    // One retry is granted, and the next indeterminate verdict closes the
    // challenge rather than holding the bond for another round.
    let retried = Challenge::buyer("alpha");
    assert_eq!(
        close_challenge(
            &fixture,
            &retried,
            FindingChallengeVerdict::Indeterminate {
                retry_deadline: Some(RETRY_DEADLINE),
            },
            NOW + 1
        ),
        FindingChallengeState::IndeterminateRetryable
    );
    let stored = fixture
        .store
        .get_challenge(&retried.challenge_id)
        .expect("get challenge")
        .expect("challenge present");
    assert_eq!(
        (stored.retry_count, stored.retry_deadline),
        (1, Some(RETRY_DEADLINE))
    );
    assert_eq!(
        fixture
            .store
            .begin_evaluation(&retried.challenge_id, NOW + 10)
            .expect("begin the granted retry"),
        FindingChallengeEvaluationStart::Started
    );
    assert_eq!(
        fixture
            .store
            .record_verdict(
                &retried.challenge_id,
                FindingChallengeVerdict::Indeterminate {
                    retry_deadline: Some(RETRY_DEADLINE),
                },
                &digest("outcome-alpha-retry"),
                NOW + 11
            )
            .expect("record the retry verdict"),
        FindingChallengeState::IndeterminateClosed,
        "the retry bound is spent, so a second indeterminate result closes"
    );
    assert_eq!(
        fixture
            .store
            .get_challenge(&retried.challenge_id)
            .expect("get challenge")
            .expect("challenge present")
            .retry_count,
        1
    );

    // Without a signed retry window there is nothing to retry inside.
    let unwindowed = Challenge::buyer("beta");
    assert_eq!(
        close_challenge(
            &fixture,
            &unwindowed,
            FindingChallengeVerdict::Indeterminate {
                retry_deadline: None,
            },
            NOW + 1
        ),
        FindingChallengeState::IndeterminateClosed
    );

    // A window that has already lapsed grants no retry.
    let lapsed = Challenge::buyer("gamma");
    assert_eq!(
        close_challenge(
            &fixture,
            &lapsed,
            FindingChallengeVerdict::Indeterminate {
                retry_deadline: Some(NOW + 2),
            },
            NOW + 5
        ),
        FindingChallengeState::IndeterminateClosed,
        "a deadline at or before the verdict clock is not a window"
    );

    // A granted window that lapses before the retry starts closes the
    // challenge at the point the late evaluation is attempted.
    let expired = Challenge::buyer("delta");
    assert_eq!(
        close_challenge(
            &fixture,
            &expired,
            FindingChallengeVerdict::Indeterminate {
                retry_deadline: Some(NOW + 100),
            },
            NOW + 1
        ),
        FindingChallengeState::IndeterminateRetryable
    );
    assert_eq!(
        fixture
            .store
            .begin_evaluation(&expired.challenge_id, NOW + 100)
            .expect("begin evaluation at the deadline"),
        FindingChallengeEvaluationStart::RetryWindowExpired
    );
    assert_eq!(
        challenge_state(&fixture, &expired.challenge_id),
        FindingChallengeState::IndeterminateClosed,
        "a lapsed retry window closes the challenge instead of admitting a late evaluation"
    );
}

#[test]
fn dispute_bond_locks_exclusively_and_disposes_exactly_once() {
    let fixture = fixture();
    let schedule = digest("dispute-schedule");
    let owner = hex64('b');

    let audit = Challenge::audit("audit");
    submit(&fixture, &audit);
    assert!(
        matches!(
            fixture.store.lock_dispute_bond(&lock_input(
                "lock-audit",
                &audit.challenge_id,
                &owner,
                &schedule
            )),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a bondless venue audit posts no dispute bond"
    );

    let upheld = Challenge::buyer("alpha");
    submit(&fixture, &upheld);
    assert!(
        matches!(
            fixture.store.lock_dispute_bond(&lock_input(
                "lock-wrong-owner",
                &upheld.challenge_id,
                &hex64('c'),
                &schedule
            )),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a bond owned by anyone but the challenger must reject"
    );
    let lock = lock_input("lock-alpha", &upheld.challenge_id, &owner, &schedule);
    assert_eq!(
        fixture.store.lock_dispute_bond(&lock).expect("lock bond"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .get_dispute_lock(&upheld.challenge_id)
            .expect("get lock")
            .expect("lock present"),
        FindingDisputeLockRecord {
            lock_id: "lock-alpha".to_string(),
            challenge_id: upheld.challenge_id.clone(),
            owner_hex: owner.clone(),
            bond_class: "dispute".to_string(),
            schedule_envelope_sha256: schedule.clone(),
            amount_units: 25,
            currency: "USD".to_string(),
            expires_at: NOW + 86_400,
            state: FindingDisputeLockState::Locked,
            locked_at: NOW,
            updated_at: NOW,
        }
    );
    assert_eq!(
        fixture.store.lock_dispute_bond(&lock).expect("replay lock"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    let mut conflicting = lock;
    conflicting.amount_units = 26;
    assert!(
        matches!(
            fixture.store.lock_dispute_bond(&conflicting),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a second bond under one challenge must reject"
    );

    // A lock id is bound to exactly one challenge and is never reused.
    let other = Challenge::buyer("beta");
    submit(&fixture, &other);
    assert!(
        matches!(
            fixture.store.lock_dispute_bond(&lock_input(
                "lock-alpha",
                &other.challenge_id,
                &owner,
                &schedule
            )),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one lock cannot back two challenges"
    );

    assert!(
        matches!(
            fixture.store.release_dispute_bond(
                &upheld.challenge_id,
                FindingDisputeLockDisposition::Returned,
                NOW + 1
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a live challenge's bond is not yet disposable"
    );

    fixture
        .store
        .begin_evaluation(&upheld.challenge_id, NOW + 1)
        .expect("begin evaluation");
    fixture
        .store
        .record_verdict(
            &upheld.challenge_id,
            FindingChallengeVerdict::Upheld,
            &digest("outcome-alpha"),
            NOW + 2,
        )
        .expect("record upheld");
    assert!(
        matches!(
            fixture.store.release_dispute_bond(
                &upheld.challenge_id,
                FindingDisputeLockDisposition::Forfeited,
                NOW + 3
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "an upheld challenge's bond can never be forfeited"
    );
    assert_eq!(
        fixture
            .store
            .release_dispute_bond(
                &upheld.challenge_id,
                FindingDisputeLockDisposition::Returned,
                NOW + 3
            )
            .expect("return bond"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .release_dispute_bond(
                &upheld.challenge_id,
                FindingDisputeLockDisposition::Returned,
                NOW + 4
            )
            .expect("replay return"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(
        matches!(
            fixture.store.release_dispute_bond(
                &upheld.challenge_id,
                FindingDisputeLockDisposition::Forfeited,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a returned bond cannot then be forfeited"
    );

    // A rejected challenge is the only one whose bond may be forfeited.
    fixture
        .store
        .lock_dispute_bond(&lock_input(
            "lock-beta",
            &other.challenge_id,
            &owner,
            &schedule,
        ))
        .expect("lock beta bond");
    fixture
        .store
        .begin_evaluation(&other.challenge_id, NOW + 1)
        .expect("begin evaluation");
    fixture
        .store
        .record_verdict(
            &other.challenge_id,
            FindingChallengeVerdict::Rejected,
            &digest("outcome-beta"),
            NOW + 2,
        )
        .expect("record rejected");
    assert_eq!(
        fixture
            .store
            .release_dispute_bond(
                &other.challenge_id,
                FindingDisputeLockDisposition::Forfeited,
                NOW + 3
            )
            .expect("forfeit bond"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .get_dispute_lock(&other.challenge_id)
            .expect("get lock")
            .expect("lock present")
            .state,
        FindingDisputeLockState::Forfeited
    );

    // An indeterminate close never forfeits for an infrastructure failure.
    let stalled = Challenge::buyer("gamma");
    submit(&fixture, &stalled);
    fixture
        .store
        .lock_dispute_bond(&lock_input(
            "lock-gamma",
            &stalled.challenge_id,
            &owner,
            &schedule,
        ))
        .expect("lock gamma bond");
    fixture
        .store
        .begin_evaluation(&stalled.challenge_id, NOW + 1)
        .expect("begin evaluation");
    fixture
        .store
        .record_verdict(
            &stalled.challenge_id,
            FindingChallengeVerdict::Indeterminate {
                retry_deadline: None,
            },
            &digest("outcome-gamma"),
            NOW + 2,
        )
        .expect("record indeterminate");
    assert!(
        matches!(
            fixture.store.release_dispute_bond(
                &stalled.challenge_id,
                FindingDisputeLockDisposition::Forfeited,
                NOW + 3
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "an indeterminate close never forfeits a bond"
    );
    assert_eq!(
        fixture
            .store
            .release_dispute_bond(
                &stalled.challenge_id,
                FindingDisputeLockDisposition::Returned,
                NOW + 3
            )
            .expect("return the stalled bond"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert!(
        matches!(
            fixture.store.release_dispute_bond(
                "challenge-absent",
                FindingDisputeLockDisposition::Returned,
                NOW
            ),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "an unlocked challenge has no bond to dispose"
    );
}

#[test]
fn liability_head_advances_only_by_compare_and_set() {
    let fixture = fixture();
    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    assert_eq!(
        open_liability(&fixture, &head),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        liability(&fixture, &head.liability_key),
        FindingLiabilityRecord {
            liability_key: head.liability_key.clone(),
            defect_key: head.defect_key.clone(),
            finding_id: head.finding_id.clone(),
            listing_id: LISTING_ID.to_string(),
            allocation_id: fixture.allocation_id.clone(),
            venue_id: "venue-01".to_string(),
            chain_id: "eip155:8453".to_string(),
            vault_contract: "0xvault".to_string(),
            vault_id: "vault-01".to_string(),
            state: FindingLiabilityState::Open,
            upheld_challenge_id: None,
            purchase_cutoff_slot: None,
            snapshot_digest: None,
            allocation_digest: None,
            publication_pending: false,
            quarantined: false,
            opened_at: NOW,
            updated_at: NOW,
        },
        "every liability column must round-trip, so a column-index swap fails here"
    );
    assert_eq!(
        open_liability(&fixture, &head),
        FindingChallengeWriteOutcome::ExistingSame
    );
    let mut conflicting = head.input();
    conflicting.vault_id = "vault-02";
    assert!(
        matches!(
            fixture.store.open_liability(&conflicting),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one liability key cannot name two vaults"
    );

    // Nothing advances before the head is upheld, and no caller can name
    // a later state to skip an edge.
    assert!(
        matches!(
            fixture.store.begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                NOW + 1
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "an open liability has not reached the appeal window"
    );
    assert!(
        matches!(
            fixture.store.begin_finalizing(
                &head.liability_key,
                FindingLiabilityState::Open,
                NOW + 1
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "open is not the source of the finalizing edge"
    );

    let challenge = Challenge::buyer("alpha");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(&head.liability_key, &challenge.challenge_id, 0, NOW + 3)
        .expect("uphold liability");
    assert!(
        matches!(
            fixture.store.begin_finalizing(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 4
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a head at upheld_pending_claims cannot skip the appeal window"
    );
    assert!(
        matches!(
            fixture.store.settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 4
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a head at upheld_pending_claims cannot skip to settled"
    );
    assert_eq!(
        fixture
            .store
            .begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                NOW + 4
            )
            .expect("open the appeal window"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                NOW + 5
            )
            .expect("replay the appeal window"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        fixture
            .store
            .begin_finalizing(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 6
            )
            .expect("finalize"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert!(
        liability(&fixture, &head.liability_key).publication_pending,
        "finalizing marks the publication pending"
    );
    assert_eq!(
        fixture
            .store
            .set_liability_quarantine(&head.liability_key, true, NOW + 7)
            .expect("quarantine"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .set_liability_quarantine(&head.liability_key, true, NOW + 8)
            .expect("replay quarantine"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    fixture
        .store
        .set_liability_quarantine(&head.liability_key, false, NOW + 9)
        .expect("clear quarantine");
    assert_eq!(
        fixture
            .store
            .settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 10
            )
            .expect("settle"),
        FindingChallengeWriteOutcome::Inserted
    );
    let settled = liability(&fixture, &head.liability_key);
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.publication_pending);
    assert!(
        matches!(
            fixture
                .store
                .set_liability_quarantine(&head.liability_key, true, NOW + 11),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a settled liability is terminal"
    );

    // The appeal terminal closes the head without an impairment.
    let reversed = Liability::new("beta", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &reversed);
    let appeal_challenge = Challenge::buyer("beta");
    close_challenge(
        &fixture,
        &appeal_challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(
            &reversed.liability_key,
            &appeal_challenge.challenge_id,
            0,
            NOW + 3,
        )
        .expect("uphold liability");
    fixture
        .store
        .begin_appeal_window(
            &reversed.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            NOW + 4,
        )
        .expect("open the appeal window");
    assert_eq!(
        fixture
            .store
            .reverse_liability_before_impairment(
                &reversed.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 5
            )
            .expect("reverse before impairment"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        liability(&fixture, &reversed.liability_key).state,
        FindingLiabilityState::ReversedBeforeImpairment
    );
    assert!(
        matches!(
            fixture.store.begin_finalizing(
                &reversed.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 6
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a reversed liability never finalizes"
    );
    assert_eq!(
        fixture
            .store
            .list_liabilities_for_defect(&head.defect_key)
            .expect("list by defect")
            .len(),
        1
    );
    assert!(
        matches!(
            fixture.store.begin_appeal_window(
                &digest("liability-absent"),
                FindingLiabilityState::UpheldPendingClaims,
                NOW
            ),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "an unknown liability has no edge to take"
    );
}

#[test]
fn upholding_blocks_new_slots_and_freezes_the_cutoff() {
    let fixture = fixture();
    assert_eq!(
        reserve_slot(&fixture, "alpha", LISTING_ID, &fixture.allocation_id),
        1
    );
    assert_eq!(
        reserve_slot(&fixture, "beta", LISTING_ID, &fixture.allocation_id),
        2
    );
    settle_slot(&fixture, "alpha", &hex64('d'), NOW + 2);

    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("alpha");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 3,
    );

    let live = Challenge::buyer("live");
    submit(&fixture, &live);
    assert!(
        matches!(
            fixture
                .store
                .uphold_liability(&head.liability_key, &live.challenge_id, 2, NOW + 5),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "only an upheld challenge can uphold a liability"
    );
    let elsewhere = Challenge::buyer("elsewhere").on_listing(OTHER_LISTING_ID);
    close_challenge(
        &fixture,
        &elsewhere,
        FindingChallengeVerdict::Upheld,
        NOW + 3,
    );
    assert!(
        matches!(
            fixture.store.uphold_liability(
                &head.liability_key,
                &elsewhere.challenge_id,
                2,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a challenge on another listing cannot uphold this liability"
    );
    assert!(
        matches!(
            fixture.store.uphold_liability(
                &head.liability_key,
                &challenge.challenge_id,
                1,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a cutoff below the slot high-water mark would strand a buyer who paid before the block"
    );
    assert!(
        !fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "a refused uphold must leave the listing selling"
    );

    assert_eq!(
        fixture
            .store
            .uphold_liability(&head.liability_key, &challenge.challenge_id, 2, NOW + 5)
            .expect("uphold liability"),
        FindingChallengeWriteOutcome::Inserted
    );
    let upheld = liability(&fixture, &head.liability_key);
    assert_eq!(upheld.state, FindingLiabilityState::UpheldPendingClaims);
    assert_eq!(
        upheld.upheld_challenge_id.as_deref(),
        Some(challenge.challenge_id.as_str())
    );
    assert_eq!(upheld.purchase_cutoff_slot, Some(2));
    assert!(
        fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "the upheld transaction blocks the listing in the same commit"
    );

    // No new slot can open above the frozen cutoff.
    let blocked_reservation = "reservation-gamma";
    fixture
        .purchases
        .open_reservation(&FindingPurchaseReservationInput {
            reservation_id: blocked_reservation,
            purchase_intent_id: "intent-gamma",
            authoritative_payment_operation_id: "payment-gamma",
            payer_hex: &hex64('b'),
            agent_id: "agent-buyer-01",
            finding_id: &hex64('a'),
            listing_id: LISTING_ID,
            bid_envelope_sha256: &digest("bid-gamma"),
            ask_digest: &digest("ask-gamma"),
            admission_envelope_sha256: &hex64('c'),
            amount_units: 10,
            currency: "USD",
            expires_at: NOW + 3_600,
            encumbrance_id: "encumbrance-gamma",
            allocation_id: &fixture.allocation_id,
            maximum_sale_exposure_units: REGISTERED_EXPOSURE_CAP,
            created_at: NOW,
        })
        .expect("open reservation");
    assert!(
        matches!(
            fixture.purchases.reserve_slot(blocked_reservation, NOW + 6),
            Err(FindingPurchaseStoreError::SalesBlocked(_))
        ),
        "no slot may open once the upheld transaction has blocked the listing"
    );

    assert_eq!(
        fixture
            .store
            .uphold_liability(&head.liability_key, &challenge.challenge_id, 2, NOW + 7)
            .expect("replay uphold"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(
        matches!(
            fixture.store.uphold_liability(
                &head.liability_key,
                &challenge.challenge_id,
                3,
                NOW + 8
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "the frozen cutoff never moves"
    );
    assert_eq!(
        liability(&fixture, &head.liability_key).purchase_cutoff_slot,
        Some(2)
    );
}

#[test]
fn pre_cutoff_wait_predicate_is_exact() {
    let fixture = fixture();
    for tag in ["alpha", "beta", "gamma"] {
        reserve_slot(&fixture, tag, LISTING_ID, &fixture.allocation_id);
    }
    assert!(
        fixture
            .purchases
            .all_slots_closed_at_or_below(LISTING_ID, 0)
            .expect("wait predicate"),
        "a cutoff of zero has nothing to wait for"
    );
    for cutoff in 1..=3 {
        assert!(
            !fixture
                .purchases
                .all_slots_closed_at_or_below(LISTING_ID, cutoff)
                .expect("wait predicate"),
            "slot {cutoff} is still reserved"
        );
    }
    settle_slot(&fixture, "alpha", &hex64('d'), NOW + 2);
    assert!(
        fixture
            .purchases
            .all_slots_closed_at_or_below(LISTING_ID, 1)
            .expect("wait predicate"),
        "the only slot at or below one has closed"
    );
    assert!(
        !fixture
            .purchases
            .all_slots_closed_at_or_below(LISTING_ID, 2)
            .expect("wait predicate"),
        "slot two is still reserved"
    );
    deny_slot(&fixture, "beta", NOW + 3);
    assert!(
        fixture
            .purchases
            .all_slots_closed_at_or_below(LISTING_ID, 2)
            .expect("wait predicate"),
        "a denial closes a slot exactly as a settled record does"
    );
    assert!(
        !fixture
            .purchases
            .all_slots_closed_at_or_below(LISTING_ID, 3)
            .expect("wait predicate"),
        "a slot above the cutoff does not satisfy a higher cutoff"
    );
    assert!(
        fixture
            .purchases
            .all_slots_closed_at_or_below("challenge-listing-unknown", 9)
            .expect("wait predicate"),
        "a listing with no slots is trivially settled"
    );
}

#[test]
fn case_head_resolves_one_live_case_and_rejects_two() {
    let fixture = fixture();
    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);

    let sanction = FindingGovernanceCaseInput {
        case_id: "case-sanction-01",
        finding_id: &head.finding_id,
        listing_id: LISTING_ID,
        liability_key: &head.liability_key,
        case_kind: FindingGovernanceCaseKind::Sanction,
        case_state: "Enforced",
        appeal_of_case_id: None,
        supersedes_case_id: None,
        recorded_at: NOW,
    };
    assert_eq!(
        fixture
            .store
            .record_governance_case(&sanction)
            .expect("record sanction"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .record_governance_case(&sanction)
            .expect("replay sanction"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    let mut conflicting = sanction;
    conflicting.case_state = "Open";
    assert!(
        matches!(
            fixture.store.record_governance_case(&conflicting),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one case id cannot carry two states"
    );
    assert_eq!(
        fixture
            .store
            .resolve_case_head(&head.liability_key)
            .expect("resolve head")
            .expect("head present")
            .case_id,
        "case-sanction-01"
    );

    let appeal = FindingGovernanceCaseInput {
        case_id: "case-appeal-01",
        case_kind: FindingGovernanceCaseKind::Appeal,
        appeal_of_case_id: Some("case-sanction-01"),
        supersedes_case_id: Some("case-sanction-01"),
        recorded_at: NOW + 10,
        ..sanction
    };
    fixture
        .store
        .record_governance_case(&appeal)
        .expect("record appeal");
    assert_eq!(
        fixture
            .store
            .resolve_case_head(&head.liability_key)
            .expect("resolve head")
            .expect("head present")
            .case_id,
        "case-appeal-01",
        "the appeal supersedes the sanction and becomes the head"
    );
    assert_eq!(
        fixture
            .store
            .get_governance_case("case-sanction-01")
            .expect("get case")
            .expect("case present")
            .superseded_by_case_id
            .as_deref(),
        Some("case-appeal-01"),
        "the supersession is stamped in the same transaction"
    );

    let second_appeal = FindingGovernanceCaseInput {
        case_id: "case-appeal-02",
        supersedes_case_id: Some("case-sanction-01"),
        recorded_at: NOW + 11,
        ..appeal
    };
    assert!(
        matches!(
            fixture.store.record_governance_case(&second_appeal),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a case is superseded exactly once"
    );
    let appeal_of_appeal = FindingGovernanceCaseInput {
        case_id: "case-appeal-03",
        appeal_of_case_id: Some("case-appeal-01"),
        supersedes_case_id: None,
        recorded_at: NOW + 12,
        ..appeal
    };
    assert!(
        matches!(
            fixture.store.record_governance_case(&appeal_of_appeal),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "an appeal targets a sanction, not another appeal"
    );

    // A second live sanction on the same defect leaves the operator unable
    // to say which case governs it, so no head resolves at all.
    let rival = FindingGovernanceCaseInput {
        case_id: "case-sanction-02",
        case_kind: FindingGovernanceCaseKind::Sanction,
        appeal_of_case_id: None,
        supersedes_case_id: None,
        recorded_at: NOW + 20,
        ..sanction
    };
    fixture
        .store
        .record_governance_case(&rival)
        .expect("record the rival sanction");
    match fixture.store.resolve_case_head(&head.liability_key) {
        Err(FindingChallengeStoreError::AmbiguousCaseHead {
            first_case_id,
            second_case_id,
            ..
        }) => assert_eq!(
            (first_case_id.as_str(), second_case_id.as_str()),
            ("case-appeal-01", "case-sanction-02")
        ),
        other => panic!("two live cases must refuse to resolve a head, got {other:?}"),
    }
    assert_eq!(
        fixture
            .store
            .list_governance_cases(&head.liability_key)
            .expect("list cases")
            .len(),
        3
    );

    // Cases are scoped to their liability, so a fresh head resolves alone.
    let other = Liability::new("beta", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &other);
    assert!(fixture
        .store
        .resolve_case_head(&other.liability_key)
        .expect("resolve empty head")
        .is_none());
    let unknown = FindingGovernanceCaseInput {
        case_id: "case-orphan",
        liability_key: &digest("liability-absent"),
        recorded_at: NOW,
        ..sanction
    };
    assert!(
        matches!(
            fixture.store.record_governance_case(&unknown),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "a case must target a recorded liability"
    );
}

#[test]
fn claim_snapshot_seals_once_against_the_frozen_cutoff() {
    let fixture = fixture();
    reserve_slot(&fixture, "alpha", LISTING_ID, &fixture.allocation_id);
    settle_slot(&fixture, "alpha", &hex64('d'), NOW + 2);
    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let snapshot_digest = digest("claim-snapshot");
    let allocation_digest = digest("allocation-snapshot");
    let sealed = FindingClaimSnapshotInput {
        liability_key: &head.liability_key,
        cutoff_slot: 1,
        snapshot_digest: &snapshot_digest,
        allocation_digest: &allocation_digest,
        total_realized_spend_units: 10,
        currency: "USD",
        buyer_pool_units: 10,
        community_fund_units: 5,
        sealed_at: NOW + 10,
    };
    assert!(
        matches!(
            fixture.store.seal_claim_snapshot(&sealed),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "an open liability has no frozen cutoff to seal against"
    );

    let challenge = Challenge::buyer("alpha");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 3,
    );
    fixture
        .store
        .uphold_liability(&head.liability_key, &challenge.challenge_id, 1, NOW + 5)
        .expect("uphold liability");

    let mut wrong_cutoff = sealed;
    wrong_cutoff.cutoff_slot = 2;
    assert!(
        matches!(
            fixture.store.seal_claim_snapshot(&wrong_cutoff),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a snapshot must seal the cutoff the uphold froze"
    );
    let mut over_capped = sealed;
    over_capped.buyer_pool_units = 11;
    assert!(
        matches!(
            fixture.store.seal_claim_snapshot(&over_capped),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "the buyer pool is capped by verified realized spend"
    );

    assert_eq!(
        fixture
            .store
            .seal_claim_snapshot(&sealed)
            .expect("seal snapshot"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .get_claim_snapshot(&head.liability_key)
            .expect("get snapshot")
            .expect("snapshot present"),
        FindingClaimSnapshotRecord {
            liability_key: head.liability_key.clone(),
            cutoff_slot: 1,
            snapshot_digest: snapshot_digest.clone(),
            allocation_digest: allocation_digest.clone(),
            total_realized_spend_units: 10,
            currency: "USD".to_string(),
            buyer_pool_units: 10,
            community_fund_units: 5,
            sealed_at: NOW + 10,
        }
    );
    let stamped = liability(&fixture, &head.liability_key);
    assert_eq!(
        stamped.snapshot_digest.as_deref(),
        Some(snapshot_digest.as_str())
    );
    assert_eq!(
        stamped.allocation_digest.as_deref(),
        Some(allocation_digest.as_str())
    );
    assert_eq!(
        fixture
            .store
            .seal_claim_snapshot(&sealed)
            .expect("replay seal"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    let mut different = sealed;
    different.community_fund_units = 6;
    assert!(
        matches!(
            fixture.store.seal_claim_snapshot(&different),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a sealed snapshot is never rewritten"
    );
}

#[test]
fn effect_intents_reconcile_identical_retries_and_reject_conflicts() {
    let fixture = fixture();
    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let intent_key = digest("chio.finding.effect.seller-impair.v1");
    let intent_digest = digest("seller-impair-commitment");

    assert_eq!(
        fixture
            .store
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::SellerImpair,
                &intent_digest,
                Some(&head.liability_key),
                NOW
            )
            .expect("record intent"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::SellerImpair,
                &intent_digest,
                Some(&head.liability_key),
                NOW + 1
            )
            .expect("identical retry reconciles"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    for (kind, commitment, liability_key) in [
        (
            FindingEffectIntentKind::SellerImpair,
            digest("seller-impair-other"),
            Some(head.liability_key.clone()),
        ),
        (
            FindingEffectIntentKind::Retraction,
            intent_digest.clone(),
            Some(head.liability_key.clone()),
        ),
        (
            FindingEffectIntentKind::SellerImpair,
            intent_digest.clone(),
            None,
        ),
    ] {
        assert!(
            matches!(
                fixture.store.record_effect_intent(
                    &intent_key,
                    kind,
                    &commitment,
                    liability_key.as_deref(),
                    NOW + 2
                ),
                Err(FindingChallengeStoreError::Conflict(_))
            ),
            "a conflicting disposition under one intent key must reject"
        );
    }
    assert_eq!(
        fixture
            .store
            .get_effect_intent(&intent_key)
            .expect("get intent")
            .expect("intent present"),
        FindingEffectIntentRecord {
            intent_key: intent_key.clone(),
            liability_key: Some(head.liability_key.clone()),
            kind: FindingEffectIntentKind::SellerImpair,
            intent_digest: intent_digest.clone(),
            state: FindingEffectIntentState::Pending,
            attempt_count: 0,
            recorded_at: NOW,
            updated_at: NOW,
        }
    );

    assert_eq!(
        fixture
            .store
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, NOW + 3)
            .expect("dispatch"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert_eq!(
        fixture
            .store
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, NOW + 4)
            .expect("replay dispatch"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(
        matches!(
            fixture.store.advance_effect_intent(
                &intent_key,
                FindingEffectIntentState::Pending,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a dispatched intent never returns to pending"
    );
    fixture
        .store
        .advance_effect_intent(&intent_key, FindingEffectIntentState::Failed, NOW + 6)
        .expect("fail");
    fixture
        .store
        .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, NOW + 7)
        .expect("redispatch");
    assert_eq!(
        fixture
            .store
            .get_effect_intent(&intent_key)
            .expect("get intent")
            .expect("intent present")
            .attempt_count,
        2,
        "each dispatch counts one attempt"
    );
    fixture
        .store
        .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, NOW + 8)
        .expect("confirm");
    assert!(
        matches!(
            fixture.store.advance_effect_intent(
                &intent_key,
                FindingEffectIntentState::Failed,
                NOW + 9
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a confirmed intent is terminal"
    );

    // A liability-free intent is legal, and an ambiguous one quarantines.
    let bond_key = digest("chio.finding.effect.challenge-bond.v1");
    fixture
        .store
        .record_effect_intent(
            &bond_key,
            FindingEffectIntentKind::ChallengeBond,
            &digest("bond-returned"),
            None,
            NOW,
        )
        .expect("record bond intent");
    fixture
        .store
        .advance_effect_intent(&bond_key, FindingEffectIntentState::Quarantined, NOW + 1)
        .expect("quarantine");
    assert!(
        matches!(
            fixture.store.advance_effect_intent(
                &bond_key,
                FindingEffectIntentState::Dispatched,
                NOW + 2
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a quarantined intent is never dispatched"
    );
    assert_eq!(
        fixture
            .store
            .list_effect_intents(&head.liability_key)
            .expect("list intents")
            .len(),
        1,
        "a liability-free intent belongs to no liability"
    );
    assert!(
        matches!(
            fixture.store.record_effect_intent(
                &digest("orphan-intent"),
                FindingEffectIntentKind::Fee,
                &digest("fee-commitment"),
                Some(&digest("liability-absent")),
                NOW
            ),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "an intent cannot name a liability that was never opened"
    );
    assert!(
        matches!(
            fixture.store.advance_effect_intent(
                &digest("intent-absent"),
                FindingEffectIntentState::Dispatched,
                NOW
            ),
            Err(FindingChallengeStoreError::NotFound)
        ),
        "an unknown intent has no state to advance"
    );
}

#[test]
fn schema_shape_is_verified_on_every_open() {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_temp_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root).expect("create lock root");
    secure_temp_directory(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    {
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
        assert!(authority
            .finding_challenge_store()
            .get_challenge("challenge-absent")
            .expect("read on a clean schema")
            .is_none());
    }

    // Drop a lifecycle trigger out of band, the way a partial restore or a
    // hand-edited database would, and confirm the open refuses rather than
    // serving a schema that no longer enforces the lifecycle.
    {
        let raw = rusqlite::Connection::open(&database).expect("open raw connection");
        raw.execute_batch("DROP TRIGGER challenges_lifecycle;")
            .expect("drop the lifecycle trigger");
    }
    assert!(
        SqliteAuthorityStore::open_serving(&database, &lock_root).is_err(),
        "a schema that differs from the canonical definition must fail the open"
    );

    // Restoring the canonical schema restores the open: every statement in
    // the schema is an idempotent guard.
    {
        let raw = rusqlite::Connection::open(&database).expect("open raw connection");
        raw.execute_batch(FINDING_CHALLENGE_SCHEMA)
            .expect("restore the canonical schema");
    }
    SqliteAuthorityStore::open_serving(&database, &lock_root).expect("reopen with intact schema");
}
