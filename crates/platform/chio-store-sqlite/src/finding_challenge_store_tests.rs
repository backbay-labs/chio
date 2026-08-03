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
use crate::finding_market_store::{FindingRecordInput, SqliteFindingMarketStore};
use crate::finding_purchase_store::{
    FindingPurchaseDeliveryInput, FindingPurchaseDenyInput, FindingPurchaseReservationInput,
    FindingPurchaseStoreError, SqliteFindingPurchaseStore,
};
use crate::SqliteAuthorityStore;

const LISTING_ID: &str = "challenge-listing-01";
const OTHER_LISTING_ID: &str = "challenge-listing-02";
const NOW: u64 = 1_750_000_000;
const RETRY_DEADLINE: u64 = NOW + 3_600;
/// Seller-signed claim window every upheld liability in these tests
/// freezes, measured from the instant the window opens.
const CLAIM_WINDOW: u64 = 604_800;
/// Seller-signed appeal duration frozen when a liability enters its
/// appeal window.
const APPEAL_WINDOW: u64 = 259_200;
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
    publish_finding(&market);
    let allocation_id = consume_allocation(&market, "vault:finding-collateral", LISTING_ID);
    purchases
        .install_active_admission_for_tests(
            &hex64('a'),
            &allocation_id,
            LISTING_ID,
            &hex64('d'),
            &hex64('c'),
            NOW,
        )
        .expect("install active admission");
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

fn publish_finding(market: &SqliteFindingMarketStore) {
    let finding_id = hex64('a');
    let artifact = format!("{{\"finding_id\":\"{finding_id}\"}}");
    market
        .put_finding(
            &FindingRecordInput {
                finding_id: &finding_id,
                artifact_json: &artifact,
                topic: "challenge-store-test",
                context_sha256: &hex64('0'),
                issued_at: 1_700_000_000,
                expires_at: 1_900_000_000,
            },
            NOW,
        )
        .expect("publish finding");
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

fn confirm_settlement_effects(fixture: &Fixture, liability_key: &str, now: u64) {
    for (tag, kind) in [
        ("seller-impair", FindingEffectIntentKind::SellerImpair),
        ("root-intent", FindingEffectIntentKind::RootIntent),
        ("retraction", FindingEffectIntentKind::Retraction),
    ] {
        let intent_key = digest(&format!("{liability_key}-{tag}-intent"));
        fixture
            .store
            .record_effect_intent(
                &intent_key,
                kind,
                &digest(&format!("{liability_key}-{tag}-commitment")),
                Some(liability_key),
                true,
                now,
            )
            .expect("record required settlement effect");
        fixture
            .store
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Dispatched, now)
            .expect("dispatch required settlement effect");
        fixture
            .store
            .advance_effect_intent(&intent_key, FindingEffectIntentState::Confirmed, now)
            .expect("confirm required settlement effect");
    }
}

fn remove_schema_fragment(schema: String, fragment: &str) -> String {
    assert!(
        schema.contains(fragment),
        "the legacy fixture fragment must match the canonical schema"
    );
    schema.replacen(fragment, "", 1)
}

fn finding_challenge_v5_schema() -> String {
    let (before, reservation_and_after) = FINDING_CHALLENGE_SCHEMA
        .split_once("CREATE TABLE IF NOT EXISTS dispute_lock_reservations")
        .expect("v6 reservation schema marker");
    let (_, after) = reservation_and_after
        .split_once("CREATE TABLE IF NOT EXISTS dispute_locks")
        .expect("dispute lock schema marker");
    format!("{before}CREATE TABLE IF NOT EXISTS dispute_locks{after}")
}

fn finding_challenge_v4_schema() -> String {
    finding_challenge_v5_schema()
        .split_once("-- Immutable local history for the challenge projection.")
        .expect("v5 projection schema marker")
        .0
        .to_owned()
}

fn finding_challenge_v3_schema() -> String {
    let schema = finding_challenge_v5_schema().replace(
        "OLD.state = 'submitted' AND NEW.state IN ('evaluating', 'indeterminate_closed')",
        "OLD.state = 'submitted' AND NEW.state = 'evaluating'",
    );
    let mut schema = remove_schema_fragment(
        schema,
        r#"    pool_principal_id TEXT NOT NULL
        CHECK (length(pool_principal_id) BETWEEN 1 AND 512),
    pool_rail_destination TEXT NOT NULL
        CHECK (length(pool_rail_destination) BETWEEN 1 AND 512),
    pool_authority_epoch INTEGER NOT NULL CHECK (pool_authority_epoch > 0),
"#,
    );
    for fragment in [
        "  OR NEW.pool_principal_id <> OLD.pool_principal_id\n",
        "  OR NEW.pool_rail_destination <> OLD.pool_rail_destination\n",
        "  OR NEW.pool_authority_epoch <> OLD.pool_authority_epoch\n",
    ] {
        schema = remove_schema_fragment(schema, fragment);
    }
    schema
}

fn finding_challenge_v2_schema() -> String {
    let mut schema = finding_challenge_v5_schema();
    for fragment in [
        r#"    -- The appeal window is derived from the seller-signed terms when the
    -- head enters pending_appeal, then frozen for the rest of the lifecycle.
    appeal_window_opened_at INTEGER CHECK (
        appeal_window_opened_at IS NULL OR appeal_window_opened_at > 0
    ),
    appeal_deadline INTEGER CHECK (
        appeal_deadline IS NULL OR appeal_deadline > 0
    ),
    appeal_terms_envelope_sha256 TEXT CHECK (
        appeal_terms_envelope_sha256 IS NULL
        OR (length(appeal_terms_envelope_sha256) = 64
            AND appeal_terms_envelope_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
"#,
        r#"    -- All three appeal-window commitments appear together exactly when the
    -- liability reaches the appeal edge or a later state.
    CHECK ((appeal_window_opened_at IS NULL) = (appeal_deadline IS NULL)),
    CHECK ((appeal_window_opened_at IS NULL)
           = (appeal_terms_envelope_sha256 IS NULL)),
    CHECK (appeal_deadline IS NULL
           OR appeal_deadline > appeal_window_opened_at),
    CHECK ((appeal_deadline IS NOT NULL) = (state IN (
        'pending_appeal', 'finalizing', 'settled',
        'reversed_before_impairment'
    ))),
"#,
        r#"  OR (OLD.appeal_window_opened_at IS NOT NULL
      AND NEW.appeal_window_opened_at IS NOT OLD.appeal_window_opened_at)
  OR (OLD.appeal_deadline IS NOT NULL
      AND NEW.appeal_deadline IS NOT OLD.appeal_deadline)
  OR (OLD.appeal_terms_envelope_sha256 IS NOT NULL
      AND NEW.appeal_terms_envelope_sha256
          IS NOT OLD.appeal_terms_envelope_sha256)
"#,
        "    settlement_required INTEGER NOT NULL CHECK (settlement_required IN (0, 1)),\n",
        "  OR NEW.settlement_required <> OLD.settlement_required\n",
    ] {
        schema = remove_schema_fragment(schema, fragment);
    }
    schema
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
        pool_principal_id: "challenge-pool",
        pool_rail_destination: "rail:challenge-pool",
        pool_authority_epoch: 1,
        expires_at: NOW + 86_400,
        locked_at: NOW,
    }
}

fn fund_lock(fixture: &Fixture, input: &FindingDisputeLockInput<'_>) {
    let key = derive_dispute_bond_funding_intent_key(input.challenge_id, input.lock_id);
    fixture
        .store
        .record_effect_intent(
            &key,
            FindingEffectIntentKind::ChallengeBond,
            &dispute_bond_funding_intent_digest(input),
            None,
            false,
            NOW,
        )
        .expect("fence dispute bond funding");
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        fixture
            .store
            .advance_effect_intent(&key, state, NOW)
            .expect("confirm dispute bond funding");
    }
}

fn confirm_lock_return(fixture: &Fixture, input: &FindingDisputeLockInput<'_>) {
    let key = derive_dispute_bond_return_intent_key(input.challenge_id, input.lock_id);
    fixture
        .store
        .record_effect_intent(
            &key,
            FindingEffectIntentKind::ChallengeBond,
            &dispute_bond_return_intent_digest(input),
            None,
            false,
            NOW,
        )
        .expect("fence dispute bond return");
    for state in [
        FindingEffectIntentState::Dispatched,
        FindingEffectIntentState::Confirmed,
    ] {
        fixture
            .store
            .advance_effect_intent(&key, state, NOW)
            .expect("confirm dispute bond return");
    }
}

fn lock_dispute_bond(
    fixture: &Fixture,
    input: &FindingDisputeLockInput<'_>,
) -> Result<FindingChallengeWriteOutcome, FindingChallengeStoreError> {
    fixture.store.reserve_dispute_lock(input, NOW)?;
    fund_lock(fixture, input);
    fixture.store.lock_dispute_bond(input)
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
            payout_destination: "0x000000000000000000000000000000000000002a",
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
            payout_destination: "rail:venue-ledger:buyer-42",
            retention_expires_at: NOW + 100_000,
            now,
        })
        .expect("settle purchase");
}

/// Every sales-block episode on one listing, oldest first, as
/// `(ordinal, state, blocked_at, lifted_at)`. Read straight from the
/// database: the raise a release leaves behind is a record this lane
/// retains, not a state the sale path serves.
fn sales_block_episodes(
    fixture: &Fixture,
    listing_id: &str,
) -> Vec<(u64, String, u64, Option<u64>)> {
    let connection =
        Connection::open(fixture._temp.path().join("authority.db")).expect("open the database");
    let mut statement = connection
        .prepare(
            r#"
            SELECT block_ordinal, state, blocked_at, lifted_at
            FROM listing_sales_blocks
            WHERE listing_id = ?1
            ORDER BY block_ordinal ASC
            "#,
        )
        .expect("prepare the episode read");
    let episodes = statement
        .query_map([listing_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .expect("read episodes")
        .collect::<Result<Vec<_>, _>>()
        .expect("episode rows");
    episodes
        .into_iter()
        .map(|(ordinal, state, blocked_at, lifted_at)| {
            (
                ordinal.unsigned_abs(),
                state,
                blocked_at.unsigned_abs(),
                lifted_at.map(i64::unsigned_abs),
            )
        })
        .collect()
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
    let audit_lock = lock_input("lock-audit", &audit.challenge_id, &owner, &schedule);
    assert!(
        matches!(
            fixture.store.reserve_dispute_lock(&audit_lock, NOW),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a bondless venue audit posts no dispute bond"
    );

    let unfunded_challenge = Challenge::buyer("unfunded");
    submit(&fixture, &unfunded_challenge);
    let unfunded = lock_input(
        "lock-unfunded",
        &unfunded_challenge.challenge_id,
        &owner,
        &schedule,
    );
    fixture
        .store
        .reserve_dispute_lock(&unfunded, NOW)
        .expect("reserve unfunded lock");
    assert!(
        matches!(
            fixture.store.lock_dispute_bond(&unfunded),
            Err(FindingChallengeStoreError::Conflict(ref detail))
                if detail.contains("independently confirmed funding")
        ),
        "a caller-provided lock id is not evidence of funded collateral"
    );
    let wrong_owner_challenge = Challenge::buyer("wrong-owner");
    submit(&fixture, &wrong_owner_challenge);
    let wrong_owner = hex64('c');
    let wrong_owner_lock = lock_input(
        "lock-wrong-owner",
        &wrong_owner_challenge.challenge_id,
        &wrong_owner,
        &schedule,
    );
    assert!(
        matches!(
            fixture.store.reserve_dispute_lock(&wrong_owner_lock, NOW),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a bond owned by anyone but the challenger must reject"
    );
    let upheld = Challenge::buyer("alpha");
    submit(&fixture, &upheld);
    let lock = lock_input("lock-alpha", &upheld.challenge_id, &owner, &schedule);
    assert_eq!(
        lock_dispute_bond(&fixture, &lock).expect("lock bond"),
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
            pool_principal_id: "challenge-pool".to_string(),
            pool_rail_destination: "rail:challenge-pool".to_string(),
            pool_authority_epoch: 1,
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
    let reused_lock = lock_input("lock-alpha", &other.challenge_id, &owner, &schedule);
    assert!(
        matches!(
            fixture.store.reserve_dispute_lock(&reused_lock, NOW),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one lock cannot be reserved for two challenges"
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
    assert!(
        matches!(
            fixture.store.release_dispute_bond(
                &upheld.challenge_id,
                FindingDisputeLockDisposition::Returned,
                NOW + 3
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "bookkeeping cannot report a return before its rail intent confirms"
    );
    confirm_lock_return(&fixture, &lock);
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
    let beta_lock = lock_input("lock-beta", &other.challenge_id, &owner, &schedule);
    lock_dispute_bond(&fixture, &beta_lock).expect("lock beta bond");
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
    let gamma_lock = lock_input("lock-gamma", &stalled.challenge_id, &owner, &schedule);
    lock_dispute_bond(&fixture, &gamma_lock).expect("lock gamma bond");
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
    confirm_lock_return(&fixture, &gamma_lock);
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
            claim_deadline: None,
            appeal_window_opened_at: None,
            appeal_deadline: None,
            appeal_terms_envelope_sha256: None,
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
                &digest("finding-market-terms-alpha"),
                APPEAL_WINDOW,
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
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
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
    assert!(
        matches!(
            fixture.store.begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest("finding-market-terms-alpha"),
                0,
                NOW + 4
            ),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "a signed appeal duration must be nonzero"
    );
    assert!(
        matches!(
            fixture.store.begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest("finding-market-terms-alpha"),
                u64::MAX,
                NOW + 4
            ),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "an appeal deadline that cannot be represented must reject"
    );
    assert_eq!(
        fixture
            .store
            .begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest("finding-market-terms-alpha"),
                APPEAL_WINDOW,
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
                &digest("finding-market-terms-alpha"),
                APPEAL_WINDOW,
                NOW + 5
            )
            .expect("replay the appeal window"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        fixture
            .store
            .begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest("finding-market-terms-alpha"),
                APPEAL_WINDOW,
                i64::MAX as u64,
            )
            .expect("replay from the maximum trusted clock"),
        FindingChallengeWriteOutcome::ExistingSame,
        "a retry must not recompute the frozen deadline from its later clock"
    );
    let appealed = liability(&fixture, &head.liability_key);
    assert_eq!(appealed.appeal_window_opened_at, Some(NOW + 4));
    assert_eq!(appealed.appeal_deadline, Some(NOW + 4 + APPEAL_WINDOW));
    assert_eq!(
        appealed.appeal_terms_envelope_sha256.as_deref(),
        Some(digest("finding-market-terms-alpha").as_str())
    );
    assert!(
        matches!(
            fixture.store.begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest("finding-market-terms-alpha"),
                APPEAL_WINDOW + 1,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a replay cannot replace the frozen signed appeal duration"
    );
    assert!(
        matches!(
            fixture.store.begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest("finding-market-terms-beta"),
                APPEAL_WINDOW,
                NOW + 5
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a replay cannot replace the frozen signed terms digest"
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
    confirm_settlement_effects(&fixture, &head.liability_key, NOW + 9);
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
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
        .expect("uphold liability");
    fixture
        .store
        .begin_appeal_window(
            &reversed.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-beta"),
            APPEAL_WINDOW,
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
                &digest("finding-market-terms-absent"),
                APPEAL_WINDOW,
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
            fixture.store.uphold_liability(
                &head.liability_key,
                &live.challenge_id,
                2,
                NOW + CLAIM_WINDOW,
                NOW + 5
            ),
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
                NOW + CLAIM_WINDOW,
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
                NOW + CLAIM_WINDOW,
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
            .uphold_liability(
                &head.liability_key,
                &challenge.challenge_id,
                2,
                NOW + CLAIM_WINDOW,
                NOW + 5,
            )
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
            payout_destination: "0x000000000000000000000000000000000000002a",
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
            .uphold_liability(
                &head.liability_key,
                &challenge.challenge_id,
                2,
                NOW + CLAIM_WINDOW,
                NOW + 7,
            )
            .expect("replay uphold"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(
        matches!(
            fixture.store.uphold_liability(
                &head.liability_key,
                &challenge.challenge_id,
                3,
                NOW + CLAIM_WINDOW,
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
fn upheld_transition_fences_the_signed_exposure_before_blocking_sales() {
    let fixture = fixture();
    assert_eq!(
        reserve_slot(
            &fixture,
            "exposure-race",
            LISTING_ID,
            &fixture.allocation_id
        ),
        1
    );
    let head = Liability::new("exposure-race", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("exposure-race");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 2,
    );

    assert!(matches!(
        fixture.store.uphold_liability_with_exposure_fence(
            &head.liability_key,
            &challenge.challenge_id,
            1,
            NOW + CLAIM_WINDOW,
            0,
            NOW + 3,
        ),
        Err(FindingChallengeStoreError::Conflict(_))
    ));
    assert_eq!(
        liability(&fixture, &head.liability_key).state,
        FindingLiabilityState::Open
    );
    assert!(!fixture
        .purchases
        .sales_blocked(LISTING_ID)
        .expect("read sales block"));

    assert_eq!(
        fixture
            .store
            .uphold_liability_with_exposure_fence(
                &head.liability_key,
                &challenge.challenge_id,
                1,
                NOW + CLAIM_WINDOW,
                10,
                NOW + 3,
            )
            .expect("matching exposure freezes the cutoff"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert!(fixture
        .purchases
        .sales_blocked(LISTING_ID)
        .expect("read sales block"));
}

#[test]
fn upheld_verdict_fences_exposure_before_becoming_terminal() {
    let fixture = fixture();
    assert_eq!(
        reserve_slot(
            &fixture,
            "verdict-exposure-race",
            LISTING_ID,
            &fixture.allocation_id
        ),
        1
    );
    let challenge = Challenge::buyer("verdict-exposure-race");
    submit(&fixture, &challenge);
    fixture
        .store
        .begin_evaluation(&challenge.challenge_id, NOW + 1)
        .expect("begin evaluation");
    let outcome_digest = digest("verdict-exposure-race-outcome");

    assert!(matches!(
        fixture.store.record_upheld_verdict_with_exposure_fence(
            &challenge.challenge_id,
            &outcome_digest,
            &fixture.allocation_id,
            0,
            NOW + 2,
        ),
        Err(FindingChallengeStoreError::Conflict(_))
    ));
    assert_eq!(
        challenge_state(&fixture, &challenge.challenge_id),
        FindingChallengeState::Evaluating
    );
    assert!(!fixture
        .purchases
        .sales_blocked(LISTING_ID)
        .expect("read sales block"));

    assert_eq!(
        fixture
            .store
            .record_upheld_verdict_with_exposure_fence(
                &challenge.challenge_id,
                &outcome_digest,
                &fixture.allocation_id,
                10,
                NOW + 2,
            )
            .expect("record fenced verdict"),
        FindingChallengeState::Upheld
    );
    assert!(fixture
        .purchases
        .sales_blocked(LISTING_ID)
        .expect("read sales block"));
}

#[test]
fn a_successful_appeal_returns_the_listing_to_selling() {
    let fixture = fixture();
    assert_eq!(
        reserve_slot(&fixture, "alpha", LISTING_ID, &fixture.allocation_id),
        1
    );
    settle_slot(&fixture, "alpha", &hex64('d'), NOW + 2);
    fixture
        .purchases
        .block_new_slots(OTHER_LISTING_ID, NOW + 2)
        .expect("block an unrelated listing");

    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("alpha");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 3,
    );
    fixture
        .store
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            1,
            NOW + CLAIM_WINDOW,
            NOW + 5,
        )
        .expect("uphold liability");
    fixture
        .store
        .begin_appeal_window(
            &head.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-alpha"),
            APPEAL_WINDOW,
            NOW + 6,
        )
        .expect("open the appeal window");
    assert!(
        fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "a head under appeal has not been exonerated yet"
    );

    assert_eq!(
        fixture
            .store
            .reverse_liability_before_impairment(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 7
            )
            .expect("reverse before impairment"),
        FindingChallengeWriteOutcome::Inserted
    );
    assert!(
        !fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "an exonerated seller is not barred from selling"
    );
    assert_eq!(
        reserve_slot(&fixture, "beta", LISTING_ID, &fixture.allocation_id),
        2,
        "the slot line resumes above the cutoff the block froze"
    );
    assert!(
        fixture
            .purchases
            .sales_blocked(OTHER_LISTING_ID)
            .expect("sales blocked"),
        "a lift reaches exactly the listing the exonerated head names"
    );

    // The raise outlives the lift: a listing selling again still records
    // that it was blocked, from when until when.
    assert_eq!(
        sales_block_episodes(&fixture, LISTING_ID),
        vec![(1, "lifted".to_owned(), NOW + 5, Some(NOW + 7))]
    );

    assert_eq!(
        fixture
            .store
            .reverse_liability_before_impairment(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 9
            )
            .expect("replay the reversal"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert_eq!(
        sales_block_episodes(&fixture, LISTING_ID),
        vec![(1, "lifted".to_owned(), NOW + 5, Some(NOW + 7))],
        "a replay must not restamp the release"
    );
}

#[test]
fn only_an_exoneration_lifts_a_listing_sales_block() {
    let fixture = fixture();
    let head = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("alpha");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
        .expect("uphold liability");

    assert!(
        matches!(
            fixture.store.reverse_liability_before_impairment(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                NOW + 4
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "the appeal window is the only source of the reversal"
    );
    assert!(
        matches!(
            fixture.store.reverse_liability_before_impairment(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 4
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a head that never entered the appeal window has no reversal to take"
    );
    assert!(
        fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "a refused reversal leaves the listing exactly as blocked as it was"
    );

    // Every other edge out of the upheld liability leaves the block
    // standing, including the settled terminal an impairment reaches.
    let still_blocked = |stage: &str| {
        assert!(
            fixture
                .purchases
                .sales_blocked(LISTING_ID)
                .expect("sales blocked"),
            "a {stage} liability keeps its listing blocked"
        );
    };
    fixture
        .store
        .begin_appeal_window(
            &head.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-alpha"),
            APPEAL_WINDOW,
            NOW + 5,
        )
        .expect("open the appeal window");
    still_blocked("pending-appeal");
    fixture
        .store
        .begin_finalizing(
            &head.liability_key,
            FindingLiabilityState::PendingAppeal,
            NOW + 6,
        )
        .expect("begin finalizing");
    still_blocked("finalizing");
    confirm_settlement_effects(&fixture, &head.liability_key, NOW + 6);
    fixture
        .store
        .settle_liability(
            &head.liability_key,
            FindingLiabilityState::Finalizing,
            NOW + 7,
        )
        .expect("settle the liability");
    still_blocked("settled");

    assert!(
        matches!(
            fixture.store.reverse_liability_before_impairment(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                NOW + 8
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a settled head cannot be walked back into an exoneration"
    );
    assert_eq!(
        sales_block_episodes(&fixture, LISTING_ID),
        vec![(1, "blocked".to_owned(), NOW + 3, None)]
    );
}

#[test]
fn a_listing_another_liability_still_holds_stays_blocked() {
    let fixture = fixture();
    let first = Liability::new("alpha", LISTING_ID, &fixture.allocation_id);
    let second = Liability::new("beta", LISTING_ID, &fixture.allocation_id);
    let first_challenge = Challenge::buyer("alpha");
    let second_challenge = Challenge::buyer("beta");
    for (head, challenge) in [(&first, &first_challenge), (&second, &second_challenge)] {
        open_liability(&fixture, head);
        close_challenge(
            &fixture,
            challenge,
            FindingChallengeVerdict::Upheld,
            NOW + 1,
        );
        fixture
            .store
            .uphold_liability(
                &head.liability_key,
                &challenge.challenge_id,
                0,
                NOW + CLAIM_WINDOW,
                NOW + 3,
            )
            .expect("uphold liability");
        fixture
            .store
            .begin_appeal_window(
                &head.liability_key,
                FindingLiabilityState::UpheldPendingClaims,
                &digest(&format!("finding-market-terms-{}", head.liability_key)),
                APPEAL_WINDOW,
                NOW + 4,
            )
            .expect("open the appeal window");
    }
    assert_eq!(
        sales_block_episodes(&fixture, LISTING_ID),
        vec![(1, "blocked".to_owned(), NOW + 3, None)],
        "one listing carries one block however many heads reach it"
    );

    fixture
        .store
        .reverse_liability_before_impairment(
            &first.liability_key,
            FindingLiabilityState::PendingAppeal,
            NOW + 5,
        )
        .expect("reverse the first head");
    assert!(
        fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "a block every live head holds is not released by one of them clearing"
    );

    fixture
        .store
        .reverse_liability_before_impairment(
            &second.liability_key,
            FindingLiabilityState::PendingAppeal,
            NOW + 6,
        )
        .expect("reverse the second head");
    assert!(
        !fixture
            .purchases
            .sales_blocked(LISTING_ID)
            .expect("sales blocked"),
        "the last head to clear releases the listing"
    );

    // A fresh defect blocks the listing again on its own episode, and the
    // released one stays exactly where it closed.
    let third = Liability::new("gamma", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &third);
    let third_challenge = Challenge::buyer("gamma");
    close_challenge(
        &fixture,
        &third_challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 7,
    );
    fixture
        .store
        .uphold_liability(
            &third.liability_key,
            &third_challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 9,
        )
        .expect("uphold the third head");
    assert!(fixture
        .purchases
        .sales_blocked(LISTING_ID)
        .expect("sales blocked"));
    assert_eq!(
        sales_block_episodes(&fixture, LISTING_ID),
        vec![
            (1, "lifted".to_owned(), NOW + 3, Some(NOW + 6)),
            (2, "blocked".to_owned(), NOW + 9, None),
        ]
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

    let challenge = Challenge::buyer("case-head");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
        .expect("uphold liability");
    fixture
        .store
        .begin_appeal_window(
            &head.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-alpha"),
            APPEAL_WINDOW,
            NOW + 4,
        )
        .expect("open appeal window");

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
fn finalizing_wins_the_race_against_appeal_supersession() {
    let fixture = fixture();
    let head = Liability::new("finality-race", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("finality-race");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
        .expect("uphold liability");

    let sanction = FindingGovernanceCaseInput {
        case_id: "case-sanction-finality-race",
        finding_id: &head.finding_id,
        listing_id: LISTING_ID,
        liability_key: &head.liability_key,
        case_kind: FindingGovernanceCaseKind::Sanction,
        case_state: "Enforced",
        appeal_of_case_id: None,
        supersedes_case_id: None,
        recorded_at: NOW + 3,
    };
    fixture
        .store
        .record_governance_case(&sanction)
        .expect("record sanction");
    fixture
        .store
        .begin_appeal_window(
            &head.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-finality-race"),
            APPEAL_WINDOW,
            NOW + 4,
        )
        .expect("open appeal window");
    fixture
        .store
        .begin_finalizing_under_sanction(
            &head.liability_key,
            FindingLiabilityState::PendingAppeal,
            sanction.case_id,
            NOW + 5,
        )
        .expect("finalizing compare-and-set wins");

    let appeal = FindingGovernanceCaseInput {
        case_id: "case-appeal-finality-race",
        case_kind: FindingGovernanceCaseKind::Appeal,
        appeal_of_case_id: Some(sanction.case_id),
        supersedes_case_id: Some(sanction.case_id),
        recorded_at: NOW + 5,
        ..sanction
    };
    assert!(
        matches!(
            fixture.store.record_governance_case(&appeal),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "an appeal cannot supersede the sanction after finalizing wins"
    );
    let resolved = fixture
        .store
        .resolve_case_head(&head.liability_key)
        .expect("resolve case head")
        .expect("sanction remains live");
    assert_eq!(resolved.case_id, sanction.case_id);
    assert_eq!(resolved.case_kind, FindingGovernanceCaseKind::Sanction);
    assert_eq!(
        liability(&fixture, &head.liability_key).state,
        FindingLiabilityState::Finalizing
    );
}

#[test]
fn appeal_supersession_wins_the_race_against_finalizing() {
    let fixture = fixture();
    let head = Liability::new("appeal-race", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("appeal-race");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
        .expect("uphold liability");

    let sanction = FindingGovernanceCaseInput {
        case_id: "case-sanction-appeal-race",
        finding_id: &head.finding_id,
        listing_id: LISTING_ID,
        liability_key: &head.liability_key,
        case_kind: FindingGovernanceCaseKind::Sanction,
        case_state: "Enforced",
        appeal_of_case_id: None,
        supersedes_case_id: None,
        recorded_at: NOW + 3,
    };
    fixture
        .store
        .record_governance_case(&sanction)
        .expect("record sanction");
    fixture
        .store
        .begin_appeal_window(
            &head.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-appeal-race"),
            APPEAL_WINDOW,
            NOW + 4,
        )
        .expect("open appeal window");

    let appeal = FindingGovernanceCaseInput {
        case_id: "case-appeal-wins-race",
        case_kind: FindingGovernanceCaseKind::Appeal,
        appeal_of_case_id: Some(sanction.case_id),
        supersedes_case_id: Some(sanction.case_id),
        recorded_at: NOW + 5,
        ..sanction
    };
    fixture
        .store
        .record_governance_case(&appeal)
        .expect("appeal supersession wins");
    assert!(
        matches!(
            fixture.store.begin_finalizing_under_sanction(
                &head.liability_key,
                FindingLiabilityState::PendingAppeal,
                sanction.case_id,
                NOW + 5,
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a superseded sanction cannot carry the head into finalizing"
    );
    fixture
        .store
        .reverse_liability_before_impairment(
            &head.liability_key,
            FindingLiabilityState::PendingAppeal,
            NOW + 6,
        )
        .expect("the successful appeal can still reverse the liability");
    assert_eq!(
        liability(&fixture, &head.liability_key).state,
        FindingLiabilityState::ReversedBeforeImpairment
    );
    assert_eq!(
        fixture
            .store
            .resolve_case_head(&head.liability_key)
            .expect("resolve case head")
            .expect("appeal remains live")
            .case_id,
        appeal.case_id
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
        sealed_at: NOW + CLAIM_WINDOW + 10,
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
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            1,
            NOW + CLAIM_WINDOW,
            NOW + 5,
        )
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
    let mut early = sealed;
    early.sealed_at = NOW + CLAIM_WINDOW - 1;
    assert!(
        matches!(
            fixture.store.seal_claim_snapshot(&early),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "the snapshot is immutable, so it never seals inside the claim window"
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
            sealed_at: NOW + CLAIM_WINDOW + 10,
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
fn settlement_waits_for_every_required_effect_confirmation() {
    let fixture = fixture();
    let head = Liability::new("settlement-gate", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let challenge = Challenge::buyer("settlement-gate");
    close_challenge(
        &fixture,
        &challenge,
        FindingChallengeVerdict::Upheld,
        NOW + 1,
    );
    fixture
        .store
        .uphold_liability(
            &head.liability_key,
            &challenge.challenge_id,
            0,
            NOW + CLAIM_WINDOW,
            NOW + 3,
        )
        .expect("uphold liability");
    fixture
        .store
        .begin_appeal_window(
            &head.liability_key,
            FindingLiabilityState::UpheldPendingClaims,
            &digest("finding-market-terms-settlement-gate"),
            APPEAL_WINDOW,
            NOW + 4,
        )
        .expect("open appeal window");
    fixture
        .store
        .begin_finalizing(
            &head.liability_key,
            FindingLiabilityState::PendingAppeal,
            NOW + 5,
        )
        .expect("begin finalizing");

    assert!(
        matches!(
            fixture.store.settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 6
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "missing required effects keep the liability finalizing"
    );

    let anchor_key = digest("settlement-gate-anchor-evidence");
    fixture
        .store
        .record_effect_intent(
            &anchor_key,
            FindingEffectIntentKind::RootIntent,
            &digest("settlement-gate-anchor-evidence-commitment"),
            Some(&head.liability_key),
            false,
            NOW + 6,
        )
        .expect("record optional anchor evidence");

    let required = [
        (
            digest("settlement-gate-seller-impair"),
            FindingEffectIntentKind::SellerImpair,
            digest("settlement-gate-seller-impair-commitment"),
        ),
        (
            digest("settlement-gate-root-intent"),
            FindingEffectIntentKind::RootIntent,
            digest("settlement-gate-root-intent-commitment"),
        ),
        (
            digest("settlement-gate-retraction"),
            FindingEffectIntentKind::Retraction,
            digest("settlement-gate-retraction-commitment"),
        ),
    ];
    for (intent_key, kind, intent_digest) in &required {
        fixture
            .store
            .record_effect_intent(
                intent_key,
                *kind,
                intent_digest,
                Some(&head.liability_key),
                true,
                NOW + 6,
            )
            .expect("record required effect");
    }
    assert!(
        matches!(
            fixture.store.settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 7
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "pending required effects keep the liability finalizing"
    );

    assert!(
        matches!(
            fixture.store.advance_effect_intent(
                &required[2].0,
                FindingEffectIntentState::Dispatched,
                NOW + 7,
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "retraction cannot dispatch before seller impairment is confirmed"
    );

    for (intent_key, kind, _) in &required[..2] {
        fixture
            .store
            .advance_effect_intent(intent_key, FindingEffectIntentState::Dispatched, NOW + 7)
            .expect("dispatch required effect");
        if *kind == FindingEffectIntentKind::SellerImpair {
            fixture
                .store
                .confirm_seller_impairment_and_quarantine(intent_key, &head.liability_key, NOW + 7)
                .expect("confirm seller impairment and quarantine liability");
        } else {
            fixture
                .store
                .advance_effect_intent(intent_key, FindingEffectIntentState::Confirmed, NOW + 7)
                .expect("confirm required effect");
        }
    }
    assert!(
        matches!(
            fixture.store.settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 8
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "one pending retraction keeps the liability finalizing"
    );
    let still_finalizing = liability(&fixture, &head.liability_key);
    assert_eq!(still_finalizing.state, FindingLiabilityState::Finalizing);
    assert!(still_finalizing.publication_pending);

    assert!(
        matches!(
            fixture.store.advance_effect_intent(
                &required[2].0,
                FindingEffectIntentState::Dispatched,
                NOW + 9,
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "a quarantined impairment cannot publish a retraction"
    );
    assert_eq!(
        fixture
            .store
            .confirm_seller_impairment_and_quarantine(&required[0].0, &head.liability_key, NOW + 9,)
            .expect("replay atomic confirmation and quarantine"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    fixture
        .store
        .set_liability_quarantine(&head.liability_key, false, NOW + 10)
        .expect("clear reconciled quarantine");
    fixture
        .store
        .advance_effect_intent(
            &required[2].0,
            FindingEffectIntentState::Dispatched,
            NOW + 10,
        )
        .expect("dispatch retraction after impairment reconciliation");
    fixture
        .store
        .advance_effect_intent(
            &required[2].0,
            FindingEffectIntentState::Confirmed,
            NOW + 10,
        )
        .expect("confirm retraction");
    assert_eq!(
        fixture
            .store
            .settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 11,
            )
            .expect("settle after every required effect confirms"),
        FindingChallengeWriteOutcome::Inserted
    );
    let settled = liability(&fixture, &head.liability_key);
    assert_eq!(settled.state, FindingLiabilityState::Settled);
    assert!(!settled.publication_pending);
    assert_eq!(
        fixture
            .store
            .get_effect_intent(&anchor_key)
            .expect("get optional anchor evidence")
            .expect("optional anchor evidence present")
            .state,
        FindingEffectIntentState::Pending,
        "a pending non-required evidence fence does not block settlement"
    );
    assert_eq!(
        fixture
            .store
            .settle_liability(
                &head.liability_key,
                FindingLiabilityState::Finalizing,
                NOW + 12,
            )
            .expect("replay settlement"),
        FindingChallengeWriteOutcome::ExistingSame
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
                false,
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
                false,
                NOW + 1
            )
            .expect("identical retry reconciles"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(
        matches!(
            fixture.store.record_effect_intent(
                &intent_key,
                FindingEffectIntentKind::SellerImpair,
                &intent_digest,
                Some(&head.liability_key),
                true,
                NOW + 1
            ),
            Err(FindingChallengeStoreError::Conflict(_))
        ),
        "the settlement gate is immutable under one intent key"
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
                    false,
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
            settlement_required: false,
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
            false,
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
                &digest("required-orphan-intent"),
                FindingEffectIntentKind::SellerImpair,
                &digest("required-orphan-commitment"),
                None,
                true,
                NOW
            ),
            Err(FindingChallengeStoreError::Invariant(_))
        ),
        "a settlement-required effect must name its liability"
    );
    assert!(
        matches!(
            fixture.store.record_effect_intent(
                &digest("orphan-intent"),
                FindingEffectIntentKind::Fee,
                &digest("fee-commitment"),
                Some(&digest("liability-absent")),
                false,
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
fn v2_schema_migrates_to_frozen_appeals_and_required_effects() {
    let mut connection = Connection::open_in_memory().expect("open legacy database");
    connection
        .execute_batch(&finding_challenge_v2_schema())
        .expect("install v2 challenge schema");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("adopt legacy database"),
        0
    );
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 2)
        .expect("stamp legacy schema");

    let liability_key = digest("legacy-v2-liability");
    connection
        .execute(
            r#"
            INSERT INTO liability_heads (
                liability_key, defect_key, finding_id, listing_id,
                allocation_id, venue_id, chain_id, vault_contract, vault_id,
                state, upheld_challenge_id, purchase_cutoff_slot,
                claim_deadline, snapshot_digest, allocation_digest,
                publication_pending, quarantined, opened_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, 'venue-legacy', 'eip155:8453',
                '0xlegacy', 'vault-legacy', 'open', NULL, NULL, NULL, NULL,
                NULL, 0, 0, ?6, ?6
            )
            "#,
            params![
                liability_key,
                digest("legacy-v2-defect"),
                hex64('a'),
                LISTING_ID,
                digest("legacy-v2-allocation"),
                sqlite_i64(NOW, "now").expect("legacy time"),
            ],
        )
        .expect("insert v2 liability");
    let intent_key = digest("legacy-v2-effect");
    connection
        .execute(
            r#"
            INSERT INTO effect_intents (
                intent_key, liability_key, kind, intent_digest, state,
                attempt_count, recorded_at, updated_at
            ) VALUES (?1, ?2, 'seller_impair', ?3, 'pending', 0, ?4, ?4)
            "#,
            params![
                intent_key,
                liability_key,
                digest("legacy-v2-effect-commitment"),
                sqlite_i64(NOW, "now").expect("legacy time"),
            ],
        )
        .expect("insert v2 effect");

    initialize_finding_challenge_schema(&mut connection).expect("migrate legacy schema");

    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
            [FINDING_CHALLENGE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .expect("read migrated version");
    assert_eq!(version, FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION);
    let appeal: (Option<i64>, Option<i64>, Option<String>) = connection
        .query_row(
            r#"
            SELECT appeal_window_opened_at, appeal_deadline,
                   appeal_terms_envelope_sha256
            FROM liability_heads WHERE liability_key = ?1
            "#,
            [&liability_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read migrated appeal commitments");
    assert_eq!(appeal, (None, None, None));
    let settlement_required: i64 = connection
        .query_row(
            "SELECT settlement_required FROM effect_intents WHERE intent_key = ?1",
            [&intent_key],
            |row| row.get(0),
        )
        .expect("read migrated settlement gate");
    assert_eq!(settlement_required, 1);
    verify_finding_challenge_invariants(&connection).expect("verify canonical schema");
}

#[test]
fn v5_schema_adds_the_pre_funding_dispute_lock_reservation() {
    let mut connection = Connection::open_in_memory().expect("open legacy database");
    connection
        .execute_batch(&finding_challenge_v5_schema())
        .expect("install v5 challenge schema");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("adopt legacy database"),
        0
    );
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 5)
        .expect("stamp previous schema");

    initialize_finding_challenge_schema(&mut connection).expect("migrate v5 schema");
    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
            [FINDING_CHALLENGE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .expect("read migrated version");
    assert_eq!(version, FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION);
    assert!(
        table_has_column(&connection, "dispute_lock_reservations", "reserved_at")
            .expect("inspect migrated reservation table")
    );
    verify_finding_challenge_invariants(&connection).expect("verify canonical schema");
}

#[test]
fn empty_v4_schema_adds_authenticated_projection_history() {
    let mut connection = Connection::open_in_memory().expect("open legacy database");
    connection
        .execute_batch(&finding_challenge_v4_schema())
        .expect("install previous challenge schema");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("adopt legacy database"),
        0
    );
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 4)
        .expect("stamp previous schema");

    initialize_finding_challenge_schema(&mut connection).expect("migrate empty previous schema");
    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
            [FINDING_CHALLENGE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .expect("read migrated version");
    assert_eq!(version, FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION);
    assert!(table_has_column(
        &connection,
        "finding_challenge_projection_commits",
        "snapshot_digest"
    )
    .expect("inspect projection history"));
}

#[test]
fn nonempty_v4_schema_is_not_adopted_without_projection_history() {
    let mut connection = Connection::open_in_memory().expect("open legacy database");
    connection
        .execute_batch(&finding_challenge_v4_schema())
        .expect("install previous challenge schema");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("adopt legacy database"),
        0
    );
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 4)
        .expect("stamp previous schema");
    connection
        .execute(
            r#"
            INSERT INTO challenges (
                challenge_id, finding_id, listing_id,
                challenge_envelope_sha256, authorization_branch,
                evidence_class, challenger_hex, state, retry_count,
                retry_deadline, outcome_envelope_sha256, submitted_at,
                updated_at
            ) VALUES (
                'legacy-challenge', ?1, 'legacy-listing', ?2,
                'buyer_submission', 'evidence_invalid', ?3,
                'submitted', 0, NULL, NULL, ?4, ?4
            )
            "#,
            params![
                hex64('a'),
                digest("legacy-v4-envelope"),
                hex64('b'),
                sqlite_i64(NOW, "now").expect("legacy time"),
            ],
        )
        .expect("insert unauthenticated v4 state");

    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("read legacy schema version"),
        4
    );
    assert!(table_has_rows_where(&connection, "challenges", "1 = 1")
        .expect("inspect unauthenticated v4 state"));

    initialize_finding_challenge_schema(&mut connection)
        .expect_err("nonempty unauthenticated v4 state must reject");
}

#[test]
fn empty_v3_schema_migrates_pool_binding_and_recovery_lifecycle() {
    let mut connection = Connection::open_in_memory().expect("open legacy database");
    connection
        .execute_batch(&finding_challenge_v3_schema())
        .expect("install v3 challenge schema");
    assert_eq!(
        crate::check_schema_version(
            &connection,
            FINDING_CHALLENGE_SCHEMA_KEY,
            FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION,
            FINDING_CHALLENGE_SCHEMA_ANCHORS,
        )
        .expect("adopt legacy database"),
        0
    );
    crate::stamp_schema_version(&connection, FINDING_CHALLENGE_SCHEMA_KEY, 3)
        .expect("stamp legacy schema");

    initialize_finding_challenge_schema(&mut connection).expect("migrate empty legacy schema");

    let version: i32 = connection
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = ?1",
            [FINDING_CHALLENGE_SCHEMA_KEY],
            |row| row.get(0),
        )
        .expect("read migrated version");
    assert_eq!(version, FINDING_CHALLENGE_SUPPORTED_SCHEMA_VERSION);
    for column in [
        "pool_principal_id",
        "pool_rail_destination",
        "pool_authority_epoch",
    ] {
        assert!(
            table_has_column(&connection, "dispute_locks", column).expect("inspect migrated lock"),
            "migration installs {column}"
        );
    }
    let trigger: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'challenges_lifecycle'",
            [],
            |row| row.get(0),
        )
        .expect("read migrated lifecycle trigger");
    assert!(trigger.contains("indeterminate_closed"));
    verify_finding_challenge_invariants(&connection).expect("verify canonical schema");
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
