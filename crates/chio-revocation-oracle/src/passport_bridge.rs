//! Bridge between `chio_credentials::PassportLifecycleRecord` revocation
//! events and the [`crate::RevocationOracle`] surface.
//!
//! `chio-credentials` owns the passport lifecycle (active / stale /
//! superseded / revoked / not-found) and emits a record every time a
//! passport transitions states. When a passport flips to
//! [`PassportLifecycleState::Revoked`], dispatch verifiers must observe
//! the revocation through the same oracle surface that revokes raw
//! credentials, so the trust-boundary surface stays single-sourced and
//! the federation gossip path carries passport revocation events
//! alongside everything else.
//!
//! ## Surface
//!
//! * [`PassportRevocationEvent`] is the bridge value: a passport-id +
//!   subject + revoked-at timestamp + optional reason. Lives here (not in
//!   `chio-credentials`) so any consumer that already speaks the oracle
//!   surface can ingest passport revocations without adding a credentials
//!   dep.
//! * [`apply_passport_revocation`] turns the bridge value into a
//!   [`RevocationKey`] and inserts it into the supplied oracle. The
//!   resulting `EpochRoot` is the same one the oracle would have produced
//!   for any other revocation: federation gossip just picks it up on the
//!   next push tick.
//! * [`PassportRevocationBridgeError`] surfaces the small set of failures
//!   the bridge can produce (already revoked, oracle rejected the insert,
//!   malformed event). All variants are fail-closed: callers MUST refuse
//!   to advance the verifier-side cache on any error.
//!
//! ## Invariant note
//!
//! The bridge is read-only from the credentials surface's perspective:
//! it does not modify any passport lifecycle field, it only reads
//! `passport_id`, `subject`, `revoked_at`, and `revoked_reason` from a
//! record that the credentials side already validated. The
//! `chio-credentials::property_passport::*` named invariants therefore
//! continue to hold.

use crate::api::{EpochNonce, EpochRoot, RevocationKey, RevocationOracle, SubjectId};

/// Schema-derived nonce salt for passport-revocation events. Combined
/// with the passport's `revoked_at` (which the credentials side validates
/// to be non-zero for any record in `Revoked` state) this produces a
/// stable, replay-resistant `EpochNonce` for the same passport: a record
/// re-emitted with a different `revoked_at` will produce a different
/// nonce, while a re-emit of the same record (same passport-id +
/// `revoked_at`) maps to the same key and is rejected fail-closed by
/// [`apply_passport_revocation`] as `AlreadyApplied`.
const PASSPORT_REVOCATION_NONCE_SALT: u64 = 0x705F_7050_7252_7600;

/// Bridge value emitted when a passport flips to `Revoked`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassportRevocationEvent {
    /// `chio_credentials::PassportLifecycleRecord::passport_id`.
    pub passport_id: String,
    /// `chio_credentials::PassportLifecycleRecord::subject`.
    pub subject: String,
    /// Unix milliseconds at which the passport was revoked. Mirrors the
    /// credentials-side `revoked_at` field (which their lifecycle
    /// validator already ensures is non-zero on a Revoked record).
    pub revoked_at_unix_ms: u64,
    /// Optional human-readable reason carried over from the credentials
    /// surface. Not used by the oracle but persisted by callers that want
    /// to plumb it through to audit logs.
    pub revoked_reason: Option<String>,
}

impl PassportRevocationEvent {
    /// Construct an event from raw fields. Returns `Err` if any required
    /// field is empty / zero (the credentials-side validator already
    /// guarantees these for a real Revoked record, but this lets bridge
    /// callers built outside the credentials crate still get a fail-
    /// closed gate).
    pub fn new(
        passport_id: impl Into<String>,
        subject: impl Into<String>,
        revoked_at_unix_ms: u64,
        revoked_reason: Option<String>,
    ) -> Result<Self, PassportRevocationBridgeError> {
        let passport_id = passport_id.into();
        let subject = subject.into();
        validate_event_text("passport_id", &passport_id)?;
        validate_event_text("subject", &subject)?;
        if revoked_at_unix_ms == 0 {
            return Err(PassportRevocationBridgeError::MalformedEvent(
                "revoked_at_unix_ms must be non-zero on a Revoked record".to_string(),
            ));
        }
        if let Some(reason) = revoked_reason.as_deref() {
            validate_event_text("revoked_reason", reason)?;
        }
        Ok(Self {
            passport_id,
            subject,
            revoked_at_unix_ms,
            revoked_reason,
        })
    }

    /// Produce the deterministic [`RevocationKey`] this passport-revocation
    /// event maps to. Stable across calls so re-applying the same event
    /// produces the same key (which the oracle rejects as
    /// `AlreadyRevoked`, surfaced through
    /// [`PassportRevocationBridgeError::AlreadyApplied`]).
    pub fn to_revocation_key(&self) -> RevocationKey {
        let nonce_value = PASSPORT_REVOCATION_NONCE_SALT ^ self.revoked_at_unix_ms;
        RevocationKey::new(
            SubjectId::from(self.subject.clone()),
            EpochNonce::new(nonce_value),
        )
    }
}

fn validate_event_text(field: &str, value: &str) -> Result<(), PassportRevocationBridgeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(PassportRevocationBridgeError::MalformedEvent(format!(
            "{field} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

/// Errors raised by the passport bridge. Every variant is fail-closed:
/// callers MUST refuse to advance the verifier-side cache on any error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassportRevocationBridgeError {
    /// Bridge event is structurally malformed (empty passport-id,
    /// subject, zero revoked_at, blank reason).
    MalformedEvent(String),
    /// Same revocation key already present in the oracle. Idempotent: the
    /// caller has likely re-emitted the same record and can ignore the
    /// duplicate, but the oracle's epoch was NOT advanced so the
    /// federation push path will not re-broadcast.
    AlreadyApplied,
    /// Oracle rejected the insert for some other reason (proof mismatch
    /// or unrelated invariant).
    OracleRejected(String),
}

impl core::fmt::Display for PassportRevocationBridgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedEvent(msg) => write!(f, "passport revocation event is malformed: {msg}"),
            Self::AlreadyApplied => write!(
                f,
                "passport revocation already present in oracle (idempotent re-emit)"
            ),
            Self::OracleRejected(msg) => {
                write!(f, "passport revocation rejected by oracle: {msg}")
            }
        }
    }
}

impl std::error::Error for PassportRevocationBridgeError {}

/// Apply a passport revocation event to the supplied oracle.
///
/// Returns the resulting [`EpochRoot`] on success. The oracle's epoch
/// counter advances by one and the federation push tick will pick up the
/// new signed root on the next flush; verifiers learn about the passport
/// revocation through the same gossip path as any other oracle insert.
pub fn apply_passport_revocation<O: RevocationOracle>(
    oracle: &mut O,
    event: &PassportRevocationEvent,
) -> Result<EpochRoot, PassportRevocationBridgeError> {
    let key = event.to_revocation_key();
    match oracle.insert(key, event.revoked_at_unix_ms) {
        Ok(root) => Ok(root),
        Err(crate::RevocationOracleError::AlreadyRevoked) => {
            Err(PassportRevocationBridgeError::AlreadyApplied)
        }
        Err(other) => Err(PassportRevocationBridgeError::OracleRejected(
            other.to_string(),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::sparse_merkle::InMemoryRevocationOracle;

    fn make_event() -> PassportRevocationEvent {
        PassportRevocationEvent::new(
            "passport-7",
            "did:chio:subject-7",
            1_700_000_000_500,
            Some("compromised key material".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn new_rejects_empty_passport_id() {
        let err = PassportRevocationEvent::new("", "s", 1, None).expect_err("empty passport-id");
        match err {
            PassportRevocationBridgeError::MalformedEvent(msg) => {
                assert!(msg.contains("passport_id"))
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_subject() {
        let err = PassportRevocationEvent::new("p", "", 1, None).expect_err("empty subject");
        match err {
            PassportRevocationBridgeError::MalformedEvent(msg) => assert!(msg.contains("subject")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn new_rejects_padded_required_fields() {
        let err = PassportRevocationEvent::new(" passport-7", "did:chio:subject-7", 1, None)
            .expect_err("padded passport-id");
        match err {
            PassportRevocationBridgeError::MalformedEvent(msg) => {
                assert!(msg.contains("passport_id"))
            }
            other => panic!("unexpected: {other:?}"),
        }

        let err = PassportRevocationEvent::new("passport-7", "did:chio:subject-7 ", 1, None)
            .expect_err("padded subject");
        match err {
            PassportRevocationBridgeError::MalformedEvent(msg) => assert!(msg.contains("subject")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn new_rejects_zero_revoked_at() {
        let err = PassportRevocationEvent::new("p", "s", 0, None).expect_err("zero ts");
        match err {
            PassportRevocationBridgeError::MalformedEvent(msg) => {
                assert!(msg.contains("revoked_at"))
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn new_rejects_blank_reason() {
        let err = PassportRevocationEvent::new("p", "s", 1, Some("   ".to_string()))
            .expect_err("blank reason");
        match err {
            PassportRevocationBridgeError::MalformedEvent(msg) => {
                assert!(msg.contains("revoked_reason"))
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn revocation_key_is_deterministic() {
        let event = make_event();
        let k1 = event.to_revocation_key();
        let k2 = event.to_revocation_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_revoked_at_yields_different_key() {
        let event_a = PassportRevocationEvent::new(
            "passport-7",
            "did:chio:subject-7",
            1_700_000_000_500,
            None,
        )
        .unwrap();
        let event_b = PassportRevocationEvent::new(
            "passport-7",
            "did:chio:subject-7",
            1_700_000_000_600,
            None,
        )
        .unwrap();
        assert_ne!(event_a.to_revocation_key(), event_b.to_revocation_key());
    }

    #[test]
    fn apply_passport_revocation_advances_oracle_epoch() {
        let mut oracle = InMemoryRevocationOracle::new();
        let event = make_event();
        let root = apply_passport_revocation(&mut oracle, &event).expect("apply");
        assert_eq!(root.epoch, 1);
        assert!(oracle.contains(&event.to_revocation_key()));
    }

    #[test]
    fn apply_is_idempotent_via_already_applied_error() {
        let mut oracle = InMemoryRevocationOracle::new();
        let event = make_event();
        apply_passport_revocation(&mut oracle, &event).expect("first apply");
        let err = apply_passport_revocation(&mut oracle, &event).expect_err("re-apply must error");
        assert_eq!(err, PassportRevocationBridgeError::AlreadyApplied);
        // Epoch did NOT advance a second time: federation push will not
        // re-broadcast a stale duplicate.
        let root = oracle.epoch_root();
        assert_eq!(root.epoch, 1);
    }

    #[test]
    fn apply_two_distinct_passports_advances_epoch_twice() {
        let mut oracle = InMemoryRevocationOracle::new();
        let event_a =
            PassportRevocationEvent::new("passport-a", "did:chio:a", 1_700_000_001_000, None)
                .unwrap();
        let event_b =
            PassportRevocationEvent::new("passport-b", "did:chio:b", 1_700_000_001_500, None)
                .unwrap();
        let root_a = apply_passport_revocation(&mut oracle, &event_a).unwrap();
        let root_b = apply_passport_revocation(&mut oracle, &event_b).unwrap();
        assert_eq!(root_a.epoch, 1);
        assert_eq!(root_b.epoch, 2);
        assert!(oracle.contains(&event_a.to_revocation_key()));
        assert!(oracle.contains(&event_b.to_revocation_key()));
    }
}
