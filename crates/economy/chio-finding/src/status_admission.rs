//! The one rule that decides whether a finding may open market state.
//!
//! The decision used to live inside the SQLite authority, mixed with that
//! store's row loading, so any profile that later needed it would have
//! reimplemented it. It lives here instead: a profile supplies the facts
//! through [`FindingStatusSource`] and this module sequences the checks,
//! keeping the market-visible legality in one place while each profile
//! keeps the referential integrity of its own rows.
//!
//! Only the SQLite authority implements the source today, and that is a
//! statement about the hosted profile rather than an omission. Hosted
//! PostgreSQL stores status as event projections with no feed floor and no
//! per-finding non-inclusion proof, so the facts this rule needs do not
//! exist there. Its catalog answers a different and deliberately coarser
//! question, which findings to stop advertising, and under-advertises once
//! any status epoch exists. Giving the hosted profile this decision means
//! first giving it a status-proof store, which is a feature and not a
//! refactor.

use core::fmt;

/// Sticky local status recorded for a finding on one feed.
///
/// A sticky row outranks any proof: once an operator records a retraction
/// intent, the finding is closed to new market state whatever the epoch
/// says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStickyStatus {
    /// A retraction is pending and the finding is closed to new state.
    Pending,
    /// The finding is retracted.
    Retracted,
}

/// Whether a stored proof asserts the finding is in the map or absent from
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatusProofKind {
    /// The finding is present in the status map, which means retracted.
    Inclusion,
    /// The finding is absent from the status map, which means live.
    NonInclusion,
}

/// What a profile knows about the feed's current authoritative floor.
///
/// Owned rather than borrowed so a profile can materialise it from a row it
/// reads inside the call, which is the shape a row-backed store has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingStatusFloorFacts {
    /// The map epoch the floor stands at.
    pub map_epoch: u64,
    /// The operator authorization the floor was advanced under.
    pub operator_authorization_sha256: String,
}

/// What a profile knows about the stored proof at the floor epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingStatusProofFacts {
    /// Whether the proof asserts presence or absence.
    pub kind: FindingStatusProofKind,
    /// When the proof was last checked against its epoch.
    pub checked_at: u64,
    /// When the proof stops standing for the finding's status.
    pub valid_until: u64,
}

/// The freshness and authorization bounds the caller admits under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindingStatusAdmissionRequest<'a> {
    /// The caller's trusted clock reading.
    pub trusted_now: u64,
    /// How old the floor epoch may be and still stand for the finding.
    pub max_epoch_age_secs: u64,
    /// The operator authorization the caller's governance pins, when the
    /// caller pins one.
    pub expected_operator_authorization_sha256: Option<&'a str>,
    /// When the caller's authenticated operator standing was observed,
    /// when the caller carries one.
    pub operator_status_observed_at: Option<u64>,
}

/// The verdict for a finding's market admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatusVerdict {
    /// A retraction is pending; the finding may not open new state.
    Pending,
    /// The finding is retracted.
    Retracted,
    /// The finding is live under a fresh proof at the current floor.
    VerifiedLive,
}

/// Why a finding was refused admission, independent of storage profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatusRefusal {
    /// The feed has no current floor, so nothing stands for the finding.
    FloorMissing,
    /// The floor was advanced under a different operator authorization
    /// than the caller's governance pins.
    OperatorNotBound,
    /// The floor has no proof recorded for this finding.
    ProofMissing,
    /// The floor epoch the proof stands at is absent.
    FloorEpochMissing,
    /// The caller's operator standing predates the current epoch, so it
    /// cannot speak for this floor.
    StandingPredatesEpoch,
    /// An inclusion proof exists without the sticky retracted row that
    /// must accompany it.
    InclusionWithoutRetraction,
    /// The proof or its epoch is outside the caller's freshness bounds.
    Stale,
}

impl FindingStatusRefusal {
    /// Stable snake_case identifier for telemetry and evidence keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FloorMissing => "floor_missing",
            Self::OperatorNotBound => "operator_not_bound",
            Self::ProofMissing => "proof_missing",
            Self::FloorEpochMissing => "floor_epoch_missing",
            Self::StandingPredatesEpoch => "standing_predates_epoch",
            Self::InclusionWithoutRetraction => "inclusion_without_retraction",
            Self::Stale => "stale",
        }
    }

    /// Operator prose for this refusal.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::FloorMissing => "status feed has no current floor",
            Self::OperatorNotBound => {
                "current status floor does not bind the governance-authorized operator"
            }
            Self::ProofMissing => "status floor has no proof for this finding",
            Self::FloorEpochMissing => "status floor points to a missing signed epoch",
            Self::StandingPredatesEpoch => {
                "authenticated operator standing predates the current status epoch"
            }
            Self::InclusionWithoutRetraction => {
                "inclusion proof exists without the required sticky retracted state"
            }
            Self::Stale => "status proof or its epoch is outside the admitted freshness bounds",
        }
    }
}

impl fmt::Display for FindingStatusRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail())
    }
}

/// A refusal, or the profile's own failure to supply the facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingStatusAdmissionError<E> {
    /// The rule refused on the facts supplied.
    Refused(FindingStatusRefusal),
    /// The profile could not supply a fact.
    Source(E),
}

impl<E: fmt::Display> fmt::Display for FindingStatusAdmissionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => refusal.fmt(f),
            Self::Source(error) => error.fmt(f),
        }
    }
}

/// The durable facts one storage profile supplies for the decision.
///
/// Each lookup is separate so a profile loads only what the rule reaches:
/// a sticky row ends the decision before any proof is read.
pub trait FindingStatusSource {
    /// How this profile reports its own read failures.
    type Error;

    /// The sticky status row for this finding, if one exists.
    fn sticky_status(&self) -> Result<Option<FindingStickyStatus>, Self::Error>;

    /// The feed's current floor, if it has one.
    fn floor(&self) -> Result<Option<FindingStatusFloorFacts>, Self::Error>;

    /// The proof recorded for this finding at `map_epoch`, if one exists.
    fn proof_at(&self, map_epoch: u64) -> Result<Option<FindingStatusProofFacts>, Self::Error>;

    /// When the signed epoch at `map_epoch` was generated, if it is
    /// present.
    fn epoch_generated_at(&self, map_epoch: u64) -> Result<Option<u64>, Self::Error>;
}

/// Decide whether a finding may open market state.
///
/// The order is load-bearing. A sticky row is authoritative on its own; a
/// floor that does not bind the caller's operator is refused before any
/// proof is read; and freshness is judged against the floor epoch rather
/// than the proof alone, so an old epoch cannot be laundered by a recently
/// checked proof.
///
/// # Errors
///
/// Returns [`FindingStatusAdmissionError::Refused`] when the facts deny
/// admission, and [`FindingStatusAdmissionError::Source`] when the profile
/// could not supply them.
pub fn decide_finding_status<S: FindingStatusSource>(
    source: &S,
    request: &FindingStatusAdmissionRequest<'_>,
) -> Result<FindingStatusVerdict, FindingStatusAdmissionError<S::Error>> {
    if let Some(sticky) = source.sticky_status().map_err(source_error)? {
        return Ok(match sticky {
            FindingStickyStatus::Pending => FindingStatusVerdict::Pending,
            FindingStickyStatus::Retracted => FindingStatusVerdict::Retracted,
        });
    }
    let floor =
        source
            .floor()
            .map_err(source_error)?
            .ok_or(FindingStatusAdmissionError::Refused(
                FindingStatusRefusal::FloorMissing,
            ))?;
    if request
        .expected_operator_authorization_sha256
        .is_some_and(|expected| floor.operator_authorization_sha256 != expected)
    {
        return Err(FindingStatusAdmissionError::Refused(
            FindingStatusRefusal::OperatorNotBound,
        ));
    }
    let proof = source
        .proof_at(floor.map_epoch)
        .map_err(source_error)?
        .ok_or(FindingStatusAdmissionError::Refused(
            FindingStatusRefusal::ProofMissing,
        ))?;
    let epoch_generated_at = source
        .epoch_generated_at(floor.map_epoch)
        .map_err(source_error)?
        .ok_or(FindingStatusAdmissionError::Refused(
            FindingStatusRefusal::FloorEpochMissing,
        ))?;
    if request
        .operator_status_observed_at
        .is_some_and(|observed_at| observed_at < epoch_generated_at)
    {
        return Err(FindingStatusAdmissionError::Refused(
            FindingStatusRefusal::StandingPredatesEpoch,
        ));
    }
    if proof.kind != FindingStatusProofKind::NonInclusion {
        return Err(FindingStatusAdmissionError::Refused(
            FindingStatusRefusal::InclusionWithoutRetraction,
        ));
    }
    if request.trusted_now < proof.checked_at
        || request.trusted_now >= proof.valid_until
        || request.trusted_now < epoch_generated_at
        || request.trusted_now.saturating_sub(epoch_generated_at) > request.max_epoch_age_secs
    {
        return Err(FindingStatusAdmissionError::Refused(
            FindingStatusRefusal::Stale,
        ));
    }
    Ok(FindingStatusVerdict::VerifiedLive)
}

const fn source_error<E>(error: E) -> FindingStatusAdmissionError<E> {
    FindingStatusAdmissionError::Source(error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Facts {
        sticky: Option<FindingStickyStatus>,
        floor: Option<(u64, String)>,
        proof: Option<FindingStatusProofFacts>,
        epoch_generated_at: Option<u64>,
        read_failure: Option<&'static str>,
    }

    impl FindingStatusSource for Facts {
        type Error = &'static str;

        fn sticky_status(&self) -> Result<Option<FindingStickyStatus>, Self::Error> {
            self.read_failure.map_or(Ok(self.sticky), Err)
        }

        fn floor(&self) -> Result<Option<FindingStatusFloorFacts>, Self::Error> {
            Ok(self
                .floor
                .as_ref()
                .map(|(map_epoch, authorization)| FindingStatusFloorFacts {
                    map_epoch: *map_epoch,
                    operator_authorization_sha256: authorization.clone(),
                }))
        }

        fn proof_at(
            &self,
            _map_epoch: u64,
        ) -> Result<Option<FindingStatusProofFacts>, Self::Error> {
            Ok(self.proof)
        }

        fn epoch_generated_at(&self, _map_epoch: u64) -> Result<Option<u64>, Self::Error> {
            Ok(self.epoch_generated_at)
        }
    }

    fn live_facts() -> Facts {
        Facts {
            floor: Some((7, "a".repeat(64))),
            proof: Some(FindingStatusProofFacts {
                kind: FindingStatusProofKind::NonInclusion,
                checked_at: 1_000,
                valid_until: 2_000,
            }),
            epoch_generated_at: Some(900),
            ..Facts::default()
        }
    }

    fn request(trusted_now: u64) -> FindingStatusAdmissionRequest<'static> {
        FindingStatusAdmissionRequest {
            trusted_now,
            max_epoch_age_secs: 600,
            expected_operator_authorization_sha256: None,
            operator_status_observed_at: None,
        }
    }

    fn decide(facts: &Facts, request: &FindingStatusAdmissionRequest<'_>) -> FindingStatusVerdict {
        decide_finding_status(facts, request).unwrap()
    }

    fn refusal(facts: &Facts, request: &FindingStatusAdmissionRequest<'_>) -> FindingStatusRefusal {
        match decide_finding_status(facts, request) {
            Err(FindingStatusAdmissionError::Refused(refusal)) => refusal,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_fresh_non_inclusion_proof_at_the_floor_is_live() {
        assert_eq!(
            decide(&live_facts(), &request(1_100)),
            FindingStatusVerdict::VerifiedLive
        );
    }

    #[test]
    fn a_sticky_row_outranks_any_proof() {
        for (sticky, expected) in [
            (FindingStickyStatus::Pending, FindingStatusVerdict::Pending),
            (
                FindingStickyStatus::Retracted,
                FindingStatusVerdict::Retracted,
            ),
        ] {
            let facts = Facts {
                sticky: Some(sticky),
                ..live_facts()
            };
            assert_eq!(decide(&facts, &request(1_100)), expected);
        }
    }

    #[test]
    fn a_floor_the_caller_does_not_pin_is_refused_before_the_proof_is_read() {
        let facts = Facts {
            proof: None,
            ..live_facts()
        };
        let pinned = FindingStatusAdmissionRequest {
            expected_operator_authorization_sha256: Some(&"b".repeat(64)),
            ..request(1_100)
        };
        assert_eq!(
            refusal(&facts, &pinned),
            FindingStatusRefusal::OperatorNotBound
        );
    }

    #[test]
    fn missing_durable_state_refuses_rather_than_admitting() {
        for (facts, expected) in [
            (
                Facts {
                    floor: None,
                    ..live_facts()
                },
                FindingStatusRefusal::FloorMissing,
            ),
            (
                Facts {
                    proof: None,
                    ..live_facts()
                },
                FindingStatusRefusal::ProofMissing,
            ),
            (
                Facts {
                    epoch_generated_at: None,
                    ..live_facts()
                },
                FindingStatusRefusal::FloorEpochMissing,
            ),
        ] {
            assert_eq!(refusal(&facts, &request(1_100)), expected);
        }
    }

    #[test]
    fn an_inclusion_proof_without_its_sticky_row_is_an_integrity_refusal() {
        let facts = Facts {
            proof: Some(FindingStatusProofFacts {
                kind: FindingStatusProofKind::Inclusion,
                checked_at: 1_000,
                valid_until: 2_000,
            }),
            ..live_facts()
        };
        assert_eq!(
            refusal(&facts, &request(1_100)),
            FindingStatusRefusal::InclusionWithoutRetraction
        );
    }

    #[test]
    fn standing_taken_before_the_epoch_cannot_speak_for_it() {
        let stale_standing = FindingStatusAdmissionRequest {
            operator_status_observed_at: Some(899),
            ..request(1_100)
        };
        assert_eq!(
            refusal(&live_facts(), &stale_standing),
            FindingStatusRefusal::StandingPredatesEpoch
        );
    }

    #[test]
    fn freshness_is_judged_against_the_epoch_not_the_proof_alone() {
        // Before the proof was checked, after it expires, before the epoch
        // was generated, and beyond the epoch age ceiling.
        for trusted_now in [999, 2_000, 899, 1_501] {
            assert_eq!(
                refusal(&live_facts(), &request(trusted_now)),
                FindingStatusRefusal::Stale,
                "trusted_now {trusted_now} must be refused as stale"
            );
        }
        assert_eq!(
            decide(&live_facts(), &request(1_500)),
            FindingStatusVerdict::VerifiedLive,
            "the epoch age ceiling is inclusive"
        );
    }

    #[test]
    fn a_source_failure_is_reported_as_the_source_not_a_refusal() {
        let facts = Facts {
            read_failure: Some("store offline"),
            ..live_facts()
        };
        assert_eq!(
            decide_finding_status(&facts, &request(1_100)),
            Err(FindingStatusAdmissionError::Source("store offline"))
        );
    }
}
