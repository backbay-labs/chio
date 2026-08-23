use super::*;
use std::time::{Duration, Instant};

pub(crate) const MAX_PULL_PAGES_PER_PEER_PER_ROUND: u32 = 64;
pub(crate) const MAX_PULL_RECORDS_PER_PEER_PER_ROUND: u64 = 200_000;
pub(crate) const PEER_ROUND_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(20);

/// A peer wire-contract VIOLATION: the peer is demoted to `Unhealthy`
/// (fail-closed). These are genuine misbehavior, distinct from a local per-round
/// pull cap (see `RoundLimit`), which is not.
#[derive(Debug)]
pub(crate) enum PeerProtocolError {
    LegacyRevocationCursorUnsupported,
    UnsupportedRevocationCursorVersion {
        version: u8,
    },
    MissingRevocationSequence,
    UnexpectedRevocationSequence,
    MissingRevocationStreamIdentity,
    RevocationStreamIdentityMismatch,
    IncompleteRevocationStreamContract,
    NonAdvancingPage {
        after_seq: u64,
        page_max_seq: u64,
    },
    /// A dense append-only page was not cursor-anchored or had an interior gap:
    /// the sorted seqs did not run consecutively from the expected next seq.
    /// `expected_seq` is the seq the puller required next; `found_seq` is the
    /// out-of-order seq that broke contiguity (either a forward cursor-jump that
    /// would skip unreplicated rows, or an internal hole).
    NonContiguousPage {
        expected_seq: u64,
        found_seq: u64,
    },
    /// A budget delta page carried usage records with NO mutation events. The
    /// honest leader only emits usage projections alongside the mutation events
    /// they derive from, so a records-only page cannot advance the global event
    /// cursor without importing unverified events.
    RecordsWithoutMutationEvents {
        record_count: usize,
    },
    AbandonedWithoutMutationEvents {
        abandoned_count: usize,
    },
    InvalidAbandonedSequence {
        seq: u64,
    },
}

impl std::fmt::Display for PeerProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyRevocationCursorUnsupported => write!(
                f,
                "peer returned the legacy revocation cursor contract to a sequence-cursor puller"
            ),
            Self::UnsupportedRevocationCursorVersion { version } => write!(
                f,
                "peer returned unsupported revocation cursor version {version}"
            ),
            Self::MissingRevocationSequence => write!(
                f,
                "peer returned a sequence-cursor revocation page with a missing seq"
            ),
            Self::UnexpectedRevocationSequence => write!(
                f,
                "peer returned a sequence value in a legacy revocation projection page"
            ),
            Self::MissingRevocationStreamIdentity => write!(
                f,
                "peer omitted the durable revocation stream identity"
            ),
            Self::RevocationStreamIdentityMismatch => write!(
                f,
                "peer returned a revocation cursor or page for a different stream identity"
            ),
            Self::IncompleteRevocationStreamContract => write!(
                f,
                "peer advertised an incomplete revocation stream contract"
            ),
            Self::NonAdvancingPage { after_seq, page_max_seq } => write!(
                f,
                "peer returned a non-empty page whose max seq {page_max_seq} did not advance past cursor {after_seq}"
            ),
            Self::NonContiguousPage { expected_seq, found_seq } => write!(
                f,
                "peer returned a page that is not cursor-anchored or has a gap: expected next seq {expected_seq}, found {found_seq}"
            ),
            Self::RecordsWithoutMutationEvents { record_count } => write!(
                f,
                "peer returned a budget delta with {record_count} usage records but no mutation events"
            ),
            Self::AbandonedWithoutMutationEvents { abandoned_count } => write!(
                f,
                "peer returned a budget delta with {abandoned_count} abandoned sequences but no mutation events"
            ),
            Self::InvalidAbandonedSequence { seq } => write!(
                f,
                "peer returned non-canonical or live-overlapping abandoned sequence {seq}"
            ),
        }
    }
}

/// Revocation replication contract advertised by a peer status response.
///
/// A peer with no top-level cursor version and stream identity is a pre-v4
/// legacy projection source. Current peers must advertise both fields even for
/// an empty stream, which prevents a database reset from masquerading as an
/// empty page at an old cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RevocationPeerContract {
    Legacy,
    Current { stream_id: String, head_seq: u64 },
}

pub(crate) fn revocation_peer_contract(
    replication: &ClusterReplicationHeadsView,
) -> Result<RevocationPeerContract, PeerProtocolError> {
    match (
        replication.revocation_cursor_version,
        replication.revocation_stream_id.as_deref(),
    ) {
        (None, None) => Ok(RevocationPeerContract::Legacy),
        (Some(version), Some(stream_id)) => {
            ensure_revocation_cursor_version(Some(version))?;
            if stream_id.is_empty() {
                return Err(PeerProtocolError::MissingRevocationStreamIdentity);
            }
            let head_seq = match replication.revocation_cursor.as_ref() {
                None => 0,
                Some(cursor)
                    if cursor.cursor_version == Some(version)
                        && cursor.stream_id.as_deref() == Some(stream_id)
                        && cursor.seq.is_some_and(|seq| seq > 0) =>
                {
                    cursor.seq.unwrap_or(0)
                }
                Some(_) => {
                    return Err(PeerProtocolError::IncompleteRevocationStreamContract);
                }
            };
            Ok(RevocationPeerContract::Current {
                stream_id: stream_id.to_string(),
                head_seq,
            })
        }
        _ => Err(PeerProtocolError::IncompleteRevocationStreamContract),
    }
}

pub(crate) fn revocation_snapshot_contract_is_compatible(
    status: &RevocationPeerContract,
    snapshot: &RevocationPeerContract,
) -> bool {
    match (status, snapshot) {
        (RevocationPeerContract::Legacy, RevocationPeerContract::Legacy) => true,
        (
            RevocationPeerContract::Current {
                stream_id: status_stream_id,
                head_seq: status_head_seq,
            },
            RevocationPeerContract::Current {
                stream_id: snapshot_stream_id,
                head_seq: snapshot_head_seq,
            },
        ) => status_stream_id == snapshot_stream_id && snapshot_head_seq >= status_head_seq,
        _ => false,
    }
}

/// The per-round pull budget was reached. This is a LOCAL cap on how much a
/// single peer is pulled per sync round, NOT peer misbehavior: a large but
/// well-ordered backlog legitimately exceeds it. The puller stops the round and
/// resumes from the advanced cursor next round WITHOUT demoting the peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RoundLimit {
    Pages,
    Records,
    Deadline,
}

pub(crate) struct PullRoundBudget {
    pages_left: u32,
    records_left: u64,
    deadline: Instant,
}

impl PullRoundBudget {
    pub(crate) fn new() -> Self {
        Self {
            pages_left: MAX_PULL_PAGES_PER_PEER_PER_ROUND,
            records_left: MAX_PULL_RECORDS_PER_PEER_PER_ROUND,
            deadline: Instant::now() + PEER_ROUND_WALL_CLOCK_BUDGET,
        }
    }

    /// Whether the round budget is already spent, checked BEFORE issuing the next
    /// (blocking) peer fetch so an exhausted stream stops without one more fetch,
    /// and so `sync_peer` can skip the remaining streams' fetches entirely.
    /// This is a read-only pre-check; `charge_page` still
    /// does the authoritative decrement + records accounting after the page lands.
    pub(crate) fn is_exhausted(&self) -> bool {
        self.pages_left == 0 || self.records_left == 0 || Instant::now() >= self.deadline
    }

    /// Charge one page of `records`. An `Err(RoundLimit)` means the LOCAL per-round
    /// cap (pages, records, or wall-clock deadline) was reached: the caller stops
    /// this round and resumes next sync round, keeping the peer Healthy. It is NOT
    /// a peer protocol violation, so it must never route through the demotion path.
    pub(crate) fn charge_page(&mut self, records: u64) -> Result<(), RoundLimit> {
        if Instant::now() >= self.deadline {
            return Err(RoundLimit::Deadline);
        }
        self.pages_left = self.pages_left.checked_sub(1).ok_or(RoundLimit::Pages)?;
        self.records_left = self
            .records_left
            .checked_sub(records)
            .ok_or(RoundLimit::Records)?;
        Ok(())
    }
}

/// Soundness guard for a dense append-only `u64` sequence puller (tool
/// receipts, child receipts, lineage, and the budget mutation-event stream).
///
/// A max-advance-only check (page max seq > cursor) is NOT enough: a peer at
/// cursor 10 that returns the page {110, 111} would pass it, get imported, and
/// advance the cursor to 111, permanently omitting the append-only rows 11..109
/// (a replication-soundness hole). This requires the returned page to be BOTH
/// cursor-anchored and gap-free: the sorted seqs must run consecutively
/// starting at `expected_next_seq`. Any forward cursor-jump (page starts past
/// the expected next row) or interior hole is a `NonContiguousPage` protocol
/// violation, which demotes the peer via the existing `update_peer_failure`
/// path and does NOT advance the cursor past the gap. An empty slice is
/// vacuously contiguous (the callers treat an empty page as "caught up" and do
/// not advance).
pub(crate) fn require_contiguous_page(
    expected_next_seq: u64,
    seqs: &[u64],
) -> Result<(), PeerProtocolError> {
    // Check the page IN ITS ORIGINAL ORDER (do not sort): the budget importer
    // applies events in the order received, so a dependency-ordered stream (an
    // authorize before its release) must arrive already ascending. Sorting here
    // would let an out-of-order page pass the guard and then import wrong (a
    // release before its hold exists), surfacing as a retryable store error
    // instead of demoting the malformed peer. Requiring
    // strictly ascending, gap-free-from-expected order rejects both a skip and a
    // reorder as a NonContiguousPage.
    let mut expected = expected_next_seq;
    for &seq in seqs {
        if seq != expected {
            return Err(PeerProtocolError::NonContiguousPage {
                expected_seq: expected,
                found_seq: seq,
            });
        }
        expected = expected.saturating_add(1);
    }
    Ok(())
}

/// Soundness guard for a NON-DENSE append-only `u64` sequence puller (tool
/// receipts, child receipts, and lineage snapshots).
///
/// Unlike the budget mutation-event stream, these seqs come from `INTEGER
/// PRIMARY KEY AUTOINCREMENT` columns (lineage paginates on the plain rowid)
/// written with `INSERT ... ON CONFLICT DO NOTHING` and are subject to
/// retention deletes, so they legitimately contain GAPS: a store can hold rows
/// 1 and 3 with no row 2. Requiring gap-free contiguity here (the dense
/// `require_contiguous_page` guard) would wrongly demote an honest peer that
/// returns seq 3 after cursor 1 and permanently break replication of that
/// stream. The safe, still fail-closed check for a non-dense stream is only
/// forward progress (the page's lowest seq is strictly above the cursor, so the
/// peer cannot resend/rewind already-consumed rows) plus within-page strict
/// monotonicity (no duplicate or repeated seq).
///
/// A legitimate gap above the cursor is accepted. Because the stream is not
/// dense, a malicious mid-stream skip is NOT reliably client-detectable (the
/// same fundamental limitation as the revocation stream); the periodic full
/// snapshot (`apply_cluster_snapshot`) is the backstop that bounds a lying peer,
/// not incremental convergence. An empty slice is vacuously valid ("caught up").
pub(crate) fn require_forward_progress(
    after_seq: u64,
    seqs: &[u64],
) -> Result<(), PeerProtocolError> {
    if seqs.is_empty() {
        return Ok(());
    }
    // Do not trust the peer's ordering: sort locally so an out-of-order page
    // cannot mask a rewind or a duplicate.
    let mut sorted = seqs.to_vec();
    sorted.sort_unstable();
    let lowest = *sorted.first().unwrap_or(&after_seq);
    let highest = *sorted.last().unwrap_or(&lowest);
    // Forward progress: every row must sit strictly above the cursor, so a page
    // can never resend or rewind rows the puller already consumed.
    if lowest <= after_seq {
        return Err(PeerProtocolError::NonAdvancingPage {
            after_seq,
            page_max_seq: highest,
        });
    }
    // Strict monotonicity: a duplicate seq is a malformed page (a PK seq column
    // cannot legitimately repeat a value within a page).
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(PeerProtocolError::NonContiguousPage {
                expected_seq: pair[0].saturating_add(1),
                found_seq: pair[1],
            });
        }
    }
    Ok(())
}

/// Validate the revocation cursor contract selected by an upgraded puller.
///
/// Version 4 is a dense append-only per-store sequence bound to a durable stream
/// identity. Earlier versions cannot share cursors with it. An unversioned
/// response remains invalid when the peer advertised the current contract, but
/// a status-verified legacy peer is handled by the separate full-projection
/// replay path.
pub(crate) fn ensure_revocation_cursor_version(
    cursor_version: Option<u8>,
) -> Result<(), PeerProtocolError> {
    match cursor_version {
        Some(REVOCATION_SEQUENCE_CURSOR_VERSION) => Ok(()),
        None => Err(PeerProtocolError::LegacyRevocationCursorUnsupported),
        Some(version) => Err(PeerProtocolError::UnsupportedRevocationCursorVersion { version }),
    }
}

pub(crate) fn ensure_current_revocation_cursor(
    cursor: Option<&RevocationCursor>,
    expected_stream_id: &str,
) -> Result<(), PeerProtocolError> {
    if let Some(cursor) = cursor {
        ensure_revocation_cursor_version(cursor.cursor_version)?;
        if cursor.stream_id.as_deref() != Some(expected_stream_id) || cursor.seq.is_none() {
            return Err(PeerProtocolError::RevocationStreamIdentityMismatch);
        }
    }
    Ok(())
}

pub(crate) fn current_revocation_cursor_requires_snapshot(
    cursor: Option<&RevocationCursor>,
    expected_stream_id: &str,
    advertised_head_seq: u64,
) -> bool {
    cursor.is_some_and(|cursor| {
        ensure_current_revocation_cursor(Some(cursor), expected_stream_id).is_err()
            || cursor.seq.unwrap_or(0) > advertised_head_seq
    })
}

pub(crate) fn ensure_revocation_page_ascending(
    cursor: Option<&RevocationCursor>,
    cursor_version: Option<u8>,
    response_stream_id: Option<&str>,
    expected_stream_id: &str,
    records: &[StoredRevocationView],
) -> Result<RevocationCursor, PeerProtocolError> {
    ensure_revocation_cursor_version(cursor_version)?;
    if response_stream_id != Some(expected_stream_id) {
        return Err(PeerProtocolError::RevocationStreamIdentityMismatch);
    }
    ensure_current_revocation_cursor(cursor, expected_stream_id)?;
    ensure_sequence_revocation_page_ascending(cursor, expected_stream_id, records)
}

fn ensure_sequence_revocation_page_ascending(
    cursor: Option<&RevocationCursor>,
    stream_id: &str,
    records: &[StoredRevocationView],
) -> Result<RevocationCursor, PeerProtocolError> {
    let after_seq = cursor.and_then(|value| value.seq).unwrap_or(0);
    let seqs = records
        .iter()
        .map(|record| {
            record
                .seq
                .ok_or(PeerProtocolError::MissingRevocationSequence)
        })
        .collect::<Result<Vec<_>, _>>()?;
    require_contiguous_page(after_seq.saturating_add(1), &seqs)?;
    let record = records.last().ok_or(PeerProtocolError::NonAdvancingPage {
        after_seq,
        page_max_seq: after_seq,
    })?;
    Ok(RevocationCursor {
        cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
        stream_id: Some(stream_id.to_string()),
        seq: record.seq,
        revoked_at: record.revoked_at,
        capability_id: record.capability_id.clone(),
    })
}

/// Validate one page from a status-verified legacy peer's full current-state
/// projection. The tuple cursor is only a within-pass pagination token. The
/// caller clears it after the first empty page so the next completed pass starts
/// at genesis and catches same-second records that sort before the prior pass's
/// head.
pub(crate) fn ensure_legacy_revocation_page_ascending(
    cursor: Option<&RevocationCursor>,
    records: &[StoredRevocationView],
) -> Result<RevocationCursor, PeerProtocolError> {
    if cursor.is_some_and(|cursor| {
        cursor.cursor_version.is_some() || cursor.stream_id.is_some() || cursor.seq.is_some()
    }) {
        return Err(PeerProtocolError::IncompleteRevocationStreamContract);
    }
    let mut previous = cursor.cloned();
    let mut head = None;
    for record in records {
        if record.seq.is_some() {
            return Err(PeerProtocolError::UnexpectedRevocationSequence);
        }
        let current = RevocationCursor {
            cursor_version: None,
            stream_id: None,
            seq: None,
            revoked_at: record.revoked_at,
            capability_id: record.capability_id.clone(),
        };
        let advances = previous.as_ref().is_none_or(|prior| {
            (current.revoked_at, current.capability_id.as_str())
                > (prior.revoked_at, prior.capability_id.as_str())
        });
        if !advances {
            return Err(PeerProtocolError::NonAdvancingPage {
                after_seq: previous
                    .as_ref()
                    .map(|value| value.revoked_at.max(0) as u64)
                    .unwrap_or(0),
                page_max_seq: current.revoked_at.max(0) as u64,
            });
        }
        previous = Some(current.clone());
        head = Some(current);
    }
    head.ok_or(PeerProtocolError::NonAdvancingPage {
        after_seq: cursor
            .map(|value| value.revoked_at.max(0) as u64)
            .unwrap_or(0),
        page_max_seq: 0,
    })
}

/// Carries the protocol-violation distinction out of the pullers so `sync_peer`
/// can demote a misbehaving peer while leaving a transient failure retryable.
#[derive(Debug)]
pub(crate) enum PullError {
    /// The peer violated the pull wire contract; demote it (fail-closed).
    Protocol(PeerProtocolError),
    /// Transport or store failure; retryable, peer keeps its standing.
    Transient(CliError),
    /// A fetched delta page's record count (events + usage projections +
    /// abandoned/tombstoned slots over the covered global-seq range) exceeds
    /// `BUDGET_DELTA_MAX_RECORDS`. The puller (`drain_budget_delta_pages`) FIRST
    /// retries the same cursor with a SMALLER event limit, since a page often
    /// overflows only because a full `MAX_LIST_LIMIT` event window also drags in its
    /// paired usages/abandoned seqs. This variant is honored as a genuine full resync
    /// ONLY when even a MINIMAL one-event page still overflows: a dense rollback burst
    /// can pack more abandoned seqs than the cap BEFORE the next live event (and an
    /// events-empty page is rejected), so no cursor-anchored page makes forward
    /// progress. This is NOT peer misbehavior: route the peer through the full
    /// snapshot recovery path (which resets the cursor to the snapshot head, skipping
    /// the unpageable window WITHOUT a delta cursor jump) rather than pinning the
    /// cursor forever with a bare `Transient`.
    ForceSnapshot(CliError),
}

impl From<PeerProtocolError> for PullError {
    fn from(error: PeerProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<CliError> for PullError {
    fn from(error: CliError) -> Self {
        Self::Transient(error)
    }
}

#[cfg(test)]
mod pull_budget_tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn charge_page_reports_round_limits_not_protocol_errors() {
        // A per-round cap is a LOCAL RoundLimit (the caller stops and resumes next
        // round), NOT a PeerProtocolError that would demote an honest backlog.
        let mut budget = PullRoundBudget::new();
        // Records budget: one page that overruns the record budget stops the round.
        let mut records_budget = PullRoundBudget::new();
        assert_eq!(
            records_budget.charge_page(MAX_PULL_RECORDS_PER_PEER_PER_ROUND + 1),
            Err(RoundLimit::Records)
        );

        // Page budget: the 65th page (>64 pages of honest backlog) stops the round.
        for _ in 0..MAX_PULL_PAGES_PER_PEER_PER_ROUND {
            assert!(budget.charge_page(1).is_ok(), "page within budget");
        }
        assert_eq!(budget.charge_page(1), Err(RoundLimit::Pages));
    }

    #[test]
    fn is_exhausted_flags_spent_budget_before_the_next_fetch() {
        // A fresh round is not exhausted, so pullers may fetch.
        let mut pages = PullRoundBudget::new();
        assert!(!pages.is_exhausted());
        // Spend the page budget: is_exhausted() flips true so the NEXT fetch is
        // skipped (no extra page beyond the cap) and sync_peer skips later streams.
        for _ in 0..MAX_PULL_PAGES_PER_PEER_PER_ROUND {
            assert!(pages.charge_page(1).is_ok());
        }
        assert!(pages.is_exhausted(), "no page budget left");

        // Record budget exhaustion also flags is_exhausted (records_left == 0).
        let mut records = PullRoundBudget::new();
        assert!(records
            .charge_page(MAX_PULL_RECORDS_PER_PEER_PER_ROUND)
            .is_ok());
        assert!(
            records.is_exhausted(),
            "no record budget left after consuming it exactly"
        );
    }

    #[test]
    fn require_contiguous_page_rejects_cursor_jump_and_interior_gap() {
        // Cursor-anchored, gap-free page from cursor 10 (expected next 11).
        assert!(require_contiguous_page(11, &[11, 12, 13]).is_ok());
        // An empty page is vacuously contiguous ("caught up").
        assert!(require_contiguous_page(11, &[]).is_ok());
        // Out-of-order is REJECTED (the importer applies events in received
        // order, so a reorder must not pass).
        assert!(matches!(
            require_contiguous_page(11, &[13, 11, 12]),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 11,
                found_seq: 13
            })
        ));
        assert!(matches!(
            require_contiguous_page(11, &[12, 11, 13]),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 11,
                found_seq: 12
            })
        ));

        // Forward cursor-jump: {110, 111} from cursor 10 would skip 11..109.
        // A max-advance-only check (110 > 10) would wrongly ACCEPT this; the
        // contiguity guard rejects it, anchored at the expected next seq.
        assert!(matches!(
            require_contiguous_page(11, &[110, 111]),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 11,
                found_seq: 110
            })
        ));
        // Interior hole: {11, 12, 14} skips 13.
        assert!(matches!(
            require_contiguous_page(11, &[11, 12, 14]),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 13,
                found_seq: 14
            })
        ));
        // A duplicate seq breaks contiguity (second 12 lands below expected 13).
        assert!(matches!(
            require_contiguous_page(11, &[11, 12, 12]),
            Err(PeerProtocolError::NonContiguousPage { .. })
        ));
    }

    #[test]
    fn require_forward_progress_accepts_legit_gaps_but_rejects_rewind_and_duplicate() {
        // Non-dense streams (tool/child receipts, lineage) legitimately gap: a
        // page {3} after cursor 1 (no row 2, retention-deleted or a burned
        // AUTOINCREMENT slot) must be ACCEPTED, unlike the dense budget stream.
        assert!(require_forward_progress(1, &[3]).is_ok());
        assert!(require_forward_progress(1, &[2, 3, 5, 8]).is_ok());
        // Empty page is vacuously valid ("caught up").
        assert!(require_forward_progress(9, &[]).is_ok());
        // Out-of-order but still all above the cursor and distinct.
        assert!(require_forward_progress(1, &[8, 3, 5]).is_ok());

        // Rewind/resend: a row at or below the cursor is forbidden (would replay
        // already-consumed rows).
        assert!(matches!(
            require_forward_progress(5, &[5, 6]),
            Err(PeerProtocolError::NonAdvancingPage { after_seq: 5, .. })
        ));
        assert!(matches!(
            require_forward_progress(5, &[3, 7]),
            Err(PeerProtocolError::NonAdvancingPage { after_seq: 5, .. })
        ));
        // A duplicate seq within the page is malformed.
        assert!(matches!(
            require_forward_progress(1, &[3, 3, 4]),
            Err(PeerProtocolError::NonContiguousPage { .. })
        ));
    }

    #[test]
    fn sequence_revocation_page_must_be_cursor_anchored_and_dense() {
        // The puller persists the page head as the next cursor. The append-only
        // source stream is dense, so accepting an ascending jump would let a peer
        // strand every omitted revocation below that new cursor.
        let rec = |seq: u64, revoked_at: i64, cap: &str| StoredRevocationView {
            seq: Some(seq),
            capability_id: cap.to_string(),
            revoked_at,
        };
        let stream_id = "01991bb4-e2f7-7e21-b75d-a59be8fbc441";
        let cursor = RevocationCursor {
            cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            stream_id: Some(stream_id.to_string()),
            seq: Some(5),
            revoked_at: 5,
            capability_id: "cap-b".to_string(),
        };

        // A cursor-anchored dense page returns its last sequence as the head.
        let Ok(head) = ensure_revocation_page_ascending(
            Some(&cursor),
            Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            Some(stream_id),
            stream_id,
            &[rec(6, 5, "cap-c"), rec(7, 6, "cap-a"), rec(8, 9, "cap-z")],
        ) else {
            panic!("a cursor-anchored dense page is valid");
        };
        assert_eq!(head.seq, Some(8));
        assert_eq!(
            head.cursor_version,
            Some(REVOCATION_SEQUENCE_CURSOR_VERSION)
        );

        // A forward jump is a protocol violation even when the page is otherwise
        // ascending: sequence 8 has not been returned.
        assert!(matches!(
            ensure_revocation_page_ascending(
                Some(&cursor),
                Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
                Some(stream_id),
                stream_id,
                &[rec(6, 7, "cap-a"), rec(7, 8, "cap-b"), rec(9, 10, "cap-c")]
            ),
            Err(PeerProtocolError::NonContiguousPage {
                expected_seq: 8,
                found_seq: 9
            })
        ));

        // The first row must be exactly the cursor successor (no rewind/resend).
        assert!(matches!(
            ensure_revocation_page_ascending(
                Some(&cursor),
                Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
                Some(stream_id),
                stream_id,
                &[rec(5, 6, "cap-b"), rec(6, 5, "cap-a")]
            ),
            Err(PeerProtocolError::NonContiguousPage { .. })
        ));

        // A fresh cursor accepts the first row unconditionally, then requires ascent.
        let Ok(head) = ensure_revocation_page_ascending(
            None,
            Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            Some(stream_id),
            stream_id,
            &[rec(1, 2, "cap-a"), rec(2, 1, "cap-a")],
        ) else {
            panic!("ascending page from a fresh cursor is valid");
        };
        assert_eq!(head.seq, Some(2));
    }

    #[test]
    fn revocation_wire_decodes_legacy_delta_and_snapshot_cursor() {
        let query: RevocationDeltaQuery =
            serde_urlencoded::from_str("afterRevokedAt=11&afterCapabilityId=cap-old&limit=25")
                .test_unwrap();
        assert_eq!(query.cursor_version, None);
        assert_eq!(query.after_seq, None);
        assert_eq!(query.after_revoked_at, Some(11));
        assert_eq!(query.after_capability_id.as_deref(), Some("cap-old"));

        let response: RevocationDeltaResponse = serde_json::from_value(serde_json::json!({
            "records": [{"capabilityId": "cap-old", "revokedAt": 11}]
        }))
        .test_unwrap();
        assert_eq!(response.cursor_version, None);
        assert_eq!(response.records[0].seq, None);

        let cursor = serde_json::from_value::<RevocationCursorView>(serde_json::json!({
            "revokedAt": 11,
            "capabilityId": "cap-old"
        }))
        .test_unwrap();
        assert_eq!(cursor.cursor_version, None);
        assert_eq!(cursor.stream_id, None);
        assert_eq!(cursor.seq, None);
    }

    #[test]
    fn upgraded_revocation_puller_rejects_legacy_downgrade() {
        let legacy_record = StoredRevocationView {
            seq: None,
            capability_id: "cap-a".to_string(),
            revoked_at: 5,
        };
        assert!(matches!(
            ensure_revocation_page_ascending(None, None, None, "current-stream", &[legacy_record]),
            Err(PeerProtocolError::LegacyRevocationCursorUnsupported)
        ));
        let retired = RevocationCursor {
            cursor_version: Some(2),
            stream_id: Some("retired-stream".to_string()),
            seq: Some(9),
            revoked_at: 5,
            capability_id: "cap-retired".to_string(),
        };
        assert!(matches!(
            ensure_current_revocation_cursor(Some(&retired), "current-stream"),
            Err(PeerProtocolError::UnsupportedRevocationCursorVersion { version: 2 })
        ));
    }

    #[test]
    fn revocation_page_rejects_mixed_and_unsupported_cursor_shapes() {
        let legacy_record = StoredRevocationView {
            seq: None,
            capability_id: "cap-a".to_string(),
            revoked_at: 1,
        };
        let sequence_record = StoredRevocationView {
            seq: Some(1),
            capability_id: "cap-a".to_string(),
            revoked_at: 1,
        };
        assert!(matches!(
            ensure_revocation_page_ascending(None, None, None, "current-stream", &[legacy_record]),
            Err(PeerProtocolError::LegacyRevocationCursorUnsupported)
        ));
        assert!(matches!(
            ensure_revocation_page_ascending(
                None,
                None,
                None,
                "current-stream",
                &[sequence_record]
            ),
            Err(PeerProtocolError::LegacyRevocationCursorUnsupported)
        ));
        assert!(matches!(
            ensure_revocation_page_ascending(
                None,
                Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
                Some("current-stream"),
                "current-stream",
                &[StoredRevocationView {
                    seq: None,
                    capability_id: "cap-missing".to_string(),
                    revoked_at: 1,
                }]
            ),
            Err(PeerProtocolError::MissingRevocationSequence)
        ));
        assert!(matches!(
            ensure_revocation_cursor_version(Some(99)),
            Err(PeerProtocolError::UnsupportedRevocationCursorVersion { version: 99 })
        ));
    }

    #[test]
    fn revocation_status_distinguishes_legacy_and_empty_current_streams() {
        let legacy: ClusterReplicationHeadsView = serde_json::from_value(serde_json::json!({
            "toolSeq": 0,
            "childSeq": 0,
            "lineageSeq": 0,
            "budgetSeq": 0,
            "revocationCursor": {
                "cursorVersion": 3,
                "seq": 9,
                "revokedAt": 11,
                "capabilityId": "cap-old"
            }
        }))
        .test_unwrap();
        assert_eq!(
            revocation_peer_contract(&legacy).test_unwrap(),
            RevocationPeerContract::Legacy
        );

        let stream_id = "01991bb4-e2f7-7e21-b75d-a59be8fbc441";
        let current = ClusterReplicationHeadsView {
            revocation_cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            revocation_stream_id: Some(stream_id.to_string()),
            ..ClusterReplicationHeadsView::default()
        };
        assert_eq!(
            revocation_peer_contract(&current).test_unwrap(),
            RevocationPeerContract::Current {
                stream_id: stream_id.to_string(),
                head_seq: 0,
            }
        );

        let incomplete = ClusterReplicationHeadsView {
            revocation_cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            ..ClusterReplicationHeadsView::default()
        };
        assert!(matches!(
            revocation_peer_contract(&incomplete),
            Err(PeerProtocolError::IncompleteRevocationStreamContract)
        ));
    }

    #[test]
    fn revocation_snapshot_contract_accepts_advancing_head_and_rejects_regression() {
        let status = RevocationPeerContract::Current {
            stream_id: "stream-a".to_string(),
            head_seq: 12,
        };
        let advanced_snapshot = RevocationPeerContract::Current {
            stream_id: "stream-a".to_string(),
            head_seq: 13,
        };
        assert!(revocation_snapshot_contract_is_compatible(
            &status,
            &advanced_snapshot
        ));
        assert!(revocation_snapshot_contract_is_compatible(&status, &status));
        assert!(!revocation_snapshot_contract_is_compatible(
            &status,
            &RevocationPeerContract::Current {
                stream_id: "stream-a".to_string(),
                head_seq: 11,
            }
        ));
        assert!(!revocation_snapshot_contract_is_compatible(
            &status,
            &RevocationPeerContract::Current {
                stream_id: "stream-b".to_string(),
                head_seq: 13,
            }
        ));
        assert!(!revocation_snapshot_contract_is_compatible(
            &status,
            &RevocationPeerContract::Legacy
        ));
    }

    #[test]
    fn revocation_cursor_detects_stream_replacement_and_head_rollback() {
        let cursor = RevocationCursor {
            cursor_version: Some(REVOCATION_SEQUENCE_CURSOR_VERSION),
            stream_id: Some("stream-a".to_string()),
            seq: Some(12),
            revoked_at: 20,
            capability_id: "cap-a".to_string(),
        };
        assert!(!current_revocation_cursor_requires_snapshot(
            Some(&cursor),
            "stream-a",
            12
        ));
        assert!(current_revocation_cursor_requires_snapshot(
            Some(&cursor),
            "stream-b",
            12
        ));
        assert!(current_revocation_cursor_requires_snapshot(
            Some(&cursor),
            "stream-a",
            11
        ));
    }

    #[test]
    fn legacy_projection_cursor_is_safe_only_within_a_full_pass() {
        let records = [
            StoredRevocationView {
                seq: None,
                capability_id: "cap-a".to_string(),
                revoked_at: 10,
            },
            StoredRevocationView {
                seq: None,
                capability_id: "cap-b".to_string(),
                revoked_at: 10,
            },
        ];
        let head = ensure_legacy_revocation_page_ascending(None, &records).test_unwrap();
        assert_eq!(head.cursor_version, None);
        assert_eq!(head.stream_id, None);
        assert_eq!(head.seq, None);
        assert_eq!(head.capability_id, "cap-b");

        let same_second_backfill = StoredRevocationView {
            seq: None,
            capability_id: "cap-0".to_string(),
            revoked_at: 10,
        };
        assert!(matches!(
            ensure_legacy_revocation_page_ascending(Some(&head), &[same_second_backfill]),
            Err(PeerProtocolError::NonAdvancingPage { .. })
        ));
        // Clearing the completed-pass cursor makes the same backfill visible on
        // the next genesis replay.
        let replay = StoredRevocationView {
            seq: None,
            capability_id: "cap-0".to_string(),
            revoked_at: 10,
        };
        assert!(ensure_legacy_revocation_page_ascending(None, &[replay]).is_ok());
    }
}
