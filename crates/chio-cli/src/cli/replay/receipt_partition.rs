// Replay-receipt partitioning and namespacing for `chio replay traffic --against`.
//
// Two collision-mitigation primitives:
// 1. Replay receipt ids are prefixed `replay:<run_id>:<frame_id>` so they
//    cannot collide with production receipts.
// 2. [`StorePartition`] enforces bidirectional refusal: production writes
//    are rejected from replay partitions and vice versa. This enforcement
//    lives at the chio-cli layer; store-layer enforcement is follow-up work.

/// Logical partition flag enforced at the chio-cli layer.
///
/// The two variants are mutually exclusive and form the type-level
/// invariant the dispatcher uses to route writes:
/// production-frame work goes through [`Self::Production`], replay
/// re-execution work through [`Self::Replay`]. The runtime check in
/// [`StorePartition::ensure_compatible_with`] returns an error when the
/// caller's expectation differs from the partition's flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorePartition {
    /// Live, production-side work. Writes through this partition emit
    /// receipts whose ids are unprefixed kernel-native ids.
    Production,
    /// Replay-mode work for a single re-execution run.
    ///
    /// `run_id` is a stable identifier (UUID-v4 by default; user-supplied
    /// via `--run-id` when callers want determinism in fixtures). Every
    /// replay receipt id under this partition is prefixed
    /// `replay:<run_id>:<frame_id>`.
    Replay { run_id: String },
}

/// Errors returned by partition-aware write helpers.
#[derive(Debug, thiserror::Error)]
pub enum PartitionError {
    /// A production-flagged caller tried to write into a replay-flagged
    /// store, or vice versa.
    #[error("partition mismatch: store is {store}, write requested {requested}")]
    Mismatch { store: &'static str, requested: &'static str },

    /// Tried to mint a production receipt-id with the replay namespace
    /// helper, or vice versa. This is the type-level dual of
    /// `Mismatch` and trips when callers swap helpers.
    #[error("receipt-id namespace mismatch: {0}")]
    NamespaceMismatch(String),
}

impl StorePartition {
    /// Construct a fresh replay partition with a randomly generated
    /// run-id. The id format is UUID-v4 lowercase hex sans dashes so
    /// the resulting `replay:<run_id>:<frame_id>` ids stay base32/base16
    /// compatible.
    pub fn replay_with_random_run_id() -> Self {
        let run_id = uuid::Uuid::new_v4().simple().to_string();
        Self::Replay { run_id }
    }

    /// Construct a replay partition with a caller-supplied run-id. The
    /// id is validated for non-emptiness and ASCII-token shape so the
    /// resulting ids stay grep-friendly. Empty or whitespace-only ids
    /// fail closed.
    pub fn replay_with_run_id(run_id: impl Into<String>) -> Result<Self, PartitionError> {
        let run_id = run_id.into();
        if run_id.is_empty() {
            return Err(PartitionError::NamespaceMismatch(
                "run_id must not be empty".to_string(),
            ));
        }
        if !run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(PartitionError::NamespaceMismatch(format!(
                "run_id {run_id:?} must be ASCII [A-Za-z0-9_-]+"
            )));
        }
        Ok(Self::Replay { run_id })
    }

    /// Static-string label for diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Replay { .. } => "replay",
        }
    }

    /// Bidirectional refusal helper. Returns `Ok(())` only when the
    /// partition kind matches the caller's stated expectation.
    pub fn ensure_compatible_with(&self, requested: &StorePartition) -> Result<(), PartitionError> {
        match (self, requested) {
            (Self::Production, Self::Production) => Ok(()),
            (Self::Replay { .. }, Self::Replay { .. }) => Ok(()),
            (a, b) => Err(PartitionError::Mismatch {
                store: a.kind(),
                requested: b.kind(),
            }),
        }
    }

    /// Return the `run_id` of a replay partition, or `None` for
    /// production. Used by the dispatcher to mint the receipt-id
    /// prefix.
    pub fn run_id(&self) -> Option<&str> {
        match self {
            Self::Production => None,
            Self::Replay { run_id } => Some(run_id),
        }
    }
}

/// Replay-receipt minting helper. The wrapper exists so callers cannot
/// accidentally mint a replay receipt id from a production partition or
/// vice versa: the [`Self::new`] constructor only succeeds for the
/// replay variant.
#[derive(Debug, Clone)]
pub struct ReplayPartition {
    run_id: String,
}

impl ReplayPartition {
    /// Construct from a [`StorePartition::Replay`]. Returns
    /// [`PartitionError::NamespaceMismatch`] when the input is the
    /// production variant; this prevents production code paths from
    /// accidentally emitting `replay:` ids.
    pub fn new(partition: &StorePartition) -> Result<Self, PartitionError> {
        match partition {
            StorePartition::Replay { run_id } => Ok(Self {
                run_id: run_id.clone(),
            }),
            StorePartition::Production => Err(PartitionError::NamespaceMismatch(
                "ReplayPartition cannot be constructed from a production-flagged store"
                    .to_string(),
            )),
        }
    }

    /// `run_id` of this replay partition.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Mint a namespaced replay-receipt id for a frame.
    ///
    /// Format: `replay:<run_id>:<frame_id>`. The frame id is the
    /// `event_id` of the source NDJSON frame (typed
    /// `chio_tee_frame::Frame::event_id`). Empty frame ids fail closed
    /// to avoid shipping degenerate `replay:<run>:` ids that could
    /// collide with future schemas.
    pub fn replay_receipt_id(&self, frame_id: &str) -> Result<String, PartitionError> {
        if frame_id.is_empty() {
            return Err(PartitionError::NamespaceMismatch(
                "frame_id must not be empty".to_string(),
            ));
        }
        Ok(format!("replay:{}:{}", self.run_id, frame_id))
    }
}

/// Free-function variant of [`ReplayPartition::replay_receipt_id`] for
/// call sites that have already extracted a `run_id`. Kept for symmetry
/// with the milestone doc's prose, which describes the namespace as a
/// pure function `(run_id, frame_id) -> id`.
pub fn replay_receipt_id(run_id: &str, frame_id: &str) -> String {
    format!("replay:{run_id}:{frame_id}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_receipt_partition_tests {
    use super::*;

    #[test]
    fn random_run_id_yields_replay_partition() {
        let p = StorePartition::replay_with_random_run_id();
        match &p {
            StorePartition::Replay { run_id } => {
                assert_eq!(run_id.len(), 32, "uuid simple form is 32 hex chars");
                assert!(
                    run_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                    "uuid simple form is lowercase hex"
                );
            }
            other => panic!("expected Replay, got {other:?}"),
        }
        assert_eq!(p.kind(), "replay");
    }

    #[test]
    fn replay_run_ids_are_unique_across_random_calls() {
        // Cheap uniqueness sanity-check: two random run-ids should not
        // collide (the chance is ~1 in 2^122 per the UUID-v4 spec). If
        // this trips we have a generator bug.
        let a = StorePartition::replay_with_random_run_id();
        let b = StorePartition::replay_with_random_run_id();
        assert_ne!(a, b);
    }

    #[test]
    fn user_supplied_run_id_round_trips() {
        let p = StorePartition::replay_with_run_id("ci-run-2026-04-25").unwrap();
        match &p {
            StorePartition::Replay { run_id } => {
                assert_eq!(run_id, "ci-run-2026-04-25");
            }
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn user_supplied_empty_run_id_rejected() {
        let err = StorePartition::replay_with_run_id("").unwrap_err();
        assert!(matches!(err, PartitionError::NamespaceMismatch(_)));
    }

    #[test]
    fn user_supplied_run_id_rejects_non_ascii_token_chars() {
        let err = StorePartition::replay_with_run_id("bad id with spaces").unwrap_err();
        assert!(matches!(err, PartitionError::NamespaceMismatch(_)));
        let err = StorePartition::replay_with_run_id("bad/id/slash").unwrap_err();
        assert!(matches!(err, PartitionError::NamespaceMismatch(_)));
    }

    #[test]
    fn production_partition_compatible_with_itself() {
        let p = StorePartition::Production;
        p.ensure_compatible_with(&StorePartition::Production).unwrap();
    }

    #[test]
    fn replay_partition_compatible_with_replay() {
        // Different run-ids still match: the partition flag is
        // categorical (production vs replay), not run-scoped.
        let a = StorePartition::replay_with_random_run_id();
        let b = StorePartition::replay_with_random_run_id();
        a.ensure_compatible_with(&b).unwrap();
    }

    #[test]
    fn production_refuses_replay_writes_bidirectionally() {
        // Forward direction: production store + replay write -> error.
        let prod = StorePartition::Production;
        let replay = StorePartition::replay_with_random_run_id();
        let err = prod.ensure_compatible_with(&replay).unwrap_err();
        match err {
            PartitionError::Mismatch { store, requested } => {
                assert_eq!(store, "production");
                assert_eq!(requested, "replay");
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn replay_refuses_production_writes_bidirectionally() {
        // Reverse direction: replay store + production write -> error.
        let replay = StorePartition::replay_with_random_run_id();
        let prod = StorePartition::Production;
        let err = replay.ensure_compatible_with(&prod).unwrap_err();
        match err {
            PartitionError::Mismatch { store, requested } => {
                assert_eq!(store, "replay");
                assert_eq!(requested, "production");
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn replay_partition_run_id_returns_some() {
        let p = StorePartition::replay_with_run_id("run-7").unwrap();
        assert_eq!(p.run_id(), Some("run-7"));
    }

    #[test]
    fn production_partition_run_id_returns_none() {
        assert_eq!(StorePartition::Production.run_id(), None);
    }

    #[test]
    fn replay_partition_constructor_rejects_production() {
        let err = ReplayPartition::new(&StorePartition::Production).unwrap_err();
        assert!(matches!(err, PartitionError::NamespaceMismatch(_)));
    }

    #[test]
    fn replay_partition_constructor_accepts_replay() {
        let store = StorePartition::replay_with_run_id("run-42").unwrap();
        let rp = ReplayPartition::new(&store).unwrap();
        assert_eq!(rp.run_id(), "run-42");
    }

    #[test]
    fn replay_receipt_id_method_uses_namespaced_format() {
        let store = StorePartition::replay_with_run_id("run-42").unwrap();
        let rp = ReplayPartition::new(&store).unwrap();
        let id = rp
            .replay_receipt_id("01H7ZZZZZZZZZZZZZZZZZZZZZZ")
            .unwrap();
        assert_eq!(id, "replay:run-42:01H7ZZZZZZZZZZZZZZZZZZZZZZ");
    }

    #[test]
    fn replay_receipt_id_method_rejects_empty_frame_id() {
        let store = StorePartition::replay_with_run_id("run-42").unwrap();
        let rp = ReplayPartition::new(&store).unwrap();
        let err = rp.replay_receipt_id("").unwrap_err();
        assert!(matches!(err, PartitionError::NamespaceMismatch(_)));
    }

    #[test]
    fn replay_receipt_id_function_matches_method() {
        let store = StorePartition::replay_with_run_id("run-42").unwrap();
        let rp = ReplayPartition::new(&store).unwrap();
        let method_form = rp.replay_receipt_id("frame-7").unwrap();
        let function_form = replay_receipt_id("run-42", "frame-7");
        assert_eq!(method_form, function_form);
        assert_eq!(method_form, "replay:run-42:frame-7");
    }

    #[test]
    fn replay_receipt_id_format_matches_milestone_doc_line_568() {
        // Pinned literal: "replay:<run_id>:<frame_id>".
        let id = replay_receipt_id("run-x", "frame-y");
        assert_eq!(id, "replay:run-x:frame-y");
        assert!(id.starts_with("replay:"));
        let parts: Vec<&str> = id.split(':').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "replay");
        assert_eq!(parts[1], "run-x");
        assert_eq!(parts[2], "frame-y");
    }
}
