//! Historical cognition-market snapshot shapes.

use super::global_commit_chain::finding_market_snapshot_digest_version;
use super::SqliteServingOwnerError;
use rusqlite::Connection;

#[derive(Clone, Copy)]
pub(super) struct FindingMarketSnapshotShape {
    pub include_lock_reservations: bool,
    pub include_liability_seller: bool,
    pub include_inflight_purchases: bool,
    pub include_root_bindings: bool,
    pub include_outcomes: bool,
    pub include_capture_intents: bool,
    pub include_failed_deliveries: bool,
    pub include_finalizing_authorizations: bool,
    pub include_finalizing_authorization_refreshes: bool,
    pub include_terminal_reservations: bool,
    pub include_seller_impairment_reconciliations: bool,
    pub include_challenge_submissions: bool,
}

impl FindingMarketSnapshotShape {
    const V2: Self = Self {
        include_lock_reservations: false,
        include_liability_seller: false,
        include_inflight_purchases: false,
        include_root_bindings: false,
        include_outcomes: false,
        include_capture_intents: false,
        include_failed_deliveries: false,
        include_finalizing_authorizations: false,
        include_finalizing_authorization_refreshes: false,
        include_terminal_reservations: false,
        include_seller_impairment_reconciliations: false,
        include_challenge_submissions: false,
    };
    const V3: Self = Self {
        include_lock_reservations: true,
        ..Self::V2
    };
    const V4: Self = Self {
        include_liability_seller: true,
        ..Self::V3
    };
    const V5: Self = Self {
        include_inflight_purchases: true,
        ..Self::V4
    };
    const V6: Self = Self {
        include_root_bindings: true,
        ..Self::V5
    };
    const V7: Self = Self {
        include_outcomes: true,
        ..Self::V6
    };
    const V8: Self = Self {
        include_capture_intents: true,
        ..Self::V7
    };
    const V9: Self = Self {
        include_failed_deliveries: true,
        ..Self::V8
    };
    const V10: Self = Self {
        include_finalizing_authorizations: true,
        ..Self::V9
    };
    const V11: Self = Self {
        include_finalizing_authorization_refreshes: true,
        ..Self::V10
    };
    const V12: Self = Self {
        include_terminal_reservations: true,
        ..Self::V11
    };
    const V13: Self = Self {
        include_seller_impairment_reconciliations: true,
        ..Self::V12
    };
    pub(super) const CURRENT: Self = Self {
        include_challenge_submissions: true,
        ..Self::V13
    };
}

macro_rules! historical_digest {
    ($name:ident, $shape:expr) => {
        pub(super) fn $name(connection: &Connection) -> Result<String, SqliteServingOwnerError> {
            finding_market_snapshot_digest_version(connection, $shape)
        }
    };
}

historical_digest!(
    finding_market_snapshot_digest_v2,
    FindingMarketSnapshotShape::V2
);
historical_digest!(
    finding_market_snapshot_digest_v3,
    FindingMarketSnapshotShape::V3
);
historical_digest!(
    finding_market_snapshot_digest_v4,
    FindingMarketSnapshotShape::V4
);
historical_digest!(
    finding_market_snapshot_digest_v5,
    FindingMarketSnapshotShape::V5
);
historical_digest!(
    finding_market_snapshot_digest_v6,
    FindingMarketSnapshotShape::V6
);
historical_digest!(
    finding_market_snapshot_digest_v7,
    FindingMarketSnapshotShape::V7
);
historical_digest!(
    finding_market_snapshot_digest_v8,
    FindingMarketSnapshotShape::V8
);
historical_digest!(
    finding_market_snapshot_digest_v9,
    FindingMarketSnapshotShape::V9
);
historical_digest!(
    finding_market_snapshot_digest_v10,
    FindingMarketSnapshotShape::V10
);
historical_digest!(
    finding_market_snapshot_digest_v11,
    FindingMarketSnapshotShape::V11
);
historical_digest!(
    finding_market_snapshot_digest_v12,
    FindingMarketSnapshotShape::V12
);
historical_digest!(
    finding_market_snapshot_digest_v13,
    FindingMarketSnapshotShape::V13
);
