use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HoldDisposition {
    Open,
    Released,
    Reversed,
    Reconciled,
    Expired,
}

impl HoldDisposition {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Released => "released",
            Self::Reversed => "reversed",
            Self::Reconciled => "reconciled",
            Self::Expired => "expired",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "released" => Some(Self::Released),
            "reversed" => Some(Self::Reversed),
            "reconciled" => Some(Self::Reconciled),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SqliteBudgetHold {
    pub(super) hold_id: String,
    pub(super) capability_id: String,
    pub(super) grant_index: usize,
    pub(super) authorized_exposure_units: u64,
    pub(super) remaining_exposure_units: u64,
    pub(super) invocation_count_debited: bool,
    pub(super) disposition: HoldDisposition,
    pub(super) authority: Option<BudgetEventAuthority>,
}
