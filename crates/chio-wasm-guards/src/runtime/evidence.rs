use crate::epoch::EpochId;

#[derive(Debug, Clone)]
pub(crate) struct LastEvaluationEvidence {
    pub(crate) epoch_id: EpochId,
    pub(crate) manifest_sha256: Option<String>,
    pub(crate) fuel_consumed: Option<u64>,
}
