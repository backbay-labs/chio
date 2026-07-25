use super::{
    validate_admission_digest, CreditAdmissionError, CreditExposureReservationRecordV1,
    CreditExposureReservationStateV1,
};

impl CreditExposureReservationRecordV1 {
    /// Prepare a release authorized by a qualified kernel terminal projection.
    ///
    /// The persistence boundary must first verify that the projection contains a
    /// complete pre-dispatch no-effect proof for this exact operation. This
    /// method keeps the credit state transition and its dense account-version
    /// rules in the owning crate while allowing that kernel proof to serve as the
    /// release authority instead of an economic-continuity effect slot.
    pub fn prepare_released_before_dispatch_from_kernel_projection(
        &self,
        verified_operation_id: &str,
        next_account_version: u64,
        next_resource_fence: u64,
    ) -> Result<Self, CreditAdmissionError> {
        validate_admission_digest("operation_id", verified_operation_id)?;
        if self.operation_id != verified_operation_id {
            return Err(CreditAdmissionError::OperationConflict);
        }
        self.transition(
            CreditExposureReservationStateV1::ReleasedBeforeDispatch,
            next_account_version,
            next_resource_fence,
        )
    }
}
