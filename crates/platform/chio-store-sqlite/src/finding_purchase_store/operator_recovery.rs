use super::*;

impl SqliteFindingPurchaseStore {
    /// One retained settled purchase record selected by its reservation.
    ///
    /// Public operator recovery uses this after the reservation reached its
    /// terminal but before its route response cache was durably written.
    pub fn get_purchase_record_by_reservation(
        &self,
        reservation_id: &str,
    ) -> Result<Option<FindingPurchaseRecordRow>, FindingPurchaseStoreError> {
        require_identifier(reservation_id, "reservation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_purchase_record_by_reservation_tx(&transaction, reservation_id)
    }

    /// One retained failed-delivery terminal selected by its reservation.
    ///
    /// This is the denial-side counterpart of
    /// [`Self::get_purchase_record_by_reservation`].
    pub fn get_failed_delivery_record_by_reservation(
        &self,
        reservation_id: &str,
    ) -> Result<Option<FindingFailedDeliveryRow>, FindingPurchaseStoreError> {
        require_identifier(reservation_id, "reservation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_failed_delivery_by_reservation_tx(&transaction, reservation_id)
    }
}
