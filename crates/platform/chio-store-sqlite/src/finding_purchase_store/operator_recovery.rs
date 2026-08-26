use super::*;

impl SqliteFindingPurchaseStore {
    /// Expire one due reservation without rewriting an already terminal row.
    /// Returns `true` when the reservation is or became expired and `false`
    /// when it is not yet due or has another terminal state.
    pub fn expire_reservation(
        &self,
        reservation_id: &str,
        now: u64,
    ) -> Result<bool, FindingPurchaseStoreError> {
        require_trusted_time(now, "now")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        let from = match reservation.state {
            FindingPurchaseReservationState::Expired => return Ok(true),
            FindingPurchaseReservationState::Open => "open",
            FindingPurchaseReservationState::SlotReserved => "slot_reserved",
            FindingPurchaseReservationState::Consumed
            | FindingPurchaseReservationState::Released => return Ok(false),
        };
        if now < reservation.expires_at {
            return Ok(false);
        }
        abandon_reservation_tx(&transaction, reservation_id, from, "expired", now)?;
        self.commit_market_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(true)
    }

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
