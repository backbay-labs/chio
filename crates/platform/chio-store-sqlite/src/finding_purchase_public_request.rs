use super::*;

/// Public request policy bound atomically to a newly opened reservation.
#[derive(Debug, Clone, Copy)]
pub struct FindingPublicPurchaseRequestBinding<'a> {
    pub request_id: &'a str,
    pub finding_id: &'a str,
    pub requested_payer: Option<&'a str>,
    pub resolved_payer: &'a str,
    pub payer_hex: &'a str,
    pub max_price_units: u64,
    pub currency: &'a str,
    pub deadline_secs: Option<u64>,
}

/// Terminal family retained for a public purchase request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPublicPurchaseTerminalKind {
    PurchaseRecord,
    FailedDelivery,
}

/// Exact durable terminal a public route is about to disclose.
#[derive(Debug, Clone, Copy)]
pub struct FindingPublicPurchaseTerminal<'a> {
    pub kind: FindingPublicPurchaseTerminalKind,
    pub terminal_id: &'a str,
    pub receipt_id: &'a str,
}

impl SqliteFindingPurchaseStore {
    /// Open a live reservation and atomically bind the complete public
    /// request policy that authorized it. Exact reservation replays require
    /// the same request binding; a different public request cannot claim the
    /// reservation or any terminal it later reaches.
    #[allow(clippy::too_many_arguments)]
    pub fn open_live_public_reservation(
        &self,
        input: &FindingPurchaseReservationInput<'_>,
        public_request: &FindingPublicPurchaseRequestBinding<'_>,
        status_feed_id: &str,
        status_operator_authorization_sha256: &str,
        status_operator_observed_at: u64,
        trusted_now: u64,
        status_max_epoch_age_secs: u64,
    ) -> Result<FindingPurchaseWriteOutcome, FindingPurchaseStoreError> {
        self.open_reservation_inner(
            input,
            Some(public_request),
            Some((
                status_feed_id,
                status_operator_authorization_sha256,
                status_operator_observed_at,
                trusted_now,
                status_max_epoch_age_secs,
            )),
        )
    }

    /// Verify that a public request owns this reservation and exact terminal.
    /// This is the final durable route fence before purchased output leaves
    /// the service boundary.
    pub fn verify_public_purchase_terminal(
        &self,
        request: &FindingPublicPurchaseRequestBinding<'_>,
        reservation_id: &str,
        terminal: &FindingPublicPurchaseTerminal<'_>,
    ) -> Result<(), FindingPurchaseStoreError> {
        require_identifier(reservation_id, "reservation_id")?;
        require_identifier(terminal.terminal_id, "terminal_id")?;
        require_identifier(terminal.receipt_id, "receipt_id")?;
        let mut connection = self.connection()?;
        {
            let transaction = self.begin_read(&mut connection)?;
            let reservation = load_reservation_tx(&transaction, reservation_id)?
                .ok_or(FindingPurchaseStoreError::NotFound)?;
            validate_public_request_binding_record(&reservation, request)?;
            if public_request_binding_exists_tx(&transaction, request.request_id)? {
                require_public_request_binding_tx(&transaction, &reservation, request)?;
                return require_public_terminal_tx(&transaction, reservation_id, terminal);
            }
        }
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        validate_public_request_binding_record(&reservation, request)?;
        let promoted = require_public_request_binding_tx(&transaction, &reservation, request)?;
        require_public_terminal_tx(&transaction, reservation_id, terminal)?;
        if !promoted {
            return Err(invariant("prebinding terminal promotion did not occur"));
        }
        self.commit_market_write(transaction)?;
        self.sync_after_write(&connection)
    }

    /// Verify the immutable public request-to-reservation binding without
    /// requiring current market standing. Completed exact replays use this
    /// before returning a receipt after the admission has expired.
    pub fn verify_public_purchase_reservation(
        &self,
        request: &FindingPublicPurchaseRequestBinding<'_>,
        reservation_id: &str,
    ) -> Result<(), FindingPurchaseStoreError> {
        require_identifier(reservation_id, "reservation_id")?;
        let mut connection = self.connection()?;
        {
            let transaction = self.begin_read(&mut connection)?;
            let reservation = load_reservation_tx(&transaction, reservation_id)?
                .ok_or(FindingPurchaseStoreError::NotFound)?;
            validate_public_request_binding_record(&reservation, request)?;
            if public_request_binding_exists_tx(&transaction, request.request_id)? {
                require_public_request_binding_tx(&transaction, &reservation, request)?;
                return Ok(());
            }
        }
        let transaction = self.begin_write(&mut connection)?;
        let reservation = load_reservation_tx(&transaction, reservation_id)?
            .ok_or(FindingPurchaseStoreError::NotFound)?;
        validate_public_request_binding_record(&reservation, request)?;
        let promoted = require_public_request_binding_tx(&transaction, &reservation, request)?;
        if !promoted {
            return Err(invariant("prebinding reservation promotion did not occur"));
        }
        self.commit_market_write(transaction)?;
        self.sync_after_write(&connection)
    }
}

pub(super) fn validate_public_request_binding(
    reservation: &FindingPurchaseReservationInput<'_>,
    request: &FindingPublicPurchaseRequestBinding<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    require_hex64(request.request_id, "request_id")?;
    require_hex64(request.finding_id, "finding_id")?;
    require_hex64(request.payer_hex, "payer_hex")?;
    require_identifier(request.resolved_payer, "resolved_payer")?;
    if let Some(requested_payer) = request.requested_payer {
        require_identifier(requested_payer, "requested_payer")?;
        if requested_payer != request.resolved_payer {
            return Err(FindingPurchaseStoreError::Conflict(
                "public purchase changed the requested payer".to_owned(),
            ));
        }
    }
    require_currency(request.currency)?;
    if request.max_price_units == 0 {
        return Err(invariant("public purchase maximum price must be nonzero"));
    }
    if request.deadline_secs == Some(0) {
        return Err(invariant("public purchase deadline must be nonzero"));
    }
    if request.finding_id != reservation.finding_id
        || request.payer_hex != reservation.payer_hex
        || request.currency != reservation.currency
        || reservation.amount_units > request.max_price_units
    {
        return Err(FindingPurchaseStoreError::Conflict(
            "public purchase policy does not authorize the reservation".to_owned(),
        ));
    }
    if let Some(deadline_secs) = request.deadline_secs {
        let deadline = reservation
            .created_at
            .checked_add(deadline_secs)
            .ok_or_else(|| invariant("public purchase deadline overflowed"))?;
        if reservation.expires_at > deadline {
            return Err(FindingPurchaseStoreError::Conflict(
                "reservation exceeds the public purchase deadline".to_owned(),
            ));
        }
    }
    Ok(())
}

fn public_request_binding_exists_tx(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> Result<bool, FindingPurchaseStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM public_purchase_requests WHERE request_id = ?1)",
            [request_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn validate_public_request_binding_record(
    reservation: &FindingPurchaseReservationRecord,
    request: &FindingPublicPurchaseRequestBinding<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    require_hex64(request.request_id, "request_id")?;
    require_hex64(request.finding_id, "finding_id")?;
    require_hex64(request.payer_hex, "payer_hex")?;
    require_identifier(request.resolved_payer, "resolved_payer")?;
    if let Some(requested_payer) = request.requested_payer {
        require_identifier(requested_payer, "requested_payer")?;
        if requested_payer != request.resolved_payer {
            return Err(FindingPurchaseStoreError::Conflict(
                "public purchase changed the requested payer".to_owned(),
            ));
        }
    }
    require_currency(request.currency)?;
    if request.max_price_units == 0
        || request.finding_id != reservation.finding_id
        || request.payer_hex != reservation.payer_hex
        || request.currency != reservation.currency
        || reservation.amount_units > request.max_price_units
    {
        return Err(FindingPurchaseStoreError::Conflict(
            "public purchase policy does not authorize the reservation".to_owned(),
        ));
    }
    if let Some(deadline_secs) = request.deadline_secs {
        if deadline_secs == 0 {
            return Err(invariant("public purchase deadline must be nonzero"));
        }
        let deadline = reservation
            .created_at
            .checked_add(deadline_secs)
            .ok_or_else(|| invariant("public purchase deadline overflowed"))?;
        if reservation.expires_at > deadline {
            return Err(FindingPurchaseStoreError::Conflict(
                "reservation exceeds the public purchase deadline".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn insert_public_request_binding_tx(
    transaction: &Transaction<'_>,
    reservation: &FindingPurchaseReservationInput<'_>,
    request: &FindingPublicPurchaseRequestBinding<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    validate_public_request_binding(reservation, request)?;
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO public_purchase_requests (
                request_id, reservation_id, finding_id, requested_payer,
                resolved_payer, payer_hex, max_price_units, currency,
                deadline_secs, terminal_kind, terminal_id, receipt_id, bound_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL, ?10)
            "#,
            params![
                request.request_id,
                reservation.reservation_id,
                request.finding_id,
                request.requested_payer,
                request.resolved_payer,
                request.payer_hex,
                sqlite_i64(request.max_price_units, "max_price_units")?,
                request.currency,
                request
                    .deadline_secs
                    .map(|value| sqlite_i64(value, "deadline_secs"))
                    .transpose()?,
                sqlite_i64(reservation.created_at, "bound_at")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "public purchase request binding did not affect one row",
        ));
    }
    Ok(())
}

pub(super) fn require_public_request_binding_tx(
    transaction: &Transaction<'_>,
    reservation: &FindingPurchaseReservationRecord,
    request: &FindingPublicPurchaseRequestBinding<'_>,
) -> Result<bool, FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT reservation_id, finding_id, requested_payer, resolved_payer,
                   payer_hex, max_price_units, currency, deadline_secs
            FROM public_purchase_requests WHERE request_id = ?1
            "#,
            [request.request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        stored_reservation_id,
        finding_id,
        requested_payer,
        resolved_payer,
        payer_hex,
        max_price_units,
        currency,
        deadline_secs,
    )) = row
    else {
        let claimed_request_id: Option<String> = transaction
            .query_row(
                "SELECT request_id FROM public_purchase_requests WHERE reservation_id = ?1",
                [&reservation.reservation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if claimed_request_id.is_some() {
            return Err(FindingPurchaseStoreError::Conflict(
                "public purchase request is bound to different durable state".to_owned(),
            ));
        }
        let (terminal_kind, terminal_id, receipt_id) =
            load_prebinding_terminal_tx(transaction, &reservation.reservation_id)?.ok_or_else(
                || {
                    FindingPurchaseStoreError::Conflict(
                        "public purchase request has no durable reservation binding".to_owned(),
                    )
                },
            )?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO public_purchase_requests (
                    request_id, reservation_id, finding_id, requested_payer,
                    resolved_payer, payer_hex, max_price_units, currency,
                    deadline_secs, terminal_kind, terminal_id, receipt_id, bound_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
                params![
                    request.request_id,
                    reservation.reservation_id,
                    request.finding_id,
                    request.requested_payer,
                    request.resolved_payer,
                    request.payer_hex,
                    sqlite_i64(request.max_price_units, "max_price_units")?,
                    request.currency,
                    request
                        .deadline_secs
                        .map(|value| sqlite_i64(value, "deadline_secs"))
                        .transpose()?,
                    terminal_kind,
                    terminal_id,
                    receipt_id,
                    sqlite_i64(reservation.created_at, "bound_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant(
                "prebinding public replay promotion did not affect one row",
            ));
        }
        return Ok(true);
    };
    if stored_reservation_id != reservation.reservation_id
        || finding_id != request.finding_id
        || requested_payer.as_deref() != request.requested_payer
        || resolved_payer != request.resolved_payer
        || payer_hex != request.payer_hex
        || stored_u64(max_price_units, "max_price_units")? != request.max_price_units
        || currency != request.currency
        || deadline_secs
            .map(|value| stored_u64(value, "deadline_secs"))
            .transpose()?
            != request.deadline_secs
    {
        return Err(FindingPurchaseStoreError::Conflict(
            "public purchase request is bound to different durable state".to_owned(),
        ));
    }
    Ok(false)
}

fn load_prebinding_terminal_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
) -> Result<Option<(String, String, String)>, FindingPurchaseStoreError> {
    transaction
        .query_row(
            r#"
            SELECT terminal_kind, terminal_id, receipt_id
            FROM prebinding_purchase_terminals WHERE reservation_id = ?1
            "#,
            [reservation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)
}

pub(super) fn carry_prebinding_purchase_terminals(
    transaction: &Transaction<'_>,
    on_disk_version: i32,
) -> Result<(), FindingPurchaseStoreError> {
    if on_disk_version >= FINDING_PURCHASE_PUBLIC_REQUEST_VERSION {
        return Ok(());
    }
    let expected: i64 = transaction
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM purchase_records)
                + (SELECT COUNT(*) FROM failed_delivery_records)
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let carried = transaction
        .execute(
            r#"
            INSERT INTO prebinding_purchase_terminals (
                reservation_id, terminal_kind, terminal_id, receipt_id
            )
            SELECT reservation_id, 'purchase_record', purchase_key, delivery_receipt_id
            FROM purchase_records
            UNION ALL
            SELECT reservation_id, 'failed_delivery', failed_delivery_id, deny_receipt_id
            FROM failed_delivery_records
            "#,
            [],
        )
        .map_err(sqlite_error)?;
    if i64::try_from(carried).unwrap_or(i64::MAX) != expected {
        return Err(invariant(format!(
            "prebinding terminal migration carried {carried} of {expected} rows"
        )));
    }
    Ok(())
}

const fn public_terminal_kind_name(kind: FindingPublicPurchaseTerminalKind) -> &'static str {
    match kind {
        FindingPublicPurchaseTerminalKind::PurchaseRecord => "purchase_record",
        FindingPublicPurchaseTerminalKind::FailedDelivery => "failed_delivery",
    }
}

fn require_public_terminal_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    terminal: &FindingPublicPurchaseTerminal<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT terminal_kind, terminal_id, receipt_id
            FROM public_purchase_requests WHERE reservation_id = ?1
            "#,
            [reservation_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((Some(kind), Some(terminal_id), Some(receipt_id))) = row else {
        return Err(FindingPurchaseStoreError::Conflict(
            "public purchase request has no durable terminal binding".to_owned(),
        ));
    };
    if kind != public_terminal_kind_name(terminal.kind)
        || terminal_id != terminal.terminal_id
        || receipt_id != terminal.receipt_id
    {
        return Err(FindingPurchaseStoreError::Conflict(
            "public purchase request is bound to a different terminal".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn bind_public_terminal_if_present_tx(
    transaction: &Transaction<'_>,
    reservation_id: &str,
    terminal: &FindingPublicPurchaseTerminal<'_>,
) -> Result<(), FindingPurchaseStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT terminal_kind, terminal_id, receipt_id
            FROM public_purchase_requests WHERE reservation_id = ?1
            "#,
            [reservation_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    match row {
        None => Ok(()),
        Some((None, None, None)) => {
            let changed = transaction
                .execute(
                    r#"
                    UPDATE public_purchase_requests
                    SET terminal_kind = ?2, terminal_id = ?3, receipt_id = ?4
                    WHERE reservation_id = ?1
                      AND terminal_kind IS NULL AND terminal_id IS NULL AND receipt_id IS NULL
                    "#,
                    params![
                        reservation_id,
                        public_terminal_kind_name(terminal.kind),
                        terminal.terminal_id,
                        terminal.receipt_id,
                    ],
                )
                .map_err(sqlite_error)?;
            if changed != 1 {
                return Err(invariant(
                    "public purchase terminal binding did not affect one row",
                ));
            }
            Ok(())
        }
        Some((Some(kind), Some(terminal_id), Some(receipt_id)))
            if kind == public_terminal_kind_name(terminal.kind)
                && terminal_id == terminal.terminal_id
                && receipt_id == terminal.receipt_id =>
        {
            Ok(())
        }
        Some((Some(_), Some(_), Some(_))) => Err(FindingPurchaseStoreError::Conflict(
            "public purchase request is already bound to a different terminal".to_owned(),
        )),
        Some(_) => Err(invariant(
            "public purchase request holds a partial terminal binding",
        )),
    }
}
