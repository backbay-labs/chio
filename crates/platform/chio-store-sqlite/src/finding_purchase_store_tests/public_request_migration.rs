use super::*;

#[test]
fn revision_ten_terminals_remain_undisclosable_without_request_ownership() {
    let mut connection = Connection::open_in_memory().expect("in-memory database");
    connection
        .execute_batch(FINDING_PURCHASE_SCHEMA)
        .expect("install current purchase schema");
    connection
        .execute_batch(
            r#"
            DROP TABLE public_purchase_requests;
            DROP TABLE prebinding_purchase_terminals;
            "#,
        )
        .expect("rewind public request binding tables");

    let reservation_id = hex64('1');
    let payer_hex = hex64('2');
    let finding_id = hex64('3');
    connection
        .execute(
            r#"
            INSERT INTO purchase_reservations (
                reservation_id, purchase_intent_id,
                authoritative_payment_operation_id, payer_hex, agent_id,
                finding_id, listing_id, bid_envelope_sha256, ask_digest,
                admission_envelope_sha256, amount_units, currency,
                expires_at, state, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'listing-v10', ?7, ?8, ?9,
                      10, 'USD', ?10, 'consumed', ?11, ?11)
            "#,
            params![
                reservation_id,
                hex64('a'),
                hex64('b'),
                payer_hex,
                "payer-principal",
                finding_id,
                hex64('4'),
                hex64('5'),
                hex64('6'),
                sqlite_i64(EXPIRES_AT, "expires_at").expect("expiry"),
                sqlite_i64(NOW, "created_at").expect("created at"),
            ],
        )
        .expect("insert revision-ten terminal reservation");
    connection
        .execute(
            r#"
            INSERT INTO purchase_payout_bindings (
                reservation_id, destination, binding_kind
            ) VALUES (?1, ?2, 'evm')
            "#,
            params![reservation_id, PAYOUT_DESTINATION],
        )
        .expect("insert payout binding");
    let purchase_key = hex64('7');
    let receipt_id = "receipt-v10";
    connection
        .execute(
            r#"
            INSERT INTO purchase_records (
                purchase_key, reservation_id, record_json, record_sha256,
                delivery_receipt_id, recorded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                purchase_key,
                reservation_id,
                b"{}".as_slice(),
                chio_core::sha256_hex(b"{}"),
                receipt_id,
                sqlite_i64(NOW, "recorded_at").expect("recorded at"),
            ],
        )
        .expect("insert revision-ten purchase record");
    let deny_reservation_id = hex64('c');
    connection
        .execute(
            r#"
            INSERT INTO purchase_reservations (
                reservation_id, purchase_intent_id,
                authoritative_payment_operation_id, payer_hex, agent_id,
                finding_id, listing_id, bid_envelope_sha256, ask_digest,
                admission_envelope_sha256, amount_units, currency,
                expires_at, state, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'listing-v10-deny', ?7, ?8, ?9,
                      10, 'USD', ?10, 'released', ?11, ?11)
            "#,
            params![
                deny_reservation_id,
                hex64('d'),
                hex64('e'),
                payer_hex,
                "payer-principal",
                finding_id,
                hex64('f'),
                hex64('0'),
                hex64('a'),
                sqlite_i64(EXPIRES_AT, "expires_at").expect("expiry"),
                sqlite_i64(NOW, "created_at").expect("created at"),
            ],
        )
        .expect("insert revision-ten denied reservation");
    connection
        .execute(
            r#"
            INSERT INTO purchase_payout_bindings (
                reservation_id, destination, binding_kind
            ) VALUES (?1, ?2, 'evm')
            "#,
            params![deny_reservation_id, PAYOUT_DESTINATION],
        )
        .expect("insert denied payout binding");
    connection
        .execute(
            r#"
            INSERT INTO failed_delivery_records (
                failed_delivery_id, reservation_id, record_json, record_sha256,
                deny_receipt_id, recorded_at
            ) VALUES ('failed-v10', ?1, ?2, ?3, 'deny-receipt-v10', ?4)
            "#,
            params![
                deny_reservation_id,
                b"{}".as_slice(),
                chio_core::sha256_hex(b"{}"),
                sqlite_i64(NOW, "recorded_at").expect("recorded at"),
            ],
        )
        .expect("insert revision-ten failed delivery");
    connection
        .execute_batch(&format!(
            "PRAGMA application_id = {};",
            crate::CHIO_SQLITE_APPLICATION_ID
        ))
        .expect("stamp application id");
    crate::stamp_schema_version(&connection, FINDING_PURCHASE_SCHEMA_KEY, 10)
        .expect("stamp revision ten");

    initialize_finding_purchase_schema(&mut connection).expect("migrate revision ten");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM prebinding_purchase_terminals",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count migrated terminals"),
        2
    );
    assert_eq!(
        connection
            .query_row(
                r#"
                SELECT terminal_kind FROM prebinding_purchase_terminals
                WHERE reservation_id = ?1
                "#,
                [&deny_reservation_id],
                |row| row.get::<_, String>(0),
            )
            .expect("read migrated denial"),
        "failed_delivery"
    );

    let request_id = hex64('8');
    let transaction = connection.transaction().expect("verification transaction");
    let reservation = load_reservation_tx(&transaction, &reservation_id)
        .expect("load reservation")
        .expect("reservation exists");
    let request = FindingPublicPurchaseRequestBinding {
        request_id: &request_id,
        finding_id: &finding_id,
        requested_payer: None,
        resolved_payer: "payer-principal",
        payer_hex: &payer_hex,
        max_price_units: 10,
        currency: "USD",
        deadline_secs: None,
    };
    let purchase_error = require_public_request_binding_tx(&transaction, &reservation, &request)
        .expect_err("legacy purchase terminal acquired public ownership");
    assert!(matches!(
        purchase_error,
        FindingPurchaseStoreError::Conflict(message)
            if message == "prebinding purchase terminal has no authenticated public request ownership"
    ));

    let changed_request_id = hex64('9');
    let changed = FindingPublicPurchaseRequestBinding {
        request_id: &changed_request_id,
        max_price_units: 11,
        ..request
    };
    assert!(matches!(
        require_public_request_binding_tx(&transaction, &reservation, &changed),
        Err(FindingPurchaseStoreError::Conflict(_))
    ));

    let deny_reservation = load_reservation_tx(&transaction, &deny_reservation_id)
        .expect("load denied reservation")
        .expect("denied reservation exists");
    let deny_request_id = hex64('b');
    let deny_request = FindingPublicPurchaseRequestBinding {
        request_id: &deny_request_id,
        finding_id: &finding_id,
        requested_payer: None,
        resolved_payer: "payer-principal",
        payer_hex: &payer_hex,
        max_price_units: 10,
        currency: "USD",
        deadline_secs: None,
    };
    let denial_error =
        require_public_request_binding_tx(&transaction, &deny_reservation, &deny_request)
            .expect_err("legacy failed-delivery terminal acquired public ownership");
    assert!(matches!(
        denial_error,
        FindingPurchaseStoreError::Conflict(message)
            if message == "prebinding purchase terminal has no authenticated public request ownership"
    ));
    assert_eq!(
        transaction
            .query_row("SELECT COUNT(*) FROM public_purchase_requests", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("count public bindings"),
        0
    );
}
