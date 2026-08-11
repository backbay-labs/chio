use chio_kernel::finding_pool::FindingPoolLedgerError;
use rusqlite::params;

use super::{invariant, parse_units, MAX_EXPIRED_RECLAMATIONS_PER_DEBIT};

pub(super) fn expired_unclaimed_reservations(
    transaction: &rusqlite::Transaction<'_>,
    allocation_envelope_sha256: &str,
    trusted_now_unix_ms: u64,
    required_purchase_id: Option<&str>,
) -> Result<Vec<(String, u64)>, FindingPoolLedgerError> {
    let trusted_now_text = trusted_now_unix_ms.to_string();
    let batch_limit = i64::try_from(MAX_EXPIRED_RECLAMATIONS_PER_DEBIT)
        .map_err(|_| invariant("expired reservation batch limit is invalid"))?;
    let mut statement = transaction
        .prepare(
            "SELECT purchase_id, amount_units, claim_deadline_unix_ms \
             FROM finding_pool_debits \
             WHERE allocation_envelope_sha256 = ?1 AND state = 'reserved' \
               AND claimed_at_unix_ms IS NULL \
               AND claim_deadline_unix_ms <> '' \
               AND claim_deadline_unix_ms NOT GLOB '*[^0-9]*' \
               AND (length(claim_deadline_unix_ms) < length(?2) \
                    OR (length(claim_deadline_unix_ms) = length(?2) \
                        AND claim_deadline_unix_ms <= ?2)) \
             ORDER BY CASE WHEN purchase_id = ?4 THEN 0 ELSE 1 END, \
                      length(claim_deadline_unix_ms), claim_deadline_unix_ms, purchase_id \
             LIMIT ?3",
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut rows = statement
        .query(params![
            allocation_envelope_sha256,
            trusted_now_text,
            batch_limit,
            required_purchase_id.unwrap_or_default(),
        ])
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut expired = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
    {
        let purchase_id = row
            .get::<_, String>(0)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let amount_text = row
            .get::<_, String>(1)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let deadline_text = row
            .get::<_, String>(2)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let amount = parse_units(&amount_text, "debit.amount_units")?;
        let deadline = parse_units(&deadline_text, "debit.claim_deadline_unix_ms")?;
        if deadline > trusted_now_unix_ms {
            return Err(invariant("expiration query returned a live reservation"));
        }
        expired.push((purchase_id, amount));
    }
    drop(rows);
    drop(statement);
    Ok(expired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_claim_precedes_earlier_rows_inside_the_batch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE finding_pool_debits (\
                purchase_id TEXT PRIMARY KEY, \
                allocation_envelope_sha256 TEXT NOT NULL, \
                amount_units TEXT NOT NULL, \
                state TEXT NOT NULL, \
                claim_deadline_unix_ms TEXT NOT NULL, \
                claimed_at_unix_ms TEXT\
             ) STRICT;",
        )?;
        let transaction = connection.transaction()?;
        let allocation_digest = "a".repeat(64);
        for index in 0..65_u64 {
            transaction.execute(
                "INSERT INTO finding_pool_debits (\
                    purchase_id, allocation_envelope_sha256, amount_units, state, \
                    claim_deadline_unix_ms, claimed_at_unix_ms\
                 ) VALUES (?1, ?2, '1', 'reserved', '29999', NULL)",
                params![format!("purchase:expired:{index:02}"), allocation_digest],
            )?;
        }
        let target = "purchase:zz-target";
        transaction.execute(
            "INSERT INTO finding_pool_debits (\
                purchase_id, allocation_envelope_sha256, amount_units, state, \
                claim_deadline_unix_ms, claimed_at_unix_ms\
             ) VALUES (?1, ?2, '1', 'reserved', '30000', NULL)",
            params![target, allocation_digest],
        )?;

        let expired =
            expired_unclaimed_reservations(&transaction, &allocation_digest, 30_000, Some(target))?;
        assert_eq!(expired.len(), MAX_EXPIRED_RECLAMATIONS_PER_DEBIT);
        assert_eq!(expired.first().map(|row| row.0.as_str()), Some(target));
        Ok(())
    }
}
