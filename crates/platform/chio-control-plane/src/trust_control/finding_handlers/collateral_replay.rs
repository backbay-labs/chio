use super::*;

pub(super) fn prepare_collateral_registration(
    store: &SqliteFindingMarketStore,
    backing: &SignedFindingBondBacking,
) -> Result<String, Response> {
    let envelope_json = chio_core::canonical_json_bytes(backing)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
        .map_err(|()| {
            plain_http_error(StatusCode::BAD_REQUEST, "backing failed canonicalization")
        })?;
    let envelope_sha256 = chio_core::sha256_hex(envelope_json.as_bytes());
    match store.get_allocation(&backing.body.allocation_id) {
        Ok(Some(existing))
            if existing.backing == backing.body
                && existing.backing_envelope_sha256 == envelope_sha256 =>
        {
            Err(Json(serde_json::json!({
                "allocationId": backing.body.allocation_id,
                "acceptedAt": existing.accepted_at,
                "exactReplay": true,
            }))
            .into_response())
        }
        Ok(Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "collateral allocation id is bound to different backing",
        )),
        Ok(None) => Ok(envelope_json),
        Err(error) => Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            &error.to_string(),
        )),
    }
}
