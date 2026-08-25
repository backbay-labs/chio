use super::*;

pub(super) fn prepare_collateral_registration(
    backing: &SignedFindingBondBacking,
) -> Result<String, Response> {
    let envelope_json = chio_core::canonical_json_bytes(backing)
        .map_err(|_| ())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| ()))
        .map_err(|()| {
            plain_http_error(StatusCode::BAD_REQUEST, "backing failed canonicalization")
        })?;
    Ok(envelope_json)
}
