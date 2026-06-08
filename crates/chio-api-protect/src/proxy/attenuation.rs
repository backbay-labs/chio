use super::*;

pub(crate) async fn sidecar_attenuate_capability_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    if let Err(response) =
        require_sidecar_control_request(&request, state.sidecar_control_token.as_deref())
    {
        return response;
    }
    let _ = axum::body::to_bytes(request.into_body(), 1024 * 1024).await;
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "error": "chio_attenuation_requires_subject_signer",
            "message": "capability attenuation requires the parent subject signer; sidecar control routes must not hold or derive that key",
            "authorization": false,
        })),
    )
        .into_response()
}
