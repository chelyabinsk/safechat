//! Administrative HTTP endpoints.

use axum::{extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::auth::bearer;
use super::validation::{require_json_content, validate_json_accept, validate_text};
use super::{
    ApiError, AppState, MAX_FINGERPRINT_BYTES, MAX_ID_BYTES, MAX_IDENTITY_B64_BYTES,
    MAX_LABEL_BYTES, MAX_SECRET_BYTES, add_allowlist, bad_request, decode_bounded_base64, internal,
    not_found, unauthorized,
};

#[derive(Deserialize, Serialize)]
pub(super) struct AdminAllowlistRequest {
    pub(super) client_id: String,
    pub(super) identity_key: String,
    pub(super) fingerprint: String,
    pub(super) enrollment_secret: String,
    #[serde(default)]
    pub(super) label: String,
}

pub(super) async fn allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<AdminAllowlistRequest>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&request.client_id, MAX_ID_BYTES, "client ID").map_err(bad_request)?;
    validate_text(&request.fingerprint, MAX_FINGERPRINT_BYTES, "fingerprint")
        .map_err(bad_request)?;
    validate_text(
        &request.enrollment_secret,
        MAX_SECRET_BYTES,
        "enrollment secret",
    )
    .map_err(bad_request)?;
    validate_text(&request.label, MAX_LABEL_BYTES, "label").map_err(bad_request)?;
    decode_bounded_base64(
        &request.identity_key,
        MAX_IDENTITY_B64_BYTES,
        128,
        "identity key",
    )
    .map_err(bad_request)?;
    let Some(expected) = state.admin_token.as_deref() else {
        return Err(not_found());
    };
    let Some(provided) = bearer(&headers) else {
        return Err(unauthorized());
    };
    if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
        return Err(unauthorized());
    }
    let db = state.db.lock().await;
    add_allowlist(
        &db,
        &request.client_id,
        &request.identity_key,
        &request.fingerprint,
        &request.enrollment_secret,
        &request.label,
    )
    .map_err(internal)?;
    Ok(axum::Json(
        serde_json::json!({"allowlisted": true, "client_id": request.client_id}),
    ))
}
