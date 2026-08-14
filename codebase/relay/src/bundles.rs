//! Device bundle publication and lookup routes.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::auth::authenticate_request;
use super::validation::{
    decode_bounded_base64, require_json_content, validate_json_accept, validate_text,
};
use super::{
    ApiError, AppState, MAX_BUNDLE_BYTES, MAX_ID_BYTES, b64, bad_request, internal, not_found, now,
};

#[derive(Deserialize)]
pub(super) struct BundleRequest {
    bundle: String,
}

#[derive(Deserialize, Serialize)]
pub(super) struct BundleResponse {
    pub(super) device_id: String,
    pub(super) bundle: String,
}

pub(super) async fn publish(
    State(state): State<AppState>,
    Path(device): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<BundleResponse>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&device, MAX_ID_BYTES, "device ID").map_err(bad_request)?;
    let auth = authenticate_request(
        &state,
        &headers,
        "PUT",
        &format!("/v1/devices/{device}/bundle"),
        &body,
        Some(&device),
    )
    .await?;
    let request: BundleRequest =
        serde_json::from_slice(&body).map_err(|error| bad_request(error.into()))?;
    let bundle = decode_bounded_base64(
        &request.bundle,
        MAX_BUNDLE_BYTES * 2,
        MAX_BUNDLE_BYTES,
        "bundle",
    )
    .map_err(bad_request)?;
    let db = state.db.lock().await;
    db.execute(
        "UPDATE devices SET bundle = ?2, last_seen_at = ?3 WHERE client_id = ?1",
        params![auth, bundle, now() as i64],
    )
    .map_err(internal)?;
    Ok(axum::Json(BundleResponse {
        device_id: device,
        bundle: request.bundle,
    }))
}

pub(super) async fn fetch(
    State(state): State<AppState>,
    Path(device): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<BundleResponse>, ApiError> {
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&device, MAX_ID_BYTES, "device ID").map_err(bad_request)?;
    authenticate_request(
        &state,
        &headers,
        "GET",
        &format!("/v1/devices/{device}/bundle"),
        &[],
        None,
    )
    .await?;
    let db = state.db.lock().await;
    let bundle: (String, Vec<u8>) = db
        .query_row(
            "SELECT client_id, bundle FROM devices WHERE client_id = ?1 OR device_address = ?1",
            params![device],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(not_found)?;
    Ok(axum::Json(BundleResponse {
        device_id: bundle.0,
        bundle: b64(&bundle.1),
    }))
}

pub(super) async fn fetch_by_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<BundleResponse>, ApiError> {
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&address, MAX_ID_BYTES, "device address").map_err(bad_request)?;
    let path = format!("/v1/devices/by-address/{address}/bundle");
    authenticate_request(&state, &headers, "GET", &path, &[], None).await?;
    let db = state.db.lock().await;
    let (device, bundle): (String, Vec<u8>) = db
        .query_row(
            "SELECT client_id, bundle FROM devices WHERE device_address = ?1",
            params![address],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(not_found)?;
    Ok(axum::Json(BundleResponse {
        device_id: device,
        bundle: b64(&bundle),
    }))
}
