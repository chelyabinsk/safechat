//! Authentication and signed-request replay protection.

use axum::http::HeaderMap;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_protocol::IdentityKey;

use super::{
    ApiError, AppState, MAX_SIGNATURE_B64_BYTES, REQUEST_DOMAIN, b64decode, hash, internal, now,
    unauthorized,
};

#[derive(Deserialize)]
pub(super) struct WsPollRequest {
    pub(super) cursor: i64,
    pub(super) nonce: String,
    pub(super) timestamp: u64,
    pub(super) signature: String,
}

pub(super) async fn verify_websocket_request(
    state: &AppState,
    device: &str,
    request: &WsPollRequest,
) -> Result<(), ApiError> {
    let body = serde_json::to_vec(&json!({
        "cursor": request.cursor,
        "nonce": request.nonce,
        "timestamp": request.timestamp
    }))
    .map_err(internal)?;
    verify_signature(
        state,
        device,
        "WS",
        "/v1/events",
        &body,
        &request.nonce,
        request.timestamp,
        &request.signature,
    )
    .await
}

pub(super) async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    expected_device: Option<&str>,
) -> Result<String, ApiError> {
    let token = bearer(headers).ok_or_else(unauthorized)?;
    if token.is_empty() || token.len() > MAX_SIGNATURE_B64_BYTES {
        return Err(unauthorized());
    }
    let db = state.db.lock().await;
    let device: String = db.query_row(
        "SELECT devices.client_id FROM devices INNER JOIN allowlist ON allowlist.client_id = devices.client_id WHERE devices.token_hash = ?1 AND allowlist.status = 'active'",
        params![hash(token)], |row| row.get(0),
    ).optional().map_err(internal)?.ok_or_else(unauthorized)?;
    drop(db);
    if expected_device.is_some_and(|expected| expected != device) {
        return Err(unauthorized());
    }
    let nonce = header(headers, "x-safechat-nonce").ok_or_else(unauthorized)?;
    let timestamp = header(headers, "x-safechat-timestamp")
        .ok_or_else(unauthorized)?
        .parse::<u64>()
        .map_err(|_| unauthorized())?;
    let signature = header(headers, "x-safechat-signature").ok_or_else(unauthorized)?;
    verify_signature(
        state, &device, method, path, body, nonce, timestamp, signature,
    )
    .await?;
    Ok(device)
}

pub(super) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub(super) fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn verify_signature(
    state: &AppState,
    device: &str,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &str,
    timestamp: u64,
    signature: &str,
) -> Result<(), ApiError> {
    if timestamp.abs_diff(now()) > 300
        || nonce.is_empty()
        || nonce.len() > 128
        || signature.len() > MAX_SIGNATURE_B64_BYTES
    {
        return Err(unauthorized());
    }
    let mut db = state.db.lock().await;
    let identity_bytes: Vec<u8> = db
        .query_row(
            "SELECT identity_key FROM devices WHERE client_id = ?1",
            params![device],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
    let identity = IdentityKey::decode(&identity_bytes).map_err(|_| unauthorized())?;
    let mut signed = REQUEST_DOMAIN.to_vec();
    signed.extend(method.as_bytes());
    signed.push(0);
    signed.extend(path.as_bytes());
    signed.push(0);
    signed.extend(Sha256::digest(body));
    signed.extend(nonce.as_bytes());
    signed.push(0);
    signed.extend(timestamp.to_be_bytes());
    let signature = b64decode(signature).map_err(|_| unauthorized())?;
    if !identity.public_key().verify_signature(&signed, &signature) {
        return Err(unauthorized());
    }
    let transaction = db.transaction().map_err(internal)?;
    transaction
        .execute(
            "DELETE FROM request_nonces WHERE expires_at < ?1",
            params![now() as i64],
        )
        .map_err(internal)?;
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO request_nonces(client_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
        params![device, nonce, (now() + 600) as i64],
    ).map_err(internal)?;
    transaction.commit().map_err(internal)?;
    if inserted == 0 {
        return Err(ApiError(
            axum::http::StatusCode::CONFLICT,
            "request nonce already used".into(),
        ));
    }
    Ok(())
}
