//! Contact-request HTTP handlers and their SQLite persistence.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use super::auth::authenticate_request;
use super::validation::{
    decode_bounded_base64, require_json_content, validate_json_accept,
    validate_optional_json_content, validate_text,
};
use super::{
    ApiError, AppState, MAX_BUNDLE_BYTES, MAX_FINGERPRINT_BYTES, MAX_ID_BYTES, MAX_LABEL_BYTES,
    b64, bad_request, internal, not_found, now,
};

#[derive(Deserialize)]
pub(super) struct ContactRequestPayload {
    request_id: String,
    recipient: String,
    sender_name: String,
    sender_fingerprint: String,
    bundle: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct ContactRequestResponse {
    pub(super) request_id: String,
    pub(super) sender_id: String,
    pub(super) recipient: String,
    pub(super) sender_name: String,
    pub(super) sender_fingerprint: String,
    pub(super) bundle: String,
    pub(super) status: String,
    pub(super) created_at: u64,
}

#[derive(Deserialize)]
pub(super) struct ContactQuery {
    direction: Option<String>,
}

pub(super) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<ContactRequestResponse>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    let sender = authenticate_request(
        &state,
        &headers,
        "POST",
        "/v1/contacts/requests",
        &body,
        None,
    )
    .await?;
    let request: ContactRequestPayload =
        serde_json::from_slice(&body).map_err(|error| bad_request(error.into()))?;
    validate_text(&request.request_id, MAX_ID_BYTES, "request ID").map_err(bad_request)?;
    validate_text(&request.recipient, MAX_ID_BYTES, "recipient").map_err(bad_request)?;
    validate_text(&request.sender_name, MAX_LABEL_BYTES, "sender name").map_err(bad_request)?;
    validate_text(
        &request.sender_fingerprint,
        MAX_FINGERPRINT_BYTES,
        "sender fingerprint",
    )
    .map_err(bad_request)?;
    let bundle = decode_bounded_base64(
        &request.bundle,
        MAX_BUNDLE_BYTES * 2,
        MAX_BUNDLE_BYTES,
        "bundle",
    )
    .map_err(bad_request)?;
    let db = state.db.lock().await;
    let recipient_exists: Option<String> = db
        .query_row(
            "SELECT client_id FROM devices WHERE client_id = ?1",
            params![request.recipient],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?;
    if recipient_exists.is_none() {
        return Err(not_found());
    }
    db.execute("INSERT OR IGNORE INTO contact_requests (request_id, sender, recipient, sender_name, sender_fingerprint, bundle, status, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8)", params![request.request_id, sender, request.recipient, request.sender_name, request.sender_fingerprint, bundle, now() as i64, (now()+86400) as i64]).map_err(internal)?;
    Ok(axum::Json(ContactRequestResponse {
        request_id: request.request_id,
        sender_id: sender,
        recipient: request.recipient,
        sender_name: request.sender_name,
        sender_fingerprint: request.sender_fingerprint,
        bundle: request.bundle,
        status: "pending".into(),
        created_at: now(),
    }))
}

pub(super) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ContactQuery>,
) -> Result<axum::Json<Vec<ContactRequestResponse>>, ApiError> {
    validate_json_accept(&headers).map_err(bad_request)?;
    if let Some(direction) = query.direction.as_deref()
        && direction != "outgoing"
    {
        return Err(bad_request(anyhow::anyhow!("invalid contact direction")));
    }
    let caller =
        authenticate_request(&state, &headers, "GET", "/v1/contacts/requests", &[], None).await?;
    let db = state.db.lock().await;
    let outgoing = query.direction.as_deref() == Some("outgoing");
    let sql = if outgoing {
        "SELECT c.request_id, c.recipient, c.recipient, d.device_address, a.fingerprint, d.bundle, c.status, c.created_at FROM contact_requests c JOIN devices d ON d.client_id = c.recipient JOIN allowlist a ON a.client_id = c.recipient WHERE c.sender = ?1 AND c.expires_at >= ?2 ORDER BY c.created_at"
    } else {
        "SELECT request_id, sender, recipient, sender_name, sender_fingerprint, bundle, status, created_at FROM contact_requests WHERE recipient = ?1 AND status = 'pending' AND expires_at >= ?2 ORDER BY created_at"
    };
    let mut statement = db.prepare(sql).map_err(internal)?;
    let rows = statement
        .query_map(params![caller, now() as i64], |row| {
            Ok(ContactRequestResponse {
                request_id: row.get(0)?,
                sender_id: row.get(1)?,
                recipient: row.get(2)?,
                sender_name: row.get(3)?,
                sender_fingerprint: row.get(4)?,
                bundle: b64(&row.get::<_, Vec<u8>>(5)?),
                status: row.get(6)?,
                created_at: row.get::<_, i64>(7)? as u64,
            })
        })
        .map_err(internal)?;
    Ok(axum::Json(
        rows.collect::<Result<Vec<_>, _>>().map_err(internal)?,
    ))
}

pub(super) async fn accept(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<ContactRequestResponse>, ApiError> {
    validate_optional_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&request_id, MAX_ID_BYTES, "request ID").map_err(bad_request)?;
    let recipient = authenticate_request(
        &state,
        &headers,
        "POST",
        &format!("/v1/contacts/requests/{request_id}/accept"),
        b"null",
        None,
    )
    .await?;
    let db = state.db.lock().await;
    db.execute("UPDATE contact_requests SET status = 'accepted' WHERE request_id = ?1 AND recipient = ?2 AND status = 'pending'", params![request_id, recipient]).map_err(internal)?;
    let response = db.query_row("SELECT request_id, sender, recipient, sender_name, sender_fingerprint, bundle, status, created_at FROM contact_requests WHERE request_id = ?1 AND recipient = ?2", params![request_id, recipient], |row| Ok(ContactRequestResponse { request_id: row.get(0)?, sender_id: row.get(1)?, recipient: row.get(2)?, sender_name: row.get(3)?, sender_fingerprint: row.get(4)?, bundle: b64(&row.get::<_, Vec<u8>>(5)?), status: row.get(6)?, created_at: row.get::<_, i64>(7)? as u64 })).optional().map_err(internal)?.ok_or_else(not_found)?;
    Ok(axum::Json(response))
}

pub(super) async fn reject(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    validate_optional_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&request_id, MAX_ID_BYTES, "request ID").map_err(bad_request)?;
    let recipient = authenticate_request(
        &state,
        &headers,
        "POST",
        &format!("/v1/contacts/requests/{request_id}/reject"),
        b"null",
        None,
    )
    .await?;
    let db = state.db.lock().await;
    db.execute(
        "UPDATE contact_requests SET status = 'rejected' WHERE request_id = ?1 AND recipient = ?2",
        params![request_id, recipient],
    )
    .map_err(internal)?;
    Ok(axum::Json(serde_json::json!({"rejected": true})))
}
