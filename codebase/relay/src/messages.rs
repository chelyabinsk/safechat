//! Message submission, retrieval, acknowledgement, and status routes.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rusqlite::{OptionalExtension, params};
use safechat_relay_protocol as relay_binary;
use serde::{Deserialize, Serialize};

use super::auth::authenticate_request;
use super::validation::{
    decode_message_request, require_json_content, validate_json_accept, validate_text,
};
use super::{
    ApiError, AppState, b64, bad_request, encode_binary_messages, internal, not_found, now,
    require_binary_accept,
};

#[derive(Deserialize, Serialize)]
pub(super) struct MessageResponse {
    pub(super) server_id: i64,
    pub(super) sender: String,
    pub(super) sender_address: Option<String>,
    pub(super) message_id: String,
    pub(super) ciphertext: String,
    pub(super) accepted_at: u64,
    pub(super) expires_at: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct AckRequest {
    acknowledged: bool,
}

#[derive(Deserialize)]
pub(super) struct CursorQuery {
    cursor: Option<i64>,
}
#[derive(Deserialize)]
pub(super) struct MessageStatusQuery {
    message_id: String,
}
#[derive(Deserialize, Serialize)]
pub(super) struct MessageStatusResponse {
    pub(super) message_id: String,
    pub(super) status: String,
}

pub(super) async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    require_binary_accept(&headers).map_err(bad_request)?;
    let sender =
        authenticate_request(&state, &headers, "POST", "/v1/messages", &body, None).await?;
    let (recipient, message_id, expires_at, ciphertext) =
        decode_message_request(&headers, &body).map_err(bad_request)?;
    if ciphertext.len() > relay_binary::MAX_CIPHERTEXT_BYTES {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "message is too large".into(),
        ));
    }
    let db = state.db.lock().await;
    let recipient_id: String = db
        .query_row(
            "SELECT client_id FROM devices WHERE client_id = ?1 OR device_address = ?1",
            params![recipient],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(not_found)?;
    let accepted_at = now();
    let result = db.execute("INSERT OR IGNORE INTO messages(sender, recipient, client_message_id, ciphertext, accepted_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![sender, recipient_id, message_id, ciphertext, accepted_at as i64, expires_at.map(|x| x as i64)]).map_err(internal)?;
    if result == 0 {
        let existing = db.query_row("SELECT messages.server_id, messages.sender, devices.device_address, messages.client_message_id, messages.ciphertext, messages.accepted_at, messages.expires_at FROM messages LEFT JOIN devices ON devices.client_id = messages.sender WHERE messages.sender = ?1 AND messages.recipient = ?2 AND messages.client_message_id = ?3", params![sender, recipient_id, message_id], |row| Ok(MessageResponse { server_id: row.get(0)?, sender: row.get(1)?, sender_address: row.get(2)?, message_id: row.get(3)?, ciphertext: b64(&row.get::<_, Vec<u8>>(4)?), accepted_at: row.get::<_, i64>(5)? as u64, expires_at: row.get::<_, Option<i64>>(6)?.map(|x| x as u64) })).optional().map_err(internal)?.ok_or_else(not_found)?;
        return Ok((
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            encode_binary_messages(&[existing]).map_err(internal)?,
        )
            .into_response());
    }
    let message = MessageResponse {
        server_id: db.last_insert_rowid(),
        sender,
        sender_address: None,
        message_id,
        ciphertext: b64(&ciphertext),
        accepted_at,
        expires_at,
    };
    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        encode_binary_messages(&[message]).map_err(internal)?,
    )
        .into_response())
}

pub(super) async fn receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CursorQuery>,
) -> Result<Response, ApiError> {
    require_binary_accept(&headers).map_err(bad_request)?;
    let recipient =
        authenticate_request(&state, &headers, "GET", "/v1/messages", &[], None).await?;
    let db = state.db.lock().await;
    db.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        params![now() as i64],
    )
    .map_err(internal)?;
    let mut statement = db.prepare("SELECT messages.server_id, messages.sender, devices.device_address, messages.client_message_id, messages.ciphertext, messages.accepted_at, messages.expires_at FROM messages LEFT JOIN devices ON devices.client_id = messages.sender WHERE messages.recipient = ?1 AND messages.server_id > ?2 AND messages.acknowledged_at IS NULL ORDER BY messages.server_id LIMIT 100").map_err(internal)?;
    let rows = statement
        .query_map(params![recipient, query.cursor.unwrap_or(0)], |row| {
            Ok(MessageResponse {
                server_id: row.get(0)?,
                sender: row.get(1)?,
                sender_address: row.get(2)?,
                message_id: row.get(3)?,
                ciphertext: b64(&row.get::<_, Vec<u8>>(4)?),
                accepted_at: row.get::<_, i64>(5)? as u64,
                expires_at: row.get::<_, Option<i64>>(6)?.map(|x| x as u64),
            })
        })
        .map_err(internal)?;
    let messages = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        encode_binary_messages(&messages).map_err(internal)?,
    )
        .into_response())
}

pub(super) async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MessageStatusQuery>,
) -> Result<axum::Json<MessageStatusResponse>, ApiError> {
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(
        &query.message_id,
        relay_binary::MAX_MESSAGE_ID_BYTES,
        "message ID",
    )
    .map_err(bad_request)?;
    let sender =
        authenticate_request(&state, &headers, "GET", "/v1/messages/status", &[], None).await?;
    let db = state.db.lock().await;
    let acknowledged_at: Option<Option<i64>> = db
        .query_row(
            "SELECT acknowledged_at FROM messages WHERE sender = ?1 AND client_message_id = ?2",
            params![sender, query.message_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?;
    let Some(acknowledged_at) = acknowledged_at else {
        return Err(not_found());
    };
    Ok(axum::Json(MessageStatusResponse {
        message_id: query.message_id,
        status: if acknowledged_at.is_some() {
            "read".to_owned()
        } else {
            "sent".to_owned()
        },
    }))
}

pub(super) async fn acknowledge(
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    let recipient = authenticate_request(
        &state,
        &headers,
        "POST",
        &format!("/v1/messages/{server_id}/ack"),
        &body,
        None,
    )
    .await?;
    let request: AckRequest =
        serde_json::from_slice(&body).map_err(|error| bad_request(error.into()))?;
    if !request.acknowledged {
        return Err(bad_request(anyhow::anyhow!("acknowledged must be true")));
    }
    let db = state.db.lock().await;
    let changed = db
        .execute(
            "UPDATE messages SET acknowledged_at = ?1 WHERE server_id = ?2 AND recipient = ?3",
            params![now() as i64, server_id, recipient],
        )
        .map_err(internal)?;
    if changed == 0 {
        return Err(not_found());
    }
    Ok(axum::Json(serde_json::json!({"acknowledged": true})))
}
