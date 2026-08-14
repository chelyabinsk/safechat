//! WebSocket event transport and signed polling.

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use rusqlite::params;

use super::{
    AppState, MessageResponse,
    auth::{WsPollRequest, verify_websocket_request},
    authenticate_request, b64,
};

pub(super) async fn route(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, super::ApiError> {
    let device = authenticate_request(&state, &headers, "GET", "/v1/events", &[], None).await?;
    Ok(ws.on_upgrade(move |socket| websocket(socket, state, device)))
}

async fn websocket(mut socket: WebSocket, state: AppState, device: String) {
    while let Some(Ok(message)) = socket.recv().await {
        match message {
            Message::Ping(payload) => {
                let _ = socket.send(Message::Pong(payload)).await;
            }
            Message::Text(text) => {
                let request: WsPollRequest = match serde_json::from_str(&text) {
                    Ok(request) => request,
                    Err(_) => {
                        let _ = socket
                            .send(Message::Text(
                                r#"{"error":"invalid websocket request"}"#.into(),
                            ))
                            .await;
                        continue;
                    }
                };
                if verify_websocket_request(&state, &device, &request)
                    .await
                    .is_err()
                {
                    let _ = socket
                        .send(Message::Text(r#"{"error":"unauthorized"}"#.into()))
                        .await;
                    continue;
                }
                let db = state.db.lock().await;
                let rows = match db.prepare("SELECT messages.server_id, messages.sender, devices.device_address, messages.client_message_id, messages.ciphertext, messages.accepted_at, messages.expires_at FROM messages LEFT JOIN devices ON devices.client_id = messages.sender WHERE messages.recipient = ?1 AND messages.server_id > ?2 AND messages.acknowledged_at IS NULL ORDER BY messages.server_id LIMIT 100").and_then(|mut statement| statement.query_map(params![device, request.cursor], |row| Ok(MessageResponse { server_id: row.get(0)?, sender: row.get(1)?, sender_address: row.get(2)?, message_id: row.get(3)?, ciphertext: b64(&row.get::<_, Vec<u8>>(4)?), accepted_at: row.get::<_, i64>(5)? as u64, expires_at: row.get::<_, Option<i64>>(6)?.map(|x| x as u64) })).and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())) {
                    Ok(rows) => rows,
                    Err(error) => {
                        eprintln!("websocket message query failed: {error}");
                        let _ = socket.send(Message::Text(r#"{"error":"internal server error"}"#.into())).await;
                        continue;
                    }
                };
                match serde_json::to_string(&rows) {
                    Ok(payload) => {
                        let _ = socket.send(Message::Text(payload.into())).await;
                    }
                    Err(error) => {
                        eprintln!("websocket message serialization failed: {error}");
                        let _ = socket
                            .send(Message::Text(r#"{"error":"internal server error"}"#.into()))
                            .await;
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}
