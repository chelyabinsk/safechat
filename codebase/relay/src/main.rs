use axum::{
    Router,
    body::Bytes,
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_protocol::IdentityKey;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const API_VERSION: &str = "safechat-relay-v1";
const REGISTER_DOMAIN: &[u8] = b"safechat-relay-register-v1\0";
const REQUEST_DOMAIN: &[u8] = b"safechat-relay-request-v1\0";
const MAX_BODY: usize = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "safechat-relay", about = "Standalone SafeChat HTTPS relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "0.0.0.0:8443")]
        bind: SocketAddr,
        #[arg(long, default_value = "relay.db")]
        database: PathBuf,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        /// Enable the live administrative allowlist endpoint.
        #[arg(long, env = "SAFECHAT_RELAY_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },
    AllowlistAdd {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        enrollment_secret: String,
        #[arg(long, default_value = "")]
        label: String,
    },
    AllowlistRevoke {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        client_id: String,
    },
    AllowlistAddRemote {
        #[arg(long)]
        url: String,
        #[arg(long, env = "SAFECHAT_RELAY_ADMIN_TOKEN")]
        admin_token: String,
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        identity_key: String,
        #[arg(long)]
        fingerprint: String,
        #[arg(long)]
        enrollment_secret: String,
        #[arg(long, default_value = "")]
        label: String,
    },
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    admin_token: Option<String>,
}

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, axum::Json(json!({"error": self.1}))).into_response()
    }
}

#[derive(Deserialize)]
struct ChallengeRequest {
    client_id: String,
    enrollment_secret: String,
}

#[derive(Deserialize, Serialize)]
struct ChallengeResponse {
    challenge: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct RegisterRequest {
    client_id: String,
    device_address: String,
    identity_key: String,
    bundle: String,
    signature: String,
}

#[derive(Deserialize, Serialize)]
struct RegisterResponse {
    access_token: String,
    device_id: String,
    api_version: String,
}

#[derive(Deserialize)]
struct BundleRequest {
    bundle: String,
}

#[derive(Deserialize, Serialize)]
struct BundleResponse {
    device_id: String,
    bundle: String,
}

#[derive(Deserialize)]
struct MessageRequest {
    recipient: String,
    message_id: String,
    ciphertext: String,
    expires_at: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct MessageResponse {
    server_id: i64,
    sender: String,
    sender_address: Option<String>,
    message_id: String,
    ciphertext: String,
    accepted_at: u64,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct AckRequest {
    acknowledged: bool,
}

#[derive(Deserialize, Serialize)]
struct AdminAllowlistRequest {
    client_id: String,
    identity_key: String,
    fingerprint: String,
    enrollment_secret: String,
    #[serde(default)]
    label: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::AllowlistAdd {
            database,
            client_id,
            identity_key,
            fingerprint,
            enrollment_secret,
            label,
        } => {
            let connection = open_database(&database)?;
            initialize_schema(&connection)?;
            add_allowlist(
                &connection,
                &client_id,
                &identity_key,
                &fingerprint,
                &enrollment_secret,
                &label,
            )?;
            println!("allowlisted {client_id}");
        }
        Command::AllowlistRevoke {
            database,
            client_id,
        } => {
            let connection = open_database(&database)?;
            initialize_schema(&connection)?;
            let changed = connection.execute(
                "UPDATE allowlist SET status = 'revoked' WHERE client_id = ?1",
                params![client_id],
            )?;
            if changed == 0 {
                anyhow::bail!("client is not present in the allowlist");
            }
            connection.execute(
                "DELETE FROM devices WHERE client_id = ?1",
                params![client_id],
            )?;
            println!("revoked {client_id}");
        }
        Command::AllowlistAddRemote {
            url,
            admin_token,
            ca_cert,
            client_id,
            identity_key,
            fingerprint,
            enrollment_secret,
            label,
        } => {
            allowlist_add_remote(
                &url,
                &admin_token,
                ca_cert.as_deref(),
                AdminAllowlistRequest {
                    client_id,
                    identity_key,
                    fingerprint,
                    enrollment_secret,
                    label,
                },
            )?;
            println!("allowlisted client through relay");
        }
        Command::Serve {
            bind,
            database,
            tls_cert,
            tls_key,
            admin_token,
        } => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();
            let connection = open_database(&database)?;
            initialize_schema(&connection)?;
            let state = AppState {
                db: Arc::new(Mutex::new(connection)),
                admin_token,
            };
            let app = router(state);
            let config = RustlsConfig::from_pem_file(tls_cert, tls_key).await?;
            println!("safechat-relay listening on https://{bind}");
            axum_server::bind_rustls(bind, config)
                .serve(app.into_make_service())
                .await?;
        }
    }
    Ok(())
}

fn allowlist_add_remote(
    base_url: &str,
    admin_token: &str,
    ca_cert: Option<&std::path::Path>,
    request: AdminAllowlistRequest,
) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(base_url)?;
    if parsed.scheme() != "https" {
        anyhow::bail!("relay URL must use HTTPS");
    }
    let mut builder = reqwest::blocking::Client::builder();
    if let Some(path) = ca_cert {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    let client = builder.build()?;
    let response = client
        .post(format!(
            "{}/v1/admin/allowlist",
            base_url.trim_end_matches('/')
        ))
        .bearer_auth(admin_token)
        .json(&request)
        .send()?;
    let status = response.status();
    let body = response.text()?;
    if !status.is_success() {
        anyhow::bail!("relay admin request failed with {status}: {body}");
    }
    println!("{body}");
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/admin/allowlist", post(admin_allowlist))
        .route("/v1/devices/challenge", post(challenge))
        .route("/v1/devices/register", post(register))
        .route(
            "/v1/devices/{device}/bundle",
            put(publish_bundle).get(fetch_bundle),
        )
        .route(
            "/v1/devices/by-address/{address}/bundle",
            get(fetch_bundle_by_address),
        )
        .route("/v1/messages", post(send_message).get(receive_messages))
        .route("/v1/messages/status", get(message_status))
        .route("/v1/messages/{server_id}/ack", post(ack_message))
        .route("/v1/events", get(events))
        .with_state(state)
}

async fn admin_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<AdminAllowlistRequest>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Err(not_found());
    };
    let Some(provided) = bearer(&headers) else {
        return Err(unauthorized());
    };
    if provided != expected {
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
    Ok(axum::Json(json!({
        "allowlisted": true,
        "client_id": request.client_id,
    })))
}

async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "ok", "api_version": API_VERSION}))
}

async fn capabilities() -> impl IntoResponse {
    axum::Json(json!({"api_version": API_VERSION, "websocket": true, "polling": true}))
}

async fn challenge(
    State(state): State<AppState>,
    axum::Json(request): axum::Json<ChallengeRequest>,
) -> Result<axum::Json<ChallengeResponse>, ApiError> {
    let challenge = random_bytes::<32>();
    let expires_at = now().saturating_add(300);
    let db = state.db.lock().await;
    let allowed: Option<(String, i64)> = db.query_row(
        "SELECT enrollment_secret_hash, enrollment_used FROM allowlist WHERE client_id = ?1 AND status = 'active'",
        params![request.client_id], |row| Ok((row.get(0)?, row.get(1)?))).optional()
        .map_err(internal)?;
    let Some((secret_hash, used)) = allowed else {
        return Err(unauthorized());
    };
    if used != 0 || secret_hash != hash(&request.enrollment_secret) {
        return Err(unauthorized());
    }
    db.execute(
        "INSERT OR REPLACE INTO challenges(client_id, challenge, expires_at) VALUES (?1, ?2, ?3)",
        params![request.client_id, challenge, expires_at as i64],
    )
    .map_err(internal)?;
    Ok(axum::Json(ChallengeResponse {
        challenge: b64(&challenge),
        expires_at,
    }))
}

async fn register(
    State(state): State<AppState>,
    axum::Json(request): axum::Json<RegisterRequest>,
) -> Result<axum::Json<RegisterResponse>, ApiError> {
    let db = state.db.lock().await;
    let (identity_bytes, secret_hash, used): (Vec<u8>, String, i64) = db.query_row(
        "SELECT identity_key, enrollment_secret_hash, enrollment_used FROM allowlist WHERE client_id = ?1 AND status = 'active'",
        params![request.client_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()
        .map_err(internal)?.ok_or_else(unauthorized)?;
    if used != 0 {
        return Err(unauthorized());
    }
    let identity = IdentityKey::decode(&b64decode(&request.identity_key).map_err(bad_request)?)
        .map_err(|_| unauthorized())?;
    if identity.serialize().as_ref() != identity_bytes.as_slice() {
        return Err(unauthorized());
    }
    let challenge: (Vec<u8>, i64) = db
        .query_row(
            "SELECT challenge, expires_at FROM challenges WHERE client_id = ?1",
            params![request.client_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
    if challenge.1 < now() as i64 || secret_hash.is_empty() {
        return Err(unauthorized());
    }
    let bundle = b64decode(&request.bundle).map_err(bad_request)?;
    let signature = b64decode(&request.signature).map_err(bad_request)?;
    let mut signed = REGISTER_DOMAIN.to_vec();
    signed.extend(request.client_id.as_bytes());
    signed.push(0);
    signed.extend(request.device_address.as_bytes());
    signed.push(0);
    signed.extend(Sha256::digest(&bundle));
    signed.extend(&challenge.0);
    if !identity.public_key().verify_signature(&signed, &signature) {
        return Err(unauthorized());
    }
    let token = random_bytes::<32>();
    db.execute(
        "UPDATE allowlist SET enrollment_used = 1, device_address = ?2 WHERE client_id = ?1",
        params![request.client_id, request.device_address],
    )
    .map_err(internal)?;
    db.execute("INSERT OR REPLACE INTO devices(client_id, identity_key, device_address, token_hash, bundle, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![request.client_id, identity_bytes, request.device_address, hash(&b64(&token)), bundle, now() as i64]).map_err(internal)?;
    db.execute(
        "DELETE FROM challenges WHERE client_id = ?1",
        params![request.client_id],
    )
    .map_err(internal)?;
    Ok(axum::Json(RegisterResponse {
        access_token: b64(&token),
        device_id: request.client_id,
        api_version: API_VERSION.to_owned(),
    }))
}

async fn publish_bundle(
    State(state): State<AppState>,
    Path(device): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<BundleResponse>, ApiError> {
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
    let bundle = b64decode(&request.bundle).map_err(bad_request)?;
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

async fn fetch_bundle(
    State(state): State<AppState>,
    Path(device): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<BundleResponse>, ApiError> {
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

async fn fetch_bundle_by_address(
    State(state): State<AppState>,
    Path(address): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<BundleResponse>, ApiError> {
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

async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<MessageResponse>, ApiError> {
    let sender =
        authenticate_request(&state, &headers, "POST", "/v1/messages", &body, None).await?;
    let request: MessageRequest =
        serde_json::from_slice(&body).map_err(|error| bad_request(error.into()))?;
    let ciphertext = b64decode(&request.ciphertext).map_err(bad_request)?;
    if ciphertext.len() > MAX_BODY {
        return Err(ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "message is too large".into(),
        ));
    }
    let db = state.db.lock().await;
    let recipient_id: String = db
        .query_row(
            "SELECT client_id FROM devices WHERE client_id = ?1 OR device_address = ?1",
            params![request.recipient],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(not_found)?;
    let accepted_at = now();
    let result = db.execute("INSERT OR IGNORE INTO messages(sender, recipient, client_message_id, ciphertext, accepted_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![sender, recipient_id, request.message_id, ciphertext, accepted_at as i64, request.expires_at.map(|x| x as i64)]).map_err(internal)?;
    if result == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "message already submitted".into(),
        ));
    }
    let id = db.last_insert_rowid();
    Ok(axum::Json(MessageResponse {
        server_id: id,
        sender,
        sender_address: None,
        message_id: request.message_id,
        ciphertext: request.ciphertext,
        accepted_at,
        expires_at: request.expires_at,
    }))
}

async fn receive_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<CursorQuery>,
) -> Result<axum::Json<Vec<MessageResponse>>, ApiError> {
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
    Ok(axum::Json(
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(internal)?,
    ))
}

#[derive(Deserialize)]
struct CursorQuery {
    cursor: Option<i64>,
}

#[derive(Deserialize)]
struct MessageStatusQuery {
    message_id: String,
}

#[derive(Deserialize, Serialize)]
struct MessageStatusResponse {
    message_id: String,
    status: String,
}

async fn message_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<MessageStatusQuery>,
) -> Result<axum::Json<MessageStatusResponse>, ApiError> {
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

async fn ack_message(
    State(state): State<AppState>,
    Path(server_id): Path<i64>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
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
    Ok(axum::Json(json!({"acknowledged": true})))
}

async fn events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
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
                let rows = db.prepare("SELECT messages.server_id, messages.sender, devices.device_address, messages.client_message_id, messages.ciphertext, messages.accepted_at, messages.expires_at FROM messages LEFT JOIN devices ON devices.client_id = messages.sender WHERE messages.recipient = ?1 AND messages.server_id > ?2 AND messages.acknowledged_at IS NULL ORDER BY messages.server_id LIMIT 100").and_then(|mut statement| statement.query_map(params![device, request.cursor], |row| Ok(MessageResponse { server_id: row.get(0)?, sender: row.get(1)?, sender_address: row.get(2)?, message_id: row.get(3)?, ciphertext: b64(&row.get::<_, Vec<u8>>(4)?), accepted_at: row.get::<_, i64>(5)? as u64, expires_at: row.get::<_, Option<i64>>(6)?.map(|x| x as u64) })).and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())).unwrap_or_default();
                if let Ok(payload) = serde_json::to_string(&rows) {
                    let _ = socket.send(Message::Text(payload.into())).await;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

#[derive(Deserialize)]
struct WsPollRequest {
    cursor: i64,
    nonce: String,
    timestamp: u64,
    signature: String,
}

async fn verify_websocket_request(
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

async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    expected_device: Option<&str>,
) -> Result<String, ApiError> {
    let token = bearer(headers).ok_or_else(unauthorized)?;
    let db = state.db.lock().await;
    let device: String = db
        .query_row(
            "SELECT devices.client_id FROM devices
             INNER JOIN allowlist ON allowlist.client_id = devices.client_id
             WHERE devices.token_hash = ?1 AND allowlist.status = 'active'",
            params![hash(token)],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
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

#[allow(clippy::too_many_arguments)]
async fn verify_signature(
    state: &AppState,
    device: &str,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &str,
    timestamp: u64,
    signature: &str,
) -> Result<(), ApiError> {
    if timestamp.abs_diff(now()) > 300 || nonce.is_empty() || nonce.len() > 128 {
        return Err(unauthorized());
    }
    let db = state.db.lock().await;
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
    let inserted = db
        .execute(
            "INSERT OR IGNORE INTO request_nonces(client_id, nonce, expires_at) VALUES (?1, ?2, ?3)",
            params![device, nonce, (now() + 600) as i64],
        )
        .map_err(internal)?;
    if inserted == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "request nonce already used".into(),
        ));
    }
    Ok(())
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn open_database(path: &PathBuf) -> anyhow::Result<Connection> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(connection)
}

fn initialize_schema(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS allowlist (client_id TEXT PRIMARY KEY, identity_key BLOB NOT NULL, fingerprint TEXT NOT NULL, enrollment_secret_hash TEXT NOT NULL, enrollment_used INTEGER NOT NULL DEFAULT 0, device_address TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, label TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS challenges (client_id TEXT PRIMARY KEY, challenge BLOB NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS devices (client_id TEXT PRIMARY KEY, identity_key BLOB NOT NULL, device_address TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, bundle BLOB NOT NULL, last_seen_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS request_nonces (client_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(client_id, nonce)); CREATE TABLE IF NOT EXISTS messages (server_id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT NOT NULL, client_message_id TEXT NOT NULL, ciphertext BLOB NOT NULL, accepted_at INTEGER NOT NULL, expires_at INTEGER, acknowledged_at INTEGER, UNIQUE(sender, recipient, client_message_id));")?;
    Ok(())
}

fn add_allowlist(
    db: &Connection,
    client_id: &str,
    identity_key: &str,
    fingerprint: &str,
    enrollment_secret: &str,
    label: &str,
) -> anyhow::Result<()> {
    let identity = b64decode(identity_key)?;
    IdentityKey::decode(&identity).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    db.execute("INSERT INTO allowlist(client_id, identity_key, fingerprint, enrollment_secret_hash, status, label, created_at) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)", params![client_id, identity, fingerprint, hash(enrollment_secret), label, now() as i64])?;
    Ok(())
}

fn random_bytes<const N: usize>() -> Vec<u8> {
    let mut bytes = [0u8; N];
    rand::fill(&mut bytes);
    bytes.to_vec()
}
fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn b64decode(value: &str) -> anyhow::Result<Vec<u8>> {
    Ok(URL_SAFE_NO_PAD.decode(value)?)
}
fn hash(value: &str) -> String {
    hash_bytes(value.as_bytes())
}
fn hash_bytes(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "unauthorized".into())
}
fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not found".into())
}
fn bad_request(error: anyhow::Error) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, error.to_string())
}
fn internal<E: std::fmt::Display>(error: E) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use signal_protocol::IdentityKeyPair;
    use std::{fs, path::PathBuf};
    use tower::ServiceExt;

    fn test_database() -> Connection {
        let database = Connection::open_in_memory().unwrap();
        initialize_schema(&database).unwrap();
        database
    }

    #[test]
    fn allowlist_stores_only_the_enrollment_secret_hash() {
        let database = test_database();
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let identity_key = b64(identity.identity_key().serialize().as_ref());
        add_allowlist(
            &database,
            "client-a",
            &identity_key,
            "fingerprint-a",
            "one-time-secret",
            "Alice",
        )
        .unwrap();
        let stored: (String, i64) = database
            .query_row(
                "SELECT enrollment_secret_hash, enrollment_used FROM allowlist WHERE client_id = 'client-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored.0, hash("one-time-secret"));
        assert_ne!(stored.0, "one-time-secret");
        assert_eq!(stored.1, 0);
    }

    #[test]
    fn request_signature_payload_is_domain_separated() {
        let mut payload = REQUEST_DOMAIN.to_vec();
        payload.extend(b"GET");
        payload.push(0);
        payload.extend(b"/v1/messages");
        payload.push(0);
        payload.extend(Sha256::digest(b"body"));
        payload.extend(b"nonce");
        payload.push(0);
        payload.extend(42u64.to_be_bytes());
        assert!(payload.starts_with(REQUEST_DOMAIN));
        assert_ne!(payload, [&b"GET"[..], b"/v1/messages"].concat());
    }

    #[tokio::test]
    async fn http_registration_and_queue_flow_requires_signed_requests() {
        let database = test_database();
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let client_id = "client-a";
        let identity_bytes = identity.identity_key().serialize();
        add_allowlist(
            &database,
            client_id,
            &b64(&identity_bytes),
            "fingerprint-a",
            "enrollment-secret",
            "Alice",
        )
        .unwrap();
        let state = AppState {
            db: Arc::new(Mutex::new(database)),
            admin_token: None,
        };
        let app = router(state.clone());
        let challenge_body = serde_json::to_vec(&json!({
            "client_id": client_id,
            "enrollment_secret": "enrollment-secret"
        }))
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/devices/challenge")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(challenge_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let challenge: ChallengeResponse = serde_json::from_slice(&response_body).unwrap();
        let challenge_bytes = b64decode(&challenge.challenge).unwrap();
        let bundle = b"opaque-public-bundle";
        let device_address = "alice.1";
        let mut register_payload = REGISTER_DOMAIN.to_vec();
        register_payload.extend(client_id.as_bytes());
        register_payload.push(0);
        register_payload.extend(device_address.as_bytes());
        register_payload.push(0);
        register_payload.extend(Sha256::digest(bundle));
        register_payload.extend(challenge_bytes);
        let signature = identity
            .private_key()
            .calculate_signature(&register_payload, &mut rng)
            .unwrap();
        let register_body = serde_json::to_vec(&json!({
            "client_id": client_id,
            "device_address": device_address,
            "identity_key": b64(&identity_bytes),
            "bundle": b64(bundle),
            "signature": b64(&signature)
        }))
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/devices/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(register_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let registered: RegisterResponse = serde_json::from_slice(&response_body).unwrap();

        let (mut headers, _) = signed_headers(
            &identity,
            &registered.access_token,
            "GET",
            "/v1/messages",
            &[],
            "nonce-invalid-signature",
        );
        headers.insert("x-safechat-signature", "not-a-signature".parse().unwrap());
        let mut request = Request::get("/v1/messages")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let message_body = serde_json::to_vec(&json!({
            "recipient": client_id,
            "message_id": "message-1",
            "ciphertext": b64(b"opaque-ciphertext")
        }))
        .unwrap();
        let replay_body = message_body.clone();
        let (headers, nonce) = signed_headers(
            &identity,
            &registered.access_token,
            "POST",
            "/v1/messages",
            &message_body,
            "nonce-message",
        );
        let mut request = Request::post("/v1/messages")
            .body(axum::body::Body::from(message_body))
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        if response.status() != StatusCode::OK {
            let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
            panic!(
                "message submission failed: {}",
                String::from_utf8_lossy(&body)
            );
        }

        let (headers, _) = signed_headers(
            &identity,
            &registered.access_token,
            "GET",
            "/v1/messages",
            &[],
            "nonce-receive",
        );
        let mut request = Request::get("/v1/messages?cursor=0")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let messages: Vec<MessageResponse> = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id, "message-1");

        let (headers, _) = signed_headers(
            &identity,
            &registered.access_token,
            "GET",
            "/v1/messages/status",
            &[],
            "nonce-status-sent",
        );
        let mut request = Request::get("/v1/messages/status?message_id=message-1")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let status: MessageStatusResponse = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(status.status, "sent");

        let ack_body = br#"{"acknowledged":true}"#.to_vec();
        let ack_path = format!("/v1/messages/{}/ack", messages[0].server_id);
        let (headers, _) = signed_headers(
            &identity,
            &registered.access_token,
            "POST",
            &ack_path,
            &ack_body,
            "nonce-ack",
        );
        let mut request = Request::post(&ack_path)
            .body(axum::body::Body::from(ack_body))
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let (headers, _) = signed_headers(
            &identity,
            &registered.access_token,
            "GET",
            "/v1/messages/status",
            &[],
            "nonce-status-read",
        );
        let mut request = Request::get("/v1/messages/status?message_id=message-1")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let status: MessageStatusResponse = serde_json::from_slice(&response_body).unwrap();
        assert_eq!(status.status, "read");

        let (headers, _) = signed_headers(
            &identity,
            &registered.access_token,
            "POST",
            "/v1/messages",
            &replay_body,
            &nonce,
        );
        let mut request = Request::post("/v1/messages")
            .body(axum::body::Body::from(replay_body))
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn live_admin_allowlisting_works_without_restarting_the_server() {
        let database = test_database();
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let state = AppState {
            db: Arc::new(Mutex::new(database)),
            admin_token: Some("admin-secret".to_owned()),
        };
        let app = router(state.clone());
        let body = serde_json::to_vec(&json!({
            "client_id": "client-live",
            "identity_key": b64(identity.identity_key().serialize().as_ref()),
            "fingerprint": "fingerprint-live",
            "enrollment_secret": "enrollment-live",
            "label": "Live client"
        }))
        .unwrap();
        let response = app
            .oneshot(
                Request::post("/v1/admin/allowlist")
                    .header("authorization", "Bearer admin-secret")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let database = state.db.lock().await;
        let stored: String = database
            .query_row(
                "SELECT fingerprint FROM allowlist WHERE client_id = 'client-live'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, "fingerprint-live");
    }

    #[tokio::test]
    async fn real_loopback_tls_server_accepts_https_health_requests() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let suffix = format!("{}-{}", std::process::id(), rand::random::<u64>());
        let certificate_path = std::env::temp_dir().join(format!("safechat-relay-{suffix}.crt"));
        let key_path = std::env::temp_dir().join(format!("safechat-relay-{suffix}.key"));
        fs::write(&certificate_path, certificate.cert.pem()).unwrap();
        fs::write(&key_path, certificate.key_pair.serialize_pem()).unwrap();

        let database = test_database();
        let state = AppState {
            db: Arc::new(Mutex::new(database)),
            admin_token: None,
        };
        let config = RustlsConfig::from_pem_file(&certificate_path, &key_path)
            .await
            .unwrap();
        let handle = axum_server::Handle::new();
        let server = axum_server::bind_rustls(([127, 0, 0, 1], 0).into(), config)
            .handle(handle.clone())
            .serve(router(state).into_make_service());
        let server_task = tokio::spawn(server);
        let address = handle.listening().await.unwrap();
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let response = client
            .get(format!("https://{address}/v1/health"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["api_version"], API_VERSION);

        handle.shutdown();
        server_task.await.unwrap().unwrap();
        remove_test_file(&certificate_path);
        remove_test_file(&key_path);
    }

    fn remove_test_file(path: &PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn signed_headers(
        identity: &IdentityKeyPair,
        token: &str,
        method: &str,
        path: &str,
        body: &[u8],
        nonce: &str,
    ) -> (HeaderMap, String) {
        let timestamp = now();
        let mut payload = REQUEST_DOMAIN.to_vec();
        payload.extend(method.as_bytes());
        payload.push(0);
        payload.extend(path.as_bytes());
        payload.push(0);
        payload.extend(Sha256::digest(body));
        payload.extend(nonce.as_bytes());
        payload.push(0);
        payload.extend(timestamp.to_be_bytes());
        let mut rng = rand::rng();
        let signature = identity
            .private_key()
            .calculate_signature(&payload, &mut rng)
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers.insert("x-safechat-nonce", nonce.parse().unwrap());
        headers.insert(
            "x-safechat-timestamp",
            timestamp.to_string().parse().unwrap(),
        );
        headers.insert("x-safechat-signature", b64(&signature).parse().unwrap());
        (headers, nonce.to_owned())
    }
}
