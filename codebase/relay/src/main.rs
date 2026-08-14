use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use safechat_relay_protocol as relay_binary;
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
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

const API_VERSION: &str = "safechat-relay-v1";
const REGISTER_DOMAIN: &[u8] = b"safechat-relay-register-v1\0";
const REQUEST_DOMAIN: &[u8] = b"safechat-relay-request-v1\0";
const ENROLLMENT_REQUEST_DOMAIN: &[u8] = b"safechat-relay-enrollment-request-v1\0";
const MAX_BODY: usize = relay_binary::MAX_BODY;
const JSON_MEDIA_TYPE: &str = "application/json";
const BINARY_MEDIA_TYPE: &str = "application/octet-stream";
const MAX_ID_BYTES: usize = 256;
const MAX_FINGERPRINT_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 512;
const MAX_IDENTITY_B64_BYTES: usize = 256;
const MAX_SIGNATURE_B64_BYTES: usize = 512;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

mod auth;
mod contacts;
mod database;
mod events;
mod validation;
use auth::*;
use contacts::{
    accept as accept_contact_request, create as create_contact_request,
    list as list_contact_requests, reject as reject_contact_request,
};
use database::{open as open_database, *};
use events::route as events_route;
use validation::*;

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
        /// Run plain HTTP. Use only on a private network behind a TLS proxy.
        #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
        http: bool,
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        #[arg(long, requires = "tls_cert")]
        tls_key: Option<PathBuf>,
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
        /// Permit an HTTP URL for a localhost/private-network admin hop.
        #[arg(long)]
        allow_http: bool,
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
    EnrollmentPending {
        #[arg(long)]
        database: PathBuf,
    },
    EnrollmentApprove {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        client_id: Option<String>,
    },
    EnrollmentReject {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        client_id: String,
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

#[derive(Deserialize)]
struct EnrollmentRequest {
    device_address: String,
    identity_key: String,
    fingerprint: String,
    bundle: String,
    enrollment_secret_hash: String,
    signature: String,
}

#[derive(Deserialize, Serialize)]
struct EnrollmentResponse {
    accepted: bool,
    client_id: String,
    expires_at: u64,
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
            allow_http,
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
                allow_http,
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
        Command::EnrollmentPending { database } => {
            let connection = open_database(&database)?;
            initialize_schema(&connection)?;
            let mut statement = connection.prepare(
                "SELECT client_id, device_address, fingerprint, created_at, expires_at
                 FROM enrollment_requests WHERE expires_at >= ?1 ORDER BY created_at",
            )?;
            let rows = statement.query_map(params![now() as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?;
            let mut found = false;
            for row in rows {
                let (client_id, address, fingerprint, created_at, expires_at) = row?;
                found = true;
                println!("Client: {client_id}");
                println!("Name: {address}");
                println!("Fingerprint: {fingerprint}");
                println!("Requested: {created_at} (expires {expires_at})");
                println!();
            }
            if !found {
                println!("No pending enrollment requests.");
            }
        }
        Command::EnrollmentApprove {
            database,
            client_id,
        } => {
            let connection = open_database(&database)?;
            initialize_schema(&connection)?;
            let client_id = client_id.unwrap_or_else(|| choose_pending_enrollment(&connection));
            approve_enrollment(&connection, &client_id)?;
            println!("approved enrollment request for {client_id}");
        }
        Command::EnrollmentReject {
            database,
            client_id,
        } => {
            let connection = open_database(&database)?;
            initialize_schema(&connection)?;
            let changed = connection.execute(
                "DELETE FROM enrollment_requests WHERE client_id = ?1",
                params![client_id],
            )?;
            if changed == 0 {
                anyhow::bail!("no pending enrollment request for {client_id}");
            }
            println!("rejected enrollment request for {client_id}");
        }
        Command::Serve {
            bind,
            database,
            http,
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
            if http {
                println!("safechat-relay listening on http://{bind} (private proxy mode)");
                let listener = tokio::net::TcpListener::bind(bind).await?;
                axum::serve(listener, app).await?;
            } else {
                let config = RustlsConfig::from_pem_file(
                    tls_cert.expect("tls_cert is required unless --http is set"),
                    tls_key.expect("tls_key is required unless --http is set"),
                )
                .await?;
                println!("safechat-relay listening on https://{bind}");
                axum_server::bind_rustls(bind, config)
                    .serve(app.into_make_service())
                    .await?;
            }
        }
    }
    Ok(())
}

fn allowlist_add_remote(
    base_url: &str,
    admin_token: &str,
    ca_cert: Option<&std::path::Path>,
    allow_http: bool,
    request: AdminAllowlistRequest,
) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(base_url)?;
    if parsed.scheme() != "https" && !(allow_http && parsed.scheme() == "http") {
        anyhow::bail!("relay URL must use HTTPS (or pass --allow-http for a private hop)");
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
        .route("/v1/devices/enrollment-requests", post(enrollment_request))
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
        .route(
            "/v1/contacts/requests",
            post(create_contact_request).get(list_contact_requests),
        )
        .route(
            "/v1/contacts/requests/{request_id}/accept",
            post(accept_contact_request),
        )
        .route(
            "/v1/contacts/requests/{request_id}/reject",
            post(reject_contact_request),
        )
        .route("/v1/messages/status", get(message_status))
        .route("/v1/messages/{server_id}/ack", post(ack_message))
        .route("/v1/events", get(events_route))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

async fn admin_allowlist(
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
    Ok(axum::Json(json!({
        "allowlisted": true,
        "client_id": request.client_id,
    })))
}

async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "ok", "api_version": API_VERSION}))
}

async fn enrollment_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<EnrollmentRequest>,
) -> Result<axum::Json<EnrollmentResponse>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    if request.device_address.len() > MAX_ID_BYTES
        || request.fingerprint.len() > MAX_FINGERPRINT_BYTES
        || request.enrollment_secret_hash.len() != 64
        || !request
            .enrollment_secret_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || request.bundle.len() > MAX_BUNDLE_BYTES * 2
    {
        return Err(bad_request(anyhow::anyhow!(
            "invalid enrollment request size"
        )));
    }
    let identity_bytes = decode_bounded_base64(
        &request.identity_key,
        MAX_IDENTITY_B64_BYTES,
        128,
        "identity key",
    )
    .map_err(bad_request)?;
    let identity = IdentityKey::decode(&identity_bytes)
        .map_err(|_| bad_request(anyhow::anyhow!("invalid identity key")))?;
    let bundle = decode_bounded_base64(
        &request.bundle,
        MAX_BUNDLE_BYTES * 2,
        MAX_BUNDLE_BYTES,
        "bundle",
    )
    .map_err(bad_request)?;
    let mut signed = ENROLLMENT_REQUEST_DOMAIN.to_vec();
    signed.extend(request.device_address.as_bytes());
    signed.push(0);
    signed.extend(request.fingerprint.as_bytes());
    signed.push(0);
    signed.extend(request.enrollment_secret_hash.as_bytes());
    signed.push(0);
    signed.extend(Sha256::digest(&bundle));
    let signature = decode_bounded_base64(
        &request.signature,
        MAX_SIGNATURE_B64_BYTES,
        256,
        "signature",
    )
    .map_err(bad_request)?;
    if !identity.public_key().verify_signature(&signed, &signature) {
        return Err(unauthorized());
    }
    let expires_at = now().saturating_add(900);
    let db = state.db.lock().await;
    let client_id = format!(
        "sc-{}",
        URL_SAFE_NO_PAD.encode(&Sha256::digest(identity.serialize().as_ref())[..12])
    );
    db.execute(
        "INSERT OR REPLACE INTO enrollment_requests
         (client_id, device_address, identity_key, fingerprint, bundle,
          enrollment_secret_hash, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            client_id,
            request.device_address,
            identity_bytes,
            request.fingerprint,
            bundle,
            request.enrollment_secret_hash,
            now() as i64,
            expires_at as i64,
        ],
    )
    .map_err(internal)?;
    Ok(axum::Json(EnrollmentResponse {
        accepted: true,
        client_id,
        expires_at,
    }))
}

async fn capabilities() -> impl IntoResponse {
    axum::Json(json!({
        "api_version": API_VERSION,
        "websocket": true,
        "polling": true,
        "message_representation": {
            "content_type": "application/octet-stream",
            "accept": "application/octet-stream",
            "protocol_version": relay_binary::VERSION,
            "schema_version": relay_binary::SCHEMA,
            "max_body_bytes": relay_binary::MAX_BODY,
            "max_messages": relay_binary::MAX_MESSAGES,
            "max_recipient_bytes": relay_binary::MAX_RECIPIENT_BYTES,
            "max_message_id_bytes": relay_binary::MAX_MESSAGE_ID_BYTES,
            "max_address_bytes": relay_binary::MAX_ADDRESS_BYTES,
            "max_ciphertext_bytes": relay_binary::MAX_CIPHERTEXT_BYTES,
        }
    }))
}

async fn challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(request): axum::Json<ChallengeRequest>,
) -> Result<axum::Json<ChallengeResponse>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&request.client_id, MAX_ID_BYTES, "client ID").map_err(bad_request)?;
    validate_text(
        &request.enrollment_secret,
        MAX_SECRET_BYTES,
        "enrollment secret",
    )
    .map_err(bad_request)?;
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
    if used != 0
        || secret_hash
            .as_bytes()
            .ct_eq(hash(&request.enrollment_secret).as_bytes())
            .unwrap_u8()
            != 1
    {
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
    headers: HeaderMap,
    axum::Json(request): axum::Json<RegisterRequest>,
) -> Result<axum::Json<RegisterResponse>, ApiError> {
    require_json_content(&headers).map_err(bad_request)?;
    validate_json_accept(&headers).map_err(bad_request)?;
    validate_text(&request.client_id, MAX_ID_BYTES, "client ID").map_err(bad_request)?;
    validate_text(&request.device_address, MAX_ID_BYTES, "device address").map_err(bad_request)?;
    let mut db = state.db.lock().await;
    let transaction = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(internal)?;
    let (identity_bytes, secret_hash, used): (Vec<u8>, String, i64) = transaction.query_row(
        "SELECT identity_key, enrollment_secret_hash, enrollment_used FROM allowlist WHERE client_id = ?1 AND status = 'active'",
        params![request.client_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()
        .map_err(internal)?.ok_or_else(unauthorized)?;
    if used != 0 {
        return Err(unauthorized());
    }
    let identity = IdentityKey::decode(
        &decode_bounded_base64(
            &request.identity_key,
            MAX_IDENTITY_B64_BYTES,
            128,
            "identity key",
        )
        .map_err(bad_request)?,
    )
    .map_err(|_| unauthorized())?;
    if identity.serialize().as_ref() != identity_bytes.as_slice() {
        return Err(unauthorized());
    }
    let challenge: (Vec<u8>, i64) = transaction
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
    let bundle = decode_bounded_base64(
        &request.bundle,
        MAX_BUNDLE_BYTES * 2,
        MAX_BUNDLE_BYTES,
        "bundle",
    )
    .map_err(bad_request)?;
    let signature = decode_bounded_base64(
        &request.signature,
        MAX_SIGNATURE_B64_BYTES,
        256,
        "signature",
    )
    .map_err(bad_request)?;
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
    let claimed = transaction.execute(
        "UPDATE allowlist SET enrollment_used = 1, device_address = ?2 WHERE client_id = ?1 AND enrollment_used = 0",
        params![request.client_id, request.device_address],
    ).map_err(internal)?;
    if claimed != 1 {
        return Err(unauthorized());
    }
    transaction.execute("INSERT OR REPLACE INTO devices(client_id, identity_key, device_address, token_hash, bundle, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![request.client_id, identity_bytes, request.device_address, hash(&b64(&token)), bundle, now() as i64]).map_err(internal)?;
    transaction
        .execute(
            "DELETE FROM challenges WHERE client_id = ?1",
            params![request.client_id],
        )
        .map_err(internal)?;
    transaction.commit().map_err(internal)?;
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

async fn fetch_bundle(
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

async fn fetch_bundle_by_address(
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

async fn send_message(
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
        let existing = db
            .query_row(
                "SELECT messages.server_id, messages.sender, devices.device_address, messages.client_message_id, messages.ciphertext, messages.accepted_at, messages.expires_at FROM messages LEFT JOIN devices ON devices.client_id = messages.sender WHERE messages.sender = ?1 AND messages.recipient = ?2 AND messages.client_message_id = ?3",
                params![sender, recipient_id, message_id],
                |row| {
                    Ok(MessageResponse {
                        server_id: row.get(0)?,
                        sender: row.get(1)?,
                        sender_address: row.get(2)?,
                        message_id: row.get(3)?,
                        ciphertext: b64(&row.get::<_, Vec<u8>>(4)?),
                        accepted_at: row.get::<_, i64>(5)? as u64,
                        expires_at: row.get::<_, Option<i64>>(6)?.map(|x| x as u64),
                    })
                },
            )
            .optional()
            .map_err(internal)?
            .ok_or_else(not_found)?;
        return Ok((
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            encode_binary_messages(&[existing]).map_err(internal)?,
        )
            .into_response());
    }
    let id = db.last_insert_rowid();
    let message = MessageResponse {
        server_id: id,
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

async fn receive_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<CursorQuery>,
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

async fn ack_message(
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
    Ok(axum::Json(json!({"acknowledged": true})))
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
    eprintln!("internal relay error: {error}");
    ApiError(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal server error".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::contacts::ContactRequestResponse;
    use super::*;
    use axum::{
        body::to_bytes,
        http::{HeaderMap, Request},
    };
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
    fn enrollment_approval_promotes_pending_request_without_plaintext_secret() {
        let database = test_database();
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let identity_bytes = identity.identity_key().serialize();
        database
            .execute(
                "INSERT INTO enrollment_requests
                 (client_id, device_address, identity_key, fingerprint, bundle,
                  enrollment_secret_hash, created_at, expires_at)
                 VALUES ('client-a', 'Alice.1', ?1, 'fingerprint-a', ?2, ?3, ?4, ?5)",
                params![
                    identity_bytes.as_ref(),
                    b"bundle",
                    hash("secret"),
                    now(),
                    now() + 900
                ],
            )
            .unwrap();
        approve_enrollment(&database, "client-a").unwrap();
        let stored: (String, String, i64) = database
            .query_row(
                "SELECT enrollment_secret_hash, status, enrollment_used FROM allowlist WHERE client_id = 'client-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored.0, hash("secret"));
        assert_eq!(stored.1, "active");
        assert_eq!(stored.2, 0);
    }

    #[tokio::test]
    async fn enrollment_request_gets_a_server_assigned_client_id() {
        let database = test_database();
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let identity_bytes = identity.identity_key().serialize();
        let device_address = "Alice.1";
        let fingerprint = "fingerprint-a";
        let secret_hash = hash("secret");
        let bundle = b"bundle";
        let mut signed = ENROLLMENT_REQUEST_DOMAIN.to_vec();
        signed.extend(device_address.as_bytes());
        signed.push(0);
        signed.extend(fingerprint.as_bytes());
        signed.push(0);
        signed.extend(secret_hash.as_bytes());
        signed.push(0);
        signed.extend(Sha256::digest(bundle));
        let signature = identity
            .private_key()
            .calculate_signature(&signed, &mut rng)
            .unwrap();
        let state = AppState {
            db: Arc::new(Mutex::new(database)),
            admin_token: None,
        };
        let response = router(state)
            .oneshot(
                Request::post("/v1/devices/enrollment-requests")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&json!({
                            "device_address": device_address,
                            "identity_key": b64(&identity_bytes),
                            "fingerprint": fingerprint,
                            "bundle": b64(bundle),
                            "enrollment_secret_hash": secret_hash,
                            "signature": b64(&signature),
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let enrollment: EnrollmentResponse = serde_json::from_slice(&body).unwrap();
        assert!(enrollment.accepted);
        assert!(enrollment.client_id.starts_with("sc-"));
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

    #[test]
    fn json_and_binary_message_representations_are_equivalent() {
        let json_message = MessageResponse {
            server_id: 7,
            sender: "alice".into(),
            sender_address: Some("Alice.1".into()),
            message_id: "message-1".into(),
            ciphertext: b64(&[0, 1, 255]),
            accepted_at: 42,
            expires_at: Some(99),
        };
        let json_round_trip: MessageResponse =
            serde_json::from_value(serde_json::to_value(&json_message).unwrap()).unwrap();
        let binary =
            relay_binary::encode_messages(&[binary_message(&json_message).unwrap()]).unwrap();
        let binary_round_trip = relay_binary::decode_messages(&binary)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(json_round_trip.server_id, binary_round_trip.server_id);
        assert_eq!(json_round_trip.sender, binary_round_trip.sender);
        assert_eq!(
            json_round_trip.sender_address,
            binary_round_trip.sender_address
        );
        assert_eq!(json_round_trip.message_id, binary_round_trip.message_id);
        assert_eq!(json_round_trip.accepted_at, binary_round_trip.accepted_at);
        assert_eq!(json_round_trip.expires_at, binary_round_trip.expires_at);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(json_round_trip.ciphertext).unwrap(),
            binary_round_trip.ciphertext
        );
    }

    #[test]
    fn invalid_stored_ciphertext_is_not_replaced_with_empty_bytes() {
        let message = MessageResponse {
            server_id: 1,
            sender: "alice".into(),
            sender_address: None,
            message_id: "message".into(),
            ciphertext: "not-base64!".into(),
            accepted_at: 1,
            expires_at: None,
        };
        assert!(binary_message(&message).is_err());
    }

    #[test]
    fn unsupported_message_media_types_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        assert!(decode_message_request(&headers, b"{}").is_err());
        headers.insert("content-type", "application/json".parse().unwrap());
        assert!(decode_message_request(&headers, b"{}").is_err());
        headers.clear();
        headers.insert("accept", "text/plain".parse().unwrap());
        assert!(wants_binary(&headers).is_err());
        headers.insert("accept", "application/octet-stream;q=0".parse().unwrap());
        assert!(wants_binary(&headers).is_err());
    }

    #[test]
    fn response_negotiation_does_not_follow_request_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
        headers.insert("accept", "application/json".parse().unwrap());
        assert!(require_binary_accept(&headers).is_err());
    }

    #[test]
    fn internal_errors_are_not_returned_to_clients() {
        let error = internal("database is locked at /secret/path");
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.1, "internal server error");
    }

    #[tokio::test]
    async fn expired_nonces_are_cleaned_when_a_signed_request_is_verified() {
        let database = test_database();
        let mut rng = rand::rng();
        let identity = IdentityKeyPair::generate(&mut rng);
        let identity_bytes = identity.identity_key().serialize();
        database.execute(
            "INSERT INTO allowlist (client_id, identity_key, fingerprint, enrollment_secret_hash, status, label, created_at) VALUES ('client', ?1, 'fp', 'hash', 'active', 'client', ?2)",
            params![identity_bytes.as_ref(), now()],
        ).unwrap();
        database.execute(
            "INSERT INTO devices (client_id, identity_key, device_address, token_hash, bundle, last_seen_at) VALUES ('client', ?1, 'Client.1', 'token', 'bundle', ?2)",
            params![identity_bytes.as_ref(), now()],
        ).unwrap();
        database.execute(
            "INSERT INTO request_nonces (client_id, nonce, expires_at) VALUES ('client', 'expired', ?1)",
            params![now() as i64 - 1],
        ).unwrap();
        let body = b"body";
        let timestamp = now();
        let nonce = "fresh";
        let mut signed = REQUEST_DOMAIN.to_vec();
        signed.extend(b"GET");
        signed.push(0);
        signed.extend(b"/v1/test");
        signed.push(0);
        signed.extend(Sha256::digest(body));
        signed.extend(nonce.as_bytes());
        signed.push(0);
        signed.extend(timestamp.to_be_bytes());
        let signature = identity
            .private_key()
            .calculate_signature(&signed, &mut rng)
            .unwrap();
        let state = AppState {
            db: Arc::new(Mutex::new(database)),
            admin_token: None,
        };
        verify_signature(
            &state,
            "client",
            "GET",
            "/v1/test",
            body,
            nonce,
            timestamp,
            &b64(&signature),
        )
        .await
        .unwrap();
        let db = state.db.lock().await;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM request_nonces WHERE nonce = 'expired'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn duplicate_message_ids_are_idempotently_stored_once() {
        let database = test_database();
        let first = database.execute(
            "INSERT INTO messages (sender, recipient, client_message_id, ciphertext, accepted_at) VALUES ('a', 'b', 'm', ?1, 1)",
            params![b"cipher"],
        ).unwrap();
        let second = database.execute(
            "INSERT OR IGNORE INTO messages (sender, recipient, client_message_id, ciphertext, accepted_at) VALUES ('a', 'b', 'm', ?1, 2)",
            params![b"other"],
        ).unwrap();
        assert_eq!(first, 1);
        assert_eq!(second, 0);
        let ciphertext: Vec<u8> = database.query_row("SELECT ciphertext FROM messages WHERE sender = 'a' AND recipient = 'b' AND client_message_id = 'm'", [], |row| row.get(0)).unwrap();
        assert_eq!(ciphertext, b"cipher");
    }

    #[tokio::test]
    async fn capabilities_advertise_binary_contract_and_limits() {
        let response = capabilities().await.into_response();
        let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["message_representation"]["protocol_version"],
            relay_binary::VERSION
        );
        assert_eq!(
            value["message_representation"]["schema_version"],
            relay_binary::SCHEMA
        );
        assert_eq!(
            value["message_representation"]["max_messages"],
            relay_binary::MAX_MESSAGES
        );
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
        request
            .headers_mut()
            .insert("accept", "application/octet-stream".parse().unwrap());
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let message_body = relay_binary::encode_submit(&relay_binary::Submit {
            recipient: client_id.into(),
            message_id: "message-1".into(),
            expires_at: None,
            ciphertext: b"opaque-ciphertext".to_vec(),
        })
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
        let mut headers = headers;
        headers.insert("content-type", "application/octet-stream".parse().unwrap());
        headers.insert("accept", "application/octet-stream".parse().unwrap());
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
        let mut headers = headers;
        headers.insert("accept", "application/octet-stream".parse().unwrap());
        let mut request = Request::get("/v1/messages?cursor=0")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = headers;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        assert!(response_body.len() >= 5);
        assert_eq!(
            u16::from_be_bytes(response_body[..2].try_into().unwrap()),
            relay_binary::VERSION
        );
        assert_eq!(
            u16::from_be_bytes(response_body[2..4].try_into().unwrap()),
            relay_binary::SCHEMA
        );
        assert_eq!(response_body[4], relay_binary::KIND_MESSAGES);
        assert!(
            response_body
                .windows(b"message-1".len())
                .any(|window| window == b"message-1")
        );
        let received_server_id =
            i64::from_be_bytes(response_body[5 + 4..5 + 12].try_into().unwrap());

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
        let ack_path = format!("/v1/messages/{}/ack", received_server_id);
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
        request
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
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
        request
            .headers_mut()
            .insert("content-type", "application/octet-stream".parse().unwrap());
        request
            .headers_mut()
            .insert("accept", "application/octet-stream".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn contact_request_can_be_submitted_accepted_and_seen_by_sender() {
        let database = test_database();
        let mut rng = rand::rng();
        let alice = IdentityKeyPair::generate(&mut rng);
        let bob = IdentityKeyPair::generate(&mut rng);
        for (id, identity, token, address) in [
            ("alice", &alice, "alice-token", "Alice.1"),
            ("bob", &bob, "bob-token", "Bob.1"),
        ] {
            let identity_bytes = identity.identity_key().serialize();
            database.execute(
                "INSERT INTO allowlist (client_id, identity_key, fingerprint, enrollment_secret_hash, status, label, created_at) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)",
                params![id, identity_bytes.as_ref(), format!("{id}-fp"), hash("secret"), address, now()],
            ).unwrap();
            database.execute(
                "INSERT INTO devices (client_id, identity_key, device_address, token_hash, bundle, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, identity_bytes.as_ref(), address, hash(token), format!("{id}-bundle").as_bytes(), now()],
            ).unwrap();
        }
        let app = router(AppState {
            db: Arc::new(Mutex::new(database)),
            admin_token: None,
        });
        let body = serde_json::to_vec(&json!({
            "request_id": "cr-1",
            "recipient": "bob",
            "sender_name": "Alice",
            "sender_fingerprint": "alice-fp",
            "bundle": b64(b"alice-bundle")
        }))
        .unwrap();
        let mut request = Request::post("/v1/contacts/requests")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))
            .unwrap();
        *request.headers_mut() = signed_headers(
            &alice,
            "alice-token",
            "POST",
            "/v1/contacts/requests",
            &body,
            "n1",
        )
        .0;
        request
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut request = Request::get("/v1/contacts/requests")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() =
            signed_headers(&bob, "bob-token", "GET", "/v1/contacts/requests", &[], "n2").0;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let incoming: Vec<ContactRequestResponse> =
            serde_json::from_slice(&to_bytes(response.into_body(), MAX_BODY).await.unwrap())
                .unwrap();
        assert_eq!(incoming.len(), 1);
        let mut request = Request::post("/v1/contacts/requests/cr-1/accept")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = signed_headers(
            &bob,
            "bob-token",
            "POST",
            "/v1/contacts/requests/cr-1/accept",
            b"null",
            "n3",
        )
        .0;
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut request = Request::get("/v1/contacts/requests?direction=outgoing")
            .body(axum::body::Body::empty())
            .unwrap();
        *request.headers_mut() = signed_headers(
            &alice,
            "alice-token",
            "GET",
            "/v1/contacts/requests",
            &[],
            "n4",
        )
        .0;
        let response = app.oneshot(request).await.unwrap();
        let outgoing: Vec<ContactRequestResponse> =
            serde_json::from_slice(&to_bytes(response.into_body(), MAX_BODY).await.unwrap())
                .unwrap();
        assert_eq!(outgoing[0].status, "accepted");
        assert_eq!(outgoing[0].bundle, b64(b"bob-bundle"));
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
