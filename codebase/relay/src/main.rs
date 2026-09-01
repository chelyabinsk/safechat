use axum::{Router, http::StatusCode, response::IntoResponse};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use rusqlite::{Connection, params};
use safechat_relay_protocol as relay_binary;
use serde_json::json;
use sha2::{Digest, Sha256};
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

mod admin;
mod auth;
mod bundles;
mod contacts;
mod database;
mod enrollment;
mod events;
mod messages;
mod router;
mod validation;
use admin::AdminAllowlistRequest;
use auth::*;
use database::{open as open_database, *};
#[cfg(test)]
use enrollment::{ChallengeResponse, EnrollmentResponse, RegisterResponse};
#[cfg(test)]
use messages::{MessageResponse, MessageStatusResponse};
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
pub(crate) struct AppState {
    db: Arc<Mutex<Connection>>,
    admin_token: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, axum::Json(json!({"error": self.1}))).into_response()
    }
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
    router::build(state)
}

async fn health() -> impl IntoResponse {
    axum::Json(json!({"status": "ok", "api_version": API_VERSION}))
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

        let message_body = relay_binary::encode_submit(&relay_binary::Submit::new(
            client_id,
            "message-1",
            None,
            b"opaque-ciphertext".to_vec(),
        ))
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
