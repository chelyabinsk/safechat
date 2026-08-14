//! Enrollment challenge, request, and device registration routes.

use axum::{extract::State, http::HeaderMap};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_protocol::IdentityKey;
use subtle::ConstantTimeEq;

use super::validation::{require_json_content, validate_json_accept, validate_text};
use super::{
    API_VERSION, ApiError, AppState, ENROLLMENT_REQUEST_DOMAIN, MAX_BUNDLE_BYTES,
    MAX_FINGERPRINT_BYTES, MAX_ID_BYTES, MAX_IDENTITY_B64_BYTES, MAX_SECRET_BYTES,
    MAX_SIGNATURE_B64_BYTES, REGISTER_DOMAIN, b64, bad_request, decode_bounded_base64, hash,
    internal, now, random_bytes, unauthorized,
};

#[derive(Deserialize)]
pub(super) struct ChallengeRequest {
    client_id: String,
    enrollment_secret: String,
}
#[derive(Deserialize, Serialize)]
pub(super) struct ChallengeResponse {
    pub(super) challenge: String,
    pub(super) expires_at: u64,
}
#[derive(Deserialize)]
pub(super) struct RegisterRequest {
    client_id: String,
    device_address: String,
    identity_key: String,
    bundle: String,
    signature: String,
}
#[derive(Deserialize)]
pub(super) struct EnrollmentRequest {
    device_address: String,
    identity_key: String,
    fingerprint: String,
    bundle: String,
    enrollment_secret_hash: String,
    signature: String,
}
#[derive(Deserialize, Serialize)]
pub(super) struct EnrollmentResponse {
    pub(super) accepted: bool,
    pub(super) client_id: String,
    pub(super) expires_at: u64,
}
#[derive(Deserialize, Serialize)]
pub(super) struct RegisterResponse {
    pub(super) access_token: String,
    pub(super) device_id: String,
    pub(super) api_version: String,
}

pub(super) async fn enrollment_request(
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
    db.execute("INSERT OR REPLACE INTO enrollment_requests (client_id, device_address, identity_key, fingerprint, bundle, enrollment_secret_hash, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", params![client_id, request.device_address, identity_bytes, request.fingerprint, bundle, request.enrollment_secret_hash, now() as i64, expires_at as i64]).map_err(internal)?;
    Ok(axum::Json(EnrollmentResponse {
        accepted: true,
        client_id,
        expires_at,
    }))
}

pub(super) async fn challenge(
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
    let allowed: Option<(String, i64)> = db.query_row("SELECT enrollment_secret_hash, enrollment_used FROM allowlist WHERE client_id = ?1 AND status = 'active'", params![request.client_id], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(internal)?;
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

pub(super) async fn register(
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
    let (identity_bytes, secret_hash, used): (Vec<u8>, String, i64) = transaction.query_row("SELECT identity_key, enrollment_secret_hash, enrollment_used FROM allowlist WHERE client_id = ?1 AND status = 'active'", params![request.client_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional().map_err(internal)?.ok_or_else(unauthorized)?;
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
    let claimed = transaction.execute("UPDATE allowlist SET enrollment_used = 1, device_address = ?2 WHERE client_id = ?1 AND enrollment_used = 0", params![request.client_id, request.device_address]).map_err(internal)?;
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
