//! Relay SQLite connection, schema, and enrollment administration.

use rusqlite::{Connection, OptionalExtension, params};
use signal_protocol::IdentityKey;
use std::path::Path;

use super::{
    MAX_FINGERPRINT_BYTES, MAX_ID_BYTES, MAX_IDENTITY_B64_BYTES, MAX_LABEL_BYTES, MAX_SECRET_BYTES,
    decode_bounded_base64, hash, now, validate_text,
};

pub(super) fn open(path: &Path) -> anyhow::Result<Connection> {
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    Ok(connection)
}

pub(super) fn initialize_schema(db: &Connection) -> anyhow::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS allowlist (client_id TEXT PRIMARY KEY, identity_key BLOB NOT NULL, fingerprint TEXT NOT NULL, enrollment_secret_hash TEXT NOT NULL, enrollment_used INTEGER NOT NULL DEFAULT 0, device_address TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, label TEXT NOT NULL, created_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS enrollment_requests (client_id TEXT PRIMARY KEY, device_address TEXT NOT NULL, identity_key BLOB NOT NULL, fingerprint TEXT NOT NULL, bundle BLOB NOT NULL, enrollment_secret_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS challenges (client_id TEXT PRIMARY KEY, challenge BLOB NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS devices (client_id TEXT PRIMARY KEY, identity_key BLOB NOT NULL, device_address TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, bundle BLOB NOT NULL, last_seen_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS request_nonces (client_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(client_id, nonce)); CREATE TABLE IF NOT EXISTS messages (server_id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT NOT NULL, client_message_id TEXT NOT NULL, ciphertext BLOB NOT NULL, accepted_at INTEGER NOT NULL, expires_at INTEGER, acknowledged_at INTEGER, UNIQUE(sender, recipient, client_message_id)); CREATE TABLE IF NOT EXISTS contact_requests (request_id TEXT PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL, sender_name TEXT NOT NULL, sender_fingerprint TEXT NOT NULL, bundle BLOB NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);")?;
    Ok(())
}

pub(super) fn approve_enrollment(db: &Connection, client_id: &str) -> anyhow::Result<()> {
    let request: (String, Vec<u8>, String, String, String) = db.query_row(
        "SELECT device_address, identity_key, fingerprint, enrollment_secret_hash, client_id FROM enrollment_requests WHERE client_id = ?1 AND expires_at >= ?2",
        params![client_id, now() as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?.ok_or_else(|| anyhow::anyhow!("no active enrollment request for {client_id}"))?;
    db.execute(
        "INSERT OR REPLACE INTO allowlist (client_id, identity_key, fingerprint, enrollment_secret_hash, enrollment_used, device_address, status, label, created_at) VALUES (?1, ?2, ?3, ?4, 0, ?5, 'active', ?5, ?6)",
        params![request.4, request.1, request.2, request.3, request.0, now() as i64],
    )?;
    db.execute(
        "DELETE FROM enrollment_requests WHERE client_id = ?1",
        params![client_id],
    )?;
    Ok(())
}

pub(super) fn choose_pending_enrollment(db: &Connection) -> String {
    let mut statement = db.prepare("SELECT client_id, device_address, fingerprint FROM enrollment_requests WHERE expires_at >= ?1 ORDER BY created_at").expect("preparing enrollment list");
    let rows = statement
        .query_map(params![now() as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .expect("listing enrollment requests")
        .collect::<Result<Vec<_>, _>>()
        .expect("reading enrollment requests");
    if rows.is_empty() {
        panic!("no active enrollment requests");
    }
    println!("Pending enrollment requests:");
    for (index, (client_id, address, fingerprint)) in rows.iter().enumerate() {
        println!("{}. {} ({})", index + 1, address, client_id);
        println!("   fingerprint: {fingerprint}");
    }
    println!("Approve request number:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("reading enrollment selection");
    let index = input.trim().parse::<usize>().expect("request number") - 1;
    rows.get(index)
        .map(|row| row.0.clone())
        .expect("request number out of range")
}

pub(super) fn add_allowlist(
    db: &Connection,
    client_id: &str,
    identity_key: &str,
    fingerprint: &str,
    enrollment_secret: &str,
    label: &str,
) -> anyhow::Result<()> {
    validate_text(client_id, MAX_ID_BYTES, "client ID")?;
    validate_text(fingerprint, MAX_FINGERPRINT_BYTES, "fingerprint")?;
    validate_text(enrollment_secret, MAX_SECRET_BYTES, "enrollment secret")?;
    validate_text(label, MAX_LABEL_BYTES, "label")?;
    let identity =
        decode_bounded_base64(identity_key, MAX_IDENTITY_B64_BYTES, 128, "identity key")?;
    IdentityKey::decode(&identity).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    db.execute("INSERT INTO allowlist(client_id, identity_key, fingerprint, enrollment_secret_hash, status, label, created_at) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)", params![client_id, identity, fingerprint, hash(enrollment_secret), label, now() as i64])?;
    Ok(())
}
