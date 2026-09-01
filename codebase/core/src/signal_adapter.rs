//! Boundary around the upstream Signal implementation.
//!
//! Application code must depend on this module rather than importing
//! `libsignal-protocol` directly. This keeps upstream API churn localized and
//! gives us one place to enforce our storage, transport, and wire-format
//! policies.

use anyhow::{Context, Result, bail};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use rusqlite::{Connection, OptionalExtension, params};
use signal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, InMemSignedPreKeyStore, KeyPair,
    KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle, PreKeyBundleContent, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SessionStore, SignalMessage, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt,
    process_prekey_bundle,
};
use signal_rand::{CryptoRng, Rng, TryRngCore};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(test)]
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

const FORMAT_VERSION: u8 = 1;
const FRAME_RECOVERY: u8 = 1;
const FRAME_BUNDLE: u8 = 2;
const FRAME_ENVELOPE: u8 = 3;
const FRAME_MESSAGE: u8 = 4;
const FRAME_MESSAGE_COMPRESSED: u8 = 5;
const ENVELOPE_HEADER_LEN: usize = 1 + 1 + 1 + 4;
const MAX_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;
const MIN_COMPRESSIBLE_MESSAGE_LEN: usize = 256;
const MAX_MESSAGE_LEN: usize = 8 * 1024 * 1024;
const MAX_BUNDLE_FIELD_LEN: usize = 16 * 1024;
const PREKEY_LOW_WATERMARK: usize = 8;
const PREKEY_TARGET: usize = 32;
const SIGNED_PREKEY_ROTATION_SECS: u64 = 30 * 24 * 60 * 60;
const SIGNED_PREKEY_OVERLAP: usize = 2;

#[cfg(test)]
static FAIL_BEFORE_PERSIST_COMMIT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static FAILPOINT_LOCK: Mutex<()> = Mutex::new(());

/// Exact upstream revision used by this workspace.
pub const LIBSIGNAL_REVISION: &str = "b5121d07c72f9e631f178d907ca892587f64f9e2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMaintenanceReport {
    pub one_time_prekeys: usize,
    pub signed_prekeys: usize,
    pub replenished: bool,
    pub rotated: bool,
    pub consecutive_failures: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMaintenanceStatus {
    pub consecutive_failures: u32,
    pub total_failures: u64,
    pub last_error: Option<String>,
    pub last_failed_at: Option<u64>,
}

/// A signed, auditable statement that an identity was replaced.
/// The old identity signs the replacement bundle, so a recipient can accept
/// it without silently trusting an arbitrary new key.
#[derive(Clone)]
pub struct IdentityRecoveryRecord {
    pub old_identity: IdentityKey,
    pub new_bundle: SignalPreKeyBundle,
    pub effective_at: u64,
    pub confirmation: bool,
    pub signature: Vec<u8>,
}

impl IdentityRecoveryRecord {
    fn payload(&self) -> Result<Vec<u8>> {
        let bundle = self.new_bundle.encode()?;
        let mut payload = vec![FORMAT_VERSION, FRAME_RECOVERY];
        put_bytes(&mut payload, &self.old_identity.serialize())?;
        put_bytes(&mut payload, &bundle)?;
        payload.extend(self.effective_at.to_be_bytes());
        payload.push(u8::from(self.confirmation));
        Ok(payload)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = self.payload()?;
        put_bytes(&mut output, &self.signature)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = BundleReader { input, offset: 0 };
        reader.expect_frame(FRAME_RECOVERY)?;
        let old_identity = IdentityKey::decode(&reader.bytes()?)?;
        let new_bundle = SignalPreKeyBundle::decode(&reader.bytes()?)?;
        let effective_at = reader.u64()?;
        let confirmation = match reader.byte()? {
            0 => false,
            1 => true,
            _ => bail!("invalid recovery confirmation"),
        };
        let signature = reader.bytes()?;
        if reader.offset != input.len() {
            bail!("trailing bytes in recovery record");
        }
        Ok(Self {
            old_identity,
            new_bundle,
            effective_at,
            confirmation,
            signature,
        })
    }

    pub fn old_fingerprint(&self) -> String {
        identity_fingerprint(&self.old_identity)
    }

    pub fn new_fingerprint(&self) -> Result<String> {
        Ok(identity_fingerprint(&self.new_bundle.identity_key()?))
    }

    pub fn verify(&self) -> Result<bool> {
        Ok(self
            .old_identity
            .public_key()
            .verify_signature(&self.payload()?, &self.signature))
    }
}

/// Carrier-neutral serialized Signal ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalEnvelope {
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
}

/// Application-level message identity carried inside the authenticated Signal
/// plaintext. Signal protects the session; SafeChat uses this ID to avoid
/// writing one logical message to history more than once.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MessageId([u8; 16]);

impl MessageId {
    pub fn generate() -> Self {
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        Self(rng.random())
    }

    pub fn encode(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn bytes(self) -> [u8; 16] {
        self.0
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| {
            anyhow::anyhow!("invalid message ID length")
        })?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeChatMessage {
    pub id: MessageId,
    pub plaintext: Vec<u8>,
}

impl SafeChatMessage {
    pub fn new(plaintext: &[u8]) -> Self {
        Self {
            id: MessageId::generate(),
            plaintext: plaintext.to_vec(),
        }
    }

    /// Encodes the application message for transport.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.plaintext.len() > MAX_MESSAGE_LEN {
            bail!("message exceeds SafeChat limit");
        }
        let length = u32::try_from(self.plaintext.len()).context("message length overflow")?;

        let mut compressed = ZlibEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut compressed, &self.plaintext)?;
        let compressed = compressed.finish()?;
        if self.plaintext.len() >= MIN_COMPRESSIBLE_MESSAGE_LEN
            && compressed.len() < self.plaintext.len()
        {
            let stored_length =
                u32::try_from(compressed.len()).context("compressed message length overflow")?;
            let mut output = Vec::with_capacity(1 + 1 + 16 + 4 + 4 + compressed.len());
            output.push(FORMAT_VERSION);
            output.push(FRAME_MESSAGE_COMPRESSED);
            output.extend(self.id.bytes());
            output.extend(length.to_be_bytes());
            output.extend(stored_length.to_be_bytes());
            output.extend(compressed);
            return Ok(output);
        }

        let mut output = Vec::with_capacity(1 + 1 + 16 + 4 + 4 + self.plaintext.len());
        output.push(FORMAT_VERSION);
        output.push(FRAME_MESSAGE);
        output.extend(self.id.bytes());
        output.extend(length.to_be_bytes());
        output.extend(length.to_be_bytes());
        output.extend(&self.plaintext);
        Ok(output)
    }

    /// Decodes and validates an application message.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < 2 {
            bail!("truncated SafeChat message");
        }
        if input[0] != FORMAT_VERSION {
            bail!("unsupported SafeChat message version");
        }
        if input[1] == FRAME_MESSAGE_COMPRESSED {
            let header_len = 1 + 1 + 16 + 4 + 4;
            if input.len() < header_len {
                bail!("truncated compressed SafeChat message");
            }
            let id_start = 2;
            let id = MessageId::from_bytes(&input[id_start..id_start + 16])?;
            let original_start = id_start + 16;
            let original_length =
                u32::from_be_bytes(input[original_start..original_start + 4].try_into()?) as usize;
            let stored_start = original_start + 4;
            let stored_length =
                u32::from_be_bytes(input[stored_start..stored_start + 4].try_into()?) as usize;
            if original_length > MAX_MESSAGE_LEN
                || stored_length > MAX_MESSAGE_LEN
                || input.len() != header_len + stored_length
            {
                bail!("invalid compressed SafeChat message length");
            }
            let decoder = ZlibDecoder::new(&input[header_len..]);
            let mut plaintext = Vec::with_capacity(original_length);
            decoder
                .take((original_length + 1) as u64)
                .read_to_end(&mut plaintext)?;
            if plaintext.len() != original_length {
                bail!("decompressed SafeChat message length mismatch");
            }
            return Ok(Self { id, plaintext });
        }

        if input[1] != FRAME_MESSAGE {
            bail!("unsupported SafeChat message frame");
        }
        if input.len() < 26 {
            bail!("truncated SafeChat message");
        }
        let id = MessageId::from_bytes(&input[2..18])?;
        let original_length = u32::from_be_bytes(input[18..22].try_into()?) as usize;
        let stored_length = u32::from_be_bytes(input[22..26].try_into()?) as usize;
        if original_length > MAX_MESSAGE_LEN
            || stored_length > MAX_MESSAGE_LEN
            || stored_length != original_length
            || input.len() != 26 + stored_length
        {
            bail!("message exceeds SafeChat limit");
        }
        let plaintext = input[26..].to_vec();
        Ok(Self { id, plaintext })
    }
}

impl SignalEnvelope {
    /// Signal message type for an established session.
    pub const WHISPER_TYPE: u8 = CiphertextMessageType::Whisper as u8;
    /// Signal message type for an initial pre-key session message.
    pub const PREKEY_TYPE: u8 = CiphertextMessageType::PreKey as u8;

    /// Serialize a libsignal ciphertext with a SafeChat-owned, bounded frame.
    pub fn from_ciphertext(message: &CiphertextMessage) -> Result<Self> {
        let message_type = message.message_type() as u8;
        if !matches!(
            message.message_type(),
            CiphertextMessageType::Whisper | CiphertextMessageType::PreKey
        ) {
            bail!("unsupported Signal ciphertext type");
        }
        let ciphertext = message.serialize().to_vec();
        if ciphertext.len() > MAX_CIPHERTEXT_LEN {
            bail!("Signal ciphertext exceeds SafeChat limit");
        }
        Ok(Self {
            message_type,
            ciphertext,
        })
    }

    /// Serialize the frame for any carrier adapter.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.message_type != CiphertextMessageType::Whisper as u8
            && self.message_type != CiphertextMessageType::PreKey as u8
        {
            bail!("unsupported Signal ciphertext type");
        }
        if self.ciphertext.len() > MAX_CIPHERTEXT_LEN {
            bail!("Signal ciphertext exceeds SafeChat limit");
        }
        let length = u32::try_from(self.ciphertext.len()).context("ciphertext length overflow")?;
        let mut output = Vec::with_capacity(ENVELOPE_HEADER_LEN + self.ciphertext.len());
        output.push(FORMAT_VERSION);
        output.push(FRAME_ENVELOPE);
        output.push(self.message_type);
        output.extend(length.to_be_bytes());
        output.extend(&self.ciphertext);
        Ok(output)
    }

    /// Parse and validate a carrier-independent frame.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < ENVELOPE_HEADER_LEN
            || input[0] != FORMAT_VERSION
            || input[1] != FRAME_ENVELOPE
        {
            bail!("invalid Signal envelope");
        }
        let message_type = input[2];
        if message_type != CiphertextMessageType::Whisper as u8
            && message_type != CiphertextMessageType::PreKey as u8
        {
            bail!("unsupported Signal ciphertext type");
        }
        let length_start = 3;
        let length = u32::from_be_bytes(input[length_start..length_start + 4].try_into()?) as usize;
        if length > MAX_CIPHERTEXT_LEN || input.len() != ENVELOPE_HEADER_LEN + length {
            bail!("invalid Signal envelope length");
        }
        Ok(Self {
            message_type,
            ciphertext: input[ENVELOPE_HEADER_LEN..].to_vec(),
        })
    }

    /// Convert the framed bytes back into the official libsignal type.
    pub fn to_ciphertext(&self) -> Result<CiphertextMessage> {
        match self.message_type {
            x if x == CiphertextMessageType::Whisper as u8 => Ok(CiphertextMessage::SignalMessage(
                SignalMessage::try_from(self.ciphertext.as_slice())?,
            )),
            x if x == CiphertextMessageType::PreKey as u8 => {
                Ok(CiphertextMessage::PreKeySignalMessage(
                    PreKeySignalMessage::try_from(self.ciphertext.as_slice())?,
                ))
            }
            _ => bail!("unsupported Signal ciphertext type"),
        }
    }
}

/// A SafeChat-owned, versioned export of the public portion of a libsignal
/// prekey bundle. It is intended to be copied through a secondary channel.
#[derive(Clone)]
pub struct SignalPreKeyBundle {
    pub name: String,
    pub device_id: DeviceId,
    pub bundle: PreKeyBundle,
}

impl SignalPreKeyBundle {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let content: PreKeyBundleContent = self.bundle.clone().into();
        let mut out = vec![FORMAT_VERSION, FRAME_BUNDLE];
        put_bytes(&mut out, self.name.as_bytes())?;
        out.extend(u32::from(self.device_id).to_be_bytes());
        out.extend(content.registration_id.unwrap().to_be_bytes());
        match (content.pre_key_id, content.pre_key_public) {
            (Some(id), Some(key)) => {
                out.push(1);
                out.extend(u32::from(id).to_be_bytes());
                put_bytes(&mut out, &key.serialize())?;
            }
            _ => out.push(0),
        }
        out.extend(u32::from(content.signed_pre_key_id.unwrap()).to_be_bytes());
        put_bytes(
            &mut out,
            &content.signed_pre_key_public.unwrap().serialize(),
        )?;
        put_bytes(&mut out, &content.signed_pre_key_signature.unwrap())?;
        out.extend(u32::from(content.kyber_pre_key_id.unwrap()).to_be_bytes());
        put_bytes(&mut out, &content.kyber_pre_key_public.unwrap().serialize())?;
        put_bytes(&mut out, &content.kyber_pre_key_signature.unwrap())?;
        put_bytes(&mut out, &content.identity_key.unwrap().serialize())?;
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut reader = BundleReader { input, offset: 0 };
        reader.expect_frame(FRAME_BUNDLE)?;
        let name = String::from_utf8(reader.bytes()?).context("bundle name is not UTF-8")?;
        let device_id = DeviceId::try_from(reader.u32()?)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let registration_id = reader.u32()?;
        let pre_key = if reader.byte()? == 1 {
            let id: PreKeyId = reader.u32()?.into();
            let key = signal_protocol::PublicKey::deserialize(&reader.bytes()?)?;
            Some((id, key))
        } else {
            None
        };
        let signed_pre_key_id: SignedPreKeyId = reader.u32()?.into();
        let signed_pre_key_public = signal_protocol::PublicKey::deserialize(&reader.bytes()?)?;
        let signed_pre_key_signature = reader.bytes()?;
        let kyber_pre_key_id = signal_protocol::KyberPreKeyId::from(reader.u32()?);
        let kyber_pre_key_public = kem::PublicKey::deserialize(&reader.bytes()?)?;
        let kyber_pre_key_signature = reader.bytes()?;
        let identity_key = IdentityKey::try_from(reader.bytes()?.as_slice())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if reader.offset != input.len() {
            bail!("trailing bytes in Signal prekey bundle");
        }
        let bundle = PreKeyBundle::try_from(PreKeyBundleContent {
            registration_id: Some(registration_id),
            device_id: Some(device_id),
            pre_key_id: pre_key.map(|(id, _)| id),
            pre_key_public: pre_key.map(|(_, key)| key),
            signed_pre_key_id: Some(signed_pre_key_id),
            signed_pre_key_public: Some(signed_pre_key_public),
            signed_pre_key_signature: Some(signed_pre_key_signature),
            identity_key: Some(identity_key),
            kyber_pre_key_id: Some(kyber_pre_key_id),
            kyber_pre_key_public: Some(kyber_pre_key_public),
            kyber_pre_key_signature: Some(kyber_pre_key_signature),
        })?;
        Ok(Self {
            name,
            device_id,
            bundle,
        })
    }

    pub fn address(&self) -> ProtocolAddress {
        ProtocolAddress::new(self.name.clone(), self.device_id)
    }

    pub fn identity_key(&self) -> Result<IdentityKey> {
        Ok(*self.bundle.identity_key()?)
    }
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BUNDLE_FIELD_LEN {
        bail!("Signal bundle field is too large");
    }
    output.extend(
        u32::try_from(bytes.len())
            .context("bundle field length overflow")?
            .to_be_bytes(),
    );
    output.extend(bytes);
    Ok(())
}

struct BundleReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> BundleReader<'a> {
    fn expect_frame(&mut self, frame: u8) -> Result<()> {
        if self.byte()? != FORMAT_VERSION || self.byte()? != frame {
            bail!("invalid SafeChat frame");
        }
        Ok(())
    }
    fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .input
            .get(self.offset)
            .context("truncated Signal bundle")?;
        self.offset += 1;
        Ok(byte)
    }
    fn u32(&mut self) -> Result<u32> {
        let end = self
            .offset
            .checked_add(4)
            .context("bundle offset overflow")?;
        let bytes = self
            .input
            .get(self.offset..end)
            .context("truncated Signal bundle")?;
        self.offset = end;
        Ok(u32::from_be_bytes(bytes.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        let end = self
            .offset
            .checked_add(8)
            .context("bundle offset overflow")?;
        let bytes = self
            .input
            .get(self.offset..end)
            .context("truncated Signal bundle")?;
        self.offset = end;
        Ok(u64::from_be_bytes(bytes.try_into()?))
    }
    fn bytes(&mut self) -> Result<Vec<u8>> {
        let length = self.u32()? as usize;
        if length > MAX_BUNDLE_FIELD_LEN {
            bail!("Signal bundle field is too large");
        }
        let end = self
            .offset
            .checked_add(length)
            .context("bundle length overflow")?;
        let bytes = self
            .input
            .get(self.offset..end)
            .context("truncated Signal bundle")?
            .to_vec();
        self.offset = end;
        Ok(bytes)
    }
}

/// Marker proving that the official protocol crate is linked into the build.
/// The actual session operations will be added behind this boundary as the
/// SQLite-backed Signal stores are migrated.
pub fn upstream_revision() -> &'static str {
    let _ = std::any::type_name::<signal_protocol::SignalProtocolError>();
    LIBSIGNAL_REVISION
}

/// SQLite-backed lifecycle state for one Signal device.
///
/// The protocol still receives libsignal's official store interfaces. SQLite
/// is the durable source of truth; the upstream in-memory stores are loaded at
/// open and snapshotted after each protocol operation. This deliberately keeps
/// database concerns outside the protocol adapter until a direct SQLite store
/// implementation is warranted.
pub struct SqliteSignalState {
    db: Connection,
    pub store: InMemSignalProtocolStore,
    path: PathBuf,
    local_address: ProtocolAddress,
}

impl SqliteSignalState {
    /// Open or create a device database, preserving its identity across restarts.
    pub async fn open(path: impl AsRef<Path>, password: &str) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        reject_plaintext_database(&path)?;
        let db = Connection::open(&path)
            .with_context(|| format!("opening Signal database {}", path.display()))?;
        db.pragma_update(None, "key", password)
            .context("unlocking encrypted Signal database")?;
        db.execute_batch("PRAGMA synchronous = FULL;")?;
        db.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS signal_meta (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 schema_version INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_device (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 name TEXT NOT NULL,
                 device_id INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_identity (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 identity_pair BLOB NOT NULL,
                 registration_id INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_sessions (
                 peer_address TEXT PRIMARY KEY,
                 record BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_trusted_identities (
                 peer_address TEXT PRIMARY KEY,
                 identity BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_prekeys (
                 id INTEGER PRIMARY KEY,
                 record BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_signed_prekeys (
                 id INTEGER PRIMARY KEY,
                 record BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_kyber_prekeys (
                 id INTEGER PRIMARY KEY,
                 record BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_key_lifecycle (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 signed_prekey_created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_maintenance_failures (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 consecutive_failures INTEGER NOT NULL DEFAULT 0,
                 total_failures INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT,
                 last_failed_at INTEGER
             );
             CREATE TABLE IF NOT EXISTS signal_recovery_records (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 old_fingerprint TEXT NOT NULL,
                 new_fingerprint TEXT NOT NULL,
                 effective_at INTEGER NOT NULL,
                 record BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS signal_revocations (
                 peer_address TEXT PRIMARY KEY,
                 old_fingerprint TEXT NOT NULL,
                 new_fingerprint TEXT,
                 effective_at INTEGER NOT NULL,
                 reason TEXT NOT NULL
             );
             INSERT INTO signal_meta(id, schema_version) VALUES (1, 1)
                 ON CONFLICT(id) DO UPDATE SET schema_version = excluded.schema_version;
             INSERT INTO signal_key_lifecycle(id, signed_prekey_created_at) VALUES (1, 0)
                 ON CONFLICT(id) DO NOTHING;
             INSERT INTO signal_maintenance_failures(id) VALUES (1)
                 ON CONFLICT(id) DO NOTHING;",
        )?;

        let identity = db
            .query_row(
                "SELECT identity_pair, registration_id FROM signal_identity WHERE id = 1",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    let registration_id: u32 = row.get(1)?;
                    Ok((bytes, registration_id))
                },
            )
            .optional()?;
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let (identity_pair, registration_id) = match identity {
            Some((bytes, registration_id)) => (
                IdentityKeyPair::try_from(bytes.as_slice())
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                registration_id,
            ),
            None => {
                let pair = IdentityKeyPair::generate(&mut rng);
                let registration_id = rng.random::<u32>() & 0x3fff;
                db.execute(
                    "INSERT INTO signal_identity(id, identity_pair, registration_id) VALUES (1, ?1, ?2)",
                    params![pair.serialize().as_ref(), registration_id],
                )?;
                (pair, registration_id)
            }
        };
        let mut state = Self {
            db,
            store: InMemSignalProtocolStore::new(identity_pair, registration_id)?,
            path,
            local_address: ProtocolAddress::new("unconfigured".to_owned(), DeviceId::new(1)?),
        };
        if let Some((name, device_id)) = state
            .db
            .query_row(
                "SELECT name, device_id FROM signal_device WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?
        {
            state.local_address = ProtocolAddress::new(
                name,
                DeviceId::try_from(device_id)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
        }
        state.load_records().await?;
        Ok(state)
    }

    /// Create or validate the local user identity and device address.
    pub async fn initialize(
        path: impl AsRef<Path>,
        name: &str,
        device_id: u8,
        password: &str,
    ) -> Result<Self> {
        let mut state = Self::open(path, password).await?;
        let device =
            DeviceId::new(device_id).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let existing = state
            .db
            .query_row(
                "SELECT name, device_id FROM signal_device WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?;
        if let Some((existing_name, existing_device)) = existing {
            if existing_name != name || existing_device != u32::from(device) {
                bail!("database is already initialized for another Signal address");
            }
        } else {
            state.db.execute(
                "INSERT INTO signal_device(id, name, device_id) VALUES (1, ?1, ?2)",
                params![name, u32::from(device)],
            )?;
        }
        state.local_address = ProtocolAddress::new(name.to_owned(), device);
        Ok(state)
    }

    /// The durable path, useful for diagnostics and backup tooling.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn local_address(&self) -> &ProtocolAddress {
        &self.local_address
    }

    pub async fn local_identity_fingerprint(&self) -> Result<String> {
        let pair = self.store.identity_store.get_identity_key_pair().await?;
        Ok(identity_fingerprint(pair.identity_key()))
    }

    /// Return the local identity key pair to a client-side transport signer.
    /// The caller must keep it in memory only and never send the private key
    /// to a relay or carrier.
    pub async fn local_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(self.store.identity_store.get_identity_key_pair().await?)
    }

    /// Record a peer identity only after its fingerprint was verified.
    pub async fn trust_peer(
        &mut self,
        peer: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<()> {
        if let Some(existing) = self.store.identity_store.get_identity(peer).await?
            && existing != *identity
        {
            bail!("peer identity changed; explicit rotation/recovery is required");
        }
        self.store
            .identity_store
            .save_identity(peer, identity)
            .await?;
        self.db.execute(
            "DELETE FROM signal_revocations WHERE peer_address = ?1",
            params![peer.to_string()],
        )?;
        self.persist_peer(peer).await
    }

    pub async fn trusted_identity(&self, peer: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        Ok(self.store.identity_store.get_identity(peer).await?)
    }

    pub async fn export_bundle(&mut self) -> Result<SignalPreKeyBundle> {
        self.maintain_key_inventory().await?;
        Ok(SignalPreKeyBundle {
            name: self.local_address.name().to_owned(),
            device_id: self.local_address.device_id(),
            bundle: bundle_from_store(&self.store, self.local_address.device_id()).await?,
        })
    }

    /// Maintain local prekeys without requiring the caller to manage bundles.
    /// This is safe to call before sending and after receiving messages.
    pub async fn maintain_key_inventory(&mut self) -> Result<KeyMaintenanceReport> {
        match self.maintain_key_inventory_inner().await {
            Ok(mut report) => {
                self.db.execute(
                    "UPDATE signal_maintenance_failures SET consecutive_failures = 0 WHERE id = 1",
                    [],
                )?;
                report.consecutive_failures = 0;
                Ok(report)
            }
            Err(error) => {
                self.record_maintenance_failure(&format!("{error:#}"))?;
                Err(error)
            }
        }
    }

    async fn maintain_key_inventory_inner(&mut self) -> Result<KeyMaintenanceReport> {
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let before_prekeys = self.store.all_pre_key_ids().count();
        let before_signed = self.store.all_signed_pre_key_ids().count();
        let (changed, rotated_at) = self
            .ensure_key_inventory(&mut rng)
            .await
            .context("maintaining Signal key inventory")?;
        let mut changed = changed;
        if self.store.all_signed_pre_key_ids().count() > SIGNED_PREKEY_OVERLAP {
            self.retain_signed_prekey_overlap().await?;
            changed = true;
        }
        if changed {
            let local = self.local_address.clone();
            self.persist_peer(&local)
                .await
                .context("persisting Signal key lifecycle state")?;
            if let Some(created_at) = rotated_at {
                self.db.execute(
                    "UPDATE signal_key_lifecycle SET signed_prekey_created_at = ?1 WHERE id = 1",
                    params![created_at],
                )?;
            }
        }
        Ok(KeyMaintenanceReport {
            one_time_prekeys: self.store.all_pre_key_ids().count(),
            signed_prekeys: self.store.all_signed_pre_key_ids().count(),
            replenished: self.store.all_pre_key_ids().count() > before_prekeys,
            rotated: rotated_at.is_some()
                || self.store.all_signed_pre_key_ids().count() > before_signed,
            consecutive_failures: 0,
        })
    }

    fn record_maintenance_failure(&mut self, error: &str) -> Result<()> {
        self.db.execute(
            "UPDATE signal_maintenance_failures
             SET consecutive_failures = consecutive_failures + 1,
                 total_failures = total_failures + 1,
                 last_error = ?1, last_failed_at = ?2 WHERE id = 1",
            params![error, unix_seconds()?],
        )?;
        Ok(())
    }

    pub fn key_maintenance_status(&self) -> Result<KeyMaintenanceStatus> {
        self.db
            .query_row(
                "SELECT consecutive_failures, total_failures, last_error, last_failed_at
             FROM signal_maintenance_failures WHERE id = 1",
                [],
                |row| {
                    Ok(KeyMaintenanceStatus {
                        consecutive_failures: row.get::<_, u32>(0)?,
                        total_failures: row.get::<_, u64>(1)?,
                        last_error: row.get(2)?,
                        last_failed_at: row
                            .get::<_, Option<i64>>(3)?
                            .map(|value| value.max(0) as u64),
                    })
                },
            )
            .map_err(Into::into)
    }

    /// Replace the local identity after compromise or device recovery.
    /// Existing sessions and trusted peer records are intentionally revoked.
    /// Callers must distribute the returned bundle and re-verify its new
    /// fingerprint through an independent trusted channel.
    pub async fn replace_identity(&mut self) -> Result<SignalPreKeyBundle> {
        Ok(self.replace_identity_with_recovery().await?.0)
    }

    pub async fn replace_identity_with_recovery(
        &mut self,
    ) -> Result<(SignalPreKeyBundle, IdentityRecoveryRecord)> {
        let old_identity_pair = self.store.identity_store.get_identity_key_pair().await?;
        let old_identity = *old_identity_pair.identity_key();
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let identity_pair = IdentityKeyPair::generate(&mut rng);
        let registration_id = rng.random::<u32>() & 0x3fff;
        let replacement_store = InMemSignalProtocolStore::new(identity_pair, registration_id)?;

        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE signal_identity SET identity_pair = ?1, registration_id = ?2 WHERE id = 1",
            params![identity_pair.serialize().as_ref(), registration_id],
        )?;
        tx.execute("DELETE FROM signal_sessions", [])?;
        tx.execute("DELETE FROM signal_trusted_identities", [])?;
        tx.execute("DELETE FROM signal_prekeys", [])?;
        tx.execute("DELETE FROM signal_signed_prekeys", [])?;
        tx.execute("DELETE FROM signal_kyber_prekeys", [])?;
        tx.execute(
            "UPDATE signal_key_lifecycle SET signed_prekey_created_at = 0 WHERE id = 1",
            [],
        )?;
        tx.commit()?;

        self.store = replacement_store;
        let bundle = self.export_bundle().await?;
        let unsigned = IdentityRecoveryRecord {
            old_identity,
            new_bundle: bundle.clone(),
            effective_at: unix_seconds()?,
            confirmation: true,
            signature: Vec::new(),
        };
        let signature = old_identity_pair
            .private_key()
            .calculate_signature(&unsigned.payload()?, &mut rng)?
            .to_vec();
        let record = IdentityRecoveryRecord {
            signature,
            ..unsigned
        };
        self.db.execute(
            "INSERT INTO signal_recovery_records(old_fingerprint, new_fingerprint, effective_at, record)
             VALUES (?1, ?2, ?3, ?4)",
            params![record.old_fingerprint(), record.new_fingerprint()?, record.effective_at, record.encode()?],
        )?;
        Ok((bundle, record))
    }

    pub async fn accept_recovery(
        &mut self,
        record: &IdentityRecoveryRecord,
        confirmed: bool,
    ) -> Result<SignalPreKeyBundle> {
        if !confirmed || !record.confirmation {
            bail!("recovery requires explicit new-fingerprint confirmation");
        }
        if !record.verify()? {
            bail!("recovery record signature is invalid");
        }
        let peer = record.new_bundle.address();
        if self.trusted_identity(&peer).await? != Some(record.old_identity) {
            bail!("recovery record is not signed by the currently trusted peer identity");
        }
        let new_identity = record.new_bundle.identity_key()?;
        self.store
            .identity_store
            .save_identity(&peer, &new_identity)
            .await?;
        self.db.execute(
            "DELETE FROM signal_sessions WHERE peer_address = ?1",
            params![peer.to_string()],
        )?;
        self.db.execute(
            "INSERT INTO signal_revocations(peer_address, old_fingerprint, new_fingerprint, effective_at, reason)
             VALUES (?1, ?2, ?3, ?4, 'identity replacement')
             ON CONFLICT(peer_address) DO UPDATE SET old_fingerprint=excluded.old_fingerprint,
             new_fingerprint=excluded.new_fingerprint, effective_at=excluded.effective_at,
             reason=excluded.reason",
            params![peer.to_string(), record.old_fingerprint(), record.new_fingerprint()?, record.effective_at],
        )?;
        self.db.execute(
            "INSERT INTO signal_recovery_records(old_fingerprint, new_fingerprint, effective_at, record)
             VALUES (?1, ?2, ?3, ?4)",
            params![record.old_fingerprint(), record.new_fingerprint()?, record.effective_at, record.encode()?],
        )?;
        self.persist_peer(&peer).await?;
        self.reset_runtime_store().await?;
        Ok(record.new_bundle.clone())
    }

    pub async fn revoke_device(&mut self, peer: &ProtocolAddress) -> Result<()> {
        let old_fingerprint = self
            .trusted_identity(peer)
            .await?
            .map(|identity| identity_fingerprint(&identity))
            .unwrap_or_else(|| "unknown".to_owned());
        self.db.execute(
            "DELETE FROM signal_sessions WHERE peer_address = ?1",
            params![peer.to_string()],
        )?;
        self.db.execute(
            "DELETE FROM signal_trusted_identities WHERE peer_address = ?1",
            params![peer.to_string()],
        )?;
        self.db.execute(
            "INSERT INTO signal_revocations(peer_address, old_fingerprint, new_fingerprint, effective_at, reason)
             VALUES (?1, ?2, NULL, ?3, 'explicit device revocation')
             ON CONFLICT(peer_address) DO UPDATE SET old_fingerprint=excluded.old_fingerprint,
             new_fingerprint=NULL, effective_at=excluded.effective_at, reason=excluded.reason",
            params![peer.to_string(), old_fingerprint, unix_seconds()?],
        )?;
        self.reset_runtime_store().await
    }

    async fn reset_runtime_store(&mut self) -> Result<()> {
        let identity = self.store.identity_store.get_identity_key_pair().await?;
        let registration_id = self
            .store
            .identity_store
            .get_local_registration_id()
            .await?;
        self.store = InMemSignalProtocolStore::new(identity, registration_id)?;
        self.load_records().await
    }

    async fn retain_signed_prekey_overlap(&mut self) -> Result<()> {
        let mut ids = self
            .store
            .all_signed_pre_key_ids()
            .copied()
            .collect::<Vec<_>>();
        ids.sort_by_key(|id| u32::from(*id));
        if ids.len() <= SIGNED_PREKEY_OVERLAP {
            return Ok(());
        }
        let retained = ids
            .into_iter()
            .rev()
            .take(SIGNED_PREKEY_OVERLAP)
            .collect::<Vec<_>>();
        let mut store = InMemSignedPreKeyStore::new();
        for id in retained {
            let record = self
                .store
                .signed_pre_key_store
                .get_signed_pre_key(id)
                .await?;
            store.save_signed_pre_key(id, &record).await?;
        }
        self.store.signed_pre_key_store = store;
        Ok(())
    }

    async fn ensure_key_inventory<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(bool, Option<u64>)> {
        let mut changed = false;
        if self.store.all_signed_pre_key_ids().next().is_none()
            || self.store.all_kyber_pre_key_ids().next().is_none()
        {
            create_prekey_bundle(&mut self.store, rng).await?;
            changed = true;
        }

        let prekey_count = self.store.all_pre_key_ids().count();
        if prekey_count < PREKEY_LOW_WATERMARK {
            let mut next_id = self
                .store
                .all_pre_key_ids()
                .map(|id| u32::from(*id))
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            while self.store.all_pre_key_ids().count() < PREKEY_TARGET {
                let id: PreKeyId = next_id.into();
                let pair = KeyPair::generate(rng);
                self.store
                    .pre_key_store
                    .save_pre_key(id, &PreKeyRecord::new(id, &pair))
                    .await?;
                changed = true;
                next_id = next_id.saturating_add(1);
            }
        }

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .as_secs();
        let created_at: u64 = self
            .db
            .query_row(
                "SELECT signed_prekey_created_at FROM signal_key_lifecycle WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|value| value.max(0) as u64)?;
        if now.saturating_sub(created_at) < SIGNED_PREKEY_ROTATION_SECS {
            return Ok((changed, None));
        }

        let next_id: SignedPreKeyId = self
            .store
            .all_signed_pre_key_ids()
            .map(|id| u32::from(*id))
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .into();
        let pair = KeyPair::generate(rng);
        let identity = self.store.identity_store.get_identity_key_pair().await?;
        let signature = identity
            .private_key()
            .calculate_signature(&pair.public_key.serialize(), rng)?;
        self.store
            .signed_pre_key_store
            .save_signed_pre_key(
                next_id,
                &SignedPreKeyRecord::new(
                    next_id,
                    Timestamp::from_epoch_millis(now.saturating_mul(1000)),
                    &pair,
                    &signature,
                ),
            )
            .await?;
        Ok((true, Some(now)))
    }

    pub async fn trust_bundle(&mut self, bundle: &SignalPreKeyBundle) -> Result<()> {
        let peer = bundle.address();
        let identity = bundle.identity_key()?;
        self.trust_peer(&peer, &identity).await
    }

    pub async fn encrypt_for(
        &mut self,
        bundle: &SignalPreKeyBundle,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let peer = bundle.address();
        let local = self.local_address.clone();
        if local.name() == "unconfigured" {
            bail!("database must be initialized before encryption");
        }
        self.maintain_key_inventory().await?;
        self.load_peer(&peer).await?;
        if self.is_revoked(&peer).await? {
            bail!("peer device is revoked; verify a replacement bundle first");
        }
        let expected = bundle.identity_key()?;
        if self.trusted_identity(&peer).await? != Some(expected) {
            bail!("peer identity is not trusted; verify and run signal trust first");
        }
        if self
            .store
            .session_store
            .load_session(&peer)
            .await?
            .is_none()
        {
            let mut rng = signal_rand::rngs::OsRng.unwrap_err();
            process_prekey_bundle(
                &peer,
                &local,
                &mut self.store.session_store,
                &mut self.store.identity_store,
                &bundle.bundle,
                SystemTime::now(),
                &mut rng,
            )
            .await?;
        }
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let ciphertext = message_encrypt(
            plaintext,
            &peer,
            &local,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        let envelope = SignalEnvelope::from_ciphertext(&ciphertext)?.encode()?;
        self.persist_peer(&peer).await?;
        Ok(envelope)
    }

    pub async fn encrypt_message_for(
        &mut self,
        bundle: &SignalPreKeyBundle,
        plaintext: &[u8],
    ) -> Result<(MessageId, Vec<u8>)> {
        let message = SafeChatMessage::new(plaintext);
        let id = message.id;
        Ok((id, self.encrypt_for(bundle, &message.encode()?).await?))
    }

    pub async fn decrypt_from(
        &mut self,
        sender: &ProtocolAddress,
        encoded_envelope: &[u8],
    ) -> Result<Vec<u8>> {
        let local = self.local_address.clone();
        self.load_peer(sender).await?;
        if self.is_revoked(sender).await? {
            bail!(
                "sender device is revoked; accept a signed recovery or verify a new bundle first"
            );
        }
        let trusted = self.trusted_identity(sender).await?;
        if trusted.is_none() {
            bail!("sender identity is not trusted; verify it before decrypting");
        }
        let envelope = SignalEnvelope::decode(encoded_envelope)?.to_ciphertext()?;
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let plaintext = message_decrypt(
            &envelope,
            sender,
            &local,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &self.store.signed_pre_key_store,
            &mut self.store.kyber_pre_key_store,
            &mut rng,
        )
        .await?;
        self.maintain_key_inventory().await?;
        self.persist_peer(sender).await?;
        Ok(plaintext)
    }

    pub async fn decrypt_message_from(
        &mut self,
        sender: &ProtocolAddress,
        encoded_envelope: &[u8],
    ) -> Result<SafeChatMessage> {
        SafeChatMessage::decode(&self.decrypt_from(sender, encoded_envelope).await?)
    }

    async fn is_revoked(&self, peer: &ProtocolAddress) -> Result<bool> {
        let revoked = self
            .db
            .query_row(
                "SELECT new_fingerprint FROM signal_revocations WHERE peer_address = ?1",
                params![peer.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        match revoked {
            None => Ok(false),
            Some(None) => Ok(true),
            Some(Some(expected)) => Ok(self
                .store
                .identity_store
                .get_identity(peer)
                .await?
                .map(|identity| identity_fingerprint(&identity) != expected)
                .unwrap_or(true)),
        }
    }

    async fn load_records(&mut self) -> Result<()> {
        let mut statement = self.db.prepare("SELECT id, record FROM signal_prekeys")?;
        let prekeys = statement
            .query_map([], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, bytes) in prekeys {
            let id: PreKeyId = id.into();
            self.store
                .pre_key_store
                .save_pre_key(id, &PreKeyRecord::deserialize(&bytes)?)
                .await?;
        }

        let mut statement = self
            .db
            .prepare("SELECT id, record FROM signal_signed_prekeys")?;
        let signed_prekeys = statement
            .query_map([], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, bytes) in signed_prekeys {
            let id: SignedPreKeyId = id.into();
            self.store
                .signed_pre_key_store
                .save_signed_pre_key(id, &SignedPreKeyRecord::deserialize(&bytes)?)
                .await?;
        }

        let mut statement = self
            .db
            .prepare("SELECT id, record FROM signal_kyber_prekeys")?;
        let kyber_prekeys = statement
            .query_map([], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, bytes) in kyber_prekeys {
            let id = signal_protocol::KyberPreKeyId::from(id);
            self.store
                .kyber_pre_key_store
                .save_kyber_pre_key(id, &KyberPreKeyRecord::deserialize(&bytes)?)
                .await?;
        }
        Ok(())
    }

    /// Load one peer's session and trusted identity into the active stores.
    pub async fn load_peer(&mut self, peer: &ProtocolAddress) -> Result<()> {
        let key = peer.to_string();
        if let Some(bytes) = self
            .db
            .query_row(
                "SELECT record FROM signal_sessions WHERE peer_address = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let record = signal_protocol::SessionRecord::deserialize(&bytes)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            self.store
                .session_store
                .store_session(peer, &record)
                .await?;
        }
        if let Some(bytes) = self
            .db
            .query_row(
                "SELECT identity FROM signal_trusted_identities WHERE peer_address = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            let identity = IdentityKey::try_from(bytes.as_slice())
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            self.store
                .identity_store
                .save_identity(peer, &identity)
                .await?;
        }
        Ok(())
    }

    /// Atomically snapshot device records and one peer session to SQLite.
    pub async fn persist_peer(&mut self, peer: &ProtocolAddress) -> Result<()> {
        let identity_pair = self.store.identity_store.get_identity_key_pair().await?;
        let registration_id = self
            .store
            .identity_store
            .get_local_registration_id()
            .await?;
        let session = self.store.session_store.load_session(peer).await?;
        let trusted_identity = self.store.identity_store.get_identity(peer).await?;

        let mut prekeys = Vec::new();
        for id in self.store.all_pre_key_ids().copied().collect::<Vec<_>>() {
            prekeys.push((
                u32::from(id),
                self.store
                    .pre_key_store
                    .get_pre_key(id)
                    .await?
                    .serialize()?,
            ));
        }
        let mut signed_prekeys = Vec::new();
        for id in self
            .store
            .all_signed_pre_key_ids()
            .copied()
            .collect::<Vec<_>>()
        {
            signed_prekeys.push((
                u32::from(id),
                self.store
                    .signed_pre_key_store
                    .get_signed_pre_key(id)
                    .await?
                    .serialize()?,
            ));
        }
        let mut kyber_prekeys = Vec::new();
        for id in self
            .store
            .all_kyber_pre_key_ids()
            .copied()
            .collect::<Vec<_>>()
        {
            kyber_prekeys.push((
                u32::from(id),
                self.store
                    .kyber_pre_key_store
                    .get_kyber_pre_key(id)
                    .await?
                    .serialize()?,
            ));
        }

        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE signal_identity SET identity_pair = ?1, registration_id = ?2 WHERE id = 1",
            params![identity_pair.serialize().as_ref(), registration_id],
        )?;
        let peer_key = peer.to_string();
        if let Some(record) = session {
            tx.execute(
                "INSERT INTO signal_sessions(peer_address, record) VALUES (?1, ?2)
                 ON CONFLICT(peer_address) DO UPDATE SET record = excluded.record",
                params![
                    peer_key,
                    record
                        .serialize()
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?
                ],
            )?;
        }
        if let Some(identity) = trusted_identity {
            tx.execute(
                "INSERT INTO signal_trusted_identities(peer_address, identity) VALUES (?1, ?2)
                 ON CONFLICT(peer_address) DO UPDATE SET identity = excluded.identity",
                params![peer_key, identity.serialize().to_vec()],
            )?;
        }
        // One-time prekeys removed by libsignal must not remain available after
        // a restart. The active in-memory store is the authoritative snapshot.
        tx.execute("DELETE FROM signal_prekeys", [])?;
        tx.execute("DELETE FROM signal_signed_prekeys", [])?;
        for (id, record) in prekeys {
            tx.execute("INSERT INTO signal_prekeys(id, record) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record", params![id, record])?;
        }
        for (id, record) in signed_prekeys {
            tx.execute("INSERT INTO signal_signed_prekeys(id, record) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record", params![id, record])?;
        }
        for (id, record) in kyber_prekeys {
            tx.execute("INSERT INTO signal_kyber_prekeys(id, record) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record", params![id, record])?;
        }
        #[cfg(test)]
        if FAIL_BEFORE_PERSIST_COMMIT.swap(false, Ordering::SeqCst) {
            bail!("injected persistence failure before commit");
        }
        tx.commit()?;
        Ok(())
    }
}

fn reject_plaintext_database(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("reading Signal database header {}", path.display()))?;
    let mut header = [0u8; 16];
    let bytes_read = file.read(&mut header)?;
    if bytes_read == header.len() && &header == b"SQLite format 3\0" {
        bail!(
            "Signal database {} is an unencrypted legacy SQLite database; migrate it before use",
            path.display()
        );
    }
    Ok(())
}

/// Run a real libsignal X3DH/Double-Ratchet exchange between two SQLite-backed
/// clients, including a restart between messages.
pub fn run_signal_demo() -> Result<Vec<u8>> {
    futures_executor::block_on(async {
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let device_id = DeviceId::new(1).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let alice_address = ProtocolAddress::new("safechat-alice".to_owned(), device_id);
        let bob_address = ProtocolAddress::new(
            "safechat-bob".to_owned(),
            DeviceId::new(1).map_err(|error| anyhow::anyhow!(error.to_string()))?,
        );
        let base =
            std::env::temp_dir().join(format!("safechat-signal-demo-{}", std::process::id()));
        let alice_path = base.with_extension("alice.db");
        let bob_path = base.with_extension("bob.db");
        let _ = std::fs::remove_file(&alice_path);
        let _ = std::fs::remove_file(&bob_path);
        let mut alice = SqliteSignalState::open(&alice_path, "demo-password").await?;
        let mut bob = SqliteSignalState::open(&bob_path, "demo-password").await?;
        let bundle = create_prekey_bundle(&mut bob.store, &mut rng).await?;
        bob.persist_peer(&alice_address).await?;
        alice.load_peer(&bob_address).await?;

        process_prekey_bundle(
            &bob_address,
            &alice_address,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
            &bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await?;

        alice.persist_peer(&bob_address).await?;
        let outgoing = message_encrypt(
            b"signal protocol smoke test",
            &bob_address,
            &alice_address,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        alice.persist_peer(&bob_address).await?;
        let envelope = SignalEnvelope::from_ciphertext(&outgoing)?;
        let incoming = envelope.to_ciphertext()?;
        bob.load_peer(&alice_address).await?;
        let plaintext = message_decrypt(
            &incoming,
            &alice_address,
            &bob_address,
            &mut bob.store.session_store,
            &mut bob.store.identity_store,
            &mut bob.store.pre_key_store,
            &bob.store.signed_pre_key_store,
            &mut bob.store.kyber_pre_key_store,
            &mut rng,
        )
        .await?;
        bob.persist_peer(&alice_address).await?;

        // Reopen both databases and prove the ratchet/session state survives.
        drop(alice);
        drop(bob);
        let mut alice = SqliteSignalState::open(&alice_path, "demo-password").await?;
        let mut bob = SqliteSignalState::open(&bob_path, "demo-password").await?;
        alice.load_peer(&bob_address).await?;
        bob.load_peer(&alice_address).await?;
        let outgoing = message_encrypt(
            b"signal protocol restart test",
            &bob_address,
            &alice_address,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
            SystemTime::now(),
            &mut rng,
        )
        .await?;
        alice.persist_peer(&bob_address).await?;
        let incoming = SignalEnvelope::from_ciphertext(&outgoing)?.to_ciphertext()?;
        let restarted_plaintext = message_decrypt(
            &incoming,
            &alice_address,
            &bob_address,
            &mut bob.store.session_store,
            &mut bob.store.identity_store,
            &mut bob.store.pre_key_store,
            &bob.store.signed_pre_key_store,
            &mut bob.store.kyber_pre_key_store,
            &mut rng,
        )
        .await?;
        bob.persist_peer(&alice_address).await?;
        if restarted_plaintext != b"signal protocol restart test" {
            bail!("restarted Signal session returned unexpected plaintext");
        }
        let _ = std::fs::remove_file(&alice_path);
        let _ = std::fs::remove_file(&bob_path);
        Ok(plaintext)
    })
    .map_err(|error: anyhow::Error| error)
}

async fn create_prekey_bundle<R: Rng + CryptoRng>(
    store: &mut InMemSignalProtocolStore,
    rng: &mut R,
) -> Result<PreKeyBundle> {
    let pre_key_pair = KeyPair::generate(rng);
    let signed_pre_key_pair = KeyPair::generate(rng);
    let identity = store.identity_store.get_identity_key_pair().await?;
    let kyber_pre_key_record =
        KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, 1.into(), identity.private_key())?;
    let signed_pre_key_id: SignedPreKeyId = 1.into();
    let pre_key_id: PreKeyId = 1.into();
    let kyber_pre_key_id = 1.into();
    let signed_signature = identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), rng)?;
    let kyber_public = kyber_pre_key_record.public_key()?;
    let kyber_signature = kyber_pre_key_record.signature()?;

    store
        .pre_key_store
        .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair))
        .await?;
    store
        .signed_pre_key_store
        .save_signed_pre_key(
            signed_pre_key_id,
            &SignedPreKeyRecord::new(
                signed_pre_key_id,
                Timestamp::from_epoch_millis(1),
                &signed_pre_key_pair,
                &signed_signature,
            ),
        )
        .await?;
    store
        .kyber_pre_key_store
        .save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key_record)
        .await?;

    Ok(PreKeyBundle::new(
        store.identity_store.get_local_registration_id().await?,
        DeviceId::new(1)?,
        Some((pre_key_id, pre_key_pair.public_key)),
        signed_pre_key_id,
        signed_pre_key_pair.public_key,
        signed_signature.to_vec(),
        kyber_pre_key_id,
        kyber_public,
        kyber_signature,
        *identity.identity_key(),
    )?)
}

async fn bundle_from_store(
    store: &InMemSignalProtocolStore,
    device_id: DeviceId,
) -> Result<PreKeyBundle> {
    let pre_key_id = *store
        .all_pre_key_ids()
        .next()
        .context("no one-time prekey available")?;
    let signed_pre_key_id = *store
        .all_signed_pre_key_ids()
        .max()
        .context("no signed prekey available")?;
    let kyber_pre_key_id = *store
        .all_kyber_pre_key_ids()
        .max()
        .context("no Kyber prekey available")?;
    let pre_key = store.pre_key_store.get_pre_key(pre_key_id).await?;
    let signed_pre_key = store
        .signed_pre_key_store
        .get_signed_pre_key(signed_pre_key_id)
        .await?;
    let kyber_pre_key = store
        .kyber_pre_key_store
        .get_kyber_pre_key(kyber_pre_key_id)
        .await?;
    let identity = store.identity_store.get_identity_key_pair().await?;
    Ok(PreKeyBundle::new(
        store.identity_store.get_local_registration_id().await?,
        device_id,
        Some((pre_key_id, pre_key.public_key()?)),
        signed_pre_key_id,
        signed_pre_key.public_key()?,
        signed_pre_key.signature()?,
        kyber_pre_key_id,
        kyber_pre_key.public_key()?,
        kyber_pre_key.signature()?,
        *identity.identity_key(),
    )?)
}

pub fn identity_fingerprint(identity: &IdentityKey) -> String {
    identity
        .serialize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_is_bounded_and_typed() {
        let envelope = SignalEnvelope {
            message_type: CiphertextMessageType::Whisper as u8,
            ciphertext: vec![1, 2, 3, 4],
        };
        let encoded = envelope.encode().unwrap();
        assert_eq!(SignalEnvelope::decode(&encoded).unwrap(), envelope);
    }

    #[test]
    fn envelope_rejects_trailing_bytes_and_unknown_types() {
        let envelope = SignalEnvelope {
            message_type: CiphertextMessageType::Whisper as u8,
            ciphertext: vec![1, 2, 3],
        };
        let mut encoded = envelope.encode().unwrap();
        encoded.push(0);
        assert!(SignalEnvelope::decode(&encoded).is_err());

        let invalid = SignalEnvelope {
            message_type: 99,
            ciphertext: vec![],
        };
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn message_id_round_trip_is_bound_to_authenticated_payload() {
        let message = SafeChatMessage::new(b"hello");
        let decoded = SafeChatMessage::decode(&message.encode().unwrap()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.plaintext, b"hello");
        assert_eq!(decoded.id.encode().len(), 32);
        assert!(SafeChatMessage::decode(&[FORMAT_VERSION, FRAME_MESSAGE]).is_err());
    }

    #[test]
    fn repetitive_messages_are_compressed_and_round_trip() {
        let message = SafeChatMessage::new(&vec![b'a'; 100_000]);
        let encoded = message.encode().unwrap();
        assert_eq!(encoded[0..2], [FORMAT_VERSION, FRAME_MESSAGE_COMPRESSED]);
        assert_eq!(SafeChatMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn small_repetitive_messages_are_not_compressed() {
        let message = SafeChatMessage::new(&vec![b'a'; MIN_COMPRESSIBLE_MESSAGE_LEN - 1]);
        let encoded = message.encode().unwrap();
        assert_eq!(encoded[0..2], [FORMAT_VERSION, FRAME_MESSAGE]);
        assert_eq!(SafeChatMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn incompressible_messages_keep_v1_compatibility() {
        let mut bytes = vec![0u8; 1024];
        let mut state = 0x9e3779b9u32;
        for byte in &mut bytes {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let message = SafeChatMessage::new(&bytes);
        let encoded = message.encode().unwrap();
        assert_eq!(encoded[0..2], [FORMAT_VERSION, FRAME_MESSAGE]);
        assert_eq!(SafeChatMessage::decode(&encoded).unwrap(), message);
    }

    #[test]
    fn sqlite_database_requires_password_and_is_not_plaintext() {
        let path = std::env::temp_dir().join(format!(
            "safechat-encrypted-db-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        futures_executor::block_on(async {
            let state = SqliteSignalState::open(&path, "correct password")
                .await
                .unwrap();
            drop(state);
            assert!(
                SqliteSignalState::open(&path, "wrong password")
                    .await
                    .is_err()
            );
        });
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes.starts_with(b"SQLite format 3\0"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn exporting_bundle_replenishes_one_time_prekeys() {
        let path = std::env::temp_dir().join(format!(
            "safechat-prekey-inventory-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        futures_executor::block_on(async {
            let mut state = SqliteSignalState::initialize(&path, "alice", 1, "correct password")
                .await
                .unwrap();
            state.export_bundle().await.unwrap();
            assert!(state.store.all_pre_key_ids().count() >= PREKEY_TARGET);
        });
        std::fs::remove_file(path).unwrap();
    }

    fn test_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "safechat-{prefix}-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    async fn paired_states(
        prefix: &str,
    ) -> (
        SqliteSignalState,
        SqliteSignalState,
        SignalPreKeyBundle,
        SignalPreKeyBundle,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let alice_path = test_path(&format!("{prefix}-alice"));
        let bob_path = test_path(&format!("{prefix}-bob"));
        let mut alice = SqliteSignalState::initialize(&alice_path, "alice", 1, "password")
            .await
            .unwrap();
        let mut bob = SqliteSignalState::initialize(&bob_path, "bob", 1, "password")
            .await
            .unwrap();
        let alice_bundle = alice.export_bundle().await.unwrap();
        let bob_bundle = bob.export_bundle().await.unwrap();
        alice.trust_bundle(&bob_bundle).await.unwrap();
        bob.trust_bundle(&alice_bundle).await.unwrap();
        (alice, bob, alice_bundle, bob_bundle, alice_path, bob_path)
    }

    fn cleanup_paths(paths: &[&std::path::Path]) {
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn duplicate_trust_is_idempotent_and_survives_sqlite_reopen() {
        futures_executor::block_on(async {
            let (mut alice, bob, _alice_bundle, bob_bundle, alice_path, bob_path) =
                paired_states("duplicate-trust").await;
            alice.trust_bundle(&bob_bundle).await.unwrap();
            drop(alice);
            drop(bob);

            let mut reopened = SqliteSignalState::open(&alice_path, "password")
                .await
                .unwrap();
            let recipient = reopened.encrypt_for(&bob_bundle, b"after reopen").await;
            assert!(
                recipient.is_ok(),
                "duplicate trust must not break the session"
            );
            drop(reopened);
            cleanup_paths(&[&alice_path, &bob_path]);
        });
    }

    #[test]
    fn ratchet_update_can_be_retried_after_persist_failure() {
        let _lock = FAILPOINT_LOCK.lock().unwrap();
        futures_executor::block_on(async {
            let (mut alice, mut bob, alice_bundle, bob_bundle, alice_path, bob_path) =
                paired_states("ratchet-recovery").await;
            let first = alice.encrypt_for(&bob_bundle, b"first").await.unwrap();
            assert_eq!(
                bob.decrypt_from(&alice_bundle.address(), &first)
                    .await
                    .unwrap(),
                b"first"
            );

            FAIL_BEFORE_PERSIST_COMMIT.store(true, Ordering::SeqCst);
            assert!(alice.encrypt_for(&bob_bundle, b"retry me").await.is_err());
            drop(alice);
            let mut alice = SqliteSignalState::open(&alice_path, "password")
                .await
                .unwrap();
            let retry = alice.encrypt_for(&bob_bundle, b"retry me").await.unwrap();
            assert_eq!(
                bob.decrypt_from(&alice_bundle.address(), &retry)
                    .await
                    .unwrap(),
                b"retry me"
            );
            drop(bob);
            cleanup_paths(&[&alice_path, &bob_path]);
        });
    }

    #[test]
    fn prekey_consumption_can_be_retried_after_persist_failure() {
        let _lock = FAILPOINT_LOCK.lock().unwrap();
        futures_executor::block_on(async {
            let (mut alice, mut bob, alice_bundle, bob_bundle, alice_path, bob_path) =
                paired_states("prekey-recovery").await;
            let first = alice
                .encrypt_for(&bob_bundle, b"prekey retry")
                .await
                .unwrap();
            FAIL_BEFORE_PERSIST_COMMIT.store(true, Ordering::SeqCst);
            assert!(
                bob.decrypt_from(&alice_bundle.address(), &first)
                    .await
                    .is_err()
            );
            drop(bob);
            let mut bob = SqliteSignalState::open(&bob_path, "password")
                .await
                .unwrap();
            assert_eq!(
                bob.decrypt_from(&alice_bundle.address(), &first)
                    .await
                    .unwrap(),
                b"prekey retry"
            );
            drop(alice);
            cleanup_paths(&[&alice_path, &bob_path]);
        });
    }

    #[test]
    fn signed_prekey_rotation_can_be_retried_after_persist_failure() {
        let _lock = FAILPOINT_LOCK.lock().unwrap();
        futures_executor::block_on(async {
            let path = test_path("rotation-recovery");
            let mut state = SqliteSignalState::initialize(&path, "alice", 1, "password")
                .await
                .unwrap();
            state.export_bundle().await.unwrap();
            let initial_count = state.store.all_signed_pre_key_ids().count();
            state
                .db
                .execute(
                    "UPDATE signal_key_lifecycle SET signed_prekey_created_at = 0 WHERE id = 1",
                    [],
                )
                .unwrap();
            FAIL_BEFORE_PERSIST_COMMIT.store(true, Ordering::SeqCst);
            assert!(state.export_bundle().await.is_err());
            drop(state);
            let mut reopened = SqliteSignalState::open(&path, "password").await.unwrap();
            assert_eq!(
                reopened.store.all_signed_pre_key_ids().count(),
                initial_count
            );
            reopened.export_bundle().await.unwrap();
            assert!(reopened.store.all_signed_pre_key_ids().count() <= SIGNED_PREKEY_OVERLAP);
            drop(reopened);
            cleanup_paths(&[&path]);
        });
    }

    #[test]
    fn identity_replacement_changes_fingerprint_and_rebuilds_keys() {
        futures_executor::block_on(async {
            let path = test_path("identity-replacement");
            let mut state = SqliteSignalState::initialize(&path, "alice", 1, "password")
                .await
                .unwrap();
            let old_fingerprint = state.local_identity_fingerprint().await.unwrap();
            let new_bundle = state.replace_identity().await.unwrap();
            let new_fingerprint = identity_fingerprint(&new_bundle.identity_key().unwrap());
            assert_ne!(old_fingerprint, new_fingerprint);
            assert_eq!(
                state.local_identity_fingerprint().await.unwrap(),
                new_fingerprint
            );
            assert!(state.store.all_pre_key_ids().count() >= PREKEY_TARGET);
            drop(state);
            cleanup_paths(&[&path]);
        });
    }

    #[test]
    fn signed_recovery_replaces_a_trusted_peer_and_revokes_old_identity() {
        futures_executor::block_on(async {
            let (alice, mut bob, alice_bundle, bob_bundle, alice_path, bob_path) =
                paired_states("signed-recovery").await;
            let old_fingerprint = identity_fingerprint(&alice_bundle.identity_key().unwrap());
            drop(alice);
            let mut replacement = SqliteSignalState::open(&alice_path, "password")
                .await
                .unwrap();
            let (new_bundle, record) = replacement.replace_identity_with_recovery().await.unwrap();
            assert_eq!(record.old_fingerprint(), old_fingerprint);
            assert!(record.verify().unwrap());
            assert_ne!(record.new_fingerprint().unwrap(), old_fingerprint);
            let accepted = bob.accept_recovery(&record, true).await.unwrap();
            assert_eq!(
                accepted.identity_key().unwrap(),
                new_bundle.identity_key().unwrap()
            );
            assert!(
                bob.decrypt_from(&alice_bundle.address(), &[])
                    .await
                    .is_err()
            );
            drop(replacement);
            drop(bob);
            cleanup_paths(&[&alice_path, &bob_path]);
            let _ = bob_bundle;
        });
    }

    #[test]
    fn explicit_device_revocation_is_persistent_and_reports_maintenance_failures() {
        futures_executor::block_on(async {
            let (mut alice, bob, alice_bundle, bob_bundle, alice_path, bob_path) =
                paired_states("device-revocation").await;
            alice.revoke_device(&bob_bundle.address()).await.unwrap();
            assert!(alice.encrypt_for(&bob_bundle, b"blocked").await.is_err());
            let reopened = SqliteSignalState::open(&alice_path, "password")
                .await
                .unwrap();
            assert!(
                reopened
                    .key_maintenance_status()
                    .unwrap()
                    .last_error
                    .is_none()
            );
            drop(reopened);
            drop(alice);
            drop(bob);
            cleanup_paths(&[&alice_path, &bob_path]);
            let _ = alice_bundle;
        });
    }

    #[test]
    fn maintenance_failures_are_counted_and_cleared_after_recovery() {
        let _lock = FAILPOINT_LOCK.lock().unwrap();
        futures_executor::block_on(async {
            let path = test_path("maintenance-failures");
            let mut state = SqliteSignalState::initialize(&path, "alice", 1, "password")
                .await
                .unwrap();
            state.export_bundle().await.unwrap();
            state
                .db
                .execute(
                    "UPDATE signal_key_lifecycle SET signed_prekey_created_at = 0 WHERE id = 1",
                    [],
                )
                .unwrap();
            FAIL_BEFORE_PERSIST_COMMIT.store(true, Ordering::SeqCst);
            assert!(state.export_bundle().await.is_err());
            let status = state.key_maintenance_status().unwrap();
            assert_eq!(status.consecutive_failures, 1);
            assert!(status.last_error.is_some());
            state.export_bundle().await.unwrap();
            assert_eq!(
                state.key_maintenance_status().unwrap().consecutive_failures,
                0
            );
            drop(state);
            cleanup_paths(&[&path]);
        });
    }
}
