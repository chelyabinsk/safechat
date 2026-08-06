//! Boundary around the upstream Signal implementation.
//!
//! Application code must depend on this module rather than importing
//! `libsignal-protocol` directly. This keeps upstream API churn localized and
//! gives us one place to enforce our storage, transport, and wire-format
//! policies.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use signal_protocol::{
    CiphertextMessage, CiphertextMessageType, DeviceId, GenericSignedPreKey, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyBundleContent, PreKeyId, PreKeyRecord,
    PreKeySignalMessage, PreKeyStore, ProtocolAddress, SessionStore, SignalMessage, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore, Timestamp, kem, message_decrypt, message_encrypt,
    process_prekey_bundle,
};
use signal_rand::{CryptoRng, Rng, TryRngCore};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const ENVELOPE_MAGIC: &[u8] = b"safechat-signal-envelope-v1\0";
const ENVELOPE_HEADER_LEN: usize = ENVELOPE_MAGIC.len() + 1 + 4;
const MAX_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024;
const BUNDLE_MAGIC: &[u8] = b"safechat-signal-bundle-v1\0";
const MAX_BUNDLE_FIELD_LEN: usize = 16 * 1024;
const PREKEY_LOW_WATERMARK: usize = 8;
const PREKEY_TARGET: usize = 32;
const SIGNED_PREKEY_ROTATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Exact upstream revision used by this workspace.
pub const LIBSIGNAL_REVISION: &str = "b5121d07c72f9e631f178d907ca892587f64f9e2";

/// Carrier-neutral serialized Signal ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalEnvelope {
    pub message_type: u8,
    pub ciphertext: Vec<u8>,
}

impl SignalEnvelope {
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
        output.extend(ENVELOPE_MAGIC);
        output.push(self.message_type);
        output.extend(length.to_be_bytes());
        output.extend(&self.ciphertext);
        Ok(output)
    }

    /// Parse and validate a carrier-independent frame.
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < ENVELOPE_HEADER_LEN || !input.starts_with(ENVELOPE_MAGIC) {
            bail!("invalid Signal envelope");
        }
        let message_type = input[ENVELOPE_MAGIC.len()];
        if message_type != CiphertextMessageType::Whisper as u8
            && message_type != CiphertextMessageType::PreKey as u8
        {
            bail!("unsupported Signal ciphertext type");
        }
        let length_start = ENVELOPE_MAGIC.len() + 1;
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
        let mut out = BUNDLE_MAGIC.to_vec();
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
        reader.expect(BUNDLE_MAGIC)?;
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
    fn expect(&mut self, prefix: &[u8]) -> Result<()> {
        if self.input.get(self.offset..self.offset + prefix.len()) != Some(prefix) {
            bail!("invalid Signal prekey bundle");
        }
        self.offset += prefix.len();
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
             INSERT INTO signal_meta(id, schema_version) VALUES (1, 1)
                 ON CONFLICT(id) DO UPDATE SET schema_version = excluded.schema_version;
             INSERT INTO signal_key_lifecycle(id, signed_prekey_created_at) VALUES (1, 0)
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
    pub async fn maintain_key_inventory(&mut self) -> Result<()> {
        let mut rng = signal_rand::rngs::OsRng.unwrap_err();
        let (changed, rotated_at) = self.ensure_key_inventory(&mut rng).await?;
        if !changed {
            return Ok(());
        }
        let local = self.local_address.clone();
        self.persist_peer(&local).await?;
        if let Some(created_at) = rotated_at {
            self.db.execute(
                "UPDATE signal_key_lifecycle SET signed_prekey_created_at = ?1 WHERE id = 1",
                params![created_at],
            )?;
        }
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

    pub async fn decrypt_from(
        &mut self,
        sender: &ProtocolAddress,
        encoded_envelope: &[u8],
    ) -> Result<Vec<u8>> {
        let local = self.local_address.clone();
        self.load_peer(sender).await?;
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
        for (id, record) in prekeys {
            tx.execute("INSERT INTO signal_prekeys(id, record) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record", params![id, record])?;
        }
        for (id, record) in signed_prekeys {
            tx.execute("INSERT INTO signal_signed_prekeys(id, record) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record", params![id, record])?;
        }
        for (id, record) in kyber_prekeys {
            tx.execute("INSERT INTO signal_kyber_prekeys(id, record) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET record = excluded.record", params![id, record])?;
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
}
