//! Encrypted profile-owned persistence.
//!
//! This module owns file formats and atomic encrypted writes for chat history
//! and transport session metadata. It deliberately does not know about the
//! UI, Signal sessions, or any particular transport implementation.

use age::secrecy::ExposeSecret;
use age::{Decryptor, Encryptor};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const PROFILE_VERSION: u32 = 1;

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryFile {
    pub version: u32,
    pub entries: Vec<HistoryEntry>,
    #[serde(default)]
    pub transport_cursor: i64,
}

impl HistoryFile {
    /// Creates an empty history using the current on-disk format version.
    pub fn empty() -> Self {
        Self {
            version: PROFILE_VERSION,
            entries: Vec::new(),
            transport_cursor: 0,
        }
    }

    /// Creates a history containing the supplied entries.
    pub fn new(entries: Vec<HistoryEntry>) -> Self {
        Self {
            entries,
            ..Self::empty()
        }
    }

    pub fn with_transport_cursor(mut self, cursor: i64) -> Self {
        self.transport_cursor = cursor;
        self
    }

    /// Returns a page ending immediately before `before`.
    ///
    /// `before == None` selects the newest page. This is a storage-neutral
    /// contract: backends that can seek encrypted records may override
    /// [`HistoryStore::load_page`] without changing application code.
    pub fn page(&self, before: Option<usize>, page_size: usize) -> HistoryPage {
        let page_size = page_size.max(1);
        let end = before.unwrap_or(self.entries.len()).min(self.entries.len());
        let start = end.saturating_sub(page_size);
        HistoryPage {
            entries: self.entries[start..end].to_vec(),
            cursor: start,
            has_more: start > 0,
            transport_cursor: self.transport_cursor,
        }
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub sender: String,
    pub text: String,
    #[serde(default)]
    pub message_id: String,
    #[serde(default)]
    pub peer: String,
    #[serde(default)]
    pub ciphertext: String,
    #[serde(default)]
    pub delivery_status: String,
    #[serde(default)]
    pub transport_recipient: String,
}

impl HistoryEntry {
    /// Creates a user-visible history entry with optional transport metadata
    /// left at its safe defaults.
    pub fn new(timestamp: u64, sender: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            timestamp,
            sender: sender.into(),
            text: text.into(),
            message_id: String::new(),
            peer: String::new(),
            ciphertext: String::new(),
            delivery_status: String::new(),
            transport_recipient: String::new(),
        }
    }

    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = message_id.into();
        self
    }

    pub fn with_peer(mut self, peer: impl Into<String>) -> Self {
        self.peer = peer.into();
        self
    }

    pub fn with_ciphertext(mut self, ciphertext: impl Into<String>) -> Self {
        self.ciphertext = ciphertext.into();
        self
    }

    pub fn with_delivery_status(mut self, status: impl Into<String>) -> Self {
        self.delivery_status = status.into();
        self
    }

    pub fn with_transport_recipient(mut self, recipient: impl Into<String>) -> Self {
        self.transport_recipient = recipient.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    pub entries: Vec<HistoryEntry>,
    pub cursor: usize,
    pub has_more: bool,
    pub transport_cursor: i64,
}

#[non_exhaustive]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    pub base_url: String,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub enrollment_secret: String,
}

impl RelayConfig {
    pub fn new(base_url: impl Into<String>, enrollment_secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            allow_insecure_http: false,
            enrollment_secret: enrollment_secret.into(),
        }
    }

    pub fn with_insecure_http(mut self, allowed: bool) -> Self {
        self.allow_insecure_http = allowed;
        self
    }
}

/// Persistence port consumed by the application chat service.
pub trait HistoryStore {
    fn load(&mut self, conversation: &str) -> Result<HistoryFile>;
    fn save(&mut self, conversation: &str, history: &HistoryFile) -> Result<()>;

    /// Loads one page of history. The default preserves compatibility with
    /// existing stores; seekable stores should override this method.
    fn load_page(
        &mut self,
        conversation: &str,
        before: Option<usize>,
        page_size: usize,
    ) -> Result<HistoryPage> {
        Ok(self.load(conversation)?.page(before, page_size))
    }
}

/// Encrypted age-backed history adapter for the desktop profile.
pub struct EncryptedHistoryStore {
    root: PathBuf,
    password: String,
    identity: age::x25519::Identity,
}

impl EncryptedHistoryStore {
    pub fn new(root: impl Into<PathBuf>, password: impl Into<String>) -> Result<Self> {
        let root = root.into();
        let password = password.into();
        fs::create_dir_all(&root)?;
        let identity = load_or_create_history_identity(&root, &password)?;
        Ok(Self {
            root,
            password,
            identity,
        })
    }

    fn path_for(&self, conversation: &str) -> PathBuf {
        let component = conversation
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        self.root.join(format!("{component}.age"))
    }
}

impl HistoryStore for EncryptedHistoryStore {
    fn load(&mut self, conversation: &str) -> Result<HistoryFile> {
        load_history(&self.path_for(conversation), &self.password)
    }

    fn save(&mut self, conversation: &str, history: &HistoryFile) -> Result<()> {
        save_history_with_identity(&self.path_for(conversation), &self.identity, history)
    }
}

pub fn load_history(path: &Path, password: &str) -> Result<HistoryFile> {
    if !path.exists() {
        return Ok(HistoryFile::empty());
    }
    let mut plaintext = decrypt_history_file(path, password)?;
    let history: HistoryFile = serde_json::from_slice(&plaintext)?;
    plaintext.fill(0);
    if history.version != PROFILE_VERSION {
        bail!("unsupported chat history version");
    }
    Ok(history)
}

pub fn save_history(path: &Path, password: &str, history: &HistoryFile) -> Result<()> {
    let parent = path
        .parent()
        .context("chat history has no parent directory")?;
    fs::create_dir_all(parent)?;
    save_encrypted(path, password, &serde_json::to_vec(history)?)
}

fn save_history_with_identity(
    path: &Path,
    identity: &age::x25519::Identity,
    history: &HistoryFile,
) -> Result<()> {
    let parent = path
        .parent()
        .context("chat history has no parent directory")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("age.tmp");
    remove_stale_temporary(&temporary)?;
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("creating temporary encrypted file {}", temporary.display()))?;
    let recipient = identity.to_public();
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
    let mut writer = encryptor.wrap_output(file)?;
    writer.write_all(&serde_json::to_vec(history)?)?;
    writer.finish()?;
    fs::rename(temporary, path)?;
    restrict_file(path)
}

pub fn load_relay_token(path: &Path, password: &str) -> Result<String> {
    let token = String::from_utf8(decrypt_file(path, password)?)?;
    if token.trim().is_empty() {
        bail!("saved relay session is empty");
    }
    Ok(token.trim().to_owned())
}

pub fn save_relay_token(path: &Path, password: &str, token: &str) -> Result<()> {
    save_encrypted(path, password, token.as_bytes())
}

pub fn load_relay_config(path: &Path, password: &str) -> Result<Option<RelayConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&decrypt_file(
        path, password,
    )?)?))
}

pub fn save_relay_config(path: &Path, password: &str, config: &RelayConfig) -> Result<()> {
    save_encrypted(path, password, &serde_json::to_vec(config)?)
}

pub fn load_relay_peer_ids(path: &Path, password: &str) -> Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    Ok(serde_json::from_slice(&decrypt_file(path, password)?)?)
}

pub fn save_relay_peer_ids(
    path: &Path,
    password: &str,
    peer_ids: &HashMap<String, String>,
) -> Result<()> {
    save_encrypted(path, password, &serde_json::to_vec(peer_ids)?)
}

fn decrypt_file(path: &Path, password: &str) -> Result<Vec<u8>> {
    let input = File::open(path)?;
    let decryptor = Decryptor::new(input)?;
    let secret = age::secrecy::SecretString::from(password.to_owned());
    let identity = age::scrypt::Identity::new(secret);
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

fn decrypt_file_with_identity(path: &Path, identity: &age::x25519::Identity) -> Result<Vec<u8>> {
    let input = File::open(path)?;
    let decryptor = Decryptor::new(input)?;
    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

fn history_key_path(root: &Path) -> PathBuf {
    root.join(".history-key.age")
}

fn load_or_create_history_identity(root: &Path, password: &str) -> Result<age::x25519::Identity> {
    let path = history_key_path(root);
    if path.exists() {
        let encoded = String::from_utf8(decrypt_file(&path, password)?)?;
        return encoded
            .trim()
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid encrypted history key: {error}"));
    }
    let identity = age::x25519::Identity::generate();
    let encoded = identity.to_string();
    save_encrypted(&path, password, encoded.expose_secret().as_bytes())?;
    Ok(identity)
}

fn decrypt_history_file(path: &Path, password: &str) -> Result<Vec<u8>> {
    match decrypt_file(path, password) {
        Ok(plaintext) => Ok(plaintext),
        Err(passphrase_error) => {
            let Some(root) = path.parent() else {
                return Err(passphrase_error);
            };
            let key_path = history_key_path(root);
            if !key_path.exists() {
                return Err(passphrase_error);
            }
            let identity = load_or_create_history_identity(root, password)?;
            decrypt_file_with_identity(path, &identity).with_context(|| {
                format!(
                    "decrypting history {} with the profile history key",
                    path.display()
                )
            })
        }
    }
}

fn save_encrypted(path: &Path, password: &str, plaintext: &[u8]) -> Result<()> {
    let temporary = path.with_extension("age.tmp");
    remove_stale_temporary(&temporary)?;
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("creating temporary encrypted file {}", temporary.display()))?;
    let secret = age::secrecy::SecretString::from(password.to_owned());
    let encryptor = Encryptor::with_user_passphrase(secret);
    let mut writer = encryptor.wrap_output(file)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    fs::rename(temporary, path)?;
    restrict_file(path)
}

fn remove_stale_temporary(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "safechat-profile-store-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before unix epoch")
                .as_nanos()
        ))
    }

    fn entry(message_id: &str, peer: &str, text: &str) -> HistoryEntry {
        HistoryEntry {
            timestamp: 42,
            sender: "alice".to_owned(),
            text: text.to_owned(),
            message_id: message_id.to_owned(),
            peer: peer.to_owned(),
            ciphertext: "ciphertext".to_owned(),
            delivery_status: "sent".to_owned(),
            transport_recipient: peer.to_owned(),
        }
    }

    #[test]
    fn encrypted_history_survives_reopen_and_keeps_conversations_isolated() {
        let root = test_root("reopen");
        let mut first =
            EncryptedHistoryStore::new(&root, "correct horse").expect("create history store");
        let mut alice_history = HistoryFile {
            version: PROFILE_VERSION,
            entries: vec![entry("m1", "alice", "hello")],
            transport_cursor: 17,
        };
        first
            .save("alice", &alice_history)
            .expect("save alice history");
        first
            .save(
                "bob",
                &HistoryFile {
                    version: PROFILE_VERSION,
                    entries: vec![entry("m2", "bob", "different conversation")],
                    transport_cursor: 3,
                },
            )
            .expect("save bob history");
        drop(first);

        let mut reopened =
            EncryptedHistoryStore::new(&root, "correct horse").expect("reopen history store");
        let loaded_alice = reopened.load("alice").expect("load alice history");
        assert_eq!(loaded_alice.transport_cursor, 17);
        assert_eq!(loaded_alice.entries[0].message_id, "m1");
        assert_eq!(
            reopened.load("bob").expect("load bob history").entries[0].message_id,
            "m2"
        );
        assert!(
            reopened
                .load("missing")
                .expect("load missing history")
                .entries
                .is_empty()
        );

        alice_history.transport_cursor = 18;
        alice_history.entries.push(entry("m3", "alice", "second"));
        reopened
            .save("alice", &alice_history)
            .expect("update alice history");
        let updated = reopened.load("alice").expect("reload updated history");
        assert_eq!(updated.transport_cursor, 18);
        assert_eq!(updated.entries.len(), 2);

        std::fs::remove_dir_all(root).expect("remove test history");
    }

    #[test]
    fn encrypted_history_rejects_wrong_password_without_overwriting_data() {
        let root = test_root("password");
        let mut store = EncryptedHistoryStore::new(&root, "right password").expect("create store");
        store
            .save(
                "peer",
                &HistoryFile {
                    version: PROFILE_VERSION,
                    entries: vec![entry("m1", "peer", "secret")],
                    transport_cursor: 1,
                },
            )
            .expect("save history");
        drop(store);

        let wrong = EncryptedHistoryStore::new(&root, "wrong password");
        assert!(
            wrong.is_err(),
            "wrong password must not create a new identity"
        );
        let mut correct =
            EncryptedHistoryStore::new(&root, "right password").expect("reopen store");
        assert_eq!(
            correct.load("peer").expect("load history").entries[0].text,
            "secret"
        );

        std::fs::remove_dir_all(root).expect("remove test history");
    }

    #[test]
    fn encrypted_history_removes_stale_temporary_file_before_save() {
        let root = test_root("stale-temp");
        let mut store = EncryptedHistoryStore::new(&root, "password").expect("create store");
        let path = root.join("peer.age");
        std::fs::write(root.join("peer.age.tmp"), b"incomplete write").expect("create stale file");
        store
            .save(
                "peer",
                &HistoryFile {
                    version: PROFILE_VERSION,
                    entries: vec![entry("m1", "peer", "complete")],
                    transport_cursor: 0,
                },
            )
            .expect("replace stale file");
        assert!(!path.with_extension("age.tmp").exists());
        assert_eq!(
            store.load("peer").expect("load saved history").entries[0].text,
            "complete"
        );

        std::fs::remove_dir_all(root).expect("remove test history");
    }
}
