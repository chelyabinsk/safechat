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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryFile {
    pub version: u32,
    pub entries: Vec<HistoryEntry>,
    #[serde(default)]
    pub transport_cursor: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    pub base_url: String,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub enrollment_secret: String,
}

/// Persistence port consumed by the application chat service.
pub trait HistoryStore {
    fn load(&mut self, conversation: &str) -> Result<HistoryFile>;
    fn save(&mut self, conversation: &str, history: &HistoryFile) -> Result<()>;
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
        return Ok(HistoryFile {
            version: PROFILE_VERSION,
            entries: Vec::new(),
            transport_cursor: 0,
        });
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
