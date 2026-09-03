//! Stable application ports used by the UI service.

use super::TransportKind;
use anyhow::Result;
use safechat_core::profile_store::HistoryFile;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileReadyData {
    pub profile: String,
    pub fingerprint: String,
    pub bundle: String,
    pub contact: Option<(String, String)>,
}

pub trait ProfileStore: Send + Sync {
    fn available_profiles(&self) -> Result<Vec<String>>;
    fn initialize(
        &self,
        profile: &str,
        password: &str,
        confirmation: &str,
    ) -> Result<ProfileReadyData>;
    fn verify_contact(
        &self,
        profile: &str,
        password: &str,
        bundle: &str,
        fingerprint: &str,
    ) -> Result<(String, String)>;
}

pub trait HistoryStore: Send + Sync {
    fn load(&self, profile: &str, password: &str, peer: &str) -> Result<HistoryFile>;
    fn save(&self, profile: &str, password: &str, peer: &str, history: &HistoryFile) -> Result<()>;
    fn delete(&self, profile: &str, password: &str, peer: &str) -> Result<()> {
        self.save(profile, password, peer, &HistoryFile::empty())
    }

    fn load_page(
        &self,
        profile: &str,
        password: &str,
        peer: &str,
        before: Option<usize>,
        page_size: usize,
    ) -> Result<safechat_core::profile_store::HistoryPage> {
        Ok(self.load(profile, password, peer)?.page(before, page_size))
    }
}

pub trait Clipboard: Send + Sync {
    fn set_text(&self, text: &str) -> Result<()>;
}

pub trait TransportSelector: Send + Sync {
    fn options(&self) -> Vec<String>;
    fn parse(&self, value: &str) -> Option<TransportKind>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

pub struct SystemClipboard {
    clipboard: Mutex<Option<copypasta::ClipboardContext>>,
}

impl SystemClipboard {
    pub fn new() -> Self {
        Self {
            clipboard: Mutex::new(None),
        }
    }
}

impl Clipboard for SystemClipboard {
    fn set_text(&self, text: &str) -> Result<()> {
        use copypasta::ClipboardProvider;

        let mut clipboard = self
            .clipboard
            .lock()
            .map_err(|_| anyhow::anyhow!("clipboard lock poisoned"))?;
        if clipboard.is_none() {
            *clipboard = Some(
                copypasta::ClipboardContext::new()
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
        }
        clipboard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("clipboard unavailable after initialization"))?
            .set_contents(text.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(())
    }
}

pub struct DefaultTransportSelector;

impl TransportSelector for DefaultTransportSelector {
    fn options(&self) -> Vec<String> {
        vec!["Copy/paste".to_owned(), "Relay".to_owned()]
    }

    fn parse(&self, value: &str) -> Option<TransportKind> {
        TransportKind::parse(value)
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

pub struct ServicePorts {
    pub profile: Arc<dyn ProfileStore>,
    pub history: Arc<dyn HistoryStore>,
    pub clipboard: Arc<dyn Clipboard>,
    pub transport: Arc<dyn TransportSelector>,
    pub clock: Arc<dyn Clock>,
}

impl ServicePorts {
    pub fn production() -> Self {
        Self {
            profile: Arc::new(super::profile::FileProfileStore),
            history: Arc::new(super::chat::EncryptedHistoryStorage),
            clipboard: Arc::new(SystemClipboard::new()),
            transport: Arc::new(DefaultTransportSelector),
            clock: Arc::new(SystemClock),
        }
    }
}

impl Default for ServicePorts {
    fn default() -> Self {
        Self::production()
    }
}
