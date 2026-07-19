use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub const TEXT_HEADER: &str = "safechat-text-v1:";

/// Reference transport for the protocol envelope.
///
/// This deliberately knows nothing about encryption or media. It gives the
/// session protocol a deterministic, asynchronous message representation while
/// carrier adapters are developed independently.
pub struct TextTransport;

impl TextTransport {
    pub fn encode(&self, envelope: &[u8]) -> String {
        format!("{TEXT_HEADER}{}\n", URL_SAFE_NO_PAD.encode(envelope))
    }

    pub fn decode(&self, message: &str) -> Result<Vec<u8>> {
        let encoded = message
            .trim()
            .strip_prefix(TEXT_HEADER)
            .context("invalid safechat text message header")?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .context("invalid safechat text message encoding")
    }
}
