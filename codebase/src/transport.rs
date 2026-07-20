#![allow(dead_code)]

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub const TEXT_HEADER: &str = "safechat-text-v1:";
pub const BUNDLE_HEADER: &str = "safechat-bundle-v1:";

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

/// Text representation for public prekey bundles exchanged through
/// text-only channels. This is distinct from encrypted message framing.
pub struct BundleTransport;

impl BundleTransport {
    pub fn encode(&self, bundle: &[u8]) -> String {
        format!("{BUNDLE_HEADER}{}\n", URL_SAFE_NO_PAD.encode(bundle))
    }

    pub fn decode(&self, message: &str) -> Result<Vec<u8>> {
        let encoded = message
            .trim()
            .strip_prefix(BUNDLE_HEADER)
            .context("invalid safechat text bundle header")?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .context("invalid safechat text bundle encoding")
    }
}

#[cfg(test)]
mod tests {
    use super::{BUNDLE_HEADER, BundleTransport};

    #[test]
    fn bundle_transport_round_trip() {
        let encoded = BundleTransport.encode(b"public bundle bytes");
        assert!(encoded.starts_with(BUNDLE_HEADER));
        assert_eq!(
            BundleTransport.decode(&encoded).unwrap(),
            b"public bundle bytes"
        );
        assert!(BundleTransport.decode("safechat-text-v1:abc").is_err());
    }
}
