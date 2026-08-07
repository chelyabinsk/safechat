#![allow(dead_code)]

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// A carrier-neutral message received from a transport.
///
/// `transport_id` is opaque to the messaging layer. HTTP relays use a server
/// row ID, while a future P2P transport can use a connection-local or
/// protocol-defined identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportMessage {
    pub transport_id: String,
    pub sender: String,
    pub sender_address: Option<String>,
    pub message_id: String,
    pub ciphertext: Vec<u8>,
    pub accepted_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    Sent,
    Read,
}

/// A carrier-neutral request to establish a private conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRequest {
    pub request_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub sender_fingerprint: String,
    pub bundle: Vec<u8>,
}

/// Boundary for contact discovery and approval. Implementations own only
/// transport delivery; the UI owns prompts and the Signal layer owns trust.
pub trait ContactTransport {
    fn request_contact(&mut self, recipient: &str, request: &ContactRequest) -> Result<()>;
    fn pending_contacts(&mut self) -> Result<Vec<ContactRequest>>;
    fn accept_contact(&mut self, request_id: &str) -> Result<ContactRequest>;
    fn reject_contact(&mut self, request_id: &str) -> Result<()>;
}

/// Common network/message-carrier boundary.
///
/// Implementations transport already-encrypted SafeChat envelopes. They do
/// not perform Signal encryption, identity verification, or history storage.
/// A future P2P adapter should implement this trait without changing the UI
/// or Signal session code.
pub trait MessageTransport {
    fn send(
        &mut self,
        recipient: &str,
        message_id: &str,
        ciphertext: &[u8],
        expires_at: Option<u64>,
    ) -> Result<()>;

    fn receive(&mut self, cursor: i64) -> Result<Vec<TransportMessage>>;

    fn acknowledge(&mut self, message: &TransportMessage) -> Result<()>;

    fn status(&mut self, message_id: &str) -> Result<DeliveryStatus>;
}

#[cfg(test)]
mod message_transport_tests {
    use super::{DeliveryStatus, MessageTransport, TransportMessage};
    use anyhow::Result;

    struct InMemoryTransport {
        messages: Vec<TransportMessage>,
    }

    impl MessageTransport for InMemoryTransport {
        fn send(
            &mut self,
            _recipient: &str,
            message_id: &str,
            ciphertext: &[u8],
            _expires_at: Option<u64>,
        ) -> Result<()> {
            self.messages.push(TransportMessage {
                transport_id: "memory-1".to_owned(),
                sender: "sender".to_owned(),
                sender_address: None,
                message_id: message_id.to_owned(),
                ciphertext: ciphertext.to_vec(),
                accepted_at: 1,
                expires_at: None,
            });
            Ok(())
        }

        fn receive(&mut self, _cursor: i64) -> Result<Vec<TransportMessage>> {
            Ok(self.messages.clone())
        }

        fn acknowledge(&mut self, _message: &TransportMessage) -> Result<()> {
            Ok(())
        }

        fn status(&mut self, _message_id: &str) -> Result<DeliveryStatus> {
            Ok(DeliveryStatus::Read)
        }
    }

    #[test]
    fn message_transport_boundary_supports_send_receive_ack_and_status() {
        let mut transport = InMemoryTransport {
            messages: Vec::new(),
        };
        transport
            .send("peer", "message-1", b"encrypted", None)
            .unwrap();
        let messages = transport.receive(0).unwrap();
        assert_eq!(messages[0].message_id, "message-1");
        transport.acknowledge(&messages[0]).unwrap();
        assert_eq!(transport.status("message-1").unwrap(), DeliveryStatus::Read);
    }
}

pub const TEXT_HEADER: &str = "safechat-text-v1:";
pub const BUNDLE_HEADER: &str = "safechat-bundle-v1:";
pub const RECOVERY_HEADER: &str = "safechat-recovery-v1:";

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

/// Text representation for signed identity recovery/revocation records.
pub struct RecoveryTransport;

impl RecoveryTransport {
    pub fn encode(&self, record: &[u8]) -> String {
        format!("{RECOVERY_HEADER}{}\n", URL_SAFE_NO_PAD.encode(record))
    }

    pub fn decode(&self, message: &str) -> Result<Vec<u8>> {
        let encoded = message
            .trim()
            .strip_prefix(RECOVERY_HEADER)
            .context("invalid safechat recovery header")?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .context("invalid safechat recovery encoding")
    }
}

#[cfg(test)]
mod tests {
    use super::{BUNDLE_HEADER, BundleTransport, RECOVERY_HEADER, RecoveryTransport};

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

    #[test]
    fn recovery_transport_round_trip_is_distinct_from_bundles() {
        let encoded = RecoveryTransport.encode(b"signed recovery record");
        assert!(encoded.starts_with(RECOVERY_HEADER));
        assert_eq!(
            RecoveryTransport.decode(&encoded).unwrap(),
            b"signed recovery record"
        );
        assert!(BundleTransport.decode(&encoded).is_err());
    }
}
