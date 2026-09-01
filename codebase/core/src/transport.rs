#![allow(dead_code)]

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// A carrier-neutral message received from a transport.
///
/// `transport_id` is opaque to the messaging layer. HTTP relays use a server
/// row ID, while a future P2P transport can use a connection-local or
/// protocol-defined identifier.
#[non_exhaustive]
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

impl TransportMessage {
    pub fn new(
        transport_id: impl Into<String>,
        sender: impl Into<String>,
        sender_address: Option<String>,
        message_id: impl Into<String>,
        ciphertext: Vec<u8>,
        accepted_at: u64,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            transport_id: transport_id.into(),
            sender: sender.into(),
            sender_address,
            message_id: message_id.into(),
            ciphertext,
            accepted_at,
            expires_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    Sent,
    Read,
}

/// A carrier-neutral request to establish a private conversation.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRequest {
    pub request_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub sender_fingerprint: String,
    pub bundle: Vec<u8>,
}

impl ContactRequest {
    pub fn new(
        request_id: impl Into<String>,
        sender_id: impl Into<String>,
        sender_name: impl Into<String>,
        sender_fingerprint: impl Into<String>,
        bundle: Vec<u8>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            sender_id: sender_id.into(),
            sender_name: sender_name.into(),
            sender_fingerprint: sender_fingerprint.into(),
            bundle,
        }
    }
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

/// Reference transport for the protocol envelope.
///
/// This deliberately knows nothing about encryption or media. It gives the
/// session protocol a deterministic, asynchronous message representation while
/// carrier adapters are developed independently.
pub struct TextTransport;

impl TextTransport {
    pub fn encode(&self, envelope: &[u8]) -> String {
        format!("{}\n", URL_SAFE_NO_PAD.encode(envelope))
    }

    pub fn decode(&self, message: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(message.trim())
            .context("invalid safechat text message encoding")
    }
}

/// Text representation for public prekey bundles exchanged through
/// text-only channels. This is distinct from encrypted message framing.
pub struct BundleTransport;

impl BundleTransport {
    pub fn encode(&self, bundle: &[u8]) -> String {
        format!("{}\n", URL_SAFE_NO_PAD.encode(bundle))
    }

    pub fn decode(&self, message: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(message.trim())
            .context("invalid safechat text bundle encoding")
    }
}

/// Text representation for signed identity recovery/revocation records.
pub struct RecoveryTransport;

impl RecoveryTransport {
    pub fn encode(&self, record: &[u8]) -> String {
        format!("{}\n", URL_SAFE_NO_PAD.encode(record))
    }

    pub fn decode(&self, message: &str) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(message.trim())
            .context("invalid safechat recovery encoding")
    }
}

#[cfg(test)]
mod tests {
    use super::{BundleTransport, RecoveryTransport, TextTransport};

    #[test]
    fn text_transport_round_trip_supports_paste_mode() {
        let encoded = TextTransport.encode(&[1, 2, 3, 0, 255]);
        assert!(!encoded.contains("safechat"));
        assert_eq!(TextTransport.decode(&encoded).unwrap(), [1, 2, 3, 0, 255]);
    }

    #[test]
    fn bundle_transport_round_trip() {
        let encoded = BundleTransport.encode(b"public bundle bytes");
        assert_eq!(
            BundleTransport.decode(&encoded).unwrap(),
            b"public bundle bytes"
        );
        assert!(BundleTransport.decode("not base64!").is_err());
    }

    #[test]
    fn recovery_transport_round_trip_is_distinct_from_bundles() {
        let encoded = RecoveryTransport.encode(b"signed recovery record");
        assert_eq!(
            RecoveryTransport.decode(&encoded).unwrap(),
            b"signed recovery record"
        );
        assert_eq!(
            BundleTransport.decode(&encoded).unwrap(),
            b"signed recovery record"
        );
    }
}
