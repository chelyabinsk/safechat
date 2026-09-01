//! Relay-specific transport adapter and peer-address mapping.

use crate::relay_client::RelayClient;
use anyhow::{Result, bail};
use safechat_core::signal::SignalPreKeyBundle;
use safechat_core::transport::{
    ContactRequest, ContactTransport, DeliveryStatus, MessageTransport, TransportMessage,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const PEER_BUNDLE_CACHE_TTL: Duration = Duration::from_secs(60);

pub struct RelayTransport {
    client: RelayClient,
    peer_ids: HashMap<String, String>,
    peer_bundles: HashMap<String, (Instant, SignalPreKeyBundle)>,
}

impl RelayTransport {
    pub fn new(client: RelayClient, peer_ids: HashMap<String, String>) -> Self {
        Self {
            client,
            peer_ids,
            peer_bundles: HashMap::new(),
        }
    }

    pub fn base_url(&self) -> &str {
        self.client.base_url()
    }

    pub fn client_id(&self) -> &str {
        self.client.client_id()
    }

    pub fn is_registered(&self) -> bool {
        self.client.is_registered()
    }

    pub fn peer_ids(&self) -> &HashMap<String, String> {
        &self.peer_ids
    }

    pub fn set_peer_id(&mut self, peer_name: String, client_id: String) {
        self.peer_ids.insert(peer_name, client_id);
    }

    pub fn recipient_for(&self, peer: &SignalPreKeyBundle) -> String {
        self.peer_ids
            .get(&peer.name)
            .cloned()
            .unwrap_or_else(|| peer.address().to_string())
    }

    pub fn sender_id_for(&self, peer: &SignalPreKeyBundle) -> Option<&str> {
        self.peer_ids.get(&peer.name).map(String::as_str)
    }

    pub fn fetch_peer_bundle(&mut self, peer: &SignalPreKeyBundle) -> Result<SignalPreKeyBundle> {
        let peer_address = peer.address().to_string();
        if let Some((fetched_at, bundle)) = self.peer_bundles.get(&peer_address)
            && fetched_at.elapsed() < PEER_BUNDLE_CACHE_TTL
        {
            return Ok(bundle.clone());
        }
        let relay_bundle = if let Some(relay_id) = self.peer_ids.get(&peer.name) {
            self.client.fetch_bundle(relay_id)?
        } else {
            self.client.fetch_bundle(&peer_address)?
        };
        let fetched = RelayClient::decode_bundle(&relay_bundle)?;
        if fetched.address() != peer.address() || fetched.identity_key()? != peer.identity_key()? {
            bail!("relay peer bundle does not match the locally verified identity");
        }
        self.peer_bundles
            .insert(peer_address, (Instant::now(), fetched.clone()));
        Ok(fetched)
    }

    pub fn fetch_peer_bundle_by_id(&mut self, client_id: &str) -> Result<SignalPreKeyBundle> {
        let relay_bundle = self.client.fetch_bundle(client_id)?;
        let fetched = RelayClient::decode_bundle(&relay_bundle)?;
        self.peer_bundles.insert(
            fetched.address().to_string(),
            (Instant::now(), fetched.clone()),
        );
        Ok(fetched)
    }

    pub fn accepted_contacts(&mut self) -> Result<Vec<ContactRequest>> {
        self.client.accepted_contacts()
    }
}

impl MessageTransport for RelayTransport {
    fn send(
        &mut self,
        recipient: &str,
        message_id: &str,
        ciphertext: &[u8],
        expires_at: Option<u64>,
    ) -> Result<()> {
        self.client
            .send_message(recipient, message_id, ciphertext, expires_at)
            .map(|_| ())
    }

    fn receive(&mut self, cursor: i64) -> Result<Vec<TransportMessage>> {
        self.client.receive(cursor)
    }

    fn acknowledge(&mut self, message: &TransportMessage) -> Result<()> {
        MessageTransport::acknowledge(&mut self.client, message)
    }

    fn status(&mut self, message_id: &str) -> Result<DeliveryStatus> {
        self.client.status(message_id)
    }
}

impl ContactTransport for RelayTransport {
    fn request_contact(&mut self, recipient: &str, request: &ContactRequest) -> Result<()> {
        self.client.request_contact(recipient, request)
    }

    fn pending_contacts(&mut self) -> Result<Vec<ContactRequest>> {
        self.client.contact_requests(false)
    }

    fn accept_contact(&mut self, request_id: &str) -> Result<ContactRequest> {
        self.client.accept_contact(request_id)
    }

    fn reject_contact(&mut self, request_id: &str) -> Result<()> {
        self.client.reject_contact(request_id)
    }
}
