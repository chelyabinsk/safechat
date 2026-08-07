//! Application-level chat operations shared by UI and future front ends.

use crate::profile_store::{HistoryEntry, HistoryFile, save_history};
use crate::signal_adapter::{SignalPreKeyBundle, SqliteSignalState};
use crate::transport::{DeliveryStatus, MessageTransport, TextTransport};
use anyhow::{Context, Result};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatEvent {
    Sent {
        timestamp: u64,
        text: String,
    },
    Read {
        timestamp: u64,
        text: String,
    },
    Received {
        timestamp: u64,
        sender: String,
        text: String,
    },
    Stale {
        transport_id: String,
    },
}

pub struct ChatService<'a> {
    state: &'a mut SqliteSignalState,
    transport: &'a mut dyn MessageTransport,
    history_path: &'a Path,
    password: &'a str,
}

impl<'a> ChatService<'a> {
    pub fn new(
        state: &'a mut SqliteSignalState,
        transport: &'a mut dyn MessageTransport,
        history_path: &'a Path,
        password: &'a str,
    ) -> Self {
        Self {
            state,
            transport,
            history_path,
            password,
        }
    }

    pub fn send_text(
        &mut self,
        history: &mut HistoryFile,
        peer: &SignalPreKeyBundle,
        encryption_peer: &SignalPreKeyBundle,
        recipient: &str,
        plaintext: &[u8],
    ) -> Result<ChatEvent> {
        let (message_id, envelope) =
            futures_executor::block_on(self.state.encrypt_message_for(encryption_peer, plaintext))?;
        self.transport
            .send(recipient, &message_id.encode(), &envelope, None)?;
        let timestamp = now();
        let text = String::from_utf8_lossy(plaintext).into_owned();
        history.entries.push(HistoryEntry {
            timestamp,
            sender: "you".to_owned(),
            text: text.clone(),
            message_id: message_id.encode(),
            peer: peer.address().to_string(),
            ciphertext: TextTransport.encode(&envelope).trim().to_owned(),
            delivery_status: "sent".to_owned(),
        });
        save_history(self.history_path, self.password, history)?;
        Ok(ChatEvent::Sent { timestamp, text })
    }

    pub fn poll(
        &mut self,
        history: &mut HistoryFile,
        peer: &SignalPreKeyBundle,
        relay_sender_id: Option<&str>,
    ) -> Result<Vec<ChatEvent>> {
        let mut events = Vec::new();
        let mut history_changed = false;
        for entry in &mut history.entries {
            if entry.sender == "you"
                && entry.delivery_status == "sent"
                && !entry.message_id.is_empty()
                && let Ok(status) = self.transport.status(&entry.message_id)
                && status == DeliveryStatus::Read
            {
                entry.delivery_status = "read".to_owned();
                history_changed = true;
                events.push(ChatEvent::Read {
                    timestamp: entry.timestamp,
                    text: entry.text.clone(),
                });
            }
        }
        if history_changed {
            save_history(self.history_path, self.password, history)?;
        }

        let peer_address = peer.address().to_string();
        for message in self.transport.receive(0)? {
            let sender_matches_address =
                message.sender_address.as_deref() == Some(peer_address.as_str());
            let sender_matches_transport_id =
                relay_sender_id.is_some_and(|id| id == message.sender);
            if !sender_matches_address && !sender_matches_transport_id {
                continue;
            }
            let decoded = match futures_executor::block_on(
                self.state
                    .decrypt_message_from(&peer.address(), &message.ciphertext),
            ) {
                Ok(decoded) => decoded,
                Err(error) if error.to_string().contains("old counter") => {
                    self.transport.acknowledge(&message)?;
                    events.push(ChatEvent::Stale {
                        transport_id: message.transport_id,
                    });
                    continue;
                }
                Err(error) => return Err(error),
            };
            let message_id = decoded.id.encode();
            if !history
                .entries
                .iter()
                .any(|entry| entry.message_id == message_id)
            {
                let text = String::from_utf8(decoded.plaintext)
                    .context("decrypted message is not UTF-8 text")?;
                let timestamp = now();
                history.entries.push(HistoryEntry {
                    timestamp,
                    sender: peer.name.clone(),
                    text: text.clone(),
                    message_id,
                    peer: peer.address().to_string(),
                    ciphertext: TextTransport.encode(&message.ciphertext).trim().to_owned(),
                    delivery_status: "received".to_owned(),
                });
                save_history(self.history_path, self.password, history)?;
                events.push(ChatEvent::Received {
                    timestamp,
                    sender: peer.name.clone(),
                    text,
                });
            }
            self.transport.acknowledge(&message)?;
        }
        Ok(events)
    }
}

fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
