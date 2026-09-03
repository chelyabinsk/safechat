//! Application-level chat operations shared by UI and future front ends.

use anyhow::{Context, Result};
use safechat_core::profile_store::{HistoryEntry, HistoryFile, HistoryStore};
use safechat_core::signal::{SignalPreKeyBundle, SqliteSignalState};
use safechat_core::transport::{DeliveryStatus, MessageTransport, TextTransport};

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
    history_store: &'a mut dyn HistoryStore,
    conversation: String,
}

impl<'a> ChatService<'a> {
    pub fn new(
        state: &'a mut SqliteSignalState,
        transport: &'a mut dyn MessageTransport,
        history_store: &'a mut dyn HistoryStore,
        conversation: impl Into<String>,
    ) -> Self {
        Self {
            state,
            transport,
            history_store,
            conversation: conversation.into(),
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
        let message_id = message_id.encode();
        let timestamp = now();
        let text = String::from_utf8_lossy(plaintext).into_owned();
        history.entries.push(
            HistoryEntry::new(timestamp, "you", text.clone())
                .with_message_id(message_id.clone())
                .with_peer(peer.address().to_string())
                .with_ciphertext(TextTransport.encode(&envelope).trim())
                .with_delivery_status("queued")
                .with_transport_recipient(recipient),
        );
        // Persist before submission so an accepted message can be retried with
        // the same authenticated message ID after a process crash.
        self.history_store.save(&self.conversation, history)?;
        self.transport
            .send(recipient, &message_id, &envelope, None)?;
        if let Some(entry) = history
            .entries
            .iter_mut()
            .find(|entry| entry.message_id == message_id)
        {
            entry.delivery_status = "sent".to_owned();
        }
        self.history_store.save(&self.conversation, history)?;
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
            self.history_store.save(&self.conversation, history)?;
        }

        // Retry durable outbox entries. A transport must treat repeated
        // submission of the same message ID as idempotent.
        let queued = history
            .entries
            .iter()
            .filter(|entry| entry.sender == "you" && entry.delivery_status == "queued")
            .map(|entry| {
                (
                    entry.message_id.clone(),
                    entry.transport_recipient.clone(),
                    entry.ciphertext.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (message_id, recipient, ciphertext) in queued {
            let Ok(envelope) = TextTransport.decode(&ciphertext) else {
                continue;
            };
            if self
                .transport
                .send(&recipient, &message_id, &envelope, None)
                .is_ok()
            {
                if let Some(entry) = history
                    .entries
                    .iter_mut()
                    .find(|entry| entry.message_id == message_id)
                {
                    entry.delivery_status = "sent".to_owned();
                }
                self.history_store.save(&self.conversation, history)?;
            }
        }

        let peer_address = peer.address().to_string();
        for message in self.transport.receive(history.transport_cursor)? {
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
                    history_changed |= self.advance_cursor(history, &message.transport_id);
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
                history.entries.push(
                    HistoryEntry::new(timestamp, peer.name.clone(), text.clone())
                        .with_message_id(message_id)
                        .with_peer(peer.address().to_string())
                        .with_ciphertext(TextTransport.encode(&message.ciphertext).trim())
                        .with_delivery_status("received"),
                );
                self.history_store.save(&self.conversation, history)?;
                events.push(ChatEvent::Received {
                    timestamp,
                    sender: peer.name.clone(),
                    text,
                });
            }
            self.transport.acknowledge(&message)?;
            history_changed |= self.advance_cursor(history, &message.transport_id);
        }
        if history_changed {
            self.history_store.save(&self.conversation, history)?;
        }
        Ok(events)
    }

    fn advance_cursor(&self, history: &mut HistoryFile, transport_id: &str) -> bool {
        if let Ok(cursor) = transport_id.parse::<i64>() {
            let previous = history.transport_cursor;
            history.transport_cursor = history.transport_cursor.max(cursor);
            return history.transport_cursor != previous;
        }
        false
    }
}

fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use safechat_core::profile_store::HistoryStore;
    use safechat_core::transport::TransportMessage;
    use std::path::PathBuf;

    struct MemoryHistoryStore {
        saves: Vec<HistoryFile>,
    }

    impl HistoryStore for MemoryHistoryStore {
        fn load(&mut self, _conversation: &str) -> Result<HistoryFile> {
            Ok(self
                .saves
                .last()
                .cloned()
                .unwrap_or_else(HistoryFile::empty))
        }

        fn save(&mut self, _conversation: &str, history: &HistoryFile) -> Result<()> {
            self.saves.push(history.clone());
            Ok(())
        }

        fn delete(&mut self, _conversation: &str) -> Result<()> {
            self.saves.push(HistoryFile::empty());
            Ok(())
        }
    }

    struct TestTransport {
        fail_send: bool,
        sent: Vec<(String, String, Vec<u8>)>,
        incoming: Vec<TransportMessage>,
        receive_cursors: Vec<i64>,
        acknowledgements: Vec<String>,
    }

    impl MessageTransport for TestTransport {
        fn send(
            &mut self,
            recipient: &str,
            message_id: &str,
            ciphertext: &[u8],
            _expires_at: Option<u64>,
        ) -> Result<()> {
            if self.fail_send {
                anyhow::bail!("transport unavailable")
            }
            self.sent.push((
                recipient.to_owned(),
                message_id.to_owned(),
                ciphertext.to_vec(),
            ));
            Ok(())
        }

        fn receive(&mut self, cursor: i64) -> Result<Vec<TransportMessage>> {
            self.receive_cursors.push(cursor);
            Ok(self.incoming.clone())
        }

        fn acknowledge(&mut self, message: &TransportMessage) -> Result<()> {
            self.acknowledgements.push(message.transport_id.clone());
            Ok(())
        }

        fn status(&mut self, _message_id: &str) -> Result<DeliveryStatus> {
            Ok(DeliveryStatus::Sent)
        }
    }

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "safechat-application-{label}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn queued_send_retries_with_the_same_message_id() {
        let (mut alice, bob_bundle, alice_path, bob_path) = futures_executor::block_on(async {
            let alice_path = test_path("queued-send-alice");
            let bob_path = test_path("queued-send-bob");
            let mut alice = SqliteSignalState::initialize(&alice_path, "alice", 1, "password")
                .await
                .unwrap();
            let mut bob = SqliteSignalState::initialize(&bob_path, "bob", 1, "password")
                .await
                .unwrap();
            alice.export_bundle().await.unwrap();
            let bob_bundle = bob.export_bundle().await.unwrap();
            alice.trust_bundle(&bob_bundle).await.unwrap();
            (alice, bob_bundle, alice_path, bob_path)
        });

        let mut transport = TestTransport {
            fail_send: true,
            sent: Vec::new(),
            incoming: Vec::new(),
            receive_cursors: Vec::new(),
            acknowledgements: Vec::new(),
        };
        let mut store = MemoryHistoryStore { saves: Vec::new() };
        let mut history = HistoryFile::empty();
        let result = ChatService::new(
            &mut alice,
            &mut transport,
            &mut store,
            bob_bundle.address().to_string(),
        )
        .send_text(
            &mut history,
            &bob_bundle,
            &bob_bundle,
            "bob-client",
            b"hello",
        );
        assert!(result.is_err());
        assert_eq!(history.entries[0].delivery_status, "queued");
        let message_id = history.entries[0].message_id.clone();

        transport.fail_send = false;
        ChatService::new(
            &mut alice,
            &mut transport,
            &mut store,
            bob_bundle.address().to_string(),
        )
        .poll(&mut history, &bob_bundle, None)
        .unwrap();
        assert_eq!(history.entries[0].delivery_status, "sent");
        assert_eq!(transport.sent.len(), 1);
        assert_eq!(transport.sent[0].1, message_id);

        drop(alice);
        let _ = std::fs::remove_file(alice_path);
        let _ = std::fs::remove_file(bob_path);
    }

    #[test]
    fn receive_ack_persists_cursor_and_suppresses_duplicate_delivery() {
        let (mut alice, bob_bundle, envelope, alice_path, bob_path) =
            futures_executor::block_on(async {
                let alice_path = test_path("receive-cursor-alice");
                let bob_path = test_path("receive-cursor-bob");
                let mut alice = SqliteSignalState::initialize(&alice_path, "alice", 1, "password")
                    .await
                    .unwrap();
                let mut bob = SqliteSignalState::initialize(&bob_path, "bob", 1, "password")
                    .await
                    .unwrap();
                let alice_bundle = alice.export_bundle().await.unwrap();
                let bob_bundle = bob.export_bundle().await.unwrap();
                alice.trust_bundle(&bob_bundle).await.unwrap();
                bob.trust_bundle(&alice_bundle).await.unwrap();
                let (_, envelope) = bob
                    .encrypt_message_for(&alice_bundle, b"incoming")
                    .await
                    .unwrap();
                (alice, bob_bundle, envelope, alice_path, bob_path)
            });
        let incoming = TransportMessage::new(
            "42",
            "bob-client",
            Some(bob_bundle.address().to_string()),
            "",
            envelope,
            1,
            None,
        );
        let mut transport = TestTransport {
            fail_send: false,
            sent: Vec::new(),
            incoming: vec![incoming],
            receive_cursors: Vec::new(),
            acknowledgements: Vec::new(),
        };
        let mut store = MemoryHistoryStore { saves: Vec::new() };
        let mut history = HistoryFile::empty();
        let events = ChatService::new(
            &mut alice,
            &mut transport,
            &mut store,
            bob_bundle.address().to_string(),
        )
        .poll(&mut history, &bob_bundle, Some("bob-client"))
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(history.transport_cursor, 42);
        assert_eq!(transport.acknowledgements, vec!["42"]);

        let events = ChatService::new(
            &mut alice,
            &mut transport,
            &mut store,
            bob_bundle.address().to_string(),
        )
        .poll(&mut history, &bob_bundle, Some("bob-client"))
        .unwrap();
        assert!(matches!(events.as_slice(), [ChatEvent::Stale { .. }]));
        assert_eq!(transport.receive_cursors, vec![0, 42]);
        assert_eq!(history.entries.len(), 1);

        drop(alice);
        let _ = std::fs::remove_file(alice_path);
        let _ = std::fs::remove_file(bob_path);
    }
}
