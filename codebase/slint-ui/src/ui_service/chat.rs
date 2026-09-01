//! Conversation domain helpers independent of the Slint view model.

use super::{ConversationMessage, ProfileSession};
use anyhow::{Context, Result};
use safechat_application::chat_service::{ChatEvent, ChatService};
use safechat_core::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryFile, HistoryPage as CoreHistoryPage, HistoryStore,
    load_relay_config, load_relay_peer_ids, load_relay_token,
};
use safechat_core::signal_adapter::SqliteSignalState;
use safechat_core::transport::TextTransport;
use safechat_transports::relay_client::{RelayClient, RelayClientConfig};
use safechat_transports::relay_transport::RelayTransport;
use std::path::PathBuf;

use super::ports::HistoryStore as HistoryStorePort;
use super::profile::{peer_bundle_from_encoded, profile_database};

pub(super) const HISTORY_PAGE_SIZE: usize = 40;

pub(super) struct HistoryPage {
    pub messages: Vec<ConversationMessage>,
    pub cursor: usize,
    pub has_more: bool,
}

fn render_core_page(page: CoreHistoryPage) -> HistoryPage {
    let messages = page
        .entries
        .iter()
        .map(|entry| ConversationMessage {
            sender: if entry.sender == "you" {
                "You".to_owned()
            } else {
                entry.sender.clone()
            },
            text: entry.text.clone(),
            timestamp: entry.timestamp,
            outgoing: entry.sender == "you",
            status: entry.delivery_status.clone(),
            ciphertext: entry.ciphertext.clone(),
        })
        .collect();
    HistoryPage {
        messages,
        cursor: page.cursor,
        has_more: page.has_more,
    }
}

pub(super) fn render_history_page(history: &HistoryFile, before: Option<usize>) -> HistoryPage {
    let end = before
        .unwrap_or(history.entries.len())
        .min(history.entries.len());
    let start = end.saturating_sub(HISTORY_PAGE_SIZE);
    HistoryPage {
        messages: history.entries[start..end]
            .iter()
            .map(|entry| ConversationMessage {
                sender: if entry.sender == "you" {
                    "You".to_owned()
                } else {
                    entry.sender.clone()
                },
                text: entry.text.clone(),
                timestamp: entry.timestamp,
                outgoing: entry.sender == "you",
                status: entry.delivery_status.clone(),
                ciphertext: entry.ciphertext.clone(),
            })
            .collect(),
        cursor: start,
        has_more: start > 0,
    }
}

pub(super) struct EncryptedHistoryStorage;

impl HistoryStorePort for EncryptedHistoryStorage {
    fn load(&self, profile: &str, password: &str, peer: &str) -> Result<HistoryFile> {
        let (_, _, _, lobby_root) = chat_paths(profile)?;
        let mut store = EncryptedHistoryStore::new(&lobby_root, password)?;
        store.load(peer)
    }

    fn save(&self, profile: &str, password: &str, peer: &str, history: &HistoryFile) -> Result<()> {
        let (_, _, _, lobby_root) = chat_paths(profile)?;
        let mut store = EncryptedHistoryStore::new(&lobby_root, password)?;
        store.save(peer, history)
    }
}

#[cfg(test)]
pub(super) fn render_history(history: &HistoryFile) -> Vec<ConversationMessage> {
    history
        .entries
        .iter()
        .map(|entry| ConversationMessage {
            sender: if entry.sender == "you" {
                "You".to_owned()
            } else {
                entry.sender.clone()
            },
            text: entry.text.clone(),
            timestamp: entry.timestamp,
            outgoing: entry.sender == "you",
            status: entry.delivery_status.clone(),
            ciphertext: entry.ciphertext.clone(),
        })
        .collect()
}

fn chat_paths(profile: &str) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let database = profile_database(profile)?;
    let root = database
        .parent()
        .context("profile database has no parent directory")?
        .to_path_buf();
    Ok((
        root.join("relay-config.age"),
        root.join("relay-session.age"),
        root.join("relay-peers.age"),
        root.join("lobbies"),
    ))
}

fn open_relay_transport(
    profile: &str,
    password: &str,
    state: &SqliteSignalState,
) -> Result<RelayTransport> {
    let (config_path, session_path, peer_ids_path, _) = chat_paths(profile)?;
    let config = load_relay_config(&config_path, password)?
        .context("relay is not configured for this profile")?;
    let token = load_relay_token(&session_path, password)?;
    let identity = futures_executor::block_on(state.local_identity_key_pair())?;
    let mut client = RelayClient::new(
        RelayClientConfig {
            base_url: config.base_url,
            client_id: String::new(),
            enrollment_secret: config.enrollment_secret,
            ca_certificate_pem: None,
            allow_insecure_http: config.allow_insecure_http,
        },
        identity,
    )?;
    client.restore_access_token(token);
    Ok(RelayTransport::new(
        client,
        load_relay_peer_ids(&peer_ids_path, password)?,
    ))
}

pub(super) fn perform_paste_send(
    session: &ProfileSession,
    encoded_peer: &str,
    plaintext: &str,
    history_store: &dyn HistoryStorePort,
    clock: &dyn super::ports::Clock,
) -> Result<(HistoryPage, String, String)> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let database = profile_database(&session.profile)?;
    let mut state =
        futures_executor::block_on(SqliteSignalState::open(&database, &session.password))?;
    let conversation = peer.address().to_string();
    let mut history = history_store.load(&session.profile, &session.password, &conversation)?;
    let (message_id, envelope) =
        futures_executor::block_on(state.encrypt_message_for(&peer, plaintext.as_bytes()))?;
    let encoded = TextTransport.encode(&envelope).trim().to_owned();
    history.entries.push(HistoryEntry {
        timestamp: clock.now(),
        sender: "you".to_owned(),
        text: plaintext.to_owned(),
        message_id: message_id.encode(),
        peer: peer.address().to_string(),
        ciphertext: encoded.clone(),
        delivery_status: "copied".to_owned(),
        transport_recipient: peer.address().to_string(),
    });
    history_store.save(&session.profile, &session.password, &conversation, &history)?;
    Ok((
        render_history_page(&history, None),
        "Encrypted message ready. Click the message to copy its ciphertext.".to_owned(),
        encoded,
    ))
}

pub(super) fn perform_paste_receive(
    session: &ProfileSession,
    encoded_peer: &str,
    encoded_ciphertext: &str,
    history_store: &dyn HistoryStorePort,
    clock: &dyn super::ports::Clock,
) -> Result<(HistoryPage, String)> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let database = profile_database(&session.profile)?;
    let mut state =
        futures_executor::block_on(SqliteSignalState::open(&database, &session.password))?;
    let envelope = TextTransport.decode(encoded_ciphertext.trim())?;
    let message =
        futures_executor::block_on(state.decrypt_message_from(&peer.address(), &envelope))?;
    let conversation = peer.address().to_string();
    let mut history = history_store.load(&session.profile, &session.password, &conversation)?;
    let message_id = message.id.encode();
    if !history
        .entries
        .iter()
        .any(|entry| entry.message_id == message_id)
    {
        let text =
            String::from_utf8(message.plaintext).context("decrypted message is not UTF-8 text")?;
        history.entries.push(HistoryEntry {
            timestamp: clock.now(),
            sender: peer.name.clone(),
            text,
            message_id,
            peer: peer.address().to_string(),
            ciphertext: encoded_ciphertext.trim().to_owned(),
            delivery_status: "received".to_owned(),
            transport_recipient: String::new(),
        });
        history_store.save(&session.profile, &session.password, &conversation, &history)?;
    }
    Ok((
        render_history_page(&history, None),
        "Encrypted message received.".to_owned(),
    ))
}

pub(super) fn load_chat_history(
    session: &ProfileSession,
    encoded_peer: &str,
    history_store: &dyn HistoryStorePort,
) -> Result<HistoryPage> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let page = history_store.load_page(
        &session.profile,
        &session.password,
        &peer.address().to_string(),
        None,
        HISTORY_PAGE_SIZE,
    )?;
    Ok(render_core_page(page))
}

pub(super) fn load_older_chat_history(
    session: &ProfileSession,
    encoded_peer: &str,
    before: usize,
    history_store: &dyn HistoryStorePort,
) -> Result<HistoryPage> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let page = history_store.load_page(
        &session.profile,
        &session.password,
        &peer.address().to_string(),
        Some(before),
        HISTORY_PAGE_SIZE,
    )?;
    Ok(render_core_page(page))
}

pub(super) fn perform_chat_action(
    session: &ProfileSession,
    encoded_peer: &str,
    plaintext: Option<&str>,
) -> Result<(HistoryPage, String)> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let database = profile_database(&session.profile)?;
    let mut state =
        futures_executor::block_on(SqliteSignalState::open(&database, &session.password))?;
    let mut relay = open_relay_transport(&session.profile, &session.password, &state)?;
    let (_, _, _, lobby_root) = chat_paths(&session.profile)?;
    let mut history_store = EncryptedHistoryStore::new(&lobby_root, &session.password)?;
    let conversation = peer.address().to_string();
    let mut history = history_store.load(&conversation)?;
    let sender_id = relay.sender_id_for(&peer).map(str::to_owned);
    let event = if let Some(text) = plaintext {
        let recipient = relay.recipient_for(&peer);
        let encryption_peer = relay.fetch_peer_bundle(&peer)?;
        let mut service = ChatService::new(
            &mut state,
            &mut relay,
            &mut history_store,
            conversation.clone(),
        );
        Some(service.send_text(
            &mut history,
            &peer,
            &encryption_peer,
            &recipient,
            text.as_bytes(),
        )?)
    } else {
        None
    };
    let mut service = ChatService::new(&mut state, &mut relay, &mut history_store, conversation);
    let events = service.poll(&mut history, &peer, sender_id.as_deref())?;
    let status = match event {
        Some(ChatEvent::Sent { .. }) => "Message sent.".to_owned(),
        None if events
            .iter()
            .any(|event| matches!(event, ChatEvent::Received { .. })) =>
        {
            "New message received.".to_owned()
        }
        _ => "Chat is up to date.".to_owned(),
    };
    Ok((render_history_page(&history, None), status))
}

#[cfg(test)]
mod tests {
    use super::{HISTORY_PAGE_SIZE, render_history, render_history_page};
    use safechat_core::profile_store::{HistoryEntry, HistoryFile, PROFILE_VERSION};

    #[test]
    fn render_history_preserves_message_state_and_labels_local_sender() {
        let history = HistoryFile {
            version: PROFILE_VERSION,
            transport_cursor: 4,
            entries: vec![
                HistoryEntry {
                    timestamp: 10,
                    sender: "you".to_owned(),
                    text: "hello".to_owned(),
                    message_id: "outgoing-id".to_owned(),
                    peer: "peer".to_owned(),
                    ciphertext: "ciphertext-1".to_owned(),
                    delivery_status: "copied".to_owned(),
                    transport_recipient: "recipient".to_owned(),
                },
                HistoryEntry {
                    timestamp: 11,
                    sender: "Bob".to_owned(),
                    text: "hi".to_owned(),
                    message_id: "incoming-id".to_owned(),
                    peer: "peer".to_owned(),
                    ciphertext: "ciphertext-2".to_owned(),
                    delivery_status: "received".to_owned(),
                    transport_recipient: String::new(),
                },
            ],
        };

        let messages = render_history(&history);

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].sender, "You");
        assert!(messages[0].outgoing);
        assert_eq!(messages[0].text, "hello");
        assert_eq!(messages[0].status, "copied");
        assert_eq!(messages[0].ciphertext, "ciphertext-1");
        assert_eq!(messages[1].sender, "Bob");
        assert!(!messages[1].outgoing);
        assert_eq!(messages[1].timestamp, 11);
    }

    #[test]
    fn render_history_empty_file_has_no_bubbles() {
        let history = HistoryFile {
            version: PROFILE_VERSION,
            transport_cursor: 0,
            entries: Vec::new(),
        };

        assert!(render_history(&history).is_empty());
    }

    #[test]
    fn history_pages_start_at_the_latest_messages() {
        let entries = (0..(HISTORY_PAGE_SIZE + 2))
            .map(|index| HistoryEntry {
                timestamp: index as u64,
                sender: "Bob".to_owned(),
                text: index.to_string(),
                message_id: index.to_string(),
                peer: "peer".to_owned(),
                ciphertext: String::new(),
                delivery_status: String::new(),
                transport_recipient: String::new(),
            })
            .collect();
        let history = HistoryFile {
            version: PROFILE_VERSION,
            transport_cursor: 0,
            entries,
        };
        let page = render_history_page(&history, None);
        assert_eq!(page.messages.first().unwrap().text, "2");
        assert_eq!(
            page.messages.last().unwrap().text,
            (HISTORY_PAGE_SIZE + 1).to_string()
        );
        assert_eq!(page.cursor, 2);
        assert!(page.has_more);
        let older = render_history_page(&history, Some(page.cursor));
        assert_eq!(older.messages.len(), 2);
        assert!(!older.has_more);
    }
}
