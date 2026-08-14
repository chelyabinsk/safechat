//! Conversation domain helpers independent of the Slint view model.

use super::{ConversationMessage, ProfileSession};
use anyhow::{Context, Result};
use safechat_application::chat_service::{ChatEvent, ChatService};
use safechat_core::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryFile, HistoryStore, load_relay_config,
    load_relay_peer_ids, load_relay_token,
};
use safechat_core::signal_adapter::SqliteSignalState;
use safechat_core::transport::TextTransport;
use safechat_transports::relay_client::{RelayClient, RelayClientConfig};
use safechat_transports::relay_transport::RelayTransport;
use std::path::PathBuf;

use super::profile::{peer_bundle_from_encoded, profile_database};

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
) -> Result<(Vec<ConversationMessage>, String, String)> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let database = profile_database(&session.profile)?;
    let mut state =
        futures_executor::block_on(SqliteSignalState::open(&database, &session.password))?;
    let (_, _, _, lobby_root) = chat_paths(&session.profile)?;
    let mut history_store = EncryptedHistoryStore::new(&lobby_root, &session.password)?;
    let conversation = peer.address().to_string();
    let mut history = history_store.load(&conversation)?;
    let (message_id, envelope) =
        futures_executor::block_on(state.encrypt_message_for(&peer, plaintext.as_bytes()))?;
    let encoded = TextTransport.encode(&envelope).trim().to_owned();
    history.entries.push(HistoryEntry {
        timestamp: now(),
        sender: "you".to_owned(),
        text: plaintext.to_owned(),
        message_id: message_id.encode(),
        peer: peer.address().to_string(),
        ciphertext: encoded.clone(),
        delivery_status: "copied".to_owned(),
        transport_recipient: peer.address().to_string(),
    });
    history_store.save(&conversation, &history)?;
    Ok((
        render_history(&history),
        "Encrypted message copied. Paste it into the recipient’s chat.".to_owned(),
        encoded,
    ))
}

pub(super) fn perform_paste_receive(
    session: &ProfileSession,
    encoded_peer: &str,
    encoded_ciphertext: &str,
) -> Result<(Vec<ConversationMessage>, String)> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let database = profile_database(&session.profile)?;
    let mut state =
        futures_executor::block_on(SqliteSignalState::open(&database, &session.password))?;
    let envelope = TextTransport.decode(encoded_ciphertext.trim())?;
    let message =
        futures_executor::block_on(state.decrypt_message_from(&peer.address(), &envelope))?;
    let (_, _, _, lobby_root) = chat_paths(&session.profile)?;
    let mut history_store = EncryptedHistoryStore::new(&lobby_root, &session.password)?;
    let conversation = peer.address().to_string();
    let mut history = history_store.load(&conversation)?;
    let message_id = message.id.encode();
    if !history
        .entries
        .iter()
        .any(|entry| entry.message_id == message_id)
    {
        let text =
            String::from_utf8(message.plaintext).context("decrypted message is not UTF-8 text")?;
        history.entries.push(HistoryEntry {
            timestamp: now(),
            sender: peer.name.clone(),
            text,
            message_id,
            peer: peer.address().to_string(),
            ciphertext: encoded_ciphertext.trim().to_owned(),
            delivery_status: "received".to_owned(),
            transport_recipient: String::new(),
        });
        history_store.save(&conversation, &history)?;
    }
    Ok((
        render_history(&history),
        "Encrypted message received.".to_owned(),
    ))
}

pub(super) fn load_chat_history(
    session: &ProfileSession,
    encoded_peer: &str,
) -> Result<Vec<ConversationMessage>> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let (_, _, _, lobby_root) = chat_paths(&session.profile)?;
    let mut history_store = EncryptedHistoryStore::new(&lobby_root, &session.password)?;
    Ok(render_history(
        &history_store.load(&peer.address().to_string())?,
    ))
}

pub(super) fn perform_chat_action(
    session: &ProfileSession,
    encoded_peer: &str,
    plaintext: Option<&str>,
) -> Result<(Vec<ConversationMessage>, String)> {
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
    Ok((render_history(&history), status))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
