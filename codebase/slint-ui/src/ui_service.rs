//! Serialized application service for the Slint client.
//!
//! The UI submits commands to one worker. Profile databases, Signal state,
//! encrypted history, and relay operations therefore never run concurrently
//! because several UI callbacks happened close together.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::ProjectDirs;
use safechat::chat_service::{ChatEvent, ChatService};
use safechat::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryStore, load_relay_config, load_relay_peer_ids,
    load_relay_token,
};
use safechat::relay_client::{RelayClient, RelayClientConfig};
use safechat::relay_transport::RelayTransport;
use safechat::signal_adapter::{SignalPreKeyBundle, SqliteSignalState, identity_fingerprint};
use safechat::transport::{BundleTransport, TextTransport};
use std::path::PathBuf;

mod chat;
mod model;
mod profile;
mod worker;
use chat::render_history;
pub use model::{ConversationMessage, TransportKind};
pub use profile::available_profiles;
pub use worker::UiService;

#[derive(Clone, Debug)]
pub struct ProfileSession {
    profile: String,
    password: String,
}

pub enum Command {
    Initialize {
        profile: String,
        password: String,
        confirmation: String,
    },
    VerifyContact {
        profile: String,
        password: String,
        bundle: String,
        fingerprint: String,
    },
    LoadHistory {
        peer: String,
    },
    Send {
        peer: String,
        transport: TransportKind,
        text: String,
    },
    ReceivePasted {
        peer: String,
        ciphertext: String,
    },
    Poll {
        peer: String,
    },
}

pub enum Event {
    ProfileReady {
        profile: String,
        fingerprint: String,
        bundle: String,
        contact: Option<(String, String)>,
    },
    ContactAdded {
        name: String,
        bundle: String,
        status: String,
    },
    ChatUpdated {
        messages: Vec<ConversationMessage>,
        status: String,
        ciphertext: Option<String>,
    },
    Error {
        operation: &'static str,
        message: String,
    },
}

fn handle_command(
    session: &mut Option<ProfileSession>,
    command: Command,
) -> std::result::Result<Option<Event>, (&'static str, String)> {
    let result = match command {
        Command::Initialize {
            profile,
            password,
            confirmation,
        } => initialize_profile(&profile, &password, &confirmation).map(|(fingerprint, bundle)| {
            *session = Some(ProfileSession {
                profile: profile.clone(),
                password,
            });
            let contact = load_saved_contact(&profile).ok().flatten();
            Some(Event::ProfileReady {
                profile,
                fingerprint,
                bundle,
                contact,
            })
        }),
        Command::VerifyContact {
            profile,
            password,
            bundle,
            fingerprint,
        } => {
            verify_add_contact(&profile, &password, &bundle, &fingerprint).map(|(name, status)| {
                Some(Event::ContactAdded {
                    name,
                    bundle,
                    status,
                })
            })
        }
        Command::LoadHistory { peer } => require_session(session)
            .and_then(|active| load_chat_history(active, &peer))
            .map(|messages| {
                Some(Event::ChatUpdated {
                    messages,
                    status: "Chat history loaded.".to_owned(),
                    ciphertext: None,
                })
            }),
        Command::Send {
            peer,
            transport,
            text,
        } => require_session(session).and_then(|active| {
            if transport == TransportKind::CopyPaste {
                perform_paste_send(active, &peer, &text).map(|(messages, status, ciphertext)| {
                    Some(Event::ChatUpdated {
                        messages,
                        status,
                        ciphertext: Some(ciphertext),
                    })
                })
            } else {
                perform_chat_action(active, &peer, Some(&text)).map(|(messages, status)| {
                    Some(Event::ChatUpdated {
                        messages,
                        status,
                        ciphertext: None,
                    })
                })
            }
        }),
        Command::ReceivePasted { peer, ciphertext } => require_session(session)
            .and_then(|active| perform_paste_receive(active, &peer, &ciphertext))
            .map(|(messages, status)| {
                Some(Event::ChatUpdated {
                    messages,
                    status,
                    ciphertext: None,
                })
            }),
        Command::Poll { peer } => require_session(session)
            .and_then(|active| perform_chat_action(active, &peer, None))
            .map(|(messages, status)| {
                Some(Event::ChatUpdated {
                    messages,
                    status,
                    ciphertext: None,
                })
            }),
    };
    result.map_err(|error| (operation_name(&error), format!("{error:#}")))
}

fn operation_name(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    if text.contains("history") {
        "history"
    } else if text.contains("relay") {
        "relay"
    } else if text.contains("contact") || text.contains("fingerprint") {
        "contact"
    } else {
        "chat"
    }
}

fn require_session(session: &Option<ProfileSession>) -> Result<&ProfileSession> {
    session.as_ref().context("profile is not unlocked")
}

fn profile_database(profile: &str) -> Result<PathBuf> {
    let profile = profile.trim();
    if profile.is_empty()
        || profile == "."
        || profile == ".."
        || profile.contains('/')
        || profile.contains('\\')
    {
        bail!("profile name must be a simple non-empty name");
    }
    let root = profile_root()?.join(profile);
    std::fs::create_dir_all(&root).context("creating the SafeChat profile directory")?;
    Ok(root.join("identity.db"))
}

fn profile_root() -> Result<PathBuf> {
    Ok(ProjectDirs::from("", "SafeChat", "safechat")
        .context("cannot determine the platform data directory")?
        .data_dir()
        .to_path_buf())
}

fn initialize_profile(
    profile: &str,
    password: &str,
    confirmation: &str,
) -> Result<(String, String)> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let database = profile_database(profile)?;
    let existing = database.exists();
    if !existing && password != confirmation {
        bail!("passwords do not match");
    }
    let mut state = if existing {
        futures_executor::block_on(SqliteSignalState::open(&database, password))?
    } else {
        futures_executor::block_on(SqliteSignalState::initialize(
            &database, profile, 1, password,
        ))?
    };
    let bundle = futures_executor::block_on(state.export_bundle())?;
    let fingerprint = futures_executor::block_on(state.local_identity_fingerprint())?;
    Ok((fingerprint, URL_SAFE_NO_PAD.encode(bundle.encode()?)))
}

fn peer_bundle_from_encoded(encoded: &str) -> Result<SignalPreKeyBundle> {
    let bytes = BundleTransport.decode(encoded.trim())?;
    SignalPreKeyBundle::decode(&bytes)
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

fn load_saved_contact(profile: &str) -> Result<Option<(String, String)>> {
    let database = profile_database(profile)?;
    let peers = database
        .parent()
        .context("profile database has no parent directory")?
        .join("peers");
    if !peers.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(peers)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("bundle") {
            continue;
        }
        let encoded = std::fs::read_to_string(path)?;
        let bundle = peer_bundle_from_encoded(&encoded)?;
        return Ok(Some((bundle.name, encoded.trim().to_owned())));
    }
    Ok(None)
}

fn verify_add_contact(
    profile: &str,
    password: &str,
    encoded_bundle: &str,
    expected_fingerprint: &str,
) -> Result<(String, String)> {
    let database = profile_database(profile)?;
    let bundle_bytes = BundleTransport.decode(encoded_bundle.trim())?;
    let bundle = SignalPreKeyBundle::decode(&bundle_bytes)?;
    let actual_fingerprint = identity_fingerprint(&bundle.identity_key()?);
    let normalize = |value: &str| {
        value
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != ':')
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    if normalize(expected_fingerprint) != normalize(&actual_fingerprint) {
        bail!("fingerprint does not match the public bundle");
    }
    let mut state = futures_executor::block_on(SqliteSignalState::open(&database, password))?;
    futures_executor::block_on(state.trust_bundle(&bundle))?;
    let peers = database
        .parent()
        .context("profile database has no parent directory")?
        .join("peers");
    std::fs::create_dir_all(&peers)?;
    let filename = bundle
        .address()
        .to_string()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    std::fs::write(
        peers.join(format!("{filename}.bundle")),
        encoded_bundle.trim(),
    )?;
    Ok((
        bundle.name.clone(),
        format!("Verified and added {}.", bundle.name),
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

fn perform_paste_send(
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

fn perform_paste_receive(
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

fn load_chat_history(
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

fn perform_chat_action(
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
