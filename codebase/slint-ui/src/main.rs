slint::include_modules!();

use anyhow::{Context, Result, bail};
use arboard::Clipboard;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::ProjectDirs;
use safechat::chat_service::{ChatEvent, ChatService};
use safechat::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryFile, HistoryStore, load_relay_config,
    load_relay_peer_ids, load_relay_token,
};
use safechat::relay_client::{RelayClient, RelayClientConfig};
use safechat::relay_transport::RelayTransport;
use safechat::signal_adapter::{SignalPreKeyBundle, SqliteSignalState, identity_fingerprint};
use safechat::transport::{BundleTransport, TextTransport};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone)]
struct ProfileSession {
    profile: String,
    password: String,
}

fn set_chat_messages(window: &MainWindow, messages: Vec<ChatMessage>) {
    let model = slint::VecModel::from(messages.into_iter().collect::<Vec<_>>());
    window.set_chat_messages(slint::ModelRc::new(model));
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
    let peer_ids = load_relay_peer_ids(&peer_ids_path, password)?;
    Ok(RelayTransport::new(client, peer_ids))
}

fn render_history(history: &HistoryFile) -> Vec<ChatMessage> {
    history
        .entries
        .iter()
        .map(|entry| {
            let sender = if entry.sender == "you" {
                "You".to_owned()
            } else {
                entry.sender.clone()
            };
            ChatMessage {
                sender: sender.into(),
                text: entry.text.clone().into(),
                timestamp: entry.timestamp.to_string().into(),
                outgoing: entry.sender == "you",
                status: entry.delivery_status.clone().into(),
                ciphertext: entry.ciphertext.clone().into(),
            }
        })
        .collect()
}

fn perform_paste_send(
    session: &ProfileSession,
    encoded_peer: &str,
    plaintext: &str,
) -> Result<(Vec<ChatMessage>, String, String)> {
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
) -> Result<(Vec<ChatMessage>, String)> {
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

fn load_chat_history(session: &ProfileSession, encoded_peer: &str) -> Result<Vec<ChatMessage>> {
    let peer = peer_bundle_from_encoded(encoded_peer)?;
    let (_, _, _, lobby_root) = chat_paths(&session.profile)?;
    let mut history_store = EncryptedHistoryStore::new(&lobby_root, &session.password)?;
    let history = history_store.load(&peer.address().to_string())?;
    Ok(render_history(&history))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn perform_chat_action(
    session: &ProfileSession,
    encoded_peer: &str,
    plaintext: Option<&str>,
) -> Result<(Vec<ChatMessage>, String)> {
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
        if text.trim().is_empty() {
            None
        } else {
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
        }
    } else {
        None
    };
    let mut service = ChatService::new(&mut state, &mut relay, &mut history_store, conversation);
    let events = service.poll(&mut history, &peer, sender_id.as_deref())?;
    let status = match event {
        Some(ChatEvent::Sent { .. }) => "Message sent.".to_owned(),
        Some(_) => "Chat updated.".to_owned(),
        None if events
            .iter()
            .any(|event| matches!(event, ChatEvent::Received { .. })) =>
        {
            "New message received.".to_owned()
        }
        None => "Chat is up to date.".to_owned(),
    };
    Ok((render_history(&history), status))
}

fn spawn_chat_action(
    window_weak: slint::Weak<MainWindow>,
    session: Arc<Mutex<Option<ProfileSession>>>,
    encoded_peer: String,
    plaintext: Option<String>,
) {
    thread::spawn(move || {
        let result = (|| {
            session
                .lock()
                .map_err(|_| anyhow::anyhow!("chat session lock poisoned"))?
                .clone()
                .context("profile is not unlocked")
                .and_then(|profile| {
                    perform_chat_action(&profile, &encoded_peer, plaintext.as_deref())
                })
        })();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window_weak.upgrade() {
                match result {
                    Ok((messages, status)) => {
                        set_chat_messages(&window, messages);
                        window.set_chat_loading(false);
                        window.set_status_text(status.into());
                    }
                    Err(error) => {
                        window.set_chat_loading(false);
                        window.set_status_text(format!("Chat failed: {error:#}").into());
                    }
                }
            }
        });
    });
}

fn spawn_paste_send(
    window_weak: slint::Weak<MainWindow>,
    session: Arc<Mutex<Option<ProfileSession>>>,
    encoded_peer: String,
    plaintext: String,
) {
    thread::spawn(move || {
        let result = (|| {
            let profile = session
                .lock()
                .map_err(|_| anyhow::anyhow!("chat session lock poisoned"))?
                .clone()
                .context("profile is not unlocked")?;
            perform_paste_send(&profile, &encoded_peer, &plaintext)
        })();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window_weak.upgrade() {
                match result {
                    Ok((messages, status, ciphertext)) => {
                        set_chat_messages(&window, messages);
                        let clipboard_status = match Clipboard::new() {
                            Ok(mut clipboard) => clipboard
                                .set_text(ciphertext)
                                .map(|_| status)
                                .unwrap_or_else(|error| {
                                    format!("Could not copy ciphertext: {error}")
                                }),
                            Err(error) => format!("Could not access clipboard: {error}"),
                        };
                        window.set_status_text(clipboard_status.into());
                    }
                    Err(error) => {
                        window.set_status_text(format!("Paste send failed: {error:#}").into())
                    }
                }
            }
        });
    });
}

fn spawn_paste_receive(
    window_weak: slint::Weak<MainWindow>,
    session: Arc<Mutex<Option<ProfileSession>>>,
    encoded_peer: String,
    ciphertext: String,
) {
    thread::spawn(move || {
        let result = (|| {
            let profile = session
                .lock()
                .map_err(|_| anyhow::anyhow!("chat session lock poisoned"))?
                .clone()
                .context("profile is not unlocked")?;
            perform_paste_receive(&profile, &encoded_peer, &ciphertext)
        })();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window_weak.upgrade() {
                match result {
                    Ok((messages, status)) => {
                        set_chat_messages(&window, messages);
                        window.set_status_text(status.into());
                    }
                    Err(error) => {
                        window.set_status_text(format!("Paste receive failed: {error:#}").into())
                    }
                }
            }
        });
    });
}

fn spawn_history_load(
    window_weak: slint::Weak<MainWindow>,
    session: Arc<Mutex<Option<ProfileSession>>>,
    encoded_peer: String,
) {
    thread::spawn(move || {
        let result = (|| {
            let profile = session
                .lock()
                .map_err(|_| anyhow::anyhow!("chat session lock poisoned"))?
                .clone()
                .context("profile is not unlocked")?;
            load_chat_history(&profile, &encoded_peer)
        })();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window_weak.upgrade() {
                match result {
                    Ok(messages) => {
                        set_chat_messages(&window, messages);
                        window.set_chat_loading(false);
                        window.set_status_text("Chat history loaded.".into());
                    }
                    Err(error) => {
                        window.set_chat_loading(false);
                        window.set_status_text(
                            format!("Could not load chat history: {error:#}").into(),
                        );
                    }
                }
            }
        });
    });
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

fn available_profiles() -> Result<Vec<String>> {
    let root = profile_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut profiles = std::fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            (path.is_dir() && path.join("identity.db").is_file())
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    profiles.sort();
    Ok(profiles)
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

fn verify_add_contact(
    profile: &str,
    password: &str,
    encoded_bundle: &str,
    expected_fingerprint: &str,
) -> Result<String> {
    let database = profile_database(profile)?;
    let bundle_bytes = BundleTransport.decode(encoded_bundle.trim())?;
    let bundle = SignalPreKeyBundle::decode(&bundle_bytes)?;
    let actual_fingerprint = identity_fingerprint(&bundle.identity_key()?);
    if normalize_fingerprint(expected_fingerprint) != normalize_fingerprint(&actual_fingerprint) {
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
    Ok(format!("Verified and added {}.", bundle.name))
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

fn initialize_profile(
    profile_id: &str,
    display_name: &str,
    password: &str,
    confirmation: &str,
) -> Result<(String, String)> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let database = profile_database(profile_id)?;
    let existing = database.exists();
    if !existing && password != confirmation {
        bail!("passwords do not match");
    }
    let mut state = if database.exists() {
        futures_executor::block_on(SqliteSignalState::open(&database, password))?
    } else {
        futures_executor::block_on(SqliteSignalState::initialize(
            &database,
            display_name.trim(),
            1,
            password,
        ))?
    };
    let bundle = futures_executor::block_on(state.export_bundle())?;
    let fingerprint = futures_executor::block_on(state.local_identity_fingerprint())?;
    let encoded = URL_SAFE_NO_PAD.encode(bundle.encode()?);
    Ok((fingerprint, encoded))
}

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    let session: Arc<Mutex<Option<ProfileSession>>> = Arc::new(Mutex::new(None));
    let profiles =
        available_profiles().map_err(|error| slint::PlatformError::Other(error.to_string()))?;
    let profile_model = slint::VecModel::from(
        profiles
            .iter()
            .cloned()
            .map(slint::SharedString::from)
            .collect::<Vec<_>>(),
    );
    window.set_available_profiles(slint::ModelRc::new(profile_model));
    window.set_transport_options(slint::ModelRc::new(slint::VecModel::from(vec![
        "Copy/paste".into(),
        "Relay".into(),
    ])));
    if let Some(profile) = profiles.first() {
        window.set_profile_name(profile.clone().into());
        window.set_selected_profile(profile.clone().into());
        window.set_profile_exists(true);
    } else {
        window.set_creating_profile(true);
    }

    let window_weak = window.as_weak();
    let session_for_initialize = Arc::clone(&session);
    window.on_initialize_profile(move |profile, password, confirmation| {
        let window_weak = window_weak.clone();
        if let Some(window) = window_weak.upgrade() {
            window.set_status_text("Creating encrypted profile…".into());
        }
        let profile = profile.to_string();
        let password = password.to_string();
        let confirmation = confirmation.to_string();
        let session = Arc::clone(&session_for_initialize);
        thread::spawn(move || {
            let result = initialize_profile(&profile, &profile, &password, &confirmation);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = window_weak.upgrade() {
                    match result {
                        Ok((fingerprint, bundle)) => {
                            if let Ok(mut active) = session.lock() {
                                *active = Some(ProfileSession {
                                    profile: profile.clone(),
                                    password: password.clone(),
                                });
                            }
                            window.set_profile_ready(true);
                            window.set_fingerprint(fingerprint.into());
                            window.set_public_bundle(bundle.into());
                            if let Ok(Some((name, encoded))) = load_saved_contact(&profile) {
                                window.set_contact_name(name.into());
                                window.set_contact_bundle(encoded.into());
                                window.set_contact_added(true);
                            }
                            window.set_status_text("Profile ready. Verify fingerprints through a separate trusted channel.".into());
                        }
                        Err(error) => window.set_status_text(format!("Setup failed: {error:#}").into()),
                    }
                }
            });
        });
    });

    let window_weak = window.as_weak();
    window.on_select_profile(move |profile| {
        if let Some(window) = window_weak.upgrade() {
            window.set_profile_name(profile.clone());
            window.set_selected_profile(profile.clone());
            window.set_profile_exists(true);
            window.set_status_text(format!("Selected profile: {profile}").into());
        }
    });

    let window_weak = window.as_weak();
    window.on_begin_create_profile(move || {
        if let Some(window) = window_weak.upgrade() {
            window.set_creating_profile(!window.get_creating_profile());
        }
    });

    let window_weak = window.as_weak();
    window.on_verify_add_contact(move |bundle, fingerprint, password| {
        let Some(window) = window_weak.upgrade() else {
            return;
        };
        let profile = window.get_profile_name().to_string();
        window.set_status_text("Verifying contact…".into());
        let window_weak = window.as_weak();
        thread::spawn(move || {
            let result = verify_add_contact(&profile, &password, &bundle, &fingerprint);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = window_weak.upgrade() {
                    window.set_status_text(match result {
                        Ok(status) => {
                            let contact_name = status
                                .strip_prefix("Verified and added ")
                                .and_then(|value| value.strip_suffix('.'))
                                .unwrap_or(&status)
                                .to_owned();
                            window.set_contact_name(contact_name.into());
                            window.set_contact_bundle(bundle);
                            window.set_contact_added(true);
                            window.set_conversation_selected(false);
                            window.set_new_chat_open(false);
                            status.into()
                        }
                        Err(error) => format!("Contact verification failed: {error:#}").into(),
                    });
                }
            });
        });
    });

    let window_weak = window.as_weak();
    let session_for_send = Arc::clone(&session);
    window.on_select_contact(move || {
        if let Some(window) = window_weak.upgrade() {
            if window.get_chat_loading() {
                return;
            }
            window.set_conversation_selected(true);
            window.set_chat_loading(true);
            window.set_status_text("Conversation selected.".into());
            let peer = window.get_contact_bundle().to_string();
            if !peer.is_empty() {
                if window.get_selected_transport() == "Relay" {
                    spawn_chat_action(window.as_weak(), Arc::clone(&session_for_send), peer, None);
                } else {
                    spawn_history_load(window.as_weak(), Arc::clone(&session_for_send), peer);
                }
            } else {
                window.set_chat_loading(false);
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_choose_transport(move |transport| {
        if let Some(window) = window_weak.upgrade() {
            window.set_status_text(format!("Selected transport: {transport}").into());
        }
    });

    let window_weak = window.as_weak();
    let session_for_send = Arc::clone(&session);
    window.on_send_message(move |message| {
        if let Some(window) = window_weak.upgrade() {
            let peer = window.get_contact_bundle().to_string();
            if peer.is_empty() {
                window.set_status_text("Add and select a contact first.".into());
            } else if message.trim().is_empty() {
                window.set_status_text("Type a message first.".into());
            } else {
                if window.get_selected_transport() == "Copy/paste" {
                    window.set_status_text("Encrypting and copying…".into());
                    spawn_paste_send(
                        window.as_weak(),
                        Arc::clone(&session_for_send),
                        peer,
                        message.to_string(),
                    );
                } else {
                    window.set_status_text("Encrypting and sending…".into());
                    spawn_chat_action(
                        window.as_weak(),
                        Arc::clone(&session_for_send),
                        peer,
                        Some(message.to_string()),
                    );
                }
            }
        }
    });

    let window_weak = window.as_weak();
    let session_for_receive = Arc::clone(&session);
    window.on_receive_pasted(move |ciphertext| {
        if let Some(window) = window_weak.upgrade() {
            let peer = window.get_contact_bundle().to_string();
            if peer.is_empty() {
                window.set_status_text("Add and select a contact first.".into());
            } else if ciphertext.trim().is_empty() {
                window.set_status_text("Paste an encrypted message first.".into());
            } else {
                window.set_status_text("Decrypting pasted message…".into());
                spawn_paste_receive(
                    window.as_weak(),
                    Arc::clone(&session_for_receive),
                    peer,
                    ciphertext.to_string(),
                );
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_copy_ciphertext(move |ciphertext| {
        if let Some(window) = window_weak.upgrade() {
            let ciphertext = ciphertext.to_string();
            let status = if ciphertext.is_empty() {
                "Ciphertext is unavailable for this message.".to_owned()
            } else {
                match Clipboard::new() {
                    Ok(mut clipboard) => clipboard
                        .set_text(ciphertext)
                        .map(|_| "Ciphertext copied to clipboard.".to_owned())
                        .unwrap_or_else(|error| format!("Could not copy ciphertext: {error}")),
                    Err(error) => format!("Could not access clipboard: {error}"),
                }
            };
            window.set_status_text(status.into());
        }
    });

    let window_weak = window.as_weak();
    window.on_new_chat(move || {
        if let Some(window) = window_weak.upgrade() {
            window.set_new_chat_open(true);
            window.set_status_text("New conversation".into());
        }
    });

    let window_weak = window.as_weak();
    window.on_copy_bundle(move || {
        if let Some(window) = window_weak.upgrade() {
            let bundle = window.get_public_bundle().to_string();
            let status = match Clipboard::new() {
                Ok(mut clipboard) => clipboard
                    .set_text(bundle)
                    .map(|_| "Public bundle copied to clipboard.".to_owned())
                    .unwrap_or_else(|error| format!("Could not copy public bundle: {error}")),
                Err(error) => format!("Could not access clipboard: {error}"),
            };
            window.set_status_text(status.into());
        }
    });

    let window_weak = window.as_weak();
    window.on_copy_fingerprint(move || {
        if let Some(window) = window_weak.upgrade() {
            let fingerprint = window.get_fingerprint().to_string();
            let status = match Clipboard::new() {
                Ok(mut clipboard) => clipboard
                    .set_text(fingerprint)
                    .map(|_| "Fingerprint copied to clipboard.".to_owned())
                    .unwrap_or_else(|error| format!("Could not copy fingerprint: {error}")),
                Err(error) => format!("Could not access clipboard: {error}"),
            };
            window.set_status_text(status.into());
        }
    });

    let poll_window = window.as_weak();
    let poll_session = Arc::clone(&session);
    let poll_timer = slint::Timer::default();
    poll_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(3),
        move || {
            let Some(window) = poll_window.upgrade() else {
                return;
            };
            if window.get_profile_ready()
                && window.get_conversation_selected()
                && window.get_selected_transport() == "Relay"
                && !window.get_contact_bundle().is_empty()
            {
                spawn_chat_action(
                    window.as_weak(),
                    Arc::clone(&poll_session),
                    window.get_contact_bundle().to_string(),
                    None,
                );
            }
        },
    );

    window.run()
}
