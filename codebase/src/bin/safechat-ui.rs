use age::{Decryptor, Encryptor};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use dialoguer::{Confirm, Input, Password, Select};
use directories::ProjectDirs;
use safechat::signal_adapter::{
    MessageId, SignalPreKeyBundle, SqliteSignalState, identity_fingerprint,
};
use safechat::transport::{BundleTransport, RecoveryTransport, TextTransport};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PROFILE_VERSION: u32 = 1;

#[derive(clap::Parser)]
#[command(name = "safechat-ui", version, about = "Friendly SafeChat text chat")]
struct Cli {
    /// Profile name stored below the platform application-data directory.
    #[arg(long, default_value = "default")]
    profile: String,
    /// Override the platform application-data directory.
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct ProfilePaths {
    root: PathBuf,
    database: PathBuf,
    history: PathBuf,
    lobby_histories: PathBuf,
    peers: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HistoryFile {
    version: u32,
    entries: Vec<HistoryEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HistoryEntry {
    timestamp: u64,
    sender: String,
    text: String,
    #[serde(default)]
    message_id: String,
    #[serde(default)]
    peer: String,
    #[serde(default)]
    ciphertext: String,
}

#[derive(Clone, Copy)]
enum HistoryView {
    Ciphertext,
    Clean,
}

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    let paths = ProfilePaths::new(cli.data_dir, &cli.profile)?;
    paths.create()?;
    let password = unlock_password(&paths.history)?;
    let mut state = futures_executor::block_on(open_or_initialize(&paths, &password))?;
    restrict_file(&paths.database)?;
    // Refresh the local prekey inventory and rotate lifecycle keys before
    // loading the private lobbies.
    futures_executor::block_on(state.export_bundle())?;

    let mut peers = load_peers(&paths.peers)?;
    if peers.is_empty() {
        println!("No conversation is configured yet.");
        println!("We will create your identity and guide you through setup.");
        peers.push(futures_executor::block_on(setup_peer(&paths, &mut state))?);
    }

    let legacy_history = paths
        .history
        .exists()
        .then(|| load_history(&paths.history, &password))
        .transpose()?;
    let mut histories = peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let path = paths.lobby_history(peer);
            if path.exists() {
                load_history(&path, &password)
            } else if let Some(legacy) = &legacy_history {
                Ok(HistoryFile {
                    version: PROFILE_VERSION,
                    entries: legacy
                        .entries
                        .iter()
                        .filter(|entry| {
                            (index == 0 && entry.peer.is_empty())
                                || entry.peer == peer.name
                                || entry.peer == peer.address().to_string()
                        })
                        .cloned()
                        .collect(),
                })
            } else {
                Ok(HistoryFile {
                    version: PROFILE_VERSION,
                    entries: Vec::new(),
                })
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let view = choose_history_view()?;
    show_history(&histories[0], view);
    chat_loop(&paths, &password, &mut histories, &mut state, peers)
}

impl ProfilePaths {
    fn new(override_dir: Option<PathBuf>, profile: &str) -> Result<Self> {
        let profile = safe_component(profile)?;
        let base = match override_dir {
            Some(path) => path,
            None => ProjectDirs::from("", "SafeChat", "safechat")
                .context("cannot determine the platform application-data directory")?
                .data_dir()
                .to_path_buf(),
        };
        let root = base.join(profile);
        Ok(Self {
            root: root.clone(),
            database: root.join("identity.db"),
            history: root.join("chat-history.age"),
            lobby_histories: root.join("lobbies"),
            peers: root.join("peers"),
        })
    }

    fn create(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        restrict_directory(&self.root)?;
        fs::create_dir_all(&self.lobby_histories)?;
        fs::create_dir_all(&self.peers)?;
        restrict_directory(&self.lobby_histories)?;
        restrict_directory(&self.peers)?;
        Ok(())
    }

    fn lobby_history(&self, peer: &SignalPreKeyBundle) -> PathBuf {
        self.lobby_histories
            .join(format!("{}.age", peer_file_component(peer)))
    }

    fn clear_peer_bundles(&self) -> Result<()> {
        for entry in fs::read_dir(&self.peers)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "bundle")
            {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn safe_component(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        bail!("profile name must be a non-empty simple name");
    }
    Ok(trimmed.to_owned())
}

fn unlock_password(history_path: &Path) -> Result<String> {
    if history_path.exists() {
        println!("Unlocking encrypted chat history.");
        Password::new()
            .with_prompt("Password")
            .interact()
            .context("reading password")
    } else {
        println!("Create a password for this profile's encrypted chat history.");
        let password = Password::new()
            .with_prompt("New password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()
            .context("reading password")?;
        if password.is_empty() {
            bail!("password must not be empty");
        }
        Ok(password)
    }
}

async fn open_or_initialize(paths: &ProfilePaths, password: &str) -> Result<SqliteSignalState> {
    if paths.database.exists() {
        let state = SqliteSignalState::open(&paths.database, password).await?;
        if state.local_address().name() != "unconfigured" {
            return Ok(state);
        }
    }

    println!("No local identity found.");
    if !Confirm::new()
        .with_prompt("Initialize this SafeChat profile now?")
        .default(true)
        .interact()?
    {
        bail!("profile initialization cancelled");
    }
    let name = Input::<String>::new()
        .with_prompt("Your display name")
        .interact_text()?;
    let state = SqliteSignalState::initialize(&paths.database, &name, 1, password).await?;
    restrict_file(&paths.database)?;
    println!("Identity created.");
    println!(
        "Your fingerprint is {}",
        state.local_identity_fingerprint().await?
    );
    Ok(state)
}

async fn setup_peer(
    paths: &ProfilePaths,
    state: &mut SqliteSignalState,
) -> Result<SignalPreKeyBundle> {
    let own_bundle = state.export_bundle().await?;
    println!();
    println!("Copy and send your public bundle to the other person:");
    println!("{}", BundleTransport.encode(&own_bundle.encode()?));
    println!(
        "Your fingerprint: {}",
        identity_fingerprint(&own_bundle.identity_key()?)
    );
    println!("Verify the other person's fingerprint through your separate trusted channel.");

    let bundle = read_bundle_prompt("Paste the other person's bundle text")?;
    let actual = identity_fingerprint(&bundle.identity_key()?);
    println!("Received bundle for {}", bundle.address());
    println!("Fingerprint: {actual}");
    let expected = Input::<String>::new()
        .with_prompt("Enter the fingerprint you verified separately")
        .interact_text()?;
    if normalize_fingerprint(&expected) != normalize_fingerprint(&actual) {
        bail!("fingerprint does not match; the peer was not trusted");
    }
    state.trust_bundle(&bundle).await?;
    let path = paths
        .peers
        .join(format!("{}.bundle", peer_file_component(&bundle)));
    write_bundle(&path, &bundle)?;
    println!("Peer trusted. You can now exchange encrypted messages.");
    Ok(bundle)
}

fn load_peers(directory: &Path) -> Result<Vec<SignalPreKeyBundle>> {
    let mut paths = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "bundle")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let loaded = paths
        .into_iter()
        .map(|path| load_bundle(&path))
        .collect::<Result<Vec<_>>>()?;
    let mut seen = HashSet::new();
    Ok(loaded
        .into_iter()
        .rev()
        .filter(|peer| seen.insert(peer.address().to_string()))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect())
}

fn peer_file_component(bundle: &SignalPreKeyBundle) -> String {
    bundle
        .address()
        .to_string()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn write_bundle(path: &Path, bundle: &SignalPreKeyBundle) -> Result<()> {
    let encoded = BundleTransport.encode(&bundle.encode()?);
    fs::write(path, encoded).with_context(|| format!("writing bundle {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn load_bundle(path: &Path) -> Result<SignalPreKeyBundle> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading peer bundle {}", path.display()))?;
    let bytes = BundleTransport.decode(&text)?;
    SignalPreKeyBundle::decode(&bytes)
}

fn read_bundle_prompt(prompt: &str) -> Result<SignalPreKeyBundle> {
    let mut text = Input::<String>::new().with_prompt(prompt).interact_text()?;
    if !text.trim().starts_with("safechat-bundle-v1:") {
        println!("Paste the remaining bundle text, then enter END on its own line.");
        loop {
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            if line.trim() == "END" {
                break;
            }
            text.push_str(&line);
        }
    }
    let bytes = BundleTransport.decode(&text)?;
    SignalPreKeyBundle::decode(&bytes)
}

fn normalize_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != ':')
        .flat_map(char::to_lowercase)
        .collect()
}

fn choose_history_view() -> Result<HistoryView> {
    let choices = ["Show encrypted chat", "Show clean chat"];
    let choice = Select::new()
        .with_prompt("History view")
        .items(&choices)
        .default(0)
        .interact()?;
    Ok(if choice == 0 {
        HistoryView::Ciphertext
    } else {
        HistoryView::Clean
    })
}

fn chat_loop(
    paths: &ProfilePaths,
    password: &str,
    histories: &mut Vec<HistoryFile>,
    state: &mut SqliteSignalState,
    mut peers: Vec<SignalPreKeyBundle>,
) -> Result<()> {
    let mut current = 0;
    println!();
    if let Some(peer) = peers.first() {
        println!("Conversation with {}", peer.address());
    } else {
        println!("No active private lobby. Use /add-peer to establish one.");
    }
    println!("Type /help for commands.");
    loop {
        let command = Input::<String>::new().with_prompt("> ").interact_text()?;
        let command = command.trim();
        if peers.is_empty()
            && (command.starts_with("/s ")
                || command.starts_with("/r ")
                || command.starts_with("/use ")
                || matches!(command, "/send" | "/receive" | "/clean" | "/cipher"))
        {
            println!("No active private lobby. Use /add-peer first.");
            continue;
        }
        if let Some(message) = command.strip_prefix("/s ") {
            if message.trim().is_empty() {
                println!("Usage: /s <plain text>");
            } else {
                send_plaintext(
                    paths,
                    password,
                    &mut histories[current],
                    state,
                    &peers[current],
                    message.as_bytes(),
                )?;
            }
            continue;
        }
        if let Some(ciphertext) = command.strip_prefix("/r ") {
            if ciphertext.trim().is_empty() {
                println!("Usage: /r <ciphertext>");
            } else {
                receive_ciphertext(
                    paths,
                    password,
                    &mut histories[current],
                    state,
                    &peers[current],
                    ciphertext,
                )?;
            }
            continue;
        }
        match command {
            "/help" => print_help(),
            "/send" => send_message(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
            )?,
            "/receive" => receive_message(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
            )?,
            "/peers" => list_peers(&peers, current)?,
            "/add-peer" => {
                let peer = futures_executor::block_on(setup_peer(paths, state))?;
                if let Some(index) = peers
                    .iter()
                    .position(|existing| existing.address() == peer.address())
                {
                    peers[index] = peer;
                    current = index;
                } else {
                    let history_path = paths.lobby_history(&peer);
                    let history = if history_path.exists() {
                        load_history(&history_path, password)?
                    } else {
                        HistoryFile {
                            version: PROFILE_VERSION,
                            entries: Vec::new(),
                        }
                    };
                    peers.push(peer);
                    histories.push(history);
                    current = peers.len() - 1;
                }
                println!("Active conversation: {}", peers[current].address());
            }
            "/keys" => match futures_executor::block_on(state.maintain_key_inventory()) {
                Ok(report) => {
                    let status = state.key_maintenance_status()?;
                    println!(
                        "Key inventory: {} one-time prekeys, {} signed prekeys{}{}",
                        report.one_time_prekeys,
                        report.signed_prekeys,
                        if report.replenished {
                            "; replenished"
                        } else {
                            ""
                        },
                        if report.rotated {
                            "; signed prekey rotated"
                        } else {
                            ""
                        },
                    );
                    println!(
                        "Maintenance failures: {} total, {} consecutive",
                        status.total_failures, status.consecutive_failures
                    );
                    if let Some(error) = status.last_error {
                        println!("Last maintenance error: {error}");
                    }
                }
                Err(error) => {
                    let status = state.key_maintenance_status()?;
                    println!("Key maintenance failed: {error:#}");
                    println!(
                        "ALERT: {} consecutive maintenance failures ({} total)",
                        status.consecutive_failures, status.total_failures
                    );
                }
            },
            "/replace-identity" => {
                if !Confirm::new()
                    .with_prompt("Replace this identity and revoke all current private lobbies?")
                    .default(false)
                    .interact()?
                {
                    continue;
                }
                let (bundle, recovery) =
                    futures_executor::block_on(state.replace_identity_with_recovery())?;
                paths.clear_peer_bundles()?;
                peers.clear();
                histories.clear();
                println!("Identity replaced. All previous sessions are revoked.");
                println!(
                    "New fingerprint: {}",
                    identity_fingerprint(&bundle.identity_key()?)
                );
                println!("Copy and send this new public bundle:");
                println!("{}", BundleTransport.encode(&bundle.encode()?));
                println!("Signed recovery record (send to existing peers):");
                println!("{}", RecoveryTransport.encode(&recovery.encode()?));
                println!("Use /add-peer to re-establish a verified private lobby.");
            }
            "/accept-recovery" => {
                let text = Input::<String>::new()
                    .with_prompt("Paste the signed recovery record")
                    .interact_text()?;
                let bytes = RecoveryTransport.decode(&text)?;
                let record = safechat::signal_adapter::IdentityRecoveryRecord::decode(&bytes)?;
                println!("Old fingerprint: {}", record.old_fingerprint());
                println!("New fingerprint: {}", record.new_fingerprint()?);
                let confirmed = Confirm::new()
                    .with_prompt(
                        "Have you verified the new fingerprint through a separate trusted channel?",
                    )
                    .default(false)
                    .interact()?;
                let bundle = futures_executor::block_on(state.accept_recovery(&record, confirmed))?;
                let history = if let Some(index) = peers
                    .iter()
                    .position(|peer| peer.address() == bundle.address())
                {
                    histories[index].clone()
                } else {
                    peers.push(bundle.clone());
                    histories.push(HistoryFile {
                        version: PROFILE_VERSION,
                        entries: Vec::new(),
                    });
                    histories.last().cloned().unwrap()
                };
                let index = peers
                    .iter()
                    .position(|peer| peer.address() == bundle.address())
                    .unwrap();
                peers[index] = bundle.clone();
                histories[index] = history;
                write_bundle(
                    &paths
                        .peers
                        .join(format!("{}.bundle", peer_file_component(&bundle))),
                    &bundle,
                )?;
                println!(
                    "Recovery accepted. The old device identity is revoked and the new lobby is ready."
                );
            }
            "/revoke-device" => {
                if peers.is_empty() {
                    println!("No active private lobby to revoke.");
                    continue;
                }
                let peer = peers[current].clone();
                if Confirm::new()
                    .with_prompt(format!(
                        "Revoke device {} and require fresh fingerprint verification?",
                        peer.address()
                    ))
                    .default(false)
                    .interact()?
                {
                    futures_executor::block_on(state.revoke_device(&peer.address()))?;
                    paths
                        .peers
                        .join(format!("{}.bundle", peer_file_component(&peer)))
                        .try_exists()
                        .ok()
                        .filter(|exists| *exists)
                        .map(|_| {
                            fs::remove_file(
                                paths
                                    .peers
                                    .join(format!("{}.bundle", peer_file_component(&peer))),
                            )
                        })
                        .transpose()?;
                    peers.remove(current);
                    histories.remove(current);
                    if peers.is_empty() {
                        println!(
                            "Device revoked. Use /add-peer to establish a fresh verified lobby."
                        );
                        current = 0;
                    } else {
                        current = current.min(peers.len() - 1);
                        println!(
                            "Device revoked. Fresh fingerprint verification is required before reuse."
                        );
                    }
                }
            }
            command if command.starts_with("/use ") => {
                let selector = command.trim_start_matches("/use ").trim();
                if let Some(index) = peers.iter().position(|peer| {
                    peer.name == selector || peer.address().to_string() == selector
                }) {
                    current = index;
                    println!("Active conversation: {}", peers[current].address());
                    show_history(&histories[current], HistoryView::Clean);
                } else {
                    println!("Unknown peer: {selector}. Use /peers to list peers.");
                }
            }
            "/clean" => show_history(&histories[current], HistoryView::Clean),
            "/cipher" => show_history(&histories[current], HistoryView::Ciphertext),
            "/bundle" => {
                let bundle = futures_executor::block_on(state.export_bundle())?;
                println!("Copy and send this public bundle:");
                println!("{}", BundleTransport.encode(&bundle.encode()?));
                println!(
                    "Fingerprint: {}",
                    identity_fingerprint(&bundle.identity_key()?)
                );
            }
            "/fingerprint" => println!(
                "Your fingerprint: {}",
                futures_executor::block_on(state.local_identity_fingerprint())?
            ),
            "/quit" | "/exit" => return Ok(()),
            "" => {}
            other => println!("Unknown command: {other}. Type /help for help."),
        }
    }
}

fn print_help() {
    println!("/s <text>  encrypt and display a message's ciphertext");
    println!("/r <cipher> decrypt a pasted ciphertext");
    println!("/send      compose and encrypt a message");
    println!("/receive   paste and decrypt ciphertext");
    println!("/peers     list trusted peers and the active conversation");
    println!("/use NAME  switch the active conversation");
    println!("/add-peer  trust another participant's bundle");
    println!("/keys      show key inventory and rotation diagnostics");
    println!("/replace-identity  revoke sessions and create a new identity");
    println!("/accept-recovery  accept a signed replacement notice after fingerprint verification");
    println!("/revoke-device  revoke the active peer device locally");
    println!("/clean     show only the readable chat");
    println!("/cipher    show the copyable encrypted chat");
    println!("/bundle    export your current public bundle");
    println!("/fingerprint  show your identity fingerprint");
    println!("/quit      close the chat");
}

fn list_peers(peers: &[SignalPreKeyBundle], active: usize) -> Result<()> {
    println!("Private lobbies:");
    for (index, peer) in peers.iter().enumerate() {
        let marker = if index == active { "*" } else { " " };
        println!(
            "{marker} {} ({})\nfingerprint: {}",
            peer.name,
            peer.address(),
            identity_fingerprint(&peer.identity_key()?)
        );
    }
    Ok(())
}

fn send_message(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
) -> Result<()> {
    let choices = ["Type a message", "Cancel"];
    let choice = Select::new()
        .with_prompt("Send")
        .items(&choices)
        .default(0)
        .interact()?;
    let plaintext = match choice {
        0 => Input::<String>::new()
            .with_prompt("Message")
            .interact_text()?
            .into_bytes(),
        _ => return Ok(()),
    };
    let (message_id, envelope) =
        futures_executor::block_on(state.encrypt_message_for(peer, &plaintext))?;
    send_envelope(
        paths, password, history, peer, message_id, &plaintext, &envelope,
    )?;
    Ok(())
}

fn send_plaintext(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
    plaintext: &[u8],
) -> Result<()> {
    let (message_id, envelope) =
        futures_executor::block_on(state.encrypt_message_for(peer, plaintext))?;
    send_envelope(
        paths, password, history, peer, message_id, plaintext, &envelope,
    )
}

fn send_envelope(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    peer: &SignalPreKeyBundle,
    message_id: MessageId,
    plaintext: &[u8],
    envelope: &[u8],
) -> Result<()> {
    let ciphertext = TextTransport.encode(envelope).trim().to_owned();
    history.entries.push(HistoryEntry {
        timestamp: now(),
        sender: "you".to_owned(),
        text: String::from_utf8_lossy(plaintext).into_owned(),
        message_id: message_id.encode(),
        peer: peer.address().to_string(),
        ciphertext: ciphertext.clone(),
    });
    save_history(&paths.lobby_history(peer), password, history)?;
    println!("Copy and send this ciphertext:");
    println!("{ciphertext}");
    Ok(())
}

fn receive_message(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
) -> Result<()> {
    let choices = ["Paste ciphertext", "Cancel"];
    let choice = Select::new()
        .with_prompt("Receive")
        .items(&choices)
        .default(0)
        .interact()?;
    let envelope = match choice {
        0 => paste_ciphertext()?,
        _ => return Ok(()),
    };
    receive_envelope(paths, password, history, state, peer, &envelope)
}

fn receive_ciphertext(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
    ciphertext: &str,
) -> Result<()> {
    let envelope = TextTransport.decode(ciphertext)?;
    receive_envelope(paths, password, history, state, peer, &envelope)
}

fn receive_envelope(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
    envelope: &[u8],
) -> Result<()> {
    let message =
        futures_executor::block_on(state.decrypt_message_from(&peer.address(), envelope))?;
    let message_id = message.id.encode();
    if history
        .entries
        .iter()
        .any(|entry| entry.message_id == message_id)
    {
        println!("Duplicate message ignored.");
        return Ok(());
    }
    let text =
        String::from_utf8(message.plaintext).context("decrypted message is not UTF-8 text")?;
    history.entries.push(HistoryEntry {
        timestamp: now(),
        sender: peer.name.clone(),
        text: text.clone(),
        message_id,
        peer: peer.address().to_string(),
        ciphertext: TextTransport.encode(envelope).trim().to_owned(),
    });
    save_history(&paths.lobby_history(peer), password, history)?;
    println!("{}: {}", peer.name, text);
    Ok(())
}

fn paste_ciphertext() -> Result<Vec<u8>> {
    let text = Input::<String>::new()
        .with_prompt("Ciphertext (paste, then press Enter)")
        .interact_text()?;
    TextTransport.decode(&text)
}

fn show_history(history: &HistoryFile, view: HistoryView) {
    if history.entries.is_empty() {
        println!("No messages yet.");
        return;
    }
    println!("Chat history:");
    for entry in &history.entries {
        let timestamp = DateTime::<Utc>::from_timestamp(entry.timestamp as i64, 0).map_or_else(
            || "unknown time".to_owned(),
            |date| date.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        match view {
            HistoryView::Ciphertext => {
                println!("[{timestamp}] {}: {}", entry.sender, entry.ciphertext)
            }
            HistoryView::Clean => println!("[{timestamp}] {}: {}", entry.sender, entry.text),
        }
    }
    println!();
}

fn load_history(path: &Path, password: &str) -> Result<HistoryFile> {
    if !path.exists() {
        return Ok(HistoryFile {
            version: PROFILE_VERSION,
            entries: Vec::new(),
        });
    }
    let input = File::open(path)?;
    let decryptor = Decryptor::new(input)?;
    let secret = age::secrecy::SecretString::from(password.to_owned());
    let identity = age::scrypt::Identity::new(secret);
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    let history: HistoryFile = serde_json::from_slice(&plaintext)?;
    if history.version != PROFILE_VERSION {
        bail!("unsupported chat history version");
    }
    Ok(history)
}

fn save_history(path: &Path, password: &str, history: &HistoryFile) -> Result<()> {
    let parent = path
        .parent()
        .context("chat history has no parent directory")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("age.tmp");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("creating temporary history {}", temporary.display()))?;
    let secret = age::secrecy::SecretString::from(password.to_owned());
    let encryptor = Encryptor::with_user_passphrase(secret);
    let mut writer = encryptor.wrap_output(file)?;
    writer.write_all(&serde_json::to_vec(history)?)?;
    writer.finish()?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
fn unique_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_history_round_trip_requires_password() {
        let path = std::env::temp_dir().join(format!("safechat-ui-history-{}.age", unique_id()));
        let history = HistoryFile {
            version: PROFILE_VERSION,
            entries: vec![HistoryEntry {
                timestamp: 1,
                sender: "alice".to_owned(),
                text: "private message".to_owned(),
                message_id: "".to_owned(),
                peer: "alice".to_owned(),
                ciphertext: "safechat-text-v1:test".to_owned(),
            }],
        };
        save_history(&path, "correct password", &history).unwrap();
        assert_eq!(
            load_history(&path, "correct password")
                .unwrap()
                .entries
                .len(),
            1
        );
        assert!(load_history(&path, "wrong password").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn fingerprint_normalization_accepts_display_separators() {
        assert_eq!(normalize_fingerprint("AA:bb cc"), "aabbcc");
    }
}
