use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use console::{Key, Term};
use dialoguer::{Confirm, Input, Password, Select};
use directories::ProjectDirs;
use safechat::chat_service::{ChatEvent, ChatService};
use safechat::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryFile, PROFILE_VERSION, RelayConfig, load_history,
    load_relay_config, load_relay_peer_ids, load_relay_token, save_history, save_relay_config,
    save_relay_peer_ids, save_relay_token,
};
use safechat::relay_client::{RelayClient, RelayClientConfig};
use safechat::relay_transport::RelayTransport;
use safechat::signal_adapter::{
    MessageId, SignalPreKeyBundle, SqliteSignalState, identity_fingerprint,
};
use safechat::transport::{BundleTransport, RecoveryTransport, TextTransport};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(clap::Parser)]
#[command(name = "safechat-ui", version, about = "Friendly SafeChat text chat")]
struct Cli {
    /// Profile name stored below the platform application-data directory.
    #[arg(long, default_value = "default")]
    profile: String,
    /// Override the platform application-data directory.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Relay endpoint. HTTPS is required unless HTTP is explicitly confirmed in the UI.
    #[arg(long)]
    relay_url: Option<String>,
    /// Allowlisted relay client ID.
    #[arg(long)]
    relay_client_id: Option<String>,
    /// One-time enrollment secret, used only when no saved relay session exists.
    #[arg(long)]
    relay_enrollment_secret: Option<String>,
    /// Optional CA certificate for a local/test relay.
    #[arg(long)]
    relay_ca_cert: Option<PathBuf>,
}

#[derive(Clone)]
struct ProfilePaths {
    root: PathBuf,
    database: PathBuf,
    history: PathBuf,
    lobby_histories: PathBuf,
    peers: PathBuf,
    relay_session: PathBuf,
    relay_config: PathBuf,
    relay_peers: PathBuf,
}

#[derive(Clone, Copy)]
enum HistoryView {
    Ciphertext,
    Clean,
}

struct RelayOptions {
    base_url: String,
    client_id: String,
    enrollment_secret: String,
    ca_certificate_pem: Option<Vec<u8>>,
    allow_insecure_http: bool,
}

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();
    let paths = ProfilePaths::new(cli.data_dir.clone(), &cli.profile)?;
    paths.create()?;
    let password = unlock_password(&paths.history)?;
    let mut state = futures_executor::block_on(open_or_initialize(&paths, &password))?;
    restrict_file(&paths.database)?;
    // Refresh the local prekey inventory and rotate lifecycle keys before
    // loading the private lobbies.
    futures_executor::block_on(state.export_bundle())?;

    let mut peers = load_peers(&paths.peers)?;
    let saved_relay_config = load_relay_config(&paths.relay_config, &password)?;
    let relay_options = choose_transport(&cli, saved_relay_config.as_ref())?;
    if let Some(options) = relay_options.as_ref() {
        save_relay_config(
            &paths.relay_config,
            &password,
            &RelayConfig {
                base_url: options.base_url.clone(),
                allow_insecure_http: options.allow_insecure_http,
            },
        )?;
    }
    let mut relay = setup_relay(&paths, &password, &mut state, relay_options.as_ref())?;
    if peers.is_empty() {
        println!("No conversation is configured yet.");
        let peer = if let Some(runtime) = relay.as_mut() {
            let name = Input::<String>::new()
                .with_prompt("Peer relay client ID")
                .interact_text()?;
            add_relay_peer(&paths, &password, &mut state, runtime, &name)?
        } else {
            println!("We will create your identity and guide you through setup.");
            futures_executor::block_on(setup_peer(&paths, &mut state))?
        };
        peers.push(peer);
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

    if let Some(history) = histories.first() {
        show_history(history, HistoryView::Clean);
    } else {
        println!("No private lobby configured. Use /add-peer.");
    }
    chat_loop(&paths, &password, &mut histories, &mut state, peers, relay)
}

fn setup_relay(
    paths: &ProfilePaths,
    password: &str,
    state: &mut SqliteSignalState,
    options: Option<&RelayOptions>,
) -> Result<Option<RelayTransport>> {
    let Some(options) = options else {
        return Ok(None);
    };
    let identity = futures_executor::block_on(state.local_identity_key_pair())?;
    let client_id = if options.client_id.is_empty() {
        generated_relay_client_id(&identity)
    } else {
        options.client_id.clone()
    };
    let config = RelayClientConfig {
        base_url: options.base_url.clone(),
        client_id: client_id.clone(),
        enrollment_secret: options.enrollment_secret.clone(),
        ca_certificate_pem: options.ca_certificate_pem.clone(),
        allow_insecure_http: options.allow_insecure_http,
    };
    let mut client = RelayClient::new(config, identity)?;
    if paths.relay_session.exists() {
        let token = load_relay_token(&paths.relay_session, password)?;
        client.restore_access_token(token);
    } else {
        let bundle = futures_executor::block_on(state.export_bundle())?;
        println!("Relay enrollment details:");
        println!("Client ID: {client_id}");
        println!(
            "Identity key: {}",
            URL_SAFE_NO_PAD.encode(identity.identity_key().serialize().as_ref())
        );
        println!(
            "Fingerprint: {}",
            futures_executor::block_on(state.local_identity_fingerprint())?
        );
        let registration = loop {
            match client.register(&bundle) {
                Ok(registration) => break registration,
                Err(error) => {
                    println!("Relay enrollment is not complete: {error:#}");
                    println!("Have the administrator allowlist the details above, then retry.");
                    if !Confirm::new()
                        .with_prompt("Retry relay enrollment now?")
                        .default(true)
                        .interact()?
                    {
                        return Err(error);
                    }
                }
            }
        };
        save_relay_token(&paths.relay_session, password, &registration.access_token)?;
    }
    println!("Relay transport enabled for {client_id}.");
    Ok(Some(RelayTransport::new(
        client,
        load_relay_peer_ids(&paths.relay_peers, password)?,
    )))
}

fn generated_relay_client_id(identity: &signal_protocol::IdentityKeyPair) -> String {
    let digest = Sha256::digest(identity.identity_key().serialize().as_ref());
    format!("sc-{}", URL_SAFE_NO_PAD.encode(&digest[..12]))
}

fn choose_transport(cli: &Cli, saved: Option<&RelayConfig>) -> Result<Option<RelayOptions>> {
    let choices = ["Copy/paste", "Relay"];
    let choice = Select::new()
        .with_prompt("Transport")
        .items(&choices)
        .default(if cli.relay_url.is_some() || saved.is_some() {
            1
        } else {
            0
        })
        .interact()?;
    if choice == 0 {
        return Ok(None);
    }
    Ok(Some(prompt_relay_options(
        cli.relay_url.as_ref(),
        cli.relay_client_id.as_ref(),
        cli.relay_enrollment_secret.as_ref(),
        cli.relay_ca_cert.as_ref(),
        saved,
    )?))
}

fn prompt_relay_options(
    base_url: Option<&String>,
    client_id: Option<&String>,
    enrollment_secret: Option<&String>,
    ca_certificate: Option<&PathBuf>,
    saved: Option<&RelayConfig>,
) -> Result<RelayOptions> {
    let base_url = base_url
        .cloned()
        .or_else(|| saved.map(|config| config.base_url.clone()))
        .unwrap_or_else(|| {
            Input::<String>::new()
                .with_prompt("Relay URL (https:// recommended)")
                .interact_text()
                .unwrap_or_default()
        });
    let allow_insecure_http = if base_url.starts_with("http://")
        && saved.map_or(true, |config| {
            config.base_url != base_url || !config.allow_insecure_http
        }) {
        Confirm::new()
            .with_prompt(
                "This relay uses unencrypted HTTP. Message contents remain end-to-end encrypted, but credentials and metadata can be intercepted. Continue?",
            )
            .default(false)
            .interact()?
    } else {
        false
    };
    let client_id = client_id.cloned().unwrap_or_default();
    let enrollment_secret = enrollment_secret.cloned().unwrap_or_else(|| {
        Password::new()
            .with_prompt("Relay enrollment secret (leave empty if already registered)")
            .allow_empty_password(true)
            .interact()
            .unwrap_or_default()
    });
    let ca_certificate_pem = match ca_certificate {
        Some(path) => Some(fs::read(path).context("reading relay CA certificate")?),
        None if saved.is_some() => None,
        None => {
            let path = Input::<String>::new()
                .with_prompt("Relay CA certificate path (leave empty for a public CA)")
                .allow_empty(true)
                .interact_text()?;
            if path.trim().is_empty() {
                None
            } else {
                Some(fs::read(path.trim()).context("reading relay CA certificate")?)
            }
        }
    };
    Ok(RelayOptions {
        base_url,
        client_id,
        enrollment_secret,
        ca_certificate_pem,
        allow_insecure_http,
    })
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
            relay_session: root.join("relay-session.age"),
            relay_config: root.join("relay-config.age"),
            relay_peers: root.join("relay-peers.age"),
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

fn add_relay_peer(
    paths: &ProfilePaths,
    password: &str,
    state: &mut SqliteSignalState,
    runtime: &mut RelayTransport,
    client_id: &str,
) -> Result<SignalPreKeyBundle> {
    let bundle = runtime.fetch_peer_bundle_by_id(client_id)?;
    let fingerprint = identity_fingerprint(&bundle.identity_key()?);
    println!(
        "Relay returned {} with fingerprint: {fingerprint}",
        bundle.address()
    );
    let expected = Input::<String>::new()
        .with_prompt("Enter the fingerprint verified separately")
        .interact_text()?;
    if normalize_fingerprint(&expected) != normalize_fingerprint(&fingerprint) {
        bail!("fingerprint does not match; the peer was not trusted");
    }
    futures_executor::block_on(state.trust_bundle(&bundle))?;
    runtime.set_peer_id(bundle.name.clone(), client_id.to_owned());
    save_relay_peer_ids(&paths.relay_peers, password, runtime.peer_ids())?;
    write_bundle(
        &paths
            .peers
            .join(format!("{}.bundle", peer_file_component(&bundle))),
        &bundle,
    )?;
    println!("Peer trusted through relay.");
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

fn chat_loop(
    paths: &ProfilePaths,
    password: &str,
    histories: &mut Vec<HistoryFile>,
    state: &mut SqliteSignalState,
    mut peers: Vec<SignalPreKeyBundle>,
    mut relay: Option<RelayTransport>,
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
        let command = if let Some(runtime) = relay.as_mut() {
            read_relay_input(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
                runtime,
            )?
        } else {
            Input::<String>::new().with_prompt("> ").interact_text()?
        };
        let command = command.trim();
        if peers.is_empty()
            && (command.starts_with("/s ")
                || command.starts_with("/r ")
                || command.starts_with("/use ")
                || matches!(command, "/r" | "/send" | "/receive" | "/clean" | "/cipher"))
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
                    relay.as_mut(),
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
                    relay.as_mut(),
                )?;
            }
            continue;
        }
        if relay.is_some() && !command.starts_with('/') && !command.is_empty() {
            send_plaintext(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
                command.as_bytes(),
                relay.as_mut(),
            )?;
            continue;
        }
        match command {
            "/help" => print_help(),
            "/transport" => show_transport_info(relay.as_ref()),
            "/transport copy" => {
                relay = None;
                println!("Transport changed to Copy/paste.");
            }
            "/transport relay" => {
                if relay.is_some() {
                    println!("Already using Relay transport.");
                    show_transport_info(relay.as_ref());
                } else {
                    let options = prompt_relay_options(None, None, None, None, None)?;
                    relay = setup_relay(paths, password, state, Some(&options))?;
                    save_relay_config(
                        &paths.relay_config,
                        password,
                        &RelayConfig {
                            base_url: options.base_url.clone(),
                            allow_insecure_http: options.allow_insecure_http,
                        },
                    )?;
                    println!("Transport changed to Relay.");
                }
            }
            "/transport relay edit" => {
                let options = prompt_relay_options(None, None, None, None, None)?;
                relay = setup_relay(paths, password, state, Some(&options))?;
                save_relay_config(
                    &paths.relay_config,
                    password,
                    &RelayConfig {
                        base_url: options.base_url.clone(),
                        allow_insecure_http: options.allow_insecure_http,
                    },
                )?;
                println!("Relay transport settings updated.");
            }
            "/send" => send_message(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
                relay.as_mut(),
            )?,
            "/r" => receive_message(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
                relay.as_mut(),
            )?,
            "/receive" => receive_message(
                paths,
                password,
                &mut histories[current],
                state,
                &peers[current],
                relay.as_mut(),
            )?,
            "/peers" => list_peers(&peers, current)?,
            "/add-peer" => {
                let peer = if let Some(runtime) = relay.as_mut() {
                    let name = Input::<String>::new()
                        .with_prompt("Peer relay client ID")
                        .interact_text()?;
                    add_relay_peer(paths, password, state, runtime, &name)?
                } else {
                    futures_executor::block_on(setup_peer(paths, state))?
                };
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
    println!("In relay mode, type normal text to send it automatically.");
    println!("/s <text>  send text (relay) or display ciphertext (copy/paste)");
    println!("/r <cipher> decrypt a pasted ciphertext, or poll relay when used alone");
    println!("/transport  show the active transport");
    println!("/transport copy|relay  change transport");
    println!("/transport relay edit  edit relay settings");
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

fn show_transport_info(relay: Option<&RelayTransport>) {
    match relay {
        Some(runtime) => {
            println!("Transport: Relay");
            println!("Relay URL: {}", runtime.base_url());
            println!("Relay client ID: {}", runtime.client_id());
            println!(
                "Relay session: {}",
                if runtime.is_registered() {
                    "registered"
                } else {
                    "not registered"
                }
            );
        }
        None => println!("Transport: Copy/paste"),
    }
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
    relay: Option<&mut RelayTransport>,
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
    send_plaintext(paths, password, history, state, peer, &plaintext, relay)
}

fn send_plaintext(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
    plaintext: &[u8],
    mut relay: Option<&mut RelayTransport>,
) -> Result<()> {
    let encryption_peer = match relay.as_deref_mut() {
        Some(runtime) => runtime.fetch_peer_bundle(peer)?,
        None => peer.clone(),
    };
    if let Some(runtime) = relay {
        let recipient = runtime.recipient_for(peer);
        let mut history_store = EncryptedHistoryStore::new(&paths.lobby_histories, password);
        let event = {
            let mut service = ChatService::new(
                state,
                runtime,
                &mut history_store,
                peer.address().to_string(),
            );
            service.send_text(history, peer, &encryption_peer, &recipient, plaintext)?
        };
        if let ChatEvent::Sent { timestamp, text } = event {
            println!("  [{}] you: {} [sent]", format_timestamp(timestamp), text);
        }
        return Ok(());
    }
    let (message_id, envelope) =
        futures_executor::block_on(state.encrypt_message_for(&encryption_peer, plaintext))?;
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
    let timestamp = now();
    history.entries.push(HistoryEntry {
        timestamp,
        sender: "you".to_owned(),
        text: String::from_utf8_lossy(plaintext).into_owned(),
        message_id: message_id.encode(),
        peer: peer.address().to_string(),
        ciphertext: ciphertext.clone(),
        delivery_status: String::new(),
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
    relay: Option<&mut RelayTransport>,
) -> Result<()> {
    if let Some(runtime) = relay {
        let received = receive_relay(paths, password, history, state, peer, runtime)?;
        if received == 0 {
            println!("No new relay messages for {}.", peer.address());
        }
        return Ok(());
    }
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
    _relay: Option<&mut RelayTransport>,
) -> Result<()> {
    let envelope = TextTransport.decode(ciphertext)?;
    receive_envelope(paths, password, history, state, peer, &envelope)
}

fn receive_relay(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
    runtime: &mut RelayTransport,
) -> Result<usize> {
    let relay_sender_id = runtime.sender_id_for(peer).map(str::to_owned);
    let mut history_store = EncryptedHistoryStore::new(&paths.lobby_histories, password);
    let events = {
        let mut service = ChatService::new(
            state,
            runtime,
            &mut history_store,
            peer.address().to_string(),
        );
        service.poll(history, peer, relay_sender_id.as_deref())?
    };
    for event in &events {
        match event {
            ChatEvent::Read { timestamp, text } => {
                println!("  [{}] you: {} [read]", format_timestamp(*timestamp), text);
            }
            ChatEvent::Received {
                timestamp,
                sender,
                text,
            } => println!("[{}] {}: {}", format_timestamp(*timestamp), sender, text),
            ChatEvent::Stale { transport_id } => {
                println!("Discarding stale relay message {transport_id} after ratchet recovery.");
            }
            ChatEvent::Sent { .. } => {}
        }
    }
    Ok(events.len())
}

/// Read a relay-mode chat line while periodically checking for incoming mail.
///
/// `dialoguer::Input` is intentionally kept for the copy/paste workflow and
/// for commands that need a secondary prompt. Relay mode gets a small terminal
/// editor so the main thread can poll the relay without waiting for Enter.
fn read_relay_input(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
    runtime: &mut RelayTransport,
) -> Result<String> {
    let term = Term::stdout();
    let _raw_mode = RawMode::new()?;
    let mut line = String::new();
    term.write_str("> ")?;
    loop {
        match read_relay_key(&term)? {
            Some(Key::Char(character)) => {
                line.push(character);
                term.write_str(&character.to_string())?;
            }
            Some(Key::Backspace) => {
                if line.pop().is_some() {
                    term.write_str("\x08 \x08")?;
                }
            }
            Some(Key::Enter) => {
                term.write_line("")?;
                return Ok(line);
            }
            Some(Key::CtrlC) => {
                term.write_line("^C")?;
                return Ok("/quit".to_owned());
            }
            Some(Key::Escape) => {
                line.clear();
                term.write_str("\r\x1b[2K> ")?;
            }
            Some(_) | None => {}
        }

        if receive_relay(paths, password, history, state, peer, runtime)? > 0 {
            term.write_str(&format!("\r\x1b[2K> {line}"))?;
        }
    }
}

#[cfg(unix)]
struct RawMode {
    original: libc::termios,
}

#[cfg(unix)]
impl RawMode {
    fn new() -> Result<Self> {
        let input = io::stdin();
        let fd = input.as_raw_fd();
        let mut original = std::mem::MaybeUninit::uninit();
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSADRAIN, &raw) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { original })
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    fn drop(&mut self) {
        let fd = io::stdin().as_raw_fd();
        unsafe {
            libc::tcsetattr(fd, libc::TCSADRAIN, &self.original);
        }
    }
}

#[cfg(not(unix))]
struct RawMode;

#[cfg(not(unix))]
impl RawMode {
    fn new() -> Result<Self> {
        Ok(Self)
    }
}

fn read_relay_key(term: &Term) -> Result<Option<Key>> {
    #[cfg(unix)]
    {
        let mut descriptor = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 500) };
        if result < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if result == 0 {
            return Ok(None);
        }
    }

    #[cfg(not(unix))]
    let _ = term;

    Ok(Some(term.read_key()?))
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
    let timestamp = now();
    history.entries.push(HistoryEntry {
        timestamp,
        sender: peer.name.clone(),
        text: text.clone(),
        message_id,
        peer: peer.address().to_string(),
        ciphertext: TextTransport.encode(envelope).trim().to_owned(),
        delivery_status: "received".to_owned(),
    });
    save_history(&paths.lobby_history(peer), password, history)?;
    println!("[{}] {}: {}", format_timestamp(timestamp), peer.name, text);
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
        let timestamp = format_timestamp(entry.timestamp);
        let indent = if entry.sender == "you" { "  " } else { "" };
        let status = match entry.delivery_status.as_str() {
            "sent" => " [sent]",
            "delivered" => " [delivered]",
            "read" => " [read]",
            "failed" => " [failed]",
            _ => "",
        };
        match view {
            HistoryView::Ciphertext => {
                println!(
                    "{indent}[{timestamp}] {}: {}{}",
                    entry.sender, entry.ciphertext, status
                )
            }
            HistoryView::Clean => {
                println!(
                    "{indent}[{timestamp}] {}: {}{}",
                    entry.sender, entry.text, status
                )
            }
        }
    }
    println!();
}

fn format_timestamp(timestamp: u64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp as i64, 0).map_or_else(
        || "unknown time".to_owned(),
        |date| date.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    )
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
                delivery_status: String::new(),
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
