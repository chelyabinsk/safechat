use age::{Decryptor, Encryptor};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use dialoguer::{Confirm, Input, Password, Select};
use directories::ProjectDirs;
use safechat::signal_adapter::{SignalPreKeyBundle, SqliteSignalState, identity_fingerprint};
use safechat::transport::{BundleTransport, TextTransport};
use serde::{Deserialize, Serialize};
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
    outbox: PathBuf,
    inbox: PathBuf,
    peers: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct HistoryFile {
    version: u32,
    entries: Vec<HistoryEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HistoryEntry {
    timestamp: u64,
    sender: String,
    text: String,
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
    let mut history = load_history(&paths.history, &password)?;
    let mut state = futures_executor::block_on(open_or_initialize(&paths))?;
    restrict_file(&paths.database)?;

    let mut peer = if paths.peer_bundle().exists() {
        Some(load_bundle(&paths.peer_bundle())?)
    } else {
        None
    };

    if peer.is_none() {
        println!("No conversation is configured yet.");
        println!("We will create your identity and guide you through setup.");
        peer = Some(futures_executor::block_on(setup_peer(&paths, &mut state))?);
    }

    let view = choose_history_view()?;
    show_history(&history, view);
    chat_loop(
        &paths,
        &password,
        &mut history,
        &mut state,
        peer.expect("peer configured"),
    )
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
            outbox: root.join("outbox"),
            inbox: root.join("inbox"),
            peers: root.join("peers"),
        })
    }

    fn create(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        restrict_directory(&self.root)?;
        fs::create_dir_all(&self.outbox)?;
        fs::create_dir_all(&self.inbox)?;
        fs::create_dir_all(&self.peers)?;
        restrict_directory(&self.outbox)?;
        restrict_directory(&self.inbox)?;
        restrict_directory(&self.peers)?;
        Ok(())
    }

    fn peer_bundle(&self) -> PathBuf {
        self.peers.join("active.bundle.txt")
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

async fn open_or_initialize(paths: &ProfilePaths) -> Result<SqliteSignalState> {
    if paths.database.exists() {
        let state = SqliteSignalState::open(&paths.database).await?;
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
    let state = SqliteSignalState::initialize(&paths.database, &name, 1).await?;
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
    let own_bundle_path = paths.outbox.join("my-bundle.txt");
    write_bundle(&own_bundle_path, &own_bundle)?;
    println!();
    println!("Send your public bundle to the other person:");
    println!("  {}", own_bundle_path.display());
    println!(
        "Your fingerprint: {}",
        identity_fingerprint(&own_bundle.identity_key()?)
    );
    println!("Verify the other person's fingerprint through your separate trusted channel.");

    let bundle = read_bundle_prompt("Enter the other person's bundle path or paste its text")?;
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
    write_bundle(&paths.peer_bundle(), &bundle)?;
    println!("Peer trusted. You can now exchange encrypted messages.");
    Ok(bundle)
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
    let first = Input::<String>::new().with_prompt(prompt).interact_text()?;
    let bytes = if Path::new(&first).is_file() {
        let text = fs::read_to_string(&first)?;
        BundleTransport.decode(&text)?
    } else {
        let mut text = first;
        if !text.trim().starts_with("safechat-bundle-v1:") {
            println!("Paste the bundle text, then enter END on its own line.");
            loop {
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                if line.trim() == "END" {
                    break;
                }
                text.push_str(&line);
            }
        }
        BundleTransport.decode(&text)?
    };
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
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: SignalPreKeyBundle,
) -> Result<()> {
    println!();
    println!("Conversation with {}", peer.address());
    println!("Type /help for commands.");
    loop {
        let command = Input::<String>::new().with_prompt("> ").interact_text()?;
        match command.trim() {
            "/help" => print_help(),
            "/send" => send_message(paths, password, history, state, &peer)?,
            "/receive" => receive_message(paths, password, history, state, &peer)?,
            "/clean" => show_history(history, HistoryView::Clean),
            "/cipher" => show_history(history, HistoryView::Ciphertext),
            "/bundle" => {
                let bundle = futures_executor::block_on(state.export_bundle())?;
                let path = paths.outbox.join("my-bundle.txt");
                write_bundle(&path, &bundle)?;
                println!("Updated public bundle written to {}", path.display());
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
    println!("/send      compose a message or choose a plaintext file");
    println!("/receive   open a ciphertext file or paste ciphertext");
    println!("/clean     show only the readable chat");
    println!("/cipher    show the copyable encrypted chat");
    println!("/bundle    export your current public bundle");
    println!("/fingerprint  show your identity fingerprint");
    println!("/quit      close the chat");
}

fn send_message(
    paths: &ProfilePaths,
    password: &str,
    history: &mut HistoryFile,
    state: &mut SqliteSignalState,
    peer: &SignalPreKeyBundle,
) -> Result<()> {
    let choices = ["Type a message", "Read a plaintext file", "Cancel"];
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
        1 => {
            let path = Input::<String>::new()
                .with_prompt("Plaintext file")
                .interact_text()?;
            let path = PathBuf::from(path);
            fs::read(&path).with_context(|| format!("reading plaintext file {}", path.display()))?
        }
        _ => return Ok(()),
    };
    let envelope = futures_executor::block_on(state.encrypt_for(peer, &plaintext))?;
    let path = paths
        .outbox
        .join(format!("message-{}.safechat", unique_id()));
    let ciphertext = TextTransport.encode(&envelope).trim().to_owned();
    fs::write(&path, &ciphertext)?;
    history.entries.push(HistoryEntry {
        timestamp: now(),
        sender: "you".to_owned(),
        text: String::from_utf8_lossy(&plaintext).into_owned(),
        ciphertext: ciphertext.clone(),
    });
    save_history(&paths.history, password, history)?;
    println!("Encrypted message written to {}", path.display());
    println!("Ciphertext to send:");
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
    let choices = [
        "Type or paste ciphertext",
        "Open a ciphertext file",
        "Cancel",
    ];
    let choice = Select::new()
        .with_prompt("Receive")
        .items(&choices)
        .default(0)
        .interact()?;
    let envelope = match choice {
        0 => paste_ciphertext()?,
        1 => {
            let path = Input::<String>::new()
                .with_prompt("Ciphertext file")
                .interact_text()?;
            let path = PathBuf::from(path);
            read_ciphertext(&path)?
        }
        _ => return Ok(()),
    };
    let plaintext = futures_executor::block_on(state.decrypt_from(&peer.address(), &envelope))?;
    let text = String::from_utf8(plaintext).context("decrypted message is not UTF-8 text")?;
    history.entries.push(HistoryEntry {
        timestamp: now(),
        sender: peer.name.clone(),
        text: text.clone(),
        ciphertext: TextTransport.encode(&envelope).trim().to_owned(),
    });
    save_history(&paths.history, password, history)?;
    println!("{}: {}", peer.name, text);
    Ok(())
}

fn read_ciphertext(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("reading ciphertext {}", path.display()))?;
    if let Ok(text) = std::str::from_utf8(&bytes)
        && text
            .trim_start()
            .starts_with(safechat::transport::TEXT_HEADER)
    {
        return TextTransport.decode(text);
    }
    Ok(bytes)
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
