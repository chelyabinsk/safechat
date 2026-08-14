//! Profile discovery and platform data-directory helpers.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::ProjectDirs;
use safechat_core::signal_adapter::{SignalPreKeyBundle, SqliteSignalState};
use safechat_core::transport::BundleTransport;
use std::path::PathBuf;

pub fn available_profiles() -> Result<Vec<String>> {
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

pub(super) fn profile_root() -> Result<PathBuf> {
    Ok(ProjectDirs::from("", "SafeChat", "safechat")
        .context("cannot determine the platform data directory")?
        .data_dir()
        .to_path_buf())
}

pub(super) fn profile_database(profile: &str) -> Result<PathBuf> {
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

pub(super) fn initialize_profile(
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

pub(super) fn peer_bundle_from_encoded(encoded: &str) -> Result<SignalPreKeyBundle> {
    let bytes = BundleTransport.decode(encoded.trim())?;
    SignalPreKeyBundle::decode(&bytes)
}

pub(super) fn load_saved_contact(profile: &str) -> Result<Option<(String, String)>> {
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

pub(super) fn verify_add_contact(
    profile: &str,
    password: &str,
    encoded_bundle: &str,
    expected_fingerprint: &str,
) -> Result<(String, String)> {
    let database = profile_database(profile)?;
    let bundle = peer_bundle_from_encoded(encoded_bundle)?;
    let actual_fingerprint =
        safechat_core::signal_adapter::identity_fingerprint(&bundle.identity_key()?);
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
