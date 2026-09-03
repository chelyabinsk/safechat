//! Profile discovery and platform data-directory helpers.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use directories::ProjectDirs;
use safechat_core::signal::{SignalPreKeyBundle, SqliteSignalState, identity_fingerprint};
use safechat_core::transport::BundleTransport;
use std::path::PathBuf;

use super::ports::{ProfileReadyData, ProfileStore};

pub(super) struct FileProfileStore;

impl ProfileStore for FileProfileStore {
    fn available_profiles(&self) -> Result<Vec<String>> {
        available_profiles()
    }

    fn initialize(
        &self,
        profile: &str,
        password: &str,
        confirmation: &str,
    ) -> Result<ProfileReadyData> {
        let (fingerprint, bundle) = initialize_profile(profile, password, confirmation)?;
        Ok(ProfileReadyData {
            profile: profile.trim().to_owned(),
            fingerprint,
            bundle,
            contact: load_saved_contact(profile).ok().flatten(),
        })
    }

    fn verify_contact(
        &self,
        profile: &str,
        password: &str,
        bundle: &str,
        fingerprint: &str,
    ) -> Result<(String, String)> {
        verify_add_contact(profile, password, bundle, fingerprint)
    }
}

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

pub fn data_directory() -> Result<PathBuf> {
    Ok(ProjectDirs::from("", "SafeChat", "safechat")
        .context("cannot determine the platform data directory")?
        .data_dir()
        .to_path_buf())
}

pub(super) fn profile_root() -> Result<PathBuf> {
    data_directory()
}

pub(super) fn profile_database(profile: &str) -> Result<PathBuf> {
    let profile = validate_profile_name(profile)?;
    let root = profile_root()?.join(profile);
    std::fs::create_dir_all(&root).context("creating the SafeChat profile directory")?;
    Ok(root.join("identity.db"))
}

pub fn profile_directory(profile: &str) -> Result<PathBuf> {
    profile_database(profile)?
        .parent()
        .map(PathBuf::from)
        .context("profile database has no parent directory")
}

pub fn chat_history_file(profile: &str, peer: &str) -> Result<PathBuf> {
    let component = peer
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(profile_directory(profile)?
        .join("lobbies")
        .join(format!("{component}.age")))
}

fn preferences_path(profile: &str) -> Result<PathBuf> {
    Ok(profile_directory(profile)?.join("preferences.json"))
}

fn load_preferences(profile: &str) -> Result<serde_json::Map<String, serde_json::Value>> {
    let path = preferences_path(profile)?;
    if !path.is_file() {
        return Ok(serde_json::Map::new());
    }
    let contents = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<serde_json::Value>(&contents)?
        .as_object()
        .cloned()
        .unwrap_or_default())
}

fn save_preferences(
    profile: &str,
    preferences: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    std::fs::write(
        preferences_path(profile)?,
        serde_json::Value::Object(preferences).to_string(),
    )?;
    Ok(())
}

pub(super) fn load_language(profile: &str) -> Result<Option<String>> {
    Ok(load_preferences(profile)?
        .get("language")
        .and_then(|value| value.as_str())
        .map(str::to_owned))
}

pub(super) fn save_language(profile: &str, language: &str) -> Result<()> {
    let mut preferences = load_preferences(profile)?;
    preferences.insert("language".to_owned(), language.into());
    save_preferences(profile, preferences)
}

pub(super) fn validate_profile_name(profile: &str) -> Result<&str> {
    let profile = profile.trim();
    if profile.is_empty()
        || profile == "."
        || profile == ".."
        || profile.contains('/')
        || profile.contains('\\')
    {
        bail!("profile name must be a simple non-empty name");
    }
    Ok(profile)
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

#[cfg(test)]
mod tests {
    use super::validate_profile_name;

    #[test]
    fn profile_names_are_trimmed_without_becoming_paths() {
        assert_eq!(validate_profile_name("  alice  ").unwrap(), "alice");
    }

    #[test]
    fn profile_names_reject_empty_and_path_like_values() {
        for value in ["", "   ", ".", "..", "alice/bob", r"alice\bob"] {
            assert!(validate_profile_name(value).is_err(), "accepted {value:?}");
        }
    }
}
