use crate::UiText;
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocaleFile {
    my_profile: String,
    ready: String,
    conversations: String,
    search_conversations: String,
    new_conversation: String,
    verified_contact: String,
    no_conversations: String,
    verified_encrypted: String,
    load_older: String,
    new_conversation_help: String,
    contact_bundle: String,
    contact_fingerprint: String,
    profile_password: String,
    verify_add_contact: String,
    contact_added: String,
    select_conversation: String,
    type_message: String,
    send: String,
    paste_encrypted: String,
    receive_pasted: String,
    unlock: String,
    create_profile: String,
    unlock_help: String,
    create_help: String,
    profile_name: String,
    password: String,
    confirm_password: String,
    create_profile_button: String,
    unlock_profile: String,
    back_to_profiles: String,
    create_new_profile: String,
    fingerprint: String,
    your_fingerprint: String,
    share_bundle: String,
    copy_bundle: String,
    close: String,
}

impl From<LocaleFile> for UiText {
    fn from(value: LocaleFile) -> Self {
        Self {
            my_profile: value.my_profile.into(),
            ready: value.ready.into(),
            conversations: value.conversations.into(),
            search_conversations: value.search_conversations.into(),
            new_conversation: value.new_conversation.into(),
            verified_contact: value.verified_contact.into(),
            no_conversations: value.no_conversations.into(),
            verified_encrypted: value.verified_encrypted.into(),
            load_older: value.load_older.into(),
            new_conversation_help: value.new_conversation_help.into(),
            contact_bundle: value.contact_bundle.into(),
            contact_fingerprint: value.contact_fingerprint.into(),
            profile_password: value.profile_password.into(),
            verify_add_contact: value.verify_add_contact.into(),
            contact_added: value.contact_added.into(),
            select_conversation: value.select_conversation.into(),
            type_message: value.type_message.into(),
            send: value.send.into(),
            paste_encrypted: value.paste_encrypted.into(),
            receive_pasted: value.receive_pasted.into(),
            unlock: value.unlock.into(),
            create_profile: value.create_profile.into(),
            unlock_help: value.unlock_help.into(),
            create_help: value.create_help.into(),
            profile_name: value.profile_name.into(),
            password: value.password.into(),
            confirm_password: value.confirm_password.into(),
            create_profile_button: value.create_profile_button.into(),
            unlock_profile: value.unlock_profile.into(),
            back_to_profiles: value.back_to_profiles.into(),
            create_new_profile: value.create_new_profile.into(),
            fingerprint: value.fingerprint.into(),
            your_fingerprint: value.your_fingerprint.into(),
            share_bundle: value.share_bundle.into(),
            copy_bundle: value.copy_bundle.into(),
            close: value.close.into(),
        }
    }
}

fn locale_paths(language: &str) -> Vec<PathBuf> {
    let filename = format!("{}.json", language.to_ascii_lowercase());
    let mut paths = Vec::new();
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            paths.push(directory.join("locales").join(&filename));
            // Cargo's development layout: target/{debug,release}/../..
            // points back to the workspace, where the UI locale directory lives.
            paths.push(directory.join("../../slint-ui/locales").join(&filename));
        }
    }
    paths.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("locales")
            .join(&filename),
    );
    paths.push(PathBuf::from("locales").join(filename));
    paths
}

fn read_locale(path: &Path) -> Result<UiText> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("could not read locale file {}", path.display()))?;
    Ok(serde_json::from_str::<LocaleFile>(&contents)
        .with_context(|| format!("could not parse locale file {}", path.display()))?
        .into())
}

/// Load a locale from files next to the executable. English is the fallback
/// when a requested locale is not installed; malformed files are reported.
pub fn load(language: &str) -> Result<UiText> {
    let requested = if language.is_empty() { "en" } else { language };
    match locale_paths(requested).iter().find(|path| path.is_file()) {
        Some(path) => read_locale(path),
        None if !requested.eq_ignore_ascii_case("en") => load("en"),
        None => Err(anyhow!("English locale file is not installed")),
    }
}

#[cfg(test)]
mod tests {
    use super::load;

    #[test]
    fn english_is_the_default_locale() {
        assert_eq!(load("en").unwrap().send, "Send");
        assert_eq!(load("unknown").unwrap().send, "Send");
    }

    #[test]
    fn russian_is_loaded_from_an_external_file() {
        assert_eq!(load("ru").unwrap().send, "Отправить");
    }
}
