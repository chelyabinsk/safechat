use crate::UiText;
use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocaleFile {
    statuses: HashMap<String, String>,
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
    you: String,
    today: String,
    yesterday: String,
    copied: String,
    chat_history_loaded: String,
    sent: String,
    received: String,
    decrypting_chat_history: String,
    encrypting_sending: String,
    decrypting_pasted: String,
    copy_paste: String,
    relay: String,
    language_english: String,
    language_russian: String,
}

fn status_key(status: &str) -> Option<(&str, &str)> {
    let exact = match status {
        "Ready" => "ready",
        "Chat history loaded." => "chat_history_loaded",
        "Unlocking encrypted profile…" => "unlocking_profile",
        "Verifying contact…" => "verifying_contact",
        "Profile ready. Verify fingerprints through a separate trusted channel." => "profile_ready",
        "Conversation selected." => "conversation_selected",
        "Message sent." => "message_sent",
        "Encrypted message ready. Click the message to copy its ciphertext." => "encrypted_ready",
        "Encrypted message received." => "encrypted_received",
        "New message received." => "new_message_received",
        "Chat is up to date." => "chat_up_to_date",
        "Add and select a contact first." => "add_contact_first",
        "Type a message first." => "type_message_first",
        "Paste an encrypted message first." => "paste_encrypted_first",
        "copied"
        | "Copied"
        | "Ciphertext copied to clipboard."
        | "Public bundle copied to clipboard."
        | "Fingerprint copied to clipboard." => "copied",
        _ => return None,
    };
    Some((exact, ""))
}

/// Translate a runtime status while leaving service-provided error details intact.
pub fn status_text(status: &str, language: &str) -> String {
    let locale = load_file(language).or_else(|_| load_file("en"));
    let Ok(locale) = locale else {
        return status.to_owned();
    };
    if let Some((key, _suffix)) = status_key(status) {
        return locale
            .statuses
            .get(key)
            .cloned()
            .unwrap_or_else(|| status.to_owned());
    }
    for (prefix, key) in [
        ("Setup failed: ", "setup_failed"),
        (
            "Contact verification failed: ",
            "contact_verification_failed",
        ),
        ("Could not open chat: ", "could_not_open_chat"),
        ("Could not load older messages: ", "could_not_load_older"),
        ("Could not send message: ", "could_not_send"),
        ("Could not receive message: ", "could_not_receive"),
        ("Could not copy to clipboard: ", "could_not_copy"),
        ("Selected transport: ", "selected_transport"),
        ("Verified and added ", "verified_and_added"),
    ] {
        if let Some(detail) = status.strip_prefix(prefix) {
            if let Some(template) = locale.statuses.get(key) {
                return format!("{template}{detail}");
            }
        }
    }
    status.to_owned()
}

pub fn transport_label(transport: crate::ui_service::TransportKind, locale: &UiText) -> String {
    match transport {
        crate::ui_service::TransportKind::CopyPaste => locale.copy_paste.to_string(),
        crate::ui_service::TransportKind::Relay => locale.relay.to_string(),
    }
}

pub fn parse_transport_label(
    label: &str,
    language: &str,
) -> Option<crate::ui_service::TransportKind> {
    let locale = load(language).ok()?;
    if locale.copy_paste == label {
        Some(crate::ui_service::TransportKind::CopyPaste)
    } else if locale.relay == label {
        Some(crate::ui_service::TransportKind::Relay)
    } else {
        None
    }
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
            you: value.you.into(),
            today: value.today.into(),
            yesterday: value.yesterday.into(),
            copied: value.copied.into(),
            chat_history_loaded: value.chat_history_loaded.into(),
            sent: value.sent.into(),
            received: value.received.into(),
            decrypting_chat_history: value.decrypting_chat_history.into(),
            encrypting_sending: value.encrypting_sending.into(),
            decrypting_pasted: value.decrypting_pasted.into(),
            copy_paste: value.copy_paste.into(),
            relay: value.relay.into(),
            language_english: value.language_english.into(),
            language_russian: value.language_russian.into(),
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

fn load_file(language: &str) -> Result<LocaleFile> {
    let path = locale_paths(language)
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| anyhow!("locale not found"))?;
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("could not read locale file {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("could not parse locale file {}", path.display()))
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
    use super::{load, status_text};

    #[test]
    fn english_is_the_default_locale() {
        assert_eq!(load("en").unwrap().send, "Send");
        assert_eq!(load("unknown").unwrap().send, "Send");
    }

    #[test]
    fn russian_is_loaded_from_an_external_file() {
        assert_eq!(load("ru").unwrap().send, "Отправить");
    }

    #[test]
    fn russian_translates_runtime_statuses_and_preserves_error_details() {
        assert_eq!(
            status_text("Chat history loaded.", "ru"),
            "История чата загружена."
        );
        assert_eq!(status_text("copied", "ru"), "Скопировано");
        assert_eq!(
            status_text("Could not send message: timeout", "ru"),
            "Не удалось отправить сообщение: timeout"
        );
    }
}
