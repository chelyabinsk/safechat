slint::include_modules!();

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use arboard::Clipboard;
use directories::ProjectDirs;
use safechat::signal_adapter::SqliteSignalState;
use std::path::PathBuf;
use std::thread;

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
    let root = ProjectDirs::from("", "SafeChat", "safechat")
        .context("cannot determine the platform data directory")?
        .data_dir()
        .join(profile);
    std::fs::create_dir_all(&root).context("creating the SafeChat profile directory")?;
    Ok(root.join("identity.db"))
}

fn initialize_profile(
    profile: &str,
    password: &str,
    confirmation: &str,
) -> Result<(String, String)> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    if password != confirmation {
        bail!("passwords do not match");
    }
    let database = profile_database(profile)?;
    let mut state = if database.exists() {
        futures_executor::block_on(SqliteSignalState::open(&database, password))?
    } else {
        futures_executor::block_on(SqliteSignalState::initialize(
            &database,
            profile.trim(),
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

    let window_weak = window.as_weak();
    window.on_initialize_profile(move |profile, password, confirmation| {
        let window_weak = window_weak.clone();
        if let Some(window) = window_weak.upgrade() {
            window.set_status_text("Creating encrypted profile…".into());
        }
        let profile = profile.to_string();
        let password = password.to_string();
        let confirmation = confirmation.to_string();
        thread::spawn(move || {
            let result = initialize_profile(&profile, &password, &confirmation);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = window_weak.upgrade() {
                    match result {
                        Ok((fingerprint, bundle)) => {
                            window.set_profile_ready(true);
                            window.set_fingerprint(fingerprint.into());
                            window.set_public_bundle(bundle.into());
                            window.set_status_text("Profile ready. Verify fingerprints through a separate trusted channel.".into());
                        }
                        Err(error) => window.set_status_text(format!("Setup failed: {error:#}").into()),
                    }
                }
            });
        });
    });

    let window_weak = window.as_weak();
    window.on_choose_transport(move |transport| {
        if let Some(window) = window_weak.upgrade() {
            window.set_status_text(format!("Selected transport: {transport}").into());
        }
    });

    let window_weak = window.as_weak();
    window.on_send_message(move |message| {
        if let Some(window) = window_weak.upgrade() {
            let status = if message.is_empty() {
                "Send action is ready for the application service.".to_owned()
            } else {
                format!(
                    "Message queued through {}.",
                    window.get_selected_transport()
                )
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

    window.run()
}
