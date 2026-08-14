slint::include_modules!();

mod ui_service;

use arboard::Clipboard;
use std::sync::Arc;
use std::time::{Duration, Instant};
use ui_service::{Command, Event, UiService, available_profiles};

fn set_chat_messages(window: &MainWindow, messages: Vec<ChatMessage>) {
    window.set_chat_messages(slint::ModelRc::new(slint::VecModel::from(messages)));
}

fn set_status(window: &MainWindow, message: impl Into<slint::SharedString>) {
    window.set_status_text(message.into());
}

fn copy_to_clipboard(text: String, success: &str) -> String {
    match Clipboard::new() {
        Ok(mut clipboard) => clipboard
            .set_text(text)
            .map(|_| success.to_owned())
            .unwrap_or_else(|error| format!("Could not copy to clipboard: {error}")),
        Err(error) => format!("Could not access clipboard: {error}"),
    }
}

fn apply_event(window: &MainWindow, event: Event) {
    match event {
        Event::ProfileReady {
            profile,
            fingerprint,
            bundle,
            contact,
        } => {
            window.set_profile_name(profile.clone().into());
            window.set_selected_profile(profile.into());
            window.set_profile_ready(true);
            window.set_fingerprint(fingerprint.into());
            window.set_public_bundle(bundle.into());
            if let Some((name, bundle)) = contact {
                window.set_contact_name(name.into());
                window.set_contact_bundle(bundle.into());
                window.set_contact_added(true);
            }
            set_status(
                window,
                "Profile ready. Verify fingerprints through a separate trusted channel.",
            );
        }
        Event::ContactAdded {
            name,
            bundle,
            status,
        } => {
            window.set_contact_name(name.into());
            window.set_contact_bundle(bundle.into());
            window.set_contact_added(true);
            window.set_conversation_selected(false);
            window.set_chat_loading(false);
            window.set_new_chat_open(false);
            set_status(window, status);
        }
        Event::ChatUpdated {
            messages,
            status,
            ciphertext,
        } => {
            set_chat_messages(window, messages);
            window.set_chat_loading(false);
            if let Some(ciphertext) = ciphertext {
                set_status(
                    window,
                    copy_to_clipboard(
                        ciphertext,
                        "Encrypted message copied. Paste it into the recipient’s chat.",
                    ),
                );
            } else {
                set_status(window, status);
            }
        }
        Event::Error { operation, message } => {
            window.set_chat_loading(false);
            set_status(window, format!("{operation} failed: {message}"));
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    let service = Arc::new(UiService::new());
    let profiles =
        available_profiles().map_err(|error| slint::PlatformError::Other(error.to_string()))?;
    window.set_available_profiles(slint::ModelRc::new(slint::VecModel::from(
        profiles
            .iter()
            .cloned()
            .map(slint::SharedString::from)
            .collect::<Vec<_>>(),
    )));
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
    let service_for_initialize = Arc::clone(&service);
    window.on_initialize_profile(move |profile, password, confirmation| {
        let command = Command::Initialize {
            profile: profile.to_string(),
            password: password.to_string(),
            confirmation: confirmation.to_string(),
        };
        if let Some(window) = window_weak.upgrade() {
            set_status(&window, "Unlocking encrypted profile…");
            if let Err(error) = service_for_initialize.submit(command) {
                set_status(&window, format!("Setup failed: {error}"));
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_select_profile(move |profile| {
        if let Some(window) = window_weak.upgrade() {
            window.set_profile_name(profile.clone());
            window.set_selected_profile(profile.clone());
            window.set_profile_exists(true);
            set_status(&window, format!("Selected profile: {profile}"));
        }
    });

    let window_weak = window.as_weak();
    window.on_begin_create_profile(move || {
        if let Some(window) = window_weak.upgrade() {
            window.set_creating_profile(!window.get_creating_profile());
        }
    });

    let window_weak = window.as_weak();
    let service_for_contact = Arc::clone(&service);
    window.on_verify_add_contact(move |bundle, fingerprint, password| {
        if let Some(window) = window_weak.upgrade() {
            set_status(&window, "Verifying contact…");
            let command = Command::VerifyContact {
                profile: window.get_profile_name().to_string(),
                password: password.to_string(),
                bundle: bundle.to_string(),
                fingerprint: fingerprint.to_string(),
            };
            if let Err(error) = service_for_contact.submit(command) {
                set_status(&window, format!("Contact verification failed: {error}"));
            }
        }
    });

    let window_weak = window.as_weak();
    let service_for_select = Arc::clone(&service);
    window.on_select_contact(move || {
        if let Some(window) = window_weak.upgrade() {
            if window.get_chat_loading() {
                return;
            }
            let peer = window.get_contact_bundle().to_string();
            if peer.is_empty() {
                return;
            }
            window.set_conversation_selected(true);
            window.set_chat_loading(true);
            set_status(&window, "Conversation selected.");
            let command = if window.get_selected_transport() == "Relay" {
                Command::Poll { peer }
            } else {
                Command::LoadHistory { peer }
            };
            if let Err(error) = service_for_select.submit(command) {
                window.set_chat_loading(false);
                set_status(&window, format!("Could not open chat: {error}"));
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_choose_transport(move |transport| {
        if let Some(window) = window_weak.upgrade() {
            set_status(&window, format!("Selected transport: {transport}"));
        }
    });

    let window_weak = window.as_weak();
    let service_for_send = Arc::clone(&service);
    window.on_send_message(move |message| {
        if let Some(window) = window_weak.upgrade() {
            let peer = window.get_contact_bundle().to_string();
            if peer.is_empty() {
                set_status(&window, "Add and select a contact first.");
            } else if message.trim().is_empty() {
                set_status(&window, "Type a message first.");
            } else {
                set_status(&window, "Encrypting and sending…");
                let command = Command::Send {
                    peer,
                    transport: window.get_selected_transport().to_string(),
                    text: message.to_string(),
                };
                if let Err(error) = service_for_send.submit(command) {
                    set_status(&window, format!("Could not send message: {error}"));
                }
            }
        }
    });

    let window_weak = window.as_weak();
    let service_for_receive = Arc::clone(&service);
    window.on_receive_pasted(move |ciphertext| {
        if let Some(window) = window_weak.upgrade() {
            let peer = window.get_contact_bundle().to_string();
            if peer.is_empty() {
                set_status(&window, "Add and select a contact first.");
            } else if ciphertext.trim().is_empty() {
                set_status(&window, "Paste an encrypted message first.");
            } else {
                set_status(&window, "Decrypting pasted message…");
                let command = Command::ReceivePasted {
                    peer,
                    ciphertext: ciphertext.to_string(),
                };
                if let Err(error) = service_for_receive.submit(command) {
                    set_status(&window, format!("Could not receive message: {error}"));
                }
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_copy_ciphertext(move |ciphertext| {
        if let Some(window) = window_weak.upgrade() {
            set_status(
                &window,
                copy_to_clipboard(ciphertext.to_string(), "Ciphertext copied to clipboard."),
            );
        }
    });

    let window_weak = window.as_weak();
    window.on_new_chat(move || {
        if let Some(window) = window_weak.upgrade() {
            window.set_new_chat_open(true);
            set_status(&window, "New conversation");
        }
    });

    let window_weak = window.as_weak();
    window.on_copy_bundle(move || {
        if let Some(window) = window_weak.upgrade() {
            set_status(
                &window,
                copy_to_clipboard(
                    window.get_public_bundle().to_string(),
                    "Public bundle copied to clipboard.",
                ),
            );
        }
    });

    let window_weak = window.as_weak();
    window.on_copy_fingerprint(move || {
        if let Some(window) = window_weak.upgrade() {
            set_status(
                &window,
                copy_to_clipboard(
                    window.get_fingerprint().to_string(),
                    "Fingerprint copied to clipboard.",
                ),
            );
        }
    });

    let event_window = window.as_weak();
    let event_service = Arc::clone(&service);
    let poll_service = Arc::clone(&service);
    let mut last_poll = Instant::now();
    let event_timer = slint::Timer::default();
    event_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(100),
        move || {
            if let Some(window) = event_window.upgrade() {
                for event in event_service.drain_events() {
                    apply_event(&window, event);
                }
                if last_poll.elapsed() >= Duration::from_secs(3)
                    && window.get_profile_ready()
                    && window.get_conversation_selected()
                    && window.get_selected_transport() == "Relay"
                    && !window.get_chat_loading()
                    && !window.get_contact_bundle().is_empty()
                {
                    last_poll = Instant::now();
                    let _ = poll_service.try_submit(Command::Poll {
                        peer: window.get_contact_bundle().to_string(),
                    });
                }
            }
        },
    );

    window.run()
}
