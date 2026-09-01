slint::include_modules!();

mod ui_service;

use chrono::{DateTime, Local, TimeDelta, Utc};
use clap::Parser;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use ui_service::{Command, Event, UiService, UiState};

#[derive(Parser)]
#[command(name = "safechat-slint-ui", version, about = "SafeChat desktop client")]
struct Cli {
    /// Print diagnostic operation messages to the launching console.
    #[arg(long)]
    debug: bool,
    /// Run the UI state/model smoke test without opening a graphical window.
    #[arg(long)]
    headless: bool,
}

fn format_timestamp(timestamp: u64) -> String {
    let Ok(timestamp) = i64::try_from(timestamp) else {
        return timestamp.to_string();
    };
    let Some(utc_time) = DateTime::<Utc>::from_timestamp(timestamp, 0) else {
        return timestamp.to_string();
    };
    let local_time = utc_time.with_timezone(&Local);
    let now = Local::now();
    let today = now.date_naive();
    let date = local_time.date_naive();
    if date == today {
        format!("Today, {}", local_time.format("%H:%M"))
    } else if date == (now - TimeDelta::days(1)).date_naive() {
        format!("Yesterday, {}", local_time.format("%H:%M"))
    } else {
        local_time.format("%Y-%m-%d %H:%M").to_string()
    }
}

fn to_slint_message(message: ui_service::ConversationMessage) -> ChatMessage {
    ChatMessage {
        sender: message.sender.into(),
        text: message.text.into(),
        timestamp: format_timestamp(message.timestamp).into(),
        outgoing: message.outgoing,
        status: message.status.into(),
        ciphertext: message.ciphertext.into(),
    }
}

fn render_state(window: &MainWindow, state: &UiState, transport_options: &[String]) {
    window.set_status_text(state.status.clone().into());
    window.set_available_profiles(slint::ModelRc::new(slint::VecModel::from(
        state
            .profiles
            .iter()
            .cloned()
            .map(slint::SharedString::from)
            .collect::<Vec<_>>(),
    )));
    window.set_transport_options(slint::ModelRc::new(slint::VecModel::from(
        transport_options
            .iter()
            .cloned()
            .map(slint::SharedString::from)
            .collect::<Vec<_>>(),
    )));
    window.set_profile_name(state.profile_name.clone().into());
    window.set_selected_profile(state.selected_profile.clone().into());
    window.set_profile_exists(state.profile_exists);
    window.set_creating_profile(state.creating_profile);
    window.set_profile_ready(state.profile_ready);
    window.set_fingerprint(state.fingerprint.clone().into());
    window.set_public_bundle(state.public_bundle.clone().into());
    window.set_contact_name(state.contact_name.clone().into());
    window.set_contact_bundle(state.contact_bundle.clone().into());
    window.set_contact_added(state.contact_added);
    window.set_conversation_selected(state.conversation_selected);
    window.set_chat_loading(state.chat_loading);
    window.set_history_loading(state.history_loading);
    window.set_loading_text(state.loading_text.clone().into());
    window.set_new_chat_open(state.new_chat_open);
    window.set_profile_info_open(state.profile_info_open);
    window.set_history_has_more(state.history_has_more);
    window.set_scroll_generation(state.scroll_generation);
    window.set_selected_transport(state.selected_transport.to_string().into());
    window.set_chat_messages(slint::ModelRc::new(slint::VecModel::from(
        state
            .messages
            .clone()
            .into_iter()
            .map(to_slint_message)
            .collect::<Vec<_>>(),
    )));
}

fn apply_event(
    window: &MainWindow,
    state: &Rc<RefCell<UiState>>,
    event: Event,
    transport_options: &[String],
    debug: bool,
) {
    if debug {
        eprintln!(
            "safechat debug: UI received {} event; messages_before={}",
            event.kind(),
            state.borrow().messages.len()
        );
    }
    state.borrow_mut().apply(&event);
    if debug {
        let state = state.borrow();
        eprintln!(
            "safechat debug: UI applied {} event; messages_after={} chat_loading={} history_loading={} conversation_selected={}",
            event.kind(),
            state.messages.len(),
            state.chat_loading,
            state.history_loading,
            state.conversation_selected,
        );
    }
    render_state(window, &state.borrow(), transport_options);
    if debug {
        eprintln!("safechat debug: UI rendered {} event", event.kind());
    }
}

fn run_headless_smoke_test(debug: bool) -> Result<(), String> {
    if debug {
        eprintln!("safechat debug: starting headless UI smoke test");
    }

    let mut state = UiState::from_profiles(vec!["alice".to_owned()]);
    state.apply(&Event::ProfileReady {
        profile: "alice".to_owned(),
        fingerprint: "fingerprint".to_owned(),
        bundle: "bundle".to_owned(),
        contact: Some(("Bob".to_owned(), "peer-bundle".to_owned())),
    });
    state.conversation_selected = true;

    let messages = (0..10)
        .map(|index| ui_service::ConversationMessage {
            sender: if index % 2 == 0 {
                "You".to_owned()
            } else {
                "Bob".to_owned()
            },
            text: format!("headless message {index}"),
            timestamp: index,
            outgoing: index % 2 == 0,
            status: "sent".to_owned(),
            ciphertext: "test-ciphertext".to_owned(),
        })
        .collect::<Vec<_>>();
    state.apply(&Event::ChatUpdated {
        messages,
        status: "Message sent.".to_owned(),
        ciphertext: None,
        history_cursor: 0,
        has_more: false,
        prepend: false,
    });

    if state.messages.len() != 10 {
        return Err(format!(
            "expected 10 messages after ChatUpdated, got {}",
            state.messages.len()
        ));
    }
    if state.chat_loading || state.history_loading {
        return Err("chat remained in a loading state after ChatUpdated".to_owned());
    }
    let projected = state
        .messages
        .iter()
        .cloned()
        .map(to_slint_message)
        .collect::<Vec<_>>();
    if projected.len() != 10 || projected[9].text != "headless message 9" {
        return Err("chat message model projection failed".to_owned());
    }

    if debug {
        eprintln!(
            "safechat debug: headless UI smoke test passed; projected_messages={}",
            projected.len()
        );
    }
    println!("headless UI smoke test passed (10 messages rendered through the UI model)");
    Ok(())
}

fn main() -> Result<(), slint::PlatformError> {
    let cli = Cli::parse();
    if cli.headless {
        return run_headless_smoke_test(cli.debug).map_err(slint::PlatformError::Other);
    }
    if cli.debug {
        eprintln!("safechat debug: GUI starting");
    }
    let window = MainWindow::new()?;
    let service = Arc::new(UiService::new_with_debug(cli.debug));
    let profiles = service
        .available_profiles()
        .map_err(|error| slint::PlatformError::Other(error.to_string()))?;
    let transport_options = service.transport_options();
    if cli.debug {
        eprintln!(
            "safechat debug: loaded {} profiles; transports={:?}",
            profiles.len(),
            transport_options
        );
    }
    let state = Rc::new(RefCell::new(UiState::from_profiles(profiles)));
    render_state(&window, &state.borrow(), &transport_options);

    let window_weak = window.as_weak();
    let service_for_initialize = Arc::clone(&service);
    let state_for_initialize = Rc::clone(&state);
    let options_for_initialize = transport_options.clone();
    window.on_initialize_profile(move |profile, password, confirmation| {
        let command = Command::Initialize {
            profile: profile.to_string(),
            password: password.to_string(),
            confirmation: confirmation.to_string(),
        };
        state_for_initialize.borrow_mut().prepare(&command);
        if let Some(window) = window_weak.upgrade() {
            render_state(
                &window,
                &state_for_initialize.borrow(),
                &options_for_initialize,
            );
            if let Err(error) = service_for_initialize.submit(command) {
                state_for_initialize.borrow_mut().status = format!("Setup failed: {error}");
                render_state(
                    &window,
                    &state_for_initialize.borrow(),
                    &options_for_initialize,
                );
            }
        }
    });

    let window_weak = window.as_weak();
    let state_for_select_profile = Rc::clone(&state);
    let options_for_select_profile = transport_options.clone();
    window.on_select_profile(move |profile| {
        let mut state = state_for_select_profile.borrow_mut();
        state.profile_name = profile.to_string();
        state.selected_profile = profile.to_string();
        state.profile_exists = true;
        state.status = format!("Selected profile: {profile}");
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state, &options_for_select_profile);
        }
    });

    let window_weak = window.as_weak();
    let state_for_create = Rc::clone(&state);
    let options_for_create = transport_options.clone();
    window.on_begin_create_profile(move || {
        let mut state = state_for_create.borrow_mut();
        state.creating_profile = !state.creating_profile;
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state, &options_for_create);
        }
    });

    let window_weak = window.as_weak();
    let service_for_contact = Arc::clone(&service);
    let state_for_contact = Rc::clone(&state);
    let options_for_contact = transport_options.clone();
    window.on_verify_add_contact(move |bundle, fingerprint, password| {
        let command = Command::VerifyContact {
            profile: state_for_contact.borrow().profile_name.clone(),
            password: password.to_string(),
            bundle: bundle.to_string(),
            fingerprint: fingerprint.to_string(),
        };
        state_for_contact.borrow_mut().prepare(&command);
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state_for_contact.borrow(), &options_for_contact);
            if let Err(error) = service_for_contact.submit(command) {
                state_for_contact.borrow_mut().status =
                    format!("Contact verification failed: {error}");
                render_state(&window, &state_for_contact.borrow(), &options_for_contact);
            }
        }
    });

    let window_weak = window.as_weak();
    let service_for_select = Arc::clone(&service);
    let state_for_select = Rc::clone(&state);
    let options_for_select = transport_options.clone();
    window.on_select_contact(move || {
        let peer = state_for_select.borrow().contact_bundle.clone();
        if peer.is_empty() || state_for_select.borrow().chat_loading {
            return;
        }
        let command =
            if state_for_select.borrow().selected_transport == ui_service::TransportKind::Relay {
                Command::Poll { peer }
            } else {
                Command::LoadHistory { peer }
            };
        {
            let mut state = state_for_select.borrow_mut();
            state.conversation_selected = true;
            state.prepare(&command);
        }
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state_for_select.borrow(), &options_for_select);
            if let Err(error) = service_for_select.submit(command) {
                state_for_select.borrow_mut().status = format!("Could not open chat: {error}");
                state_for_select.borrow_mut().chat_loading = false;
                state_for_select.borrow_mut().history_loading = false;
                render_state(&window, &state_for_select.borrow(), &options_for_select);
            }
        }
    });

    let window_weak = window.as_weak();
    let service_for_older = Arc::clone(&service);
    let state_for_older = Rc::clone(&state);
    let options_for_older = transport_options.clone();
    window.on_load_older_history(move || {
        let snapshot = state_for_older.borrow().clone();
        if snapshot.chat_loading || !snapshot.history_has_more || snapshot.contact_bundle.is_empty()
        {
            return;
        }
        let command = Command::LoadOlderHistory {
            peer: snapshot.contact_bundle,
            before: snapshot.history_cursor,
        };
        state_for_older.borrow_mut().prepare(&command);
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state_for_older.borrow(), &options_for_older);
            if let Err(error) = service_for_older.submit(command) {
                state_for_older.borrow_mut().status =
                    format!("Could not load older messages: {error}");
                state_for_older.borrow_mut().chat_loading = false;
                state_for_older.borrow_mut().history_loading = false;
                render_state(&window, &state_for_older.borrow(), &options_for_older);
            }
        }
    });

    let window_weak = window.as_weak();
    let service_for_transport = Arc::clone(&service);
    let state_for_transport = Rc::clone(&state);
    let options_for_transport = transport_options.clone();
    window.on_choose_transport(move |transport| {
        if let Some(transport) = service_for_transport.parse_transport(transport.as_str()) {
            state_for_transport.borrow_mut().select_transport(transport);
            if let Some(window) = window_weak.upgrade() {
                render_state(
                    &window,
                    &state_for_transport.borrow(),
                    &options_for_transport,
                );
            }
        }
    });

    let window_weak = window.as_weak();
    let service_for_send = Arc::clone(&service);
    let state_for_send = Rc::clone(&state);
    let options_for_send = transport_options.clone();
    let debug_for_send = cli.debug;
    window.on_send_message(move |message| {
        let state_snapshot = state_for_send.borrow().clone();
        if debug_for_send {
            eprintln!(
                "safechat debug: send callback invoked; text_len={} trimmed_len={} contact_selected={} transport={}",
                message.len(),
                message.trim().len(),
                !state_snapshot.contact_bundle.is_empty(),
                state_snapshot.selected_transport,
            );
        }
        if state_snapshot.contact_bundle.is_empty() {
            state_for_send.borrow_mut().status = "Add and select a contact first.".to_owned();
        } else if message.trim().is_empty() {
            state_for_send.borrow_mut().status = "Type a message first.".to_owned();
        } else {
            let command = Command::Send {
                peer: state_snapshot.contact_bundle,
                transport: state_snapshot.selected_transport,
                text: message.to_string(),
            };
            state_for_send.borrow_mut().prepare(&command);
            if let Err(error) = service_for_send.submit(command) {
                state_for_send.borrow_mut().status = format!("Could not send message: {error}");
                state_for_send.borrow_mut().chat_loading = false;
                state_for_send.borrow_mut().history_loading = false;
            }
        }
        if debug_for_send {
            let state = state_for_send.borrow();
            eprintln!(
                "safechat debug: send callback finished; status={:?} chat_loading={} messages={}",
                state.status,
                state.chat_loading,
                state.messages.len(),
            );
        }
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state_for_send.borrow(), &options_for_send);
        }
    });

    let window_weak = window.as_weak();
    let service_for_receive = Arc::clone(&service);
    let state_for_receive = Rc::clone(&state);
    let options_for_receive = transport_options.clone();
    window.on_receive_pasted(move |ciphertext| {
        let state_snapshot = state_for_receive.borrow().clone();
        if state_snapshot.contact_bundle.is_empty() {
            state_for_receive.borrow_mut().status = "Add and select a contact first.".to_owned();
        } else if ciphertext.trim().is_empty() {
            state_for_receive.borrow_mut().status = "Paste an encrypted message first.".to_owned();
        } else {
            let command = Command::ReceivePasted {
                peer: state_snapshot.contact_bundle,
                ciphertext: ciphertext.to_string(),
            };
            state_for_receive.borrow_mut().prepare(&command);
            if let Err(error) = service_for_receive.submit(command) {
                state_for_receive.borrow_mut().status =
                    format!("Could not receive message: {error}");
                state_for_receive.borrow_mut().chat_loading = false;
                state_for_receive.borrow_mut().history_loading = false;
            }
        }
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state_for_receive.borrow(), &options_for_receive);
        }
    });

    let window_weak = window.as_weak();
    let service_for_copy = Arc::clone(&service);
    let state_for_copy = Rc::clone(&state);
    let copy_feedback_timer = slint::Timer::default();
    window.on_copy_ciphertext(move |text| {
        let status = match service_for_copy.copy_text(text.as_str()) {
            Ok(()) => {
                if let Some(window) = window_weak.upgrade() {
                    window.set_copied_ciphertext(text.clone());
                }
                "Ciphertext copied to clipboard.".to_owned()
            }
            Err(error) => format!("Could not copy to clipboard: {error}"),
        };
        state_for_copy.borrow_mut().status = status;
        if let Some(window) = window_weak.upgrade() {
            window.set_status_text(state_for_copy.borrow().status.clone().into());
        }
        let timer_window = window_weak.clone();
        copy_feedback_timer.start(
            slint::TimerMode::SingleShot,
            Duration::from_millis(1500),
            move || {
                if let Some(window) = timer_window.upgrade() {
                    window.set_copied_ciphertext("".into());
                    if window.get_status_text() == "Ciphertext copied to clipboard." {
                        window.set_status_text("Ready".into());
                    }
                }
            },
        );
    });

    let window_weak = window.as_weak();
    let state_for_new_chat = Rc::clone(&state);
    let options_for_new_chat = transport_options.clone();
    window.on_new_chat(move || {
        state_for_new_chat.borrow_mut().new_chat_open = true;
        if let Some(window) = window_weak.upgrade() {
            render_state(&window, &state_for_new_chat.borrow(), &options_for_new_chat);
        }
    });

    let window_weak = window.as_weak();
    let service_for_bundle = Arc::clone(&service);
    let state_for_bundle = Rc::clone(&state);
    let options_for_bundle = transport_options.clone();
    window.on_copy_bundle(move || {
        if let Some(window) = window_weak.upgrade() {
            let text = window.get_public_bundle().to_string();
            state_for_bundle.borrow_mut().status = match service_for_bundle.copy_text(&text) {
                Ok(()) => "Public bundle copied to clipboard.".to_owned(),
                Err(error) => format!("Could not copy to clipboard: {error}"),
            };
            render_state(&window, &state_for_bundle.borrow(), &options_for_bundle);
        }
    });

    let window_weak = window.as_weak();
    let service_for_fingerprint = Arc::clone(&service);
    let state_for_fingerprint = Rc::clone(&state);
    let options_for_fingerprint = transport_options.clone();
    window.on_copy_fingerprint(move || {
        if let Some(window) = window_weak.upgrade() {
            let text = window.get_fingerprint().to_string();
            state_for_fingerprint.borrow_mut().status =
                match service_for_fingerprint.copy_text(&text) {
                    Ok(()) => "Fingerprint copied to clipboard.".to_owned(),
                    Err(error) => format!("Could not copy to clipboard: {error}"),
                };
            render_state(
                &window,
                &state_for_fingerprint.borrow(),
                &options_for_fingerprint,
            );
        }
    });

    let event_window = window.as_weak();
    let event_service = Arc::clone(&service);
    let event_state = Rc::clone(&state);
    let poll_service = Arc::clone(&service);
    let poll_state = Rc::clone(&state);
    let poll_options = transport_options.clone();
    let debug_for_events = cli.debug;
    let mut last_poll = Instant::now();
    let event_timer = slint::Timer::default();
    event_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(100),
        move || {
            if let Some(window) = event_window.upgrade() {
                let events = event_service.drain_events();
                if debug_for_events && !events.is_empty() {
                    eprintln!(
                        "safechat debug: UI event timer drained {} event(s)",
                        events.len()
                    );
                }
                for event in events {
                    apply_event(
                        &window,
                        &event_state,
                        event,
                        &poll_options,
                        debug_for_events,
                    );
                }
                let snapshot = poll_state.borrow().clone();
                if last_poll.elapsed() >= Duration::from_secs(3)
                    && snapshot.profile_ready
                    && snapshot.conversation_selected
                    && snapshot.selected_transport == ui_service::TransportKind::Relay
                    && !snapshot.chat_loading
                    && !snapshot.contact_bundle.is_empty()
                {
                    last_poll = Instant::now();
                    let command = Command::Poll {
                        peer: snapshot.contact_bundle,
                    };
                    poll_state.borrow_mut().prepare(&command);
                    render_state(&window, &poll_state.borrow(), &poll_options);
                    let _ = poll_service.try_submit(command);
                }
            }
        },
    );

    window.run()
}

#[cfg(test)]
mod tests {
    use super::to_slint_message;
    use crate::ui_service::ConversationMessage;

    #[test]
    fn chat_model_projection_preserves_fields_for_the_view() {
        let message = to_slint_message(ConversationMessage {
            sender: "Bob".to_owned(),
            text: "A long message".to_owned(),
            timestamp: 42,
            outgoing: false,
            status: "received".to_owned(),
            ciphertext: "encrypted".to_owned(),
        });

        assert_eq!(message.sender.to_string(), "Bob");
        assert_eq!(message.text.to_string(), "A long message");
        assert!(message.timestamp.to_string().starts_with("1970-01-01 "));
        assert!(!message.outgoing);
        assert_eq!(message.status.to_string(), "received");
        assert_eq!(message.ciphertext.to_string(), "encrypted");
    }
}
