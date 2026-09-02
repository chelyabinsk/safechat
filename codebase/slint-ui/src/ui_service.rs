//! Serialized application service for the Slint client.
//!
//! The UI submits commands to one worker. Profile databases, Signal state,
//! encrypted history, and relay operations therefore never run concurrently
//! because several UI callbacks happened close together.

use anyhow::{Context, Result};

mod chat;
mod contracts;
mod model;
mod ports;
mod profile;
mod state;
mod worker;
use chat::{
    load_chat_history, load_older_chat_history, perform_chat_action, perform_paste_receive,
    perform_paste_send,
};
pub use contracts::{Command, Event, Operation};
pub use model::{ConversationMessage, TransportKind};
pub use ports::ServicePorts;
pub use state::UiState;
pub use worker::UiService;

pub fn load_profile_language(profile: &str) -> anyhow::Result<Option<String>> {
    profile::load_language(profile)
}

pub fn save_profile_language(profile: &str, language: &str) -> anyhow::Result<()> {
    profile::save_language(profile, language)
}

#[derive(Clone, Debug)]
pub struct ProfileSession {
    pub(super) profile: String,
    pub(super) password: String,
}

pub(super) fn handle_command(
    session: &mut Option<ProfileSession>,
    command: Command,
    ports: &ports::ServicePorts,
) -> std::result::Result<Option<Event>, contracts::ServiceError> {
    let operation = match &command {
        Command::Initialize { .. } => Operation::Profile,
        Command::VerifyContact { .. } => Operation::Contact,
        Command::LoadHistory { .. } | Command::LoadOlderHistory { .. } => Operation::History,
        Command::Send { transport, .. } => {
            if matches!(transport, TransportKind::Relay) {
                Operation::Relay
            } else {
                Operation::Chat
            }
        }
        Command::Poll { .. } => Operation::Relay,
        Command::ReceivePasted { .. } => Operation::Chat,
    };
    let result = match command {
        Command::Initialize {
            profile,
            password,
            confirmation,
        } => ports
            .profile
            .initialize(&profile, &password, &confirmation)
            .map(|ready| {
                *session = Some(ProfileSession {
                    profile: ready.profile.clone(),
                    password,
                });
                Some(Event::ProfileReady {
                    profile: ready.profile,
                    fingerprint: ready.fingerprint,
                    bundle: ready.bundle,
                    contact: ready.contact,
                })
            }),
        Command::VerifyContact {
            profile,
            password,
            bundle,
            fingerprint,
        } => ports
            .profile
            .verify_contact(&profile, &password, &bundle, &fingerprint)
            .map(|(name, status)| {
                Some(Event::ContactAdded {
                    name,
                    bundle,
                    status,
                })
            }),
        Command::LoadHistory { peer } => require_session(session)
            .and_then(|active| load_chat_history(active, &peer, ports.history.as_ref()))
            .map(|page| {
                Some(Event::ChatUpdated {
                    messages: page.messages,
                    status: "Chat history loaded.".to_owned(),
                    history_cursor: page.cursor,
                    has_more: page.has_more,
                    prepend: false,
                })
            }),
        Command::LoadOlderHistory { peer, before } => require_session(session)
            .and_then(|active| {
                load_older_chat_history(active, &peer, before, ports.history.as_ref())
            })
            .map(|page| {
                Some(Event::ChatUpdated {
                    messages: page.messages,
                    status: "Older messages loaded.".to_owned(),
                    history_cursor: page.cursor,
                    has_more: page.has_more,
                    prepend: true,
                })
            }),
        Command::Send {
            peer,
            transport,
            text,
        } => require_session(session).and_then(|active| {
            if transport == TransportKind::CopyPaste {
                perform_paste_send(
                    active,
                    &peer,
                    &text,
                    ports.history.as_ref(),
                    ports.clock.as_ref(),
                )
                .map(|(page, status, _ciphertext)| {
                    Some(Event::ChatUpdated {
                        messages: page.messages,
                        status,
                        history_cursor: page.cursor,
                        has_more: page.has_more,
                        prepend: false,
                    })
                })
            } else {
                perform_chat_action(active, &peer, Some(&text)).map(|(page, status)| {
                    Some(Event::ChatUpdated {
                        messages: page.messages,
                        status,
                        history_cursor: page.cursor,
                        has_more: page.has_more,
                        prepend: false,
                    })
                })
            }
        }),
        Command::ReceivePasted { peer, ciphertext } => require_session(session)
            .and_then(|active| {
                perform_paste_receive(
                    active,
                    &peer,
                    &ciphertext,
                    ports.history.as_ref(),
                    ports.clock.as_ref(),
                )
            })
            .map(|(page, status)| {
                Some(Event::ChatUpdated {
                    messages: page.messages,
                    status,
                    history_cursor: page.cursor,
                    has_more: page.has_more,
                    prepend: false,
                })
            }),
        Command::Poll { peer } => require_session(session)
            .and_then(|active| perform_chat_action(active, &peer, None))
            .map(|(page, status)| {
                Some(Event::ChatUpdated {
                    messages: page.messages,
                    status,
                    history_cursor: page.cursor,
                    has_more: page.has_more,
                    prepend: false,
                })
            }),
    };
    result.map_err(|error| contracts::ServiceError::new(operation, error))
}

fn require_session(session: &Option<ProfileSession>) -> Result<&ProfileSession> {
    session.as_ref().context("profile is not unlocked")
}
