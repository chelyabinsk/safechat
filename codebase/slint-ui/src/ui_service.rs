//! Serialized application service for the Slint client.
//!
//! The UI submits commands to one worker. Profile databases, Signal state,
//! encrypted history, and relay operations therefore never run concurrently
//! because several UI callbacks happened close together.

use anyhow::{Context, Result};

mod chat;
mod contracts;
mod model;
mod profile;
mod worker;
use chat::{load_chat_history, perform_chat_action, perform_paste_receive, perform_paste_send};
pub use contracts::{Command, Event, Operation};
pub use model::{ConversationMessage, TransportKind};
pub use profile::available_profiles;
use profile::{initialize_profile, load_saved_contact, verify_add_contact};
pub use worker::UiService;

#[derive(Clone, Debug)]
pub struct ProfileSession {
    pub(super) profile: String,
    pub(super) password: String,
}

pub(super) fn handle_command(
    session: &mut Option<ProfileSession>,
    command: Command,
) -> std::result::Result<Option<Event>, contracts::ServiceError> {
    let operation = match &command {
        Command::Initialize { .. } => Operation::Profile,
        Command::VerifyContact { .. } => Operation::Contact,
        Command::LoadHistory { .. } => Operation::History,
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
        } => initialize_profile(&profile, &password, &confirmation).map(|(fingerprint, bundle)| {
            *session = Some(ProfileSession {
                profile: profile.clone(),
                password,
            });
            let contact = load_saved_contact(&profile).ok().flatten();
            Some(Event::ProfileReady {
                profile,
                fingerprint,
                bundle,
                contact,
            })
        }),
        Command::VerifyContact {
            profile,
            password,
            bundle,
            fingerprint,
        } => {
            verify_add_contact(&profile, &password, &bundle, &fingerprint).map(|(name, status)| {
                Some(Event::ContactAdded {
                    name,
                    bundle,
                    status,
                })
            })
        }
        Command::LoadHistory { peer } => require_session(session)
            .and_then(|active| load_chat_history(active, &peer))
            .map(|messages| {
                Some(Event::ChatUpdated {
                    messages,
                    status: "Chat history loaded.".to_owned(),
                    ciphertext: None,
                })
            }),
        Command::Send {
            peer,
            transport,
            text,
        } => require_session(session).and_then(|active| {
            if transport == TransportKind::CopyPaste {
                perform_paste_send(active, &peer, &text).map(|(messages, status, ciphertext)| {
                    Some(Event::ChatUpdated {
                        messages,
                        status,
                        ciphertext: Some(ciphertext),
                    })
                })
            } else {
                perform_chat_action(active, &peer, Some(&text)).map(|(messages, status)| {
                    Some(Event::ChatUpdated {
                        messages,
                        status,
                        ciphertext: None,
                    })
                })
            }
        }),
        Command::ReceivePasted { peer, ciphertext } => require_session(session)
            .and_then(|active| perform_paste_receive(active, &peer, &ciphertext))
            .map(|(messages, status)| {
                Some(Event::ChatUpdated {
                    messages,
                    status,
                    ciphertext: None,
                })
            }),
        Command::Poll { peer } => require_session(session)
            .and_then(|active| perform_chat_action(active, &peer, None))
            .map(|(messages, status)| {
                Some(Event::ChatUpdated {
                    messages,
                    status,
                    ciphertext: None,
                })
            }),
    };
    result.map_err(|error| contracts::ServiceError::new(operation, error))
}

fn require_session(session: &Option<ProfileSession>) -> Result<&ProfileSession> {
    session.as_ref().context("profile is not unlocked")
}
