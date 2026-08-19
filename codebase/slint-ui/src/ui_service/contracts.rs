//! Commands, events, and error contracts between the UI and application worker.

use super::ConversationMessage;
use std::fmt;

pub enum Command {
    Initialize {
        profile: String,
        password: String,
        confirmation: String,
    },
    VerifyContact {
        profile: String,
        password: String,
        bundle: String,
        fingerprint: String,
    },
    LoadHistory {
        peer: String,
    },
    LoadOlderHistory {
        peer: String,
        before: usize,
    },
    Send {
        peer: String,
        transport: super::TransportKind,
        text: String,
    },
    ReceivePasted {
        peer: String,
        ciphertext: String,
    },
    Poll {
        peer: String,
    },
}

pub enum Event {
    ProfileReady {
        profile: String,
        fingerprint: String,
        bundle: String,
        contact: Option<(String, String)>,
    },
    ContactAdded {
        name: String,
        bundle: String,
        status: String,
    },
    ChatUpdated {
        messages: Vec<ConversationMessage>,
        status: String,
        ciphertext: Option<String>,
        history_cursor: usize,
        has_more: bool,
        prepend: bool,
    },
    Error {
        operation: Operation,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Profile,
    Contact,
    History,
    Chat,
    Relay,
}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Profile => "profile",
            Self::Contact => "contact",
            Self::History => "history",
            Self::Chat => "chat",
            Self::Relay => "relay",
        })
    }
}

pub struct ServiceError {
    pub operation: Operation,
    pub source: anyhow::Error,
}

impl ServiceError {
    pub fn new(operation: Operation, source: anyhow::Error) -> Self {
        Self { operation, source }
    }
}

#[cfg(test)]
mod tests {
    use super::Operation;

    #[test]
    fn operation_names_are_stable_for_user_facing_errors() {
        assert_eq!(Operation::Profile.to_string(), "profile");
        assert_eq!(Operation::Contact.to_string(), "contact");
        assert_eq!(Operation::History.to_string(), "history");
        assert_eq!(Operation::Chat.to_string(), "chat");
        assert_eq!(Operation::Relay.to_string(), "relay");
    }
}
