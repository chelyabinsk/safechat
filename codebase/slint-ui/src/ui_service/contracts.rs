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
