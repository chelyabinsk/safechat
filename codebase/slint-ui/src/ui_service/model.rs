//! UI-independent models exchanged by the worker and the front end.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    CopyPaste,
    Relay,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CopyPaste => "Copy/paste",
            Self::Relay => "Relay",
        })
    }
}

impl TransportKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "Copy/paste" => Some(Self::CopyPaste),
            "Relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationMessage {
    pub sender: String,
    pub text: String,
    pub timestamp: u64,
    pub outgoing: bool,
    pub status: String,
    pub ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::TransportKind;

    #[test]
    fn transport_selection_is_typed_and_rejects_unknown_values() {
        assert_eq!(
            TransportKind::parse("Copy/paste"),
            Some(TransportKind::CopyPaste)
        );
        assert_eq!(TransportKind::parse("Relay"), Some(TransportKind::Relay));
        assert_eq!(TransportKind::parse("custom"), None);
    }
}
