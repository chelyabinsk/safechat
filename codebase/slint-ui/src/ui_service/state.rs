//! UI state and event-driven state transitions.

use super::{Command, ConversationMessage, Event, TransportKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiState {
    pub status: String,
    pub profiles: Vec<String>,
    pub profile_name: String,
    pub selected_profile: String,
    pub profile_exists: bool,
    pub creating_profile: bool,
    pub profile_ready: bool,
    pub fingerprint: String,
    pub public_bundle: String,
    pub contact_name: String,
    pub contact_bundle: String,
    pub contact_added: bool,
    pub conversation_selected: bool,
    pub chat_loading: bool,
    pub messages: Vec<ConversationMessage>,
    pub selected_transport: TransportKind,
    pub new_chat_open: bool,
    pub profile_info_open: bool,
    pub history_cursor: usize,
    pub history_has_more: bool,
    pub scroll_to_latest: bool,
    pub scroll_generation: i32,
}

impl UiState {
    pub fn from_profiles(profiles: Vec<String>) -> Self {
        let selected_profile = profiles.first().cloned().unwrap_or_default();
        Self {
            status: "Ready".to_owned(),
            profile_exists: !selected_profile.is_empty(),
            creating_profile: selected_profile.is_empty(),
            profile_name: selected_profile.clone(),
            selected_profile,
            profiles,
            profile_ready: false,
            fingerprint: String::new(),
            public_bundle: String::new(),
            contact_name: String::new(),
            contact_bundle: String::new(),
            contact_added: false,
            conversation_selected: false,
            chat_loading: false,
            messages: Vec::new(),
            selected_transport: TransportKind::CopyPaste,
            new_chat_open: false,
            profile_info_open: false,
            history_cursor: 0,
            history_has_more: false,
            scroll_to_latest: false,
            scroll_generation: 0,
        }
    }

    pub fn prepare(&mut self, command: &Command) {
        match command {
            Command::Initialize { .. } => self.status = "Unlocking encrypted profile…".to_owned(),
            Command::VerifyContact { .. } => self.status = "Verifying contact…".to_owned(),
            Command::LoadHistory { .. }
            | Command::LoadOlderHistory { .. }
            | Command::Poll { .. } => {
                self.chat_loading = true;
                self.status = "Conversation selected.".to_owned();
            }
            Command::Send { .. } => {
                self.chat_loading = true;
                self.status = "Encrypting and sending…".to_owned();
            }
            Command::ReceivePasted { .. } => {
                self.chat_loading = true;
                self.status = "Decrypting pasted message…".to_owned();
            }
        }
    }

    pub fn apply(&mut self, event: &Event) {
        match event {
            Event::ProfileReady {
                profile,
                fingerprint,
                bundle,
                contact,
            } => {
                self.profile_name = profile.clone();
                self.selected_profile = profile.clone();
                self.profile_exists = true;
                self.profile_ready = true;
                self.fingerprint = fingerprint.clone();
                self.public_bundle = bundle.clone();
                if let Some((name, bundle)) = contact {
                    self.contact_name = name.clone();
                    self.contact_bundle = bundle.clone();
                    self.contact_added = true;
                }
                self.status =
                    "Profile ready. Verify fingerprints through a separate trusted channel."
                        .to_owned();
            }
            Event::ContactAdded {
                name,
                bundle,
                status,
            } => {
                self.contact_name = name.clone();
                self.contact_bundle = bundle.clone();
                self.contact_added = true;
                self.conversation_selected = false;
                self.chat_loading = false;
                self.new_chat_open = false;
                self.status = status.clone();
            }
            Event::ChatUpdated {
                messages,
                status,
                history_cursor,
                has_more,
                prepend,
                ..
            } => {
                if *prepend {
                    let mut combined = messages.clone();
                    combined.extend(self.messages.clone());
                    self.messages = combined;
                } else {
                    self.messages = messages.clone();
                }
                self.history_cursor = *history_cursor;
                self.history_has_more = *has_more;
                self.scroll_to_latest = !*prepend;
                if !*prepend {
                    self.scroll_generation = self.scroll_generation.wrapping_add(1);
                }
                self.chat_loading = false;
                self.status = status.clone();
            }
            Event::Error { operation, message } => {
                self.chat_loading = false;
                self.status = format!("{operation} failed: {message}");
            }
        }
    }

    pub fn select_transport(&mut self, transport: TransportKind) {
        self.selected_transport = transport;
        self.status = format!("Selected transport: {transport}");
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Event, TransportKind, UiState};

    #[test]
    fn state_transitions_capture_loading_and_results_without_view_access() {
        let mut state = UiState::from_profiles(vec!["alice".to_owned()]);
        state.conversation_selected = true;
        state.prepare(&Command::LoadHistory {
            peer: "peer".to_owned(),
        });
        assert!(state.chat_loading);

        state.apply(&Event::ChatUpdated {
            messages: Vec::new(),
            status: "Chat history loaded.".to_owned(),
            ciphertext: None,
            history_cursor: 0,
            has_more: false,
            prepend: false,
        });
        assert!(!state.chat_loading);
        assert_eq!(state.status, "Chat history loaded.");
    }

    #[test]
    fn state_keeps_selected_transport_typed() {
        let mut state = UiState::from_profiles(Vec::new());
        state.select_transport(TransportKind::Relay);
        assert_eq!(state.selected_transport, TransportKind::Relay);
    }
}
