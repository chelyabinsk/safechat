//! UI state and event-driven state transitions.

use super::{Command, ConversationMessage, Event, TransportKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiState {
    pub language: String,
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
    pub history_loading: bool,
    pub loading_text: String,
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
            language: "en".to_owned(),
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
            history_loading: false,
            loading_text: "Decrypting chat history…".to_owned(),
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
            Command::LoadHistory { .. } | Command::Poll { .. } => {
                self.new_chat_open = false;
                self.conversation_selected = true;
                self.chat_loading = true;
                self.history_loading = true;
                self.loading_text = "Decrypting chat history…".to_owned();
                self.status = "Conversation selected.".to_owned();
            }
            Command::LoadOlderHistory { .. } => {
                self.chat_loading = true;
                self.history_loading = true;
                self.loading_text = "Decrypting chat history…".to_owned();
                self.status = "Conversation selected.".to_owned();
            }
            Command::Send { .. } => {
                self.chat_loading = true;
                self.history_loading = false;
                self.loading_text = "Encrypting and sending…".to_owned();
                self.status = "Encrypting and sending…".to_owned();
            }
            Command::ReceivePasted { .. } => {
                self.chat_loading = true;
                self.history_loading = false;
                self.loading_text = "Decrypting pasted message…".to_owned();
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
                self.history_loading = false;
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
                self.history_loading = false;
                self.status = status.clone();
            }
            Event::Error { operation, message } => {
                self.chat_loading = false;
                self.history_loading = false;
                self.status = format!("{operation} failed: {message}");
            }
        }
    }

    pub fn select_transport(&mut self, transport: TransportKind) {
        self.selected_transport = transport;
        self.status = format!("Selected transport: {transport}");
    }

    /// Returns to the already-loaded conversation without starting another
    /// history operation.
    pub fn return_to_existing_chat(&mut self) {
        self.new_chat_open = false;
        self.conversation_selected = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, ConversationMessage, Event, TransportKind, UiState};

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

    #[test]
    fn loading_text_identifies_the_active_chat_operation() {
        let mut state = UiState::from_profiles(vec!["alice".to_owned()]);
        state.prepare(&Command::LoadHistory {
            peer: "peer".to_owned(),
        });
        assert_eq!(state.loading_text, "Decrypting chat history…");
        state.prepare(&Command::Send {
            peer: "peer".to_owned(),
            transport: TransportKind::CopyPaste,
            text: "hello".to_owned(),
        });
        assert_eq!(state.loading_text, "Encrypting and sending…");
    }

    #[test]
    fn selecting_existing_chat_closes_new_chat_mode() {
        let mut state = UiState::from_profiles(vec!["alice".to_owned()]);
        state.new_chat_open = true;

        state.prepare(&Command::LoadHistory {
            peer: "peer".to_owned(),
        });

        assert!(!state.new_chat_open);
        assert!(state.conversation_selected);
        assert!(state.history_loading);
    }

    #[test]
    fn returning_to_loaded_chat_only_changes_view_state() {
        let mut state = UiState::from_profiles(vec!["alice".to_owned()]);
        state.conversation_selected = true;
        state.new_chat_open = true;
        state.chat_loading = false;
        state.history_loading = false;
        state.messages.push(ConversationMessage {
            sender: "You".to_owned(),
            text: "hello".to_owned(),
            timestamp: 0,
            outgoing: true,
            status: "sent".to_owned(),
            ciphertext: String::new(),
        });

        state.return_to_existing_chat();

        assert!(!state.new_chat_open);
        assert!(state.conversation_selected);
        assert!(!state.chat_loading);
        assert!(!state.history_loading);
        assert_eq!(state.messages.len(), 1);

        state.return_to_existing_chat();
        assert!(!state.chat_loading);
        assert!(!state.history_loading);
        assert_eq!(state.messages.len(), 1);
    }
}
