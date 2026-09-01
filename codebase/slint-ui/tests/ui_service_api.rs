use safechat_slint_ui::ui_service::{Command, Event, TransportKind, UiState};

#[test]
fn public_ui_state_contract_tracks_loading_and_chat_results() {
    let mut state = UiState::from_profiles(vec!["alice".to_owned()]);
    assert_eq!(state.selected_transport, TransportKind::CopyPaste);
    assert!(!state.conversation_selected);

    let command = Command::LoadHistory {
        peer: "peer-bundle".to_owned(),
    };
    state.prepare(&command);
    assert!(state.chat_loading);
    assert!(state.history_loading);

    state.apply(&Event::ChatUpdated {
        messages: Vec::new(),
        status: "Conversation selected.".to_owned(),
        history_cursor: 0,
        has_more: false,
        prepend: false,
    });
    assert!(!state.chat_loading);
    assert!(!state.history_loading);
    assert_eq!(state.status, "Conversation selected.");
}

#[test]
fn public_ui_command_operation_is_transport_aware() {
    assert_eq!(
        Command::Send {
            peer: "peer".to_owned(),
            transport: TransportKind::CopyPaste,
            text: "hello".to_owned(),
        }
        .operation()
        .to_string(),
        "chat"
    );
    assert_eq!(
        Command::Send {
            peer: "peer".to_owned(),
            transport: TransportKind::Relay,
            text: "hello".to_owned(),
        }
        .operation()
        .to_string(),
        "relay"
    );
}
