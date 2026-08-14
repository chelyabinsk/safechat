//! Conversation domain helpers independent of the Slint view model.

use super::ConversationMessage;
use safechat::profile_store::HistoryFile;

pub(super) fn render_history(history: &HistoryFile) -> Vec<ConversationMessage> {
    history
        .entries
        .iter()
        .map(|entry| ConversationMessage {
            sender: if entry.sender == "you" {
                "You".to_owned()
            } else {
                entry.sender.clone()
            },
            text: entry.text.clone(),
            timestamp: entry.timestamp,
            outgoing: entry.sender == "you",
            status: entry.delivery_status.clone(),
            ciphertext: entry.ciphertext.clone(),
        })
        .collect()
}
