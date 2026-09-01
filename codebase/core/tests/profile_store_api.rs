use safechat_core::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryFile, HistoryStore, PROFILE_VERSION,
};

fn temporary_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "safechat-public-api-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after unix epoch")
            .as_nanos()
    ))
}

#[test]
fn encrypted_history_store_public_contract_round_trips_and_pages() {
    let root = temporary_root();
    let mut store = EncryptedHistoryStore::new(&root, "test password").expect("create store");
    let history = HistoryFile {
        version: PROFILE_VERSION,
        transport_cursor: 9,
        entries: (0..3)
            .map(|index| HistoryEntry {
                timestamp: index,
                sender: "peer".to_owned(),
                text: format!("message {index}"),
                message_id: format!("id-{index}"),
                peer: "peer".to_owned(),
                ciphertext: String::new(),
                delivery_status: "received".to_owned(),
                transport_recipient: String::new(),
            })
            .collect(),
    };

    store.save("peer", &history).expect("save history");
    let page = store.load_page("peer", None, 2).expect("load newest page");
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].text, "message 1");
    assert_eq!(page.cursor, 1);
    assert!(page.has_more);
    assert_eq!(page.transport_cursor, 9);

    let non_empty_page = store
        .load_page("peer", None, 0)
        .expect("zero-sized request must still make progress");
    assert_eq!(non_empty_page.entries.len(), 1);

    std::fs::remove_dir_all(root).expect("clean up test store");
}
