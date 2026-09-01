use safechat_core::profile_store::{
    EncryptedHistoryStore, HistoryEntry, HistoryFile, HistoryStore,
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
    let history = HistoryFile::new(
        (0..3)
            .map(|index| {
                HistoryEntry::new(index, "peer", format!("message {index}"))
                    .with_message_id(format!("id-{index}"))
                    .with_peer("peer")
                    .with_delivery_status("received")
            })
            .collect(),
    )
    .with_transport_cursor(9);

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

#[test]
fn public_history_builders_preserve_optional_metadata_defaults() {
    let entry = HistoryEntry::new(42, "alice", "hello")
        .with_peer("peer-address")
        .with_delivery_status("sent");
    assert_eq!(entry.timestamp, 42);
    assert_eq!(entry.sender, "alice");
    assert_eq!(entry.text, "hello");
    assert_eq!(entry.peer, "peer-address");
    assert_eq!(entry.delivery_status, "sent");
    assert!(entry.message_id.is_empty());
    assert!(entry.ciphertext.is_empty());

    let config = safechat_core::profile_store::RelayConfig::new("https://relay", "secret")
        .with_insecure_http(true);
    assert_eq!(config.base_url, "https://relay");
    assert_eq!(config.enrollment_secret, "secret");
    assert!(config.allow_insecure_http);
}
