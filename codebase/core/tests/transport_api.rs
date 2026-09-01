use safechat_core::transport::{BundleTransport, RecoveryTransport, TextTransport};

#[test]
fn public_transport_adapters_round_trip_payloads_independently() {
    let payload = b"already encrypted bytes";
    let text = TextTransport;
    let bundle = BundleTransport;
    let recovery = RecoveryTransport;

    assert_eq!(
        text.decode(&text.encode(payload)).expect("text decode"),
        payload
    );
    assert_eq!(
        bundle
            .decode(&bundle.encode(payload))
            .expect("bundle decode"),
        payload
    );
    assert_eq!(
        recovery
            .decode(&recovery.encode(payload))
            .expect("recovery decode"),
        payload
    );
}
