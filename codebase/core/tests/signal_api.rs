use safechat_core::signal::{MessageId, SafeChatMessage, SignalEnvelope};

#[test]
fn public_signal_envelope_round_trips_without_private_state() {
    let message = SafeChatMessage::new(b"public api test");
    let envelope = SignalEnvelope {
        ciphertext: message.encode().expect("encode message"),
        message_type: SignalEnvelope::WHISPER_TYPE,
    };
    let decoded = SignalEnvelope::decode(&envelope.encode().expect("encode envelope"))
        .expect("decode envelope");
    assert_eq!(decoded.message_type, SignalEnvelope::WHISPER_TYPE);
    assert_eq!(
        SafeChatMessage::decode(&decoded.ciphertext)
            .expect("decode message")
            .plaintext,
        b"public api test"
    );
}

#[test]
fn public_message_ids_are_non_empty_and_stable_when_encoded() {
    let id = MessageId::generate();
    let encoded = id.encode();
    assert!(!encoded.is_empty());
    assert_eq!(encoded.len(), 32);
}
