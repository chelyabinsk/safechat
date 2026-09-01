use safechat_relay_protocol::{
    Message, Submit, decode_messages, decode_submit, encode_messages, encode_submit,
};

#[test]
fn public_submit_codec_round_trips() {
    let value = Submit {
        recipient: "recipient".to_owned(),
        message_id: "message-id".to_owned(),
        expires_at: None,
        ciphertext: vec![1, 2, 3, 4],
    };
    assert_eq!(
        decode_submit(&encode_submit(&value).expect("encode")).expect("decode"),
        value
    );
}

#[test]
fn public_message_codec_rejects_trailing_bytes() {
    let encoded = encode_messages(&[Message {
        server_id: 1,
        sender: "sender".to_owned(),
        sender_address: None,
        message_id: "message-id".to_owned(),
        ciphertext: vec![9],
        accepted_at: 10,
        expires_at: None,
    }])
    .expect("encode");
    let mut malformed = encoded;
    malformed.push(0);
    assert!(decode_messages(&malformed).is_err());
}
